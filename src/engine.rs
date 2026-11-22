//! An authoritative SNMPv3 engine: the receiving side of USM (RFC 3414
//! §3.2), shared by the agent and the
//! [notification receiver](crate::notification). Feature `v3`.
//!
//! [`LocalEngine::receive`] takes a datagram and says what to do with it:
//! hand an authenticated request to the application, answer with a
//! Report (engine discovery, unknown user, wrong digest, time window …)
//! or drop it. [`LocalEngine::respond`] secures the answer at the
//! request's level.
//!
//! Traps come the other way round: their *sender* is the authoritative
//! engine. The engine accepts them from any engine id for which it knows
//! the user (keys are localized per sending engine on first use) and
//! tracks each sender's boots and time to refuse replays.
//!
//! ```
//! use snmpify::engine::{LocalEngine, Received};
//! use snmpify::usm::{AuthProtocol, UsmUser};
//!
//! let user = UsmUser::new("monitor").with_auth(AuthProtocol::Sha256, "auth-password")?;
//! let engine = LocalEngine::new(LocalEngine::generate_id()).with_user(user);
//! # let datagram: &[u8] = &[];
//! match engine.receive(datagram) {
//!     Received::Message(request) => { /* answer with engine.respond(&request, pdu) */ }
//!     Received::Report(bytes) => { /* send bytes back */ }
//!     Received::Drop(_) => {}
//! }
//! # Ok::<(), snmpify::usm::UsmError>(())
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::usm::{LocalizedUser, SecurityLevel, UsmError, UsmUser};
use crate::v3::{
    flags, ReportKind, ScopedPdu, ScopedPduData, UsmParams, V3Message, DEFAULT_MAX_SIZE,
};
use crate::{Pdu, PduType, Value, VarBind};

/// Why a message was dropped without an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropReason {
    /// Not a valid SNMPv3 message.
    Invalid,
    /// Failed a USM check and no report may be sent (not reportable, or
    /// an unconfirmed PDU such as a trap).
    Usm(UsmError),
    /// A notification from another engine, older than the last one seen
    /// from it (a replay).
    NotInTimeWindow,
    /// A PDU this engine does not take from another engine.
    WrongPduForEngine,
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DropReason::Invalid => f.write_str("invalid message"),
            DropReason::Usm(e) => write!(f, "{e}"),
            DropReason::NotInTimeWindow => f.write_str("not in time window"),
            DropReason::WrongPduForEngine => f.write_str("PDU not accepted from another engine"),
        }
    }
}

/// What to do with a received datagram.
#[derive(Debug)]
pub enum Received {
    /// An authentic message: a request or inform for this engine, or a
    /// trap from another engine.
    Message(Box<Request>),
    /// Send these bytes back to the sender (a Report PDU).
    Report(Vec<u8>),
    /// Ignore the datagram.
    Drop(DropReason),
}

/// An SNMPv3 message that passed the USM checks.
#[derive(Clone)]
pub struct Request {
    /// `msgID`, echoed in the response.
    pub msg_id: i32,
    /// The largest response the sender takes.
    pub max_size: i32,
    /// The user.
    pub user_name: Vec<u8>,
    /// The level the message came at.
    pub level: SecurityLevel,
    /// Whether the sender takes reports.
    pub reportable: bool,
    /// The authoritative engine: this one, or a trap sender's.
    pub engine_id: Vec<u8>,
    /// `contextEngineID`.
    pub context_engine_id: Vec<u8>,
    /// `contextName`.
    pub context_name: Vec<u8>,
    /// The PDU.
    pub pdu: Pdu,
    keys: Arc<LocalizedUser>,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("msg_id", &self.msg_id)
            .field("user_name", &String::from_utf8_lossy(&self.user_name))
            .field("level", &self.level)
            .field("engine_id", &self.engine_id)
            .field("context_name", &String::from_utf8_lossy(&self.context_name))
            .field("pdu", &self.pdu)
            .finish_non_exhaustive()
    }
}

/// The usmStats counters (RFC 3414 §5), reported in Report PDUs.
#[derive(Debug, Default)]
pub struct UsmStats {
    unsupported_sec_levels: AtomicU32,
    not_in_time_windows: AtomicU32,
    unknown_user_names: AtomicU32,
    unknown_engine_ids: AtomicU32,
    wrong_digests: AtomicU32,
    decryption_errors: AtomicU32,
}

impl UsmStats {
    fn counter(&self, k: &ReportKind) -> &AtomicU32 {
        match k {
            ReportKind::UnsupportedSecurityLevel => &self.unsupported_sec_levels,
            ReportKind::NotInTimeWindow => &self.not_in_time_windows,
            ReportKind::UnknownUserName => &self.unknown_user_names,
            ReportKind::UnknownEngineId => &self.unknown_engine_ids,
            ReportKind::WrongDigest => &self.wrong_digests,
            _ => &self.decryption_errors,
        }
    }

    fn bump(&self, k: &ReportKind) -> u32 {
        self.counter(k)
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// The current value of a counter.
    pub fn get(&self, k: &ReportKind) -> u32 {
        self.counter(k).load(Ordering::Relaxed)
    }
}

/// Another engine that sent us notifications: its clock and our keys.
struct Remote {
    boots: u32,
    time: u32,
    at: Instant,
    keys: HashMap<Vec<u8>, Arc<LocalizedUser>>,
}

/// An authoritative SNMPv3 engine with its users.
pub struct LocalEngine {
    id: Vec<u8>,
    boots: u32,
    start: Instant,
    users: HashMap<Vec<u8>, (UsmUser, Arc<LocalizedUser>)>,
    remotes: Mutex<HashMap<Vec<u8>, Remote>>,
    salt: AtomicU64,
    stats: UsmStats,
}

impl fmt::Debug for LocalEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEngine")
            .field("id", &self.id)
            .field("boots", &self.boots)
            .field(
                "users",
                &self.users.values().map(|u| &u.0).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Engines further apart than this (seconds) are out of the time window.
const TIME_WINDOW: u32 = 150;

impl LocalEngine {
    /// An engine with this id (5 to 32 octets, RFC 3411), booted once.
    pub fn new(id: impl Into<Vec<u8>>) -> Self {
        let id = id.into();
        let seed = Self::random(&id);
        LocalEngine {
            id,
            boots: 1,
            start: Instant::now(),
            users: HashMap::new(),
            remotes: Mutex::new(HashMap::new()),
            salt: AtomicU64::new(u64::from_be_bytes(seed[..8].try_into().unwrap_or([1; 8]))),
            stats: UsmStats::default(),
        }
    }

    /// A random engine id in the RFC 3411 "octets" format (enterprise 0,
    /// format 5, 8 random octets). Agents should keep theirs across
    /// restarts: managers cache it.
    pub fn generate_id() -> Vec<u8> {
        let r = Self::random(b"engine id");
        let mut id = vec![0x80, 0x00, 0x00, 0x00, 0x05];
        id.extend_from_slice(&r[..8]);
        id
    }

    fn random(extra: &[u8]) -> [u8; 32] {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let local = 0u8;
        let mut h = Sha256::new();
        h.update(now.to_be_bytes());
        h.update(std::process::id().to_be_bytes());
        h.update((&local as *const u8 as usize).to_be_bytes());
        h.update(format!("{:?}", std::thread::current().id()));
        h.update(extra);
        h.finalize().into()
    }

    /// Sets `snmpEngineBoots` (increment and persist it on every start).
    pub fn with_boots(mut self, boots: u32) -> Self {
        self.boots = boots.min(i32::MAX as u32);
        self
    }

    /// Adds a user (its keys are localized to this engine now).
    pub fn with_user(mut self, user: UsmUser) -> Self {
        let keys = Arc::new(user.localize(&self.id));
        self.users.insert(user.name().to_vec(), (user, keys));
        self
    }

    /// `snmpEngineID`.
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// `snmpEngineBoots`.
    pub fn boots(&self) -> u32 {
        self.boots
    }

    /// `snmpEngineTime`: seconds since the engine was made.
    pub fn time(&self) -> u32 {
        self.start.elapsed().as_secs().min(i32::MAX as u64) as u32
    }

    /// Hundredths of a second since the engine was made (sysUpTime).
    pub fn uptime(&self) -> u32 {
        (self.start.elapsed().as_millis() / 10) as u32
    }

    /// The usmStats counters.
    pub fn stats(&self) -> &UsmStats {
        &self.stats
    }

    fn next_salt(&self) -> u64 {
        self.salt.fetch_add(1, Ordering::Relaxed)
    }

    /// A Report for `msg` (unauthenticated unless `keys` is given).
    fn report(&self, msg: &V3Message, kind: ReportKind, keys: Option<&LocalizedUser>) -> Received {
        let count = self.stats.bump(&kind);
        if msg.flags & flags::REPORTABLE == 0 {
            return Received::Drop(DropReason::Usm(match kind {
                ReportKind::UnknownUserName => UsmError::UnknownUserName,
                ReportKind::UnknownEngineId => UsmError::UnknownEngineId,
                ReportKind::WrongDigest => UsmError::WrongDigest,
                ReportKind::DecryptionError => UsmError::DecryptionError,
                _ => UsmError::UnsupportedSecurityLevel,
            }));
        }
        let (request_id, context_name) = match &msg.data {
            ScopedPduData::Plaintext(s) => (s.pdu.request_id, s.context_name.clone()),
            ScopedPduData::Encrypted(_) => (0, Vec::new()),
        };
        let report = V3Message {
            msg_id: msg.msg_id,
            max_size: DEFAULT_MAX_SIZE,
            flags: 0,
            usm: UsmParams {
                engine_id: self.id.clone(),
                engine_boots: self.boots,
                engine_time: self.time(),
                user_name: msg.usm.user_name.clone(),
                ..UsmParams::default()
            },
            data: ScopedPduData::Plaintext(ScopedPdu::new(
                self.id.clone(),
                context_name,
                Pdu {
                    pdu_type: PduType::Report,
                    request_id,
                    error_status: 0,
                    error_index: 0,
                    varbinds: vec![VarBind::new(kind.oid(), Value::Counter32(count))],
                },
            )),
        };
        let bytes = match keys {
            // RFC 3414 §3.2.7 a): notInTimeWindow is reported at authNoPriv.
            Some(k) => k.seal_with_level(report, SecurityLevel::AuthNoPriv, self.next_salt()),
            None => Ok(report.encode()),
        };
        match bytes {
            Ok(b) => Received::Report(b),
            Err(e) => Received::Drop(DropReason::Usm(e)),
        }
    }

    /// Processes a received datagram (RFC 3414 §3.2).
    pub fn receive(&self, bytes: &[u8]) -> Received {
        let Ok(msg) = V3Message::decode(bytes) else {
            return Received::Drop(DropReason::Invalid);
        };
        if msg.usm.engine_id != self.id {
            if msg.usm.engine_id.is_empty() || !self.users.contains_key(&msg.usm.user_name) {
                // Engine discovery, or a request for another engine.
                return self.report(&msg, ReportKind::UnknownEngineId, None);
            }
            return self.receive_remote(bytes, msg);
        }
        let Some((_, keys)) = self.users.get(&msg.usm.user_name) else {
            return self.report(&msg, ReportKind::UnknownUserName, None);
        };
        let opened = match keys.open(bytes) {
            Ok(m) => m,
            Err(UsmError::WrongDigest) => return self.report(&msg, ReportKind::WrongDigest, None),
            Err(UsmError::DecryptionError) => {
                return self.report(&msg, ReportKind::DecryptionError, None)
            }
            Err(UsmError::Decode(_)) => return Received::Drop(DropReason::Invalid),
            Err(_) => return self.report(&msg, ReportKind::UnsupportedSecurityLevel, None),
        };
        let level = SecurityLevel::from_flags(opened.flags);
        if level != SecurityLevel::NoAuthNoPriv {
            let (b, t) = (opened.usm.engine_boots, opened.usm.engine_time);
            if self.boots == i32::MAX as u32
                || b != self.boots
                || t.abs_diff(self.time()) > TIME_WINDOW
            {
                return self.report(&msg, ReportKind::NotInTimeWindow, Some(keys));
            }
        }
        Received::Message(Box::new(Self::request(opened, level, keys.clone())))
    }

    fn request(m: V3Message, level: SecurityLevel, keys: Arc<LocalizedUser>) -> Request {
        let ScopedPduData::Plaintext(s) = m.data else {
            unreachable!("open returns a plaintext scoped PDU")
        };
        Request {
            msg_id: m.msg_id,
            max_size: m.max_size,
            user_name: m.usm.user_name,
            level,
            reportable: m.flags & flags::REPORTABLE != 0,
            engine_id: m.usm.engine_id,
            context_engine_id: s.context_engine_id,
            context_name: s.context_name,
            pdu: s.pdu,
            keys,
        }
    }

    /// A notification from another (authoritative) engine.
    fn receive_remote(&self, bytes: &[u8], msg: V3Message) -> Received {
        let engine = msg.usm.engine_id.clone();
        let name = msg.usm.user_name.clone();
        let keys = {
            let mut remotes = self.remotes.lock().unwrap_or_else(|e| e.into_inner());
            let r = remotes.entry(engine.clone()).or_insert_with(|| Remote {
                boots: 0,
                time: 0,
                at: Instant::now(),
                keys: HashMap::new(),
            });
            let user = &self.users[&name].0;
            r.keys
                .entry(name)
                .or_insert_with(|| Arc::new(user.localize(&engine)))
                .clone()
        };
        // Notifications are unconfirmed and never reportable; anything
        // reportable under another engine id is a request for an engine
        // we are not (e.g. a manager with a stale engine id): tell it.
        if msg.flags & flags::REPORTABLE != 0 {
            return self.report(&msg, ReportKind::UnknownEngineId, None);
        }
        let opened = match keys.open(bytes) {
            Ok(m) => m,
            Err(e) => return Received::Drop(DropReason::Usm(e)),
        };
        let level = SecurityLevel::from_flags(opened.flags);
        let ScopedPduData::Plaintext(s) = &opened.data else {
            return Received::Drop(DropReason::Invalid);
        };
        if s.pdu.pdu_type != PduType::TrapV2 {
            // Only notifications come with the sender's engine id.
            return Received::Drop(DropReason::WrongPduForEngine);
        }
        if level != SecurityLevel::NoAuthNoPriv {
            // RFC 3414 §3.2.7 b), as the non-authoritative side.
            let (b, t) = (opened.usm.engine_boots, opened.usm.engine_time);
            let mut remotes = self.remotes.lock().unwrap_or_else(|e| e.into_inner());
            let r = remotes.get_mut(&engine).expect("inserted above");
            let estimate = r.time.saturating_add(r.at.elapsed().as_secs() as u32);
            let known = r.boots != 0 || r.time != 0;
            if known
                && (b == i32::MAX as u32
                    || b < r.boots
                    || (b == r.boots && t.saturating_add(TIME_WINDOW) < estimate))
            {
                return Received::Drop(DropReason::NotInTimeWindow);
            }
            if !known || b > r.boots || (b == r.boots && t > r.time) {
                r.boots = b;
                r.time = t;
                r.at = Instant::now();
            }
        }
        Received::Message(Box::new(Self::request(opened, level, keys)))
    }

    /// The answer to `request`: `pdu` sealed at the request's level with
    /// the same msgID and context.
    pub fn respond(&self, request: &Request, pdu: Pdu) -> Result<Vec<u8>, UsmError> {
        let msg = V3Message {
            msg_id: request.msg_id,
            max_size: DEFAULT_MAX_SIZE,
            flags: 0,
            usm: UsmParams {
                engine_boots: self.boots,
                engine_time: self.time(),
                ..UsmParams::default()
            },
            data: ScopedPduData::Plaintext(ScopedPdu::new(
                request.context_engine_id.clone(),
                request.context_name.clone(),
                pdu,
            )),
        };
        request
            .keys
            .seal_with_level(msg, request.level, self.next_salt())
    }

    /// A message from this engine as the authoritative one (a trap):
    /// sealed for `user` at its level, with this engine's boots and time.
    pub fn originate(
        &self,
        user: &[u8],
        msg_id: i32,
        context_name: &[u8],
        pdu: Pdu,
    ) -> Result<Vec<u8>, UsmError> {
        let Some((_, keys)) = self.users.get(user) else {
            return Err(UsmError::UnknownUserName);
        };
        let msg = V3Message {
            msg_id,
            max_size: DEFAULT_MAX_SIZE,
            flags: 0,
            usm: UsmParams {
                engine_boots: self.boots,
                engine_time: self.time(),
                ..UsmParams::default()
            },
            data: ScopedPduData::Plaintext(ScopedPdu::new(self.id.clone(), context_name, pdu)),
        };
        keys.seal(msg, self.next_salt())
    }
}

#[cfg(test)]
mod tests;
