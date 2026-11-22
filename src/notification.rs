//! Receiving notifications: traps (SNMPv1, v2c, v3) and informs, which
//! are acknowledged. Sending them: [`Client::trap`](crate::client::Client::trap),
//! [`Client::inform`](crate::client::Client::inform) and
//! [`Client::trap_v1`](crate::client::Client::trap_v1).
//!
//! ```no_run
//! use snmpify::engine::LocalEngine;
//! use snmpify::notification::NotificationReceiver;
//! use snmpify::usm::{AuthProtocol, UsmUser};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let user = UsmUser::new("traps").with_auth(AuthProtocol::Sha256, "auth-password")?;
//! let mut rx = NotificationReceiver::bind("0.0.0.0:162")
//!     .await?
//!     .with_community("public")
//!     .with_engine(LocalEngine::new(LocalEngine::generate_id()).with_user(user));
//! loop {
//!     let n = rx.recv().await?;
//!     println!("{} from {}: {}", n.kind, n.source, n.trap_oid);
//!     for vb in &n.varbinds {
//!         println!("  {vb}");
//!     }
//! }
//! # }
//! ```

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::{lookup_host, UdpSocket};

use crate::engine::{LocalEngine, Received};
use crate::usm::SecurityLevel;
use crate::{AnyPdu, CommunityMessage, Oid, Pdu, PduType, TrapV1Pdu, Value, VarBind, Version};

/// `sysUpTime.0`, the first binding of a notification.
pub const SYS_UPTIME: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 3, 0];
/// `snmpTrapOID.0`, the second binding: which notification this is.
pub const SNMP_TRAP_OID: [u32; 11] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];
/// `snmpTraps`: the standard notifications (coldStart is `.1`).
pub const SNMP_TRAPS: [u32; 9] = [1, 3, 6, 1, 6, 3, 1, 1, 5];

/// A trap or an inform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotificationKind {
    /// Unconfirmed (v1 Trap-PDU or SNMPv2-Trap-PDU).
    Trap,
    /// Confirmed: acknowledged with a Response.
    Inform,
}

impl fmt::Display for NotificationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NotificationKind::Trap => "trap",
            NotificationKind::Inform => "inform",
        })
    }
}

/// Who sent a notification, and how it was secured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sender {
    /// SNMPv1 or v2c with this community.
    Community(Vec<u8>),
    /// SNMPv3.
    Usm {
        /// The user.
        user: Vec<u8>,
        /// The level it came at.
        level: SecurityLevel,
        /// The authoritative engine (the sender's for a trap, ours for an
        /// inform).
        engine_id: Vec<u8>,
        /// `contextName`.
        context_name: Vec<u8>,
    },
}

/// A received notification, in SNMPv2 form (RFC 3416 §4.2.6; v1 traps are
/// translated as in RFC 3584 §3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// The sender's address.
    pub source: SocketAddr,
    /// The message version.
    pub version: Version,
    /// Community or SNMPv3 user.
    pub sender: Sender,
    /// Trap or inform.
    pub kind: NotificationKind,
    /// `sysUpTime.0` of the sender, hundredths of a second.
    pub uptime: Option<u32>,
    /// `snmpTrapOID.0`: which notification.
    pub trap_oid: Oid,
    /// The bindings after sysUpTime.0 and snmpTrapOID.0.
    pub varbinds: Vec<VarBind>,
    /// The original PDU of an SNMPv1 trap.
    pub v1: Option<TrapV1Pdu>,
}

impl Notification {
    /// The SNMPv2 form of an SNMPv1 trap (RFC 3584 §3.1): generic traps
    /// 0–5 become `snmpTraps.1`–`.6` (coldStart … egpNeighborLoss),
    /// enterprise-specific ones `enterprise.0.specific`.
    pub fn v1_trap_oid(t: &TrapV1Pdu) -> Oid {
        if (0..6).contains(&t.generic_trap) {
            Oid::from(SNMP_TRAPS).child(&[t.generic_trap as u32 + 1])
        } else {
            t.enterprise.child(&[0, t.specific_trap as u32])
        }
    }

    fn from_v2(
        source: SocketAddr,
        version: Version,
        sender: Sender,
        kind: NotificationKind,
        pdu: Pdu,
    ) -> Option<Notification> {
        let mut vbs = pdu.varbinds.into_iter().peekable();
        let mut uptime = None;
        if vbs.peek().is_some_and(|vb| vb.oid.as_slice() == SYS_UPTIME) {
            if let Some(Value::TimeTicks(t)) = vbs.next().map(|vb| vb.value) {
                uptime = Some(t);
            }
        }
        let trap_oid = match vbs.next() {
            Some(VarBind {
                oid,
                value: Value::ObjectId(o),
            }) if oid.as_slice() == SNMP_TRAP_OID => o,
            _ => return None,
        };
        Some(Notification {
            source,
            version,
            sender,
            kind,
            uptime,
            trap_oid,
            varbinds: vbs.collect(),
            v1: None,
        })
    }
}

/// Receives notifications on a UDP socket (usually port 162).
///
/// Community-based notifications are accepted only for the communities
/// given ([`with_community`](Self::with_community)), SNMPv3 ones only for
/// the users of the [engine](Self::with_engine). Everything else is
/// dropped and counted ([`dropped`](Self::dropped)).
pub struct NotificationReceiver {
    socket: UdpSocket,
    communities: Vec<Vec<u8>>,
    any_community: bool,
    engine: Option<Arc<LocalEngine>>,
    buf: Vec<u8>,
    dropped: u64,
}

impl fmt::Debug for NotificationReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationReceiver")
            .field("local_addr", &self.socket.local_addr().ok())
            .field("engine", &self.engine.as_ref().map(|e| e.id().to_vec()))
            .field("dropped", &self.dropped)
            .finish_non_exhaustive()
    }
}

impl NotificationReceiver {
    /// Binds a receiver (`"0.0.0.0:162"`, `"[::]:162"`; port 162 needs
    /// privileges on most systems).
    pub async fn bind(addr: &str) -> io::Result<Self> {
        let addr = lookup_host(addr).await?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "address does not resolve")
        })?;
        Ok(NotificationReceiver {
            socket: UdpSocket::bind(addr).await?,
            communities: Vec::new(),
            any_community: false,
            engine: None,
            buf: vec![0; 65_535],
            dropped: 0,
        })
    }

    /// Accepts SNMPv1/v2c notifications with this community.
    pub fn with_community(mut self, community: impl AsRef<[u8]>) -> Self {
        self.communities.push(community.as_ref().to_vec());
        self
    }

    /// Accepts SNMPv1/v2c notifications with any community.
    pub fn with_any_community(mut self) -> Self {
        self.any_community = true;
        self
    }

    /// Accepts SNMPv3 notifications for this engine's users: traps from
    /// any engine, informs to this engine (whose id senders discover).
    pub fn with_engine(mut self, engine: LocalEngine) -> Self {
        self.engine = Some(Arc::new(engine));
        self
    }

    /// The local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Datagrams dropped so far (malformed, unknown community or user,
    /// failed authentication, not a notification).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The next notification. Informs are acknowledged before it is
    /// returned. Fails only on socket errors.
    pub async fn recv(&mut self) -> io::Result<Notification> {
        loop {
            let (n, from) = self.socket.recv_from(&mut self.buf).await?;
            let bytes = self.buf[..n].to_vec();
            match self.handle(&bytes, from).await? {
                Some(note) => return Ok(note),
                None => self.dropped += 1,
            }
        }
    }

    async fn handle(&self, bytes: &[u8], from: SocketAddr) -> io::Result<Option<Notification>> {
        match crate::peek_version(bytes) {
            Ok(Version::V3) => self.handle_v3(bytes, from).await,
            Ok(_) => self.handle_community(bytes, from).await,
            Err(_) => Ok(None),
        }
    }

    async fn handle_community(
        &self,
        bytes: &[u8],
        from: SocketAddr,
    ) -> io::Result<Option<Notification>> {
        let Ok(msg) = CommunityMessage::decode(bytes) else {
            return Ok(None);
        };
        if !self.any_community && !self.communities.contains(&msg.community) {
            return Ok(None);
        }
        let sender = Sender::Community(msg.community.clone());
        match msg.pdu {
            AnyPdu::TrapV1(t) if msg.version == Version::V1 => Ok(Some(Notification {
                source: from,
                version: Version::V1,
                sender,
                kind: NotificationKind::Trap,
                uptime: Some(t.timestamp),
                trap_oid: Notification::v1_trap_oid(&t),
                varbinds: t.varbinds.clone(),
                v1: Some(t),
            })),
            AnyPdu::Pdu(p) if msg.version == Version::V2c => match p.pdu_type {
                PduType::TrapV2 => Ok(Notification::from_v2(
                    from,
                    Version::V2c,
                    sender,
                    NotificationKind::Trap,
                    p,
                )),
                PduType::Inform => {
                    let ack = CommunityMessage::new(Version::V2c, &msg.community, ack(&p)).encode();
                    let Some(note) = Notification::from_v2(
                        from,
                        Version::V2c,
                        sender,
                        NotificationKind::Inform,
                        p,
                    ) else {
                        return Ok(None);
                    };
                    self.socket.send_to(&ack, from).await?;
                    Ok(Some(note))
                }
                _ => Ok(None),
            },
            _ => Ok(None),
        }
    }

    async fn handle_v3(&self, bytes: &[u8], from: SocketAddr) -> io::Result<Option<Notification>> {
        let Some(engine) = &self.engine else {
            return Ok(None);
        };
        let req = match engine.receive(bytes) {
            Received::Message(r) => r,
            Received::Report(b) => {
                // Discovery by an inform sender, or a USM failure it may learn from.
                self.socket.send_to(&b, from).await?;
                return Ok(None);
            }
            Received::Drop(_) => return Ok(None),
        };
        let sender = Sender::Usm {
            user: req.user_name.clone(),
            level: req.level,
            engine_id: req.engine_id.clone(),
            context_name: req.context_name.clone(),
        };
        let kind = match req.pdu.pdu_type {
            PduType::TrapV2 => NotificationKind::Trap,
            PduType::Inform => NotificationKind::Inform,
            _ => return Ok(None),
        };
        let Some(note) = Notification::from_v2(from, Version::V3, sender, kind, req.pdu.clone())
        else {
            return Ok(None);
        };
        if kind == NotificationKind::Inform {
            if let Ok(b) = engine.respond(&req, ack(&req.pdu)) {
                self.socket.send_to(&b, from).await?;
            }
        }
        Ok(Some(note))
    }
}

/// The Response acknowledging an inform: same id and bindings.
fn ack(p: &Pdu) -> Pdu {
    Pdu {
        pdu_type: PduType::Response,
        request_id: p.request_id,
        error_status: 0,
        error_index: 0,
        varbinds: p.varbinds.clone(),
    }
}

/// The bindings of a notification: sysUpTime.0, snmpTrapOID.0, then
/// `varbinds`.
pub fn notification_varbinds(uptime: u32, trap_oid: Oid, varbinds: Vec<VarBind>) -> Vec<VarBind> {
    let mut v = Vec::with_capacity(varbinds.len() + 2);
    v.push(VarBind::new(SYS_UPTIME, Value::TimeTicks(uptime)));
    v.push(VarBind::new(SNMP_TRAP_OID, Value::ObjectId(trap_oid)));
    v.extend(varbinds);
    v
}

/// A v1 trap for the standard `generic` traps (0 coldStart … 5
/// egpNeighborLoss) or an enterprise-specific one (generic 6).
pub fn trap_v1(
    enterprise: Oid,
    agent_addr: Ipv4Addr,
    generic_trap: i32,
    specific_trap: i32,
    timestamp: u32,
    varbinds: Vec<VarBind>,
) -> TrapV1Pdu {
    TrapV1Pdu {
        enterprise,
        agent_addr,
        generic_trap,
        specific_trap,
        timestamp,
        varbinds,
    }
}
