//! Async SNMP client (tokio): SNMPv1, v2c and v3.
//!
//! A [`Client`] talks to one agent. Clients made by one [`Manager`] share a
//! single UDP socket and receive task, so polling thousands of agents costs
//! one socket, not thousands. Requests can run concurrently on a cloned
//! client; responses are matched by request id and source address, and
//! retransmitted on timeout.
//!
//! ```no_run
//! use snmpify::client::{Client, Community};
//!
//! # async fn run() -> Result<(), snmpify::client::Error> {
//! let client = Client::connect("192.0.2.1:161", Community::v2c("public")).await?;
//! let descr = client.get_one("1.3.6.1.2.1.1.1.0").await?;
//! println!("{descr}");
//!
//! let mut walk = client.walk("1.3.6.1.2.1.2.2")?; // ifTable, with GetBulk
//! while let Some(vb) = walk.next().await {
//!     println!("{}", vb?);
//! }
//! # Ok(()) }
//! ```
//!
//! SNMPv3: the same client with a [`UsmUser`]. The agent's engine id,
//! boots and time are discovered on the first request (RFC 3414 §4) and
//! kept in sync; responses must be authenticated (and decrypted) with the
//! user's keys, so forged answers are ignored.
//!
//! ```no_run
//! use snmpify::client::Client;
//! use snmpify::usm::{AuthProtocol, PrivProtocol, UsmUser};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let user = UsmUser::new("monitor")
//!     .with_auth(AuthProtocol::Sha256, "auth-password")?
//!     .with_privacy(PrivProtocol::Aes128, "priv-password")?;
//! let client = Client::connect("192.0.2.1:161", user).await?;
//! println!("{}", client.get_one("1.3.6.1.2.1.1.5.0").await?);
//! # Ok(()) }
//! ```

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::engine::LocalEngine;
use crate::notification::notification_varbinds;
use crate::usm::{LocalizedUser, SecurityLevel, UsmError, UsmUser};
use crate::v3::{
    flags, peek_msg_id, ReportKind, ScopedPdu, ScopedPduData, UsmParams, V3Message,
    DEFAULT_MAX_SIZE,
};
use crate::{
    peek_version, AnyPdu, CommunityMessage, DecodeError, ErrorStatus, Oid, ParseOidError, Pdu,
    PduType, Value, VarBind, Version,
};

/// Client errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// No response after all retries.
    Timeout,
    /// A socket error.
    Io(io::Error),
    /// A response that could not be decoded.
    Decode(DecodeError),
    /// The agent answered with an error status.
    Snmp {
        /// The error status.
        status: ErrorStatus,
        /// 1-based index of the failing binding (0: the whole request).
        index: u32,
        /// The OID of the failing binding, when the index names one.
        oid: Option<Box<Oid>>,
    },
    /// A walk received an OID that does not come after the previous one
    /// (a broken agent; walking on would loop forever).
    NotIncreasing {
        /// The previous OID.
        previous: Box<Oid>,
        /// The OID that came next.
        next: Box<Oid>,
    },
    /// An OID string that does not parse.
    InvalidOid(ParseOidError),
    /// An argument the request cannot carry (e.g. GetBulk with SNMPv1).
    InvalidArgument(&'static str),
    /// The response did not match the request (wrong PDU type or bindings).
    UnexpectedResponse(&'static str),
    /// SNMPv3: the agent answered with a Report (e.g. unknown user, wrong
    /// digest: wrong password or protocol).
    Report(ReportKind),
    /// SNMPv3: the request could not be secured (e.g. a user name longer
    /// than 32 octets).
    Usm(UsmError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Timeout => f.write_str("timeout: no response from the agent"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Decode(e) => write!(f, "invalid response: {e}"),
            Error::Snmp { status, index, oid } => match oid {
                Some(o) => write!(f, "agent error {status} at binding {index} ({o})"),
                None => write!(f, "agent error {status}"),
            },
            Error::NotIncreasing { previous, next } => {
                write!(f, "OID not increasing: {next} after {previous}")
            }
            Error::InvalidOid(e) => write!(f, "{e}"),
            Error::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Error::UnexpectedResponse(m) => write!(f, "unexpected response: {m}"),
            Error::Report(k) => write!(f, "agent report: {k}"),
            Error::Usm(e) => write!(f, "SNMPv3: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Decode(e) => Some(e),
            Error::InvalidOid(e) => Some(e),
            Error::Usm(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ParseOidError> for Error {
    fn from(e: ParseOidError) -> Self {
        Error::InvalidOid(e)
    }
}

/// A result with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Something that names an OID: an [`Oid`], a dotted string or an array.
pub trait IntoOid {
    /// Converts to an [`Oid`].
    fn into_oid(self) -> Result<Oid>;
}

impl IntoOid for Oid {
    fn into_oid(self) -> Result<Oid> {
        Ok(self)
    }
}
impl IntoOid for &Oid {
    fn into_oid(self) -> Result<Oid> {
        Ok(self.clone())
    }
}
impl IntoOid for &str {
    fn into_oid(self) -> Result<Oid> {
        Ok(self.parse()?)
    }
}
impl IntoOid for String {
    fn into_oid(self) -> Result<Oid> {
        Ok(self.parse()?)
    }
}
impl IntoOid for &[u32] {
    fn into_oid(self) -> Result<Oid> {
        Ok(Oid::from_slice(self))
    }
}
impl<const N: usize> IntoOid for [u32; N] {
    fn into_oid(self) -> Result<Oid> {
        Ok(Oid::from(self))
    }
}

fn oids<I: IntoOid>(it: impl IntoIterator<Item = I>) -> Result<Vec<Oid>> {
    it.into_iter().map(IntoOid::into_oid).collect()
}

/// Community-based credentials: SNMP version and community string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Community {
    version: Version,
    community: Arc<[u8]>,
}

impl Community {
    /// SNMPv1 with a community.
    pub fn v1(community: impl AsRef<[u8]>) -> Self {
        Self {
            version: Version::V1,
            community: community.as_ref().into(),
        }
    }

    /// SNMPv2c with a community.
    pub fn v2c(community: impl AsRef<[u8]>) -> Self {
        Self {
            version: Version::V2c,
            community: community.as_ref().into(),
        }
    }

    /// The version.
    pub fn version(&self) -> Version {
        self.version
    }
}

/// SNMPv3 credentials: a user and the context to address.
#[derive(Clone, Debug)]
pub struct Usm {
    user: UsmUser,
    context_name: Vec<u8>,
    engine_id: Option<Vec<u8>>,
}

impl Usm {
    /// The user, with the default (empty) context.
    pub fn new(user: UsmUser) -> Self {
        Self {
            user,
            context_name: Vec::new(),
            engine_id: None,
        }
    }

    /// This side's engine id, used when sending SNMPv3 traps (the sender
    /// of a trap is the authoritative engine). Default: a random one per
    /// client ([`LocalEngine::generate_id`]); receivers that check the
    /// engine id need a fixed one.
    pub fn with_engine_id(mut self, id: impl Into<Vec<u8>>) -> Self {
        self.engine_id = Some(id.into());
        self
    }

    /// Addresses a named context (e.g. a VLAN or a VRF on some agents).
    pub fn with_context(mut self, name: impl AsRef<[u8]>) -> Self {
        self.context_name = name.as_ref().to_vec();
        self
    }
}

/// What a client authenticates with: a community (v1, v2c) or an SNMPv3
/// user. Made from a [`Community`], a [`UsmUser`] or a [`Usm`].
#[derive(Clone, Debug)]
pub enum Credentials {
    /// SNMPv1 or v2c.
    Community(Community),
    /// SNMPv3 with the User-based Security Model.
    Usm(Usm),
}

impl From<Community> for Credentials {
    fn from(c: Community) -> Self {
        Credentials::Community(c)
    }
}

impl From<Usm> for Credentials {
    fn from(u: Usm) -> Self {
        Credentials::Usm(u)
    }
}

impl From<UsmUser> for Credentials {
    fn from(u: UsmUser) -> Self {
        Credentials::Usm(Usm::new(u))
    }
}

/// Requests a socket has in flight at most by default
/// ([`Manager::with_max_in_flight`]). A burst of answers larger than the
/// socket's receive buffer (about 200 datagrams with Linux defaults) is
/// partly dropped and must be retried; waiting for a slot is far faster.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

/// Timeouts, retries and walk settings.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Time to wait for each attempt. Default 1 s.
    pub timeout: Duration,
    /// Retransmissions after the first attempt. Default 2.
    pub retries: u32,
    /// Bindings asked per GetBulk in a walk. Default 25.
    pub max_repetitions: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            retries: 2,
            max_repetitions: 25,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared transport: one socket, one receive task, many outstanding requests
// ---------------------------------------------------------------------------

/// Request ids are already spread out: a multiplicative hash is enough
/// (SipHash would cost more than the rest of the lookup).
#[derive(Default, Clone, Copy)]
struct IdHasher(u64);

impl std::hash::Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 << 8) | b as u64;
        }
    }
    fn write_i32(&mut self, v: i32) {
        self.0 = v as u32 as u64;
    }
}

type IdHash = std::hash::BuildHasherDefault<IdHasher>;

/// What an answer must be to be accepted for a request.
#[derive(Clone)]
enum Expect {
    Community {
        version: Version,
        community: Arc<[u8]>,
    },
    V3 {
        keys: Arc<LocalizedUser>,
        level: SecurityLevel,
        /// The engine boots and time the request was sent with.
        window: (u32, u32),
    },
}

enum Reply {
    /// The whole message (decoded by the request: owned or in place).
    Community(Vec<u8>),
    V3 {
        pdu: Pdu,
        usm: UsmParams,
        authenticated: bool,
    },
}

struct Waiter {
    from: SocketAddr,
    expect: Expect,
    tx: oneshot::Sender<Reply>,
    /// When the current attempt times out (UDP; the reader expires it).
    deadline: Instant,
}

/// What the request reading the UDP socket holds: the buffer, and one
/// sleep for every request's deadline. The sleep is armed at the earliest
/// deadline and re-armed only when it fires or an earlier deadline comes
/// (`Shared::rearm`), so a request costs no timer of its own.
struct Receiver {
    buf: Vec<u8>,
    sleep: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    armed: Option<Instant>,
}

impl Receiver {
    /// Arms the sleep for `d` if it is earlier than what is armed.
    fn arm(&mut self, d: Instant) {
        if self.armed.is_some_and(|a| a <= d) {
            return;
        }
        self.armed = Some(d);
        match &mut self.sleep {
            Some(s) => s.as_mut().reset(d.into()),
            None => self.sleep = Some(Box::pin(tokio::time::sleep_until(d.into()))),
        }
    }
}

/// UDP, or one TCP connection to one agent (RFC 3430).
enum Socket {
    Udp(UdpSocket),
    Tcp {
        write: tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>,
        local: SocketAddr,
    },
}

struct Shared {
    socket: Socket,
    /// UDP connected to its one agent (cheaper sends; the kernel filters
    /// the source).
    connected: bool,
    pending: Mutex<HashMap<i32, Waiter, IdHash>>,
    /// The right to read the UDP socket, with the receive buffer. A waiting
    /// request takes it, reads until its own answer comes (no hand-off for
    /// that one) and passes the others' answers on; then the next waiting
    /// request takes it (the lock is fair: no thundering herd).
    receiver: Mutex<Option<Receiver>>,
    /// Signalled when the receiver is put back (a waiting request may take
    /// it).
    receiver_free: tokio::sync::Notify,
    /// The earliest deadline any request registered (as nanoseconds since
    /// `start`); a request with a deadline before it wakes the reader to
    /// re-arm.
    earliest: AtomicU64,
    rearm: std::sync::atomic::AtomicBool,
    reader_waker: Mutex<Option<std::task::Waker>>,
    next_id: AtomicU32,
    /// Privacy salts: must not repeat for a key, so a counter.
    next_salt: AtomicU64,
    check_source: bool,
    /// For sysUpTime.0 in notifications.
    start: Instant,
    /// Requests in flight on the socket; more wait for a permit, so a burst
    /// of answers does not overflow the socket's receive buffer.
    in_flight: std::sync::atomic::AtomicUsize,
    in_flight_limit: std::sync::atomic::AtomicUsize,
    in_flight_free: tokio::sync::Notify,
}

impl Shared {
    async fn send(&self, bytes: &[u8], target: SocketAddr) -> io::Result<()> {
        match &self.socket {
            Socket::Udp(s) if self.connected => s.send(bytes).await.map(|_| ()),
            Socket::Udp(s) => s.send_to(bytes, target).await.map(|_| ()),
            Socket::Tcp { write, .. } => {
                use tokio::io::AsyncWriteExt;
                write.lock().await.write_all(bytes).await
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.socket {
            Socket::Udp(s) => s.local_addr(),
            Socket::Tcp { local, .. } => Ok(*local),
        }
    }

    fn is_tcp(&self) -> bool {
        matches!(self.socket, Socket::Tcp { .. })
    }

    /// Notes a new deadline; wakes the reader if it must re-arm earlier.
    fn register_deadline(&self, d: Instant) {
        let ns = d.saturating_duration_since(self.start).as_nanos() as u64;
        if self.earliest.fetch_min(ns, Ordering::AcqRel) > ns {
            self.rearm.store(true, Ordering::Release);
            if let Some(w) = &*self.reader_waker.lock().unwrap_or_else(|e| e.into_inner()) {
                w.wake_by_ref();
            }
        }
    }

    /// A slot for a request in flight (waits while the limit is reached).
    async fn slot(&self) -> Slot<'_> {
        loop {
            let limit = self.in_flight_limit.load(Ordering::Acquire);
            let cur = self.in_flight.load(Ordering::Acquire);
            if cur < limit {
                if self
                    .in_flight
                    .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Slot(self);
                }
                continue;
            }
            let freed = self.in_flight_free.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if self.in_flight.load(Ordering::Acquire) < self.in_flight_limit.load(Ordering::Acquire)
            {
                continue;
            }
            freed.await;
        }
    }

    /// The receiver, if nobody holds it.
    fn try_take_receiver(&self) -> Option<ReceiverGuard<'_>> {
        let r = self
            .receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()?;
        Some(ReceiverGuard {
            shared: self,
            r: Some(r),
        })
    }

    /// The receiver (the right to read the socket), when it is free.
    async fn take_receiver(&self) -> ReceiverGuard<'_> {
        loop {
            let freed = self.receiver_free.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if let Some(r) = self
                .receiver
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                return ReceiverGuard {
                    shared: self,
                    r: Some(r),
                };
            }
            freed.await;
        }
    }

    /// Ready when a request registered a deadline earlier than the armed
    /// one (the reader then re-arms).
    fn poll_rearm(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        if self.rearm.swap(false, Ordering::AcqRel) {
            return std::task::Poll::Ready(());
        }
        {
            let mut w = self.reader_waker.lock().unwrap_or_else(|e| e.into_inner());
            if !w.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                *w = Some(cx.waker().clone());
            }
        }
        if self.rearm.swap(false, Ordering::AcqRel) {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }

    /// Drops the waiters past their deadline (except `own`, which the
    /// reader handles itself); returns the earliest deadline left.
    fn expire(&self, now: Instant, own: i32) -> Option<Instant> {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        p.retain(|id, w| *id == own || w.deadline > now);
        let next = p.values().map(|w| w.deadline).min();
        let ns = next.map_or(u64::MAX, |d| {
            d.saturating_duration_since(self.start).as_nanos() as u64
        });
        self.earliest.store(ns, Ordering::Release);
        next
    }

    fn take(&self, id: i32) -> Option<Waiter> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
    }
}

struct Transport {
    shared: Arc<Shared>,
    /// The TCP reader (UDP needs no task: requests read the socket).
    task: Option<JoinHandle<()>>,
}

impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}

impl Transport {
    /// A UDP socket; `connect`ed to its agent when it has only one.
    async fn bind(
        local: SocketAddr,
        check_source: bool,
        connect: Option<SocketAddr>,
    ) -> io::Result<Arc<Transport>> {
        let socket = UdpSocket::bind(local).await?;
        if let Some(target) = connect {
            socket.connect(target).await?;
        }
        Ok(Self::start(
            Socket::Udp(socket),
            check_source,
            connect.is_some(),
            None,
        ))
    }

    /// A TCP connection to `target`.
    async fn connect_tcp(target: SocketAddr) -> io::Result<Arc<Transport>> {
        let stream = tokio::net::TcpStream::connect(target).await?;
        stream.set_nodelay(true)?;
        let local = stream.local_addr()?;
        let (read, write) = stream.into_split();
        let socket = Socket::Tcp {
            write: tokio::sync::Mutex::new(write),
            local,
        };
        Ok(Self::start(socket, false, false, Some((read, target))))
    }

    fn start(
        socket: Socket,
        check_source: bool,
        connected: bool,
        tcp: Option<(tokio::net::tcp::OwnedReadHalf, SocketAddr)>,
    ) -> Arc<Transport> {
        // Start request ids somewhere unpredictable, like net-snmp, so that a
        // restarted manager does not accept late answers to its predecessor.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32).rotate_left(16))
            .unwrap_or(1)
            ^ std::process::id();
        let shared = Arc::new(Shared {
            socket,
            connected,
            pending: Mutex::new(HashMap::default()),
            receiver: Mutex::new(Some(Receiver {
                buf: Vec::new(),
                sleep: None,
                armed: None,
            })),
            receiver_free: tokio::sync::Notify::new(),
            earliest: AtomicU64::new(u64::MAX),
            rearm: std::sync::atomic::AtomicBool::new(false),
            reader_waker: Mutex::new(None),
            next_id: AtomicU32::new(seed),
            next_salt: AtomicU64::new(((seed as u64) << 32) ^ seed.rotate_left(7) as u64),
            check_source,
            start: Instant::now(),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            in_flight_limit: std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_IN_FLIGHT),
            in_flight_free: tokio::sync::Notify::new(),
        });
        let task = tcp.map(|(read, peer)| tokio::spawn(receive_tcp(shared.clone(), read, peer)));
        Arc::new(Transport { shared, task })
    }

    fn next_id(&self) -> i32 {
        (self.shared.next_id.fetch_add(1, Ordering::Relaxed) & 0x7FFF_FFFF) as i32
    }

    fn next_salt(&self) -> u64 {
        self.shared.next_salt.fetch_add(1, Ordering::Relaxed)
    }
}

/// Reads messages from a TCP connection until it ends; then fails the
/// requests still waiting (their channels close).
async fn receive_tcp(
    shared: Arc<Shared>,
    mut read: tokio::net::tcp::OwnedReadHalf,
    peer: SocketAddr,
) {
    while let Ok(Some(msg)) = crate::tcp::read_message(&mut read).await {
        dispatch(&shared, &msg, peer, None);
    }
    shared
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

/// What a request's answer is handed over as: in place (still in the
/// receive buffer) or owned.
enum ReplyRef<'a> {
    Community(&'a [u8]),
    Owned(Reply),
}

/// The reader's own answer, as `dispatch` found it.
enum Mine {
    /// A valid community answer: the datagram itself.
    Raw,
    /// An answer already decoded (SNMPv3: decrypted).
    Reply(Reply),
}

/// The request reading the socket: its id, expectation and agent.
struct Own<'a> {
    id: i32,
    expect: &'a Expect,
    target: SocketAddr,
}

/// Hands an answer to the request it belongs to, if it passes the checks;
/// an answer for `own` (the request doing the reading, not in the table)
/// is returned instead.
fn dispatch(
    shared: &Shared,
    bytes: &[u8],
    from: SocketAddr,
    own: Option<&Own<'_>>,
) -> Option<Mine> {
    {
        // Not SNMP or malformed: ignore, the request may retry.
        let Ok(version) = peek_version(bytes) else {
            return None;
        };
        // Community messages: the headers are enough to match (the
        // request decodes the bindings, owned or in place).
        let (id, community) = if version == Version::V3 {
            let id = peek_msg_id(bytes)?;
            (id, None)
        } else {
            let (v, c, pdu) = crate::view::community_pdu(bytes).ok()?;
            (pdu.request_id, Some((v, c)))
        };
        let mine = own.filter(|o| o.id == id);
        let waiter = match mine {
            Some(_) => None,
            None => Some(shared.take(id)?),
        };
        let (expect, expected_from) = match (mine, &waiter) {
            (Some(o), _) => (o.expect, o.target),
            (None, Some(w)) => (&w.expect, w.from),
            (None, None) => return None,
        };
        let reply = if shared.check_source && expected_from != from {
            None
        } else {
            match (expect, community) {
                (
                    Expect::Community {
                        version,
                        community: c,
                    },
                    Some((v, mc)),
                ) if *version == v && **c == *mc => Some(Mine::Raw),
                (Expect::V3 { .. }, None) => accept_v3(expect, bytes).map(Mine::Reply),
                _ => None,
            }
        };
        let Some(w) = waiter else {
            return reply; // ours (or not a valid answer: ignored)
        };
        match reply {
            Some(m) => {
                let r = match m {
                    Mine::Raw => Reply::Community(bytes.to_vec()),
                    Mine::Reply(r) => r,
                };
                let _ = w.tx.send(r);
                None
            }
            None => {
                // Not our answer (spoofed, forged, another agent): keep waiting.
                shared
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id, w);
                None
            }
        }
    }
}

/// Verifies an SNMPv3 answer (RFC 3412 §7.2, RFC 3414 §3.2): a Response
/// must come at the request's security level, for its engine, within the
/// time window; a Report may come unauthenticated (unknown user, wrong
/// digest and engine discovery reports always do).
fn accept_v3(expect: &Expect, bytes: &[u8]) -> Option<Reply> {
    let Expect::V3 {
        keys,
        level,
        window,
    } = expect
    else {
        return None;
    };
    let msg = keys.open(bytes).ok()?;
    let ScopedPduData::Plaintext(scoped) = msg.data else {
        return None;
    };
    let got = SecurityLevel::from_flags(msg.flags);
    let authenticated = got != SecurityLevel::NoAuthNoPriv;
    match scoped.pdu.pdu_type {
        PduType::Response => {
            if got != *level || msg.usm.engine_id != keys.engine_id() {
                return None;
            }
        }
        PduType::Report => {}
        _ => return None,
    }
    if authenticated && !timely(*window, &msg.usm) {
        return None;
    }
    Some(Reply::V3 {
        pdu: scoped.pdu,
        usm: msg.usm,
        authenticated,
    })
}

/// RFC 3414 §3.2.7 b), for the non-authoritative side: a message is late
/// when the agent's boots went back or its time is 150 s behind ours.
fn timely((boots, time): (u32, u32), usm: &UsmParams) -> bool {
    !(usm.engine_boots == i32::MAX as u32
        || usm.engine_boots < boots
        || (usm.engine_boots == boots && usm.engine_time.saturating_add(150) < time))
}

/// A request in flight; frees its place when dropped.
struct Slot<'a>(&'a Shared);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
        // Always: two places freed before a woken waiter runs would
        // otherwise leave the second waiter asleep. Cheap without waiters.
        self.0.in_flight_free.notify_one();
    }
}

/// The receiver taken by a request; put back (and the next waiting
/// request told) when dropped, even if the request is cancelled.
struct ReceiverGuard<'a> {
    shared: &'a Shared,
    r: Option<Receiver>,
}

impl std::ops::Deref for ReceiverGuard<'_> {
    type Target = Receiver;
    fn deref(&self) -> &Receiver {
        self.r.as_ref().expect("held until dropped")
    }
}

impl std::ops::DerefMut for ReceiverGuard<'_> {
    fn deref_mut(&mut self) -> &mut Receiver {
        self.r.as_mut().expect("held until dropped")
    }
}

impl Drop for ReceiverGuard<'_> {
    fn drop(&mut self) {
        *self
            .shared
            .receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = self.r.take();
        self.shared.receiver_free.notify_one();
    }
}

/// Removes a pending request when its future is dropped (cancellation).
struct PendingGuard<'a> {
    shared: &'a Shared,
    id: i32,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.shared.take(self.id);
    }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// Many agents over one UDP socket.
///
/// ```no_run
/// use snmpify::client::{Community, Manager};
///
/// # async fn run(hosts: Vec<std::net::SocketAddr>) -> Result<(), snmpify::client::Error> {
/// let manager = Manager::bind("0.0.0.0:0").await?;
/// let mut tasks = Vec::new();
/// for host in hosts {
///     let client = manager.client(host, Community::v2c("public"));
///     tasks.push(tokio::spawn(async move { client.get_one("1.3.6.1.2.1.1.3.0").await }));
/// }
/// for t in tasks {
///     println!("{:?}", t.await.unwrap());
/// }
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct Manager {
    transport: Arc<Transport>,
    options: Options,
}

impl Manager {
    /// A manager on a local address (`"0.0.0.0:0"` for any port, or
    /// `"[::]:0"` for IPv6).
    pub async fn bind(local: &str) -> Result<Manager> {
        let local = lookup_host(local)
            .await?
            .next()
            .ok_or(Error::InvalidArgument("local address does not resolve"))?;
        Ok(Manager {
            transport: Transport::bind(local, true, None).await?,
            options: Options::default(),
        })
    }

    /// Default options for the clients made from now on.
    pub fn with_options(mut self, options: Options) -> Self {
        self.options = options;
        self
    }

    /// The local address of the socket.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.transport.shared.local_addr()?)
    }

    /// At most `n` requests in flight on the socket at once (default
    /// [`DEFAULT_MAX_IN_FLIGHT`]); more wait their turn. Raise it with
    /// remote agents and a large receive buffer (`net.core.rmem_default`).
    pub fn with_max_in_flight(self, n: usize) -> Self {
        let shared = &self.transport.shared;
        shared.in_flight_limit.store(n.max(1), Ordering::Release);
        shared.in_flight_free.notify_waiters();
        self
    }

    /// A client for one agent; cheap (no socket of its own). With
    /// SNMPv3, make the [`UsmUser`] once and pass clones: its keys are
    /// hashed from the passwords only once.
    pub fn client(&self, target: SocketAddr, credentials: impl Into<Credentials>) -> Client {
        Client {
            transport: self.transport.clone(),
            target,
            security: Security::new(credentials.into()),
            options: self.options,
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// The agent's engine as discovered, and the user's keys for it.
struct Engine {
    keys: Arc<LocalizedUser>,
    boots: u32,
    /// The latest engine time received, and when.
    time: u32,
    at: Instant,
}

impl Engine {
    /// The agent's boots and time now, estimated from the last answer.
    fn now(&self) -> (u32, u32) {
        let t = u64::from(self.time) + self.at.elapsed().as_secs();
        (self.boots, t.min(i32::MAX as u64) as u32)
    }
}

/// SNMPv3 state shared by a client's clones.
struct Session {
    usm: Usm,
    engine: Mutex<Option<Arc<Engine>>>,
    discovery: tokio::sync::Mutex<()>,
    /// This side as the authoritative engine, for traps.
    local: LocalEngine,
}

impl Session {
    fn current(&self) -> Option<Arc<Engine>> {
        self.engine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set(&self, e: Option<Arc<Engine>>) {
        *self.engine.lock().unwrap_or_else(|e| e.into_inner()) = e;
    }

    /// Takes newer boots/time from an authenticated message (RFC 3414
    /// §3.2.7 b).
    fn observe(&self, usm: &UsmParams) {
        let mut g = self.engine.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = g.as_ref() {
            if usm.engine_boots > e.boots
                || (usm.engine_boots == e.boots && usm.engine_time > e.time)
            {
                *g = Some(Arc::new(Engine {
                    keys: e.keys.clone(),
                    boots: usm.engine_boots,
                    time: usm.engine_time,
                    at: Instant::now(),
                }));
            }
        }
    }
}

#[derive(Clone)]
enum Security {
    Community(Community),
    Usm(Arc<Session>),
}

impl Security {
    fn new(c: Credentials) -> Self {
        match c {
            Credentials::Community(c) => Security::Community(c),
            Credentials::Usm(usm) => {
                let id = usm
                    .engine_id
                    .clone()
                    .unwrap_or_else(LocalEngine::generate_id);
                let local = LocalEngine::new(id).with_user(usm.user.clone());
                Security::Usm(Arc::new(Session {
                    usm,
                    engine: Mutex::new(None),
                    discovery: tokio::sync::Mutex::new(()),
                    local,
                }))
            }
        }
    }
}

/// A client for one agent. Cloning is cheap; clones share the socket
/// and, with SNMPv3, the discovered engine.
#[derive(Clone)]
pub struct Client {
    transport: Arc<Transport>,
    target: SocketAddr,
    security: Security,
    options: Options,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("target", &self.target)
            .field("version", &self.version())
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client with its own socket. `target` is `"host:port"` (port 161 is
    /// not implied); `credentials` a [`Community`] or a [`UsmUser`].
    pub async fn connect(target: &str, credentials: impl Into<Credentials>) -> Result<Client> {
        let target = lookup_host(target)
            .await?
            .next()
            .ok_or(Error::InvalidArgument("target does not resolve"))?;
        let local: SocketAddr = if target.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        Ok(Client {
            transport: Transport::bind(local, true, Some(target)).await?,
            target,
            security: Security::new(credentials.into()),
            options: Options::default(),
        })
    }

    /// A client over TCP (RFC 3430), with a connection of its own:
    /// messages are not retransmitted (the request waits as long as all
    /// attempts would); a closed connection fails pending requests with
    /// [`Error::Io`].
    pub async fn connect_tcp(target: &str, credentials: impl Into<Credentials>) -> Result<Client> {
        let target = lookup_host(target)
            .await?
            .next()
            .ok_or(Error::InvalidArgument("target does not resolve"))?;
        Ok(Client {
            transport: Transport::connect_tcp(target).await?,
            target,
            security: Security::new(credentials.into()),
            options: Options::default(),
        })
    }

    /// The same client with other options.
    pub fn with_options(mut self, options: Options) -> Self {
        self.options = options;
        self
    }

    /// The options.
    pub fn options(&self) -> Options {
        self.options
    }

    /// The agent's address.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// The SNMP version.
    pub fn version(&self) -> Version {
        match &self.security {
            Security::Community(c) => c.version,
            Security::Usm(_) => Version::V3,
        }
    }

    /// SNMPv3: the agent's engine id, once discovered.
    pub fn engine_id(&self) -> Option<Vec<u8>> {
        match &self.security {
            Security::Usm(s) => s.current().map(|e| e.keys.engine_id().to_vec()),
            Security::Community(_) => None,
        }
    }

    /// Sends a PDU (its request id is replaced) and returns the response
    /// PDU as is, without interpreting the error status.
    pub async fn request(&self, mut pdu: Pdu) -> Result<Pdu> {
        let c = match &self.security {
            Security::Community(c) => c,
            Security::Usm(s) => return self.request_v3(s, pdu).await,
        };
        let id = self.transport.next_id();
        pdu.request_id = id;
        let bytes = crate::pdu::encode_community(c.version, &c.community, &pdu);
        let expect = Expect::Community {
            version: c.version,
            community: c.community.clone(),
        };
        self.exchange_map(id, &bytes, expect, |r| {
            let raw = match &r {
                ReplyRef::Community(b) => *b,
                ReplyRef::Owned(Reply::Community(v)) => v.as_slice(),
                ReplyRef::Owned(Reply::V3 { .. }) => {
                    return Err(Error::UnexpectedResponse("SNMPv3 answer"))
                }
            };
            match CommunityMessage::decode(raw).map_err(Error::Decode)?.pdu {
                AnyPdu::Pdu(p) => Ok(p),
                AnyPdu::TrapV1(_) => Err(Error::UnexpectedResponse("an SNMPv1 trap")),
            }
        })
        .await
    }

    /// A community request whose answer is handed to `map` as a message,
    /// where it lies (for decoding in place).
    async fn request_with<T>(
        &self,
        c: &Community,
        mut pdu: Pdu,
        map: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        let id = self.transport.next_id();
        pdu.request_id = id;
        let bytes = crate::pdu::encode_community(c.version, &c.community, &pdu);
        let expect = Expect::Community {
            version: c.version,
            community: c.community.clone(),
        };
        self.exchange_map(id, &bytes, expect, |r| match r {
            ReplyRef::Community(b) => map(b),
            ReplyRef::Owned(Reply::Community(v)) => map(&v),
            ReplyRef::Owned(Reply::V3 { .. }) => Err(Error::UnexpectedResponse("SNMPv3 answer")),
        })
        .await
    }

    /// Sends `bytes` until an answer for `id` passes `expect`, retrying on
    /// timeout.
    async fn exchange(&self, id: i32, bytes: &[u8], expect: Expect) -> Result<Reply> {
        self.exchange_map(id, bytes, expect, |r| {
            Ok(match r {
                ReplyRef::Community(b) => Reply::Community(b.to_vec()),
                ReplyRef::Owned(r) => r,
            })
        })
        .await
    }

    /// Like `exchange`, handing the answer to `map` where it lies (the
    /// reader's own answer is not copied out of the receive buffer).
    async fn exchange_map<T>(
        &self,
        id: i32,
        bytes: &[u8],
        expect: Expect,
        map: impl FnOnce(ReplyRef<'_>) -> Result<T>,
    ) -> Result<T> {
        let shared = &self.transport.shared;
        let _slot = shared.slot().await;
        let timeout = self.options.timeout;
        if shared.is_tcp() {
            // TCP delivers or fails: no retransmission (RFC 3430 §2.1); the
            // request gets the time all attempts would have had.
            let (tx, rx) = oneshot::channel();
            shared
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    id,
                    Waiter {
                        from: self.target,
                        expect,
                        tx,
                        deadline: Instant::now(),
                    },
                );
            let _guard = PendingGuard { shared, id };
            shared.send(bytes, self.target).await?;
            return match tokio::time::timeout(timeout * (self.options.retries + 1), rx).await {
                Ok(Ok(reply)) => map(ReplyRef::Owned(reply)),
                Ok(Err(_)) => Err(Error::Io(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the agent closed the connection",
                ))),
                Err(_) => Err(Error::Timeout),
            };
        }
        let mut deadline = Instant::now() + timeout;
        let mut retries_left = self.options.retries;
        // The common case: nobody is reading the socket, so read it
        // ourselves: no table entry, no channel, no hand-off. Decide before
        // sending: an answer must never arrive before its request is either
        // reading or in the table (the reader would drop it).
        let mut reader = match shared.try_take_receiver() {
            Some(r) => {
                shared.send(bytes, self.target).await?;
                r
            }
            None => {
                // Others read: wait in the table for our answer, or for our
                // turn to read.
                let (tx, mut rx) = oneshot::channel();
                let waiter = |tx, deadline| Waiter {
                    from: self.target,
                    expect: expect.clone(),
                    tx,
                    deadline,
                };
                shared
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id, waiter(tx, deadline));
                shared.register_deadline(deadline);
                let _guard = PendingGuard { shared, id };
                shared.send(bytes, self.target).await?;
                loop {
                    tokio::select! {
                        biased;
                        got = &mut rx => match got {
                            Ok(reply) => return map(ReplyRef::Owned(reply)),
                            // Expired by the reader: try again.
                            Err(_) => {
                                if retries_left == 0 {
                                    return Err(Error::Timeout);
                                }
                                retries_left -= 1;
                                deadline = Instant::now() + timeout;
                                let (tx, new_rx) = oneshot::channel();
                                rx = new_rx;
                                shared
                                    .pending
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(id, waiter(tx, deadline));
                                shared.register_deadline(deadline);
                                shared.send(bytes, self.target).await?;
                            }
                        },
                        r = shared.take_receiver() => {
                            // Our turn to read: leave the table (nobody else
                            // reads now), unless the answer already came.
                            shared.take(id);
                            if let Ok(reply) = rx.try_recv() {
                                return map(ReplyRef::Owned(reply));
                            }
                            break r;
                        }
                    }
                }
            }
        };
        let Socket::Udp(socket) = &shared.socket else {
            unreachable!("TCP handled above")
        };
        let own = Own {
            id,
            expect: &expect,
            target: self.target,
        };
        let r = &mut *reader;
        if r.buf.is_empty() {
            r.buf.resize(65_535, 0);
        }
        r.arm(deadline);
        loop {
            let sleep = r.sleep.as_mut().expect("armed above");
            tokio::select! {
                biased;
                res = socket.recv_from(&mut r.buf) => {
                    // ICMP errors (port unreachable) and the like: the
                    // request times out (and is retried) instead.
                    if let Ok((n, from)) = res {
                        match dispatch(shared, &r.buf[..n], from, Some(&own)) {
                            Some(Mine::Raw) => return map(ReplyRef::Community(&r.buf[..n])),
                            Some(Mine::Reply(reply)) => return map(ReplyRef::Owned(reply)),
                            None => {}
                        }
                    }
                }
                () = sleep.as_mut() => {
                    let now = Instant::now();
                    r.armed = None;
                    if deadline <= now {
                        if retries_left == 0 {
                            return Err(Error::Timeout);
                        }
                        retries_left -= 1;
                        deadline = now + timeout;
                        shared.send(bytes, self.target).await?;
                    }
                    let next = shared.expire(now, id);
                    r.arm(next.map_or(deadline, |n| n.min(deadline)));
                }
                () = std::future::poll_fn(|cx| shared.poll_rearm(cx)) => {
                    let e = shared.earliest.load(Ordering::Acquire);
                    if e != u64::MAX {
                        r.arm(shared.start + Duration::from_nanos(e));
                    }
                }
            }
        }
    }

    /// The engine, discovering it first if needed (once for all clones).
    async fn engine(&self, s: &Session) -> Result<Arc<Engine>> {
        if let Some(e) = s.current() {
            return Ok(e);
        }
        let _one = s.discovery.lock().await;
        if let Some(e) = s.current() {
            return Ok(e);
        }
        let e = Arc::new(self.discover(s).await?);
        s.set(Some(e.clone()));
        Ok(e)
    }

    /// Engine discovery (RFC 3414 §4): an unauthenticated, empty request
    /// that the agent answers with a Report carrying its engine id, boots
    /// and time.
    async fn discover(&self, s: &Session) -> Result<Engine> {
        let id = self.transport.next_id();
        let probe = V3Message {
            msg_id: id,
            max_size: DEFAULT_MAX_SIZE,
            flags: flags::REPORTABLE,
            usm: UsmParams::default(),
            data: ScopedPduData::Plaintext(ScopedPdu::new(
                Vec::new(),
                Vec::new(),
                Pdu::get(id, Vec::<Oid>::new()),
            )),
        };
        let expect = Expect::V3 {
            keys: Arc::new(UsmUser::new("").localize(&[])),
            level: SecurityLevel::NoAuthNoPriv,
            window: (0, 0),
        };
        let Reply::V3 { pdu, usm, .. } = self.exchange(id, &probe.encode(), expect).await? else {
            return Err(Error::UnexpectedResponse("not an SNMPv3 answer"));
        };
        if pdu.pdu_type != PduType::Report || usm.engine_id.is_empty() || usm.engine_id.len() > 32 {
            return Err(Error::UnexpectedResponse(
                "engine discovery: no engine id in the answer",
            ));
        }
        Ok(Engine {
            keys: Arc::new(s.usm.user.localize(&usm.engine_id)),
            boots: usm.engine_boots,
            time: usm.engine_time,
            at: Instant::now(),
        })
    }

    async fn request_v3(&self, s: &Session, pdu: Pdu) -> Result<Pdu> {
        let mut resynced = false;
        let mut rediscovered = false;
        loop {
            let engine = self.engine(s).await?;
            let id = self.transport.next_id();
            let mut p = pdu.clone();
            p.request_id = id;
            let (boots, time) = engine.now();
            let msg = V3Message {
                msg_id: id,
                max_size: DEFAULT_MAX_SIZE,
                flags: flags::REPORTABLE,
                usm: UsmParams {
                    engine_boots: boots,
                    engine_time: time,
                    ..UsmParams::default()
                },
                data: ScopedPduData::Plaintext(ScopedPdu::new(
                    engine.keys.engine_id(),
                    s.usm.context_name.clone(),
                    p,
                )),
            };
            let bytes = engine
                .keys
                .seal(msg, self.transport.next_salt())
                .map_err(Error::Usm)?;
            let expect = Expect::V3 {
                keys: engine.keys.clone(),
                level: engine.keys.level(),
                window: (boots, time),
            };
            let Reply::V3 {
                pdu: r,
                usm,
                authenticated,
            } = self.exchange(id, &bytes, expect).await?
            else {
                return Err(Error::UnexpectedResponse("not an SNMPv3 answer"));
            };
            if authenticated {
                s.observe(&usm);
            }
            if r.pdu_type == PduType::Report {
                let kind = r
                    .varbinds
                    .first()
                    .map(|vb| ReportKind::from_oid(&vb.oid))
                    .unwrap_or(ReportKind::Other(Oid::from_slice(&[])));
                match kind {
                    // Our idea of the agent's clock was off; the
                    // (authenticated) report brought the right one.
                    ReportKind::NotInTimeWindow if authenticated && !resynced => {
                        resynced = true;
                    }
                    // The agent's engine changed (e.g. reinstalled).
                    ReportKind::UnknownEngineId if !rediscovered => {
                        rediscovered = true;
                        s.set(None);
                    }
                    k => return Err(Error::Report(k)),
                }
                continue;
            }
            if r.request_id != id {
                return Err(Error::UnexpectedResponse("request id differs"));
            }
            return Ok(r);
        }
    }

    /// Like [`request`](Self::request), but an error status becomes
    /// [`Error::Snmp`].
    async fn checked(&self, pdu: Pdu) -> Result<Vec<VarBind>> {
        let r = self.request(pdu).await?;
        match r.status() {
            ErrorStatus::NoError => Ok(r.varbinds),
            status => {
                let index = u32::try_from(r.error_index).unwrap_or(0);
                let oid = (index as usize)
                    .checked_sub(1)
                    .and_then(|i| r.varbinds.get(i))
                    .map(|vb| Box::new(vb.oid.clone()));
                Err(Error::Snmp { status, index, oid })
            }
        }
    }

    /// GetRequest. In v2c, missing objects come back as
    /// [`Value::NoSuchObject`] / [`Value::NoSuchInstance`]; in v1 the agent
    /// answers noSuchName ([`Error::Snmp`]).
    pub async fn get<I: IntoOid>(&self, oids: impl IntoIterator<Item = I>) -> Result<Vec<VarBind>> {
        let oids = oids_checked(oids)?;
        let n = oids.len();
        let vbs = self.checked(Pdu::get(0, oids)).await?;
        if vbs.len() != n {
            return Err(Error::UnexpectedResponse(
                "binding count differs from the request",
            ));
        }
        Ok(vbs)
    }

    /// GetRequest for one OID, returning its value.
    pub async fn get_one(&self, oid: impl IntoOid) -> Result<Value> {
        let oid = oid.into_oid()?;
        if !oid.is_valid() {
            return Err(Error::InvalidArgument(
                "OIDs need two arcs or more, the first 0-2",
            ));
        }
        let mut vbs = self.checked(Pdu::get(0, [oid])).await?;
        if vbs.len() != 1 {
            return Err(Error::UnexpectedResponse(
                "binding count differs from the request",
            ));
        }
        Ok(vbs.pop().map(|vb| vb.value).unwrap_or(Value::Null))
    }

    /// GetNextRequest.
    pub async fn get_next<I: IntoOid>(
        &self,
        oids: impl IntoIterator<Item = I>,
    ) -> Result<Vec<VarBind>> {
        let oids = oids_checked(oids)?;
        self.checked(Pdu::get_next(0, oids)).await
    }

    /// GetBulkRequest (v2c only).
    pub async fn get_bulk<I: IntoOid>(
        &self,
        non_repeaters: u32,
        max_repetitions: u32,
        oids: impl IntoIterator<Item = I>,
    ) -> Result<Vec<VarBind>> {
        if self.version() == Version::V1 {
            return Err(Error::InvalidArgument("GetBulk needs SNMPv2c or v3"));
        }
        let oids = oids_checked(oids)?;
        self.checked(Pdu::get_bulk(
            0,
            clamp_i32(non_repeaters),
            clamp_i32(max_repetitions),
            oids,
        ))
        .await
    }

    /// SetRequest; returns the agent's bindings.
    pub async fn set(&self, varbinds: Vec<VarBind>) -> Result<Vec<VarBind>> {
        if varbinds.is_empty() {
            return Err(Error::InvalidArgument("no bindings"));
        }
        self.checked(Pdu::set(0, varbinds)).await
    }

    /// Hundredths of a second since the client's socket was made: the
    /// sysUpTime.0 sent with notifications.
    pub fn uptime(&self) -> u32 {
        (self.transport.shared.start.elapsed().as_millis() / 10) as u32
    }

    /// Sends an SNMPv2 trap (v2c or v3; unconfirmed, nothing comes back):
    /// sysUpTime.0, snmpTrapOID.0 = `trap_oid`, then `varbinds`. With
    /// SNMPv3 this side is the authoritative engine
    /// ([`Usm::with_engine_id`]).
    pub async fn trap(&self, trap_oid: impl IntoOid, varbinds: Vec<VarBind>) -> Result<()> {
        let trap_oid = trap_oid.into_oid()?;
        let id = self.transport.next_id();
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: id,
            error_status: 0,
            error_index: 0,
            varbinds: notification_varbinds(self.uptime(), trap_oid, varbinds),
        };
        let bytes = match &self.security {
            Security::Community(c) if c.version == Version::V1 => {
                return Err(Error::InvalidArgument(
                    "SNMPv1 has its own trap format: use trap_v1",
                ))
            }
            Security::Community(c) => crate::pdu::encode_community(c.version, &c.community, &pdu),
            Security::Usm(s) => s
                .local
                .originate(s.usm.user.name(), id, &s.usm.context_name, pdu)
                .map_err(Error::Usm)?,
        };
        self.transport.shared.send(&bytes, self.target).await?;
        Ok(())
    }

    /// Sends an SNMPv1 Trap-PDU (SNMPv1 only).
    pub async fn trap_v1(&self, trap: crate::TrapV1Pdu) -> Result<()> {
        let c = match &self.security {
            Security::Community(c) if c.version == Version::V1 => c,
            _ => {
                return Err(Error::InvalidArgument(
                    "trap_v1 needs SNMPv1; use trap for v2c and v3",
                ))
            }
        };
        let bytes = CommunityMessage::new(Version::V1, &*c.community, trap).encode();
        self.transport.shared.send(&bytes, self.target).await?;
        Ok(())
    }

    /// Sends an InformRequest (v2c or v3) and waits for the receiver's
    /// acknowledgement, retrying like any request. With SNMPv3 the
    /// receiver is the authoritative engine, discovered first.
    pub async fn inform(
        &self,
        trap_oid: impl IntoOid,
        varbinds: Vec<VarBind>,
    ) -> Result<Vec<VarBind>> {
        if self.version() == Version::V1 {
            return Err(Error::InvalidArgument("informs need SNMPv2c or v3"));
        }
        let trap_oid = trap_oid.into_oid()?;
        let pdu = Pdu {
            pdu_type: PduType::Inform,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds: notification_varbinds(self.uptime(), trap_oid, varbinds),
        };
        self.checked(pdu).await
    }

    /// Walks the subtree under `root`: GetBulk in v2c, GetNext in v1.
    pub fn walk(&self, root: impl IntoOid) -> Result<Walk> {
        let root = root.into_oid()?;
        Ok(Walk {
            client: self.clone(),
            cursor: root.clone(),
            root,
            buf: VecDeque::new(),
            done: false,
        })
    }

    /// Walks the subtree under `root` like [`walk`](Self::walk), handing
    /// each binding to `f` as it is read from the answer, without
    /// allocating (SNMPv1/v2c; SNMPv3 answers, decrypted, go through the
    /// owned decoder). Returns the number of bindings.
    ///
    /// ```no_run
    /// # async fn f(client: snmpify::client::Client) -> snmpify::client::Result<()> {
    /// let mut octets = 0u64;
    /// client
    ///     .walk_with("1.3.6.1.2.1.31.1.1.1.6", |vb| octets += vb.value.as_u64().unwrap_or(0))
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub async fn walk_with(
        &self,
        root: impl IntoOid,
        mut f: impl FnMut(crate::view::VarBindRef<'_>),
    ) -> Result<usize> {
        use crate::view::{ber_contents, community_pdu, ValueRef};
        let root = root.into_oid()?;
        let c = match &self.security {
            Security::Community(c) => c,
            Security::Usm(_) => {
                // Owned batches, re-read as views.
                let mut w = self.walk(root)?;
                let mut n = 0;
                let mut batch = Vec::new();
                loop {
                    batch.clear();
                    w.fill(&mut batch).await?;
                    if !batch.is_empty() {
                        let msg = CommunityMessage::new(
                            Version::V2c,
                            "",
                            Pdu::set(0, std::mem::take(&mut batch)),
                        )
                        .encode();
                        let (_, _, p) = community_pdu(&msg).map_err(Error::Decode)?;
                        for vb in p.varbinds {
                            f(vb.map_err(Error::Decode)?);
                            n += 1;
                        }
                    }
                    if w.done {
                        return Ok(n);
                    }
                }
            }
        };
        let root_ber = ber_contents(&root);
        let mut cursor = root.clone();
        let mut cursor_ber = root_ber.clone();
        let mut n = 0;
        let v1 = c.version == Version::V1;
        loop {
            let pdu = if v1 {
                Pdu::get_next(0, [cursor.clone()])
            } else {
                Pdu::get_bulk(
                    0,
                    0,
                    clamp_i32(self.options.max_repetitions.max(1)),
                    [cursor.clone()],
                )
            };
            let (next, end) = self
                .request_with(c, pdu, |raw| {
                    let (_, _, p) = community_pdu(raw).map_err(Error::Decode)?;
                    match p.error_status {
                        0 => {}
                        // v1's end of the MIB view.
                        2 if v1 => return Ok((None, true)),
                        code => {
                            return Err(Error::Snmp {
                                status: ErrorStatus::from_code(code),
                                index: u32::try_from(p.error_index).unwrap_or(0),
                                oid: None,
                            })
                        }
                    }
                    let mut last: Option<&[u8]> = None;
                    let mut end = false;
                    for vb in p.varbinds {
                        let vb = vb.map_err(Error::Decode)?;
                        if vb.value == ValueRef::EndOfMibView || !vb.oid.starts_with_ber(&root_ber)
                        {
                            end = true;
                            break;
                        }
                        let prev = last.unwrap_or(&cursor_ber);
                        if vb.oid.cmp_ber(prev) != std::cmp::Ordering::Greater {
                            return Err(Error::NotIncreasing {
                                previous: Box::new(
                                    Oid::from_ber(prev).unwrap_or_else(|_| cursor.clone()),
                                ),
                                next: Box::new(vb.oid.to_oid().unwrap_or_else(|_| cursor.clone())),
                            });
                        }
                        last = Some(vb.oid.as_ber());
                        f(vb);
                        n += 1;
                    }
                    let end = end || last.is_none();
                    Ok((last.map(<[u8]>::to_vec), end))
                })
                .await?;
            let Some(last) = next.filter(|_| !end) else {
                return Ok(n);
            };
            cursor_ber = last;
            cursor =
                Oid::from_ber(&cursor_ber).map_err(|k| Error::Decode(DecodeError::new(k, 0)))?;
        }
    }

    /// The whole subtree under `root` as a vector.
    pub async fn walk_all(&self, root: impl IntoOid) -> Result<Vec<VarBind>> {
        let mut w = self.walk(root)?;
        let mut out = Vec::new();
        w.collect_into(&mut out).await?;
        Ok(out)
    }
}

fn clamp_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn oids_checked<I: IntoOid>(it: impl IntoIterator<Item = I>) -> Result<Vec<Oid>> {
    let v = oids(it)?;
    if v.is_empty() {
        return Err(Error::InvalidArgument("no OIDs"));
    }
    if v.iter().any(|o| !o.is_valid()) {
        return Err(Error::InvalidArgument(
            "OIDs need two arcs or more, the first 0-2",
        ));
    }
    Ok(v)
}

/// A subtree walk, pulled one binding at a time with [`Walk::next`].
///
/// Stops at the end of the subtree or the MIB view; fails with
/// [`Error::NotIncreasing`] instead of looping on a broken agent.
pub struct Walk {
    client: Client,
    root: Oid,
    cursor: Oid,
    buf: VecDeque<VarBind>,
    done: bool,
}

impl Walk {
    /// The next binding, or `None` at the end of the subtree.
    pub async fn next(&mut self) -> Option<Result<VarBind>> {
        if let Some(vb) = self.buf.pop_front() {
            return Some(Ok(vb));
        }
        if self.done {
            return None;
        }
        let mut buf = std::mem::take(&mut self.buf);
        let r = self.fill(&mut buf).await;
        self.buf = buf;
        if let Err(e) = r {
            self.done = true;
            return Some(Err(e));
        }
        self.buf.pop_front().map(Ok)
    }

    /// Every remaining binding into `out`.
    async fn collect_into(&mut self, out: &mut Vec<VarBind>) -> Result<()> {
        out.extend(self.buf.drain(..));
        while !self.done {
            if let Err(e) = self.fill(out).await {
                self.done = true;
                return Err(e);
            }
        }
        Ok(())
    }

    /// One request's worth of the subtree into `sink`.
    async fn fill(&mut self, sink: &mut impl Extend<VarBind>) -> Result<()> {
        let c = &self.client;
        let mut vbs = if c.version() == Version::V1 {
            match c.get_next([self.cursor.clone()]).await {
                Err(Error::Snmp {
                    status: ErrorStatus::NoSuchName,
                    ..
                }) => {
                    // v1's end of the MIB view.
                    self.done = true;
                    return Ok(());
                }
                r => r?,
            }
        } else {
            c.checked(Pdu::get_bulk(
                0,
                0,
                clamp_i32(c.options.max_repetitions.max(1)),
                [self.cursor.clone()],
            ))
            .await?
        };
        if vbs.is_empty() {
            self.done = true;
        }
        let mut keep = vbs.len();
        for i in 0..vbs.len() {
            let vb = &vbs[i];
            if vb.value == Value::EndOfMibView || !vb.oid.starts_with(&self.root) {
                self.done = true;
                keep = i;
                break;
            }
            let prev = if i == 0 {
                &self.cursor
            } else {
                &vbs[i - 1].oid
            };
            if vb.oid <= *prev {
                return Err(Error::NotIncreasing {
                    previous: Box::new(prev.clone()),
                    next: Box::new(vb.oid.clone()),
                });
            }
        }
        vbs.truncate(keep);
        if let Some(last) = vbs.last() {
            self.cursor = last.oid.clone();
        }
        sink.extend(vbs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_and_sources() {
        use std::error::Error as _;
        let oid = Oid::from([1, 3, 6, 1]);
        let cases: Vec<(Error, &str, bool)> = vec![
            (Error::Timeout, "timeout", false),
            (io::Error::other("boom").into(), "I/O error: boom", true),
            (
                Error::Decode(DecodeError::new(crate::DecodeErrorKind::TrailingData, 4)),
                "invalid response: trailing data at byte 4",
                true,
            ),
            (
                Error::Snmp {
                    status: ErrorStatus::NoAccess,
                    index: 2,
                    oid: Some(Box::new(oid.clone())),
                },
                "agent error noAccess at binding 2 (1.3.6.1)",
                false,
            ),
            (
                Error::Snmp {
                    status: ErrorStatus::GenErr,
                    index: 0,
                    oid: None,
                },
                "agent error genErr",
                false,
            ),
            (
                Error::NotIncreasing {
                    previous: Box::new(oid.clone()),
                    next: Box::new(oid.clone()),
                },
                "OID not increasing: 1.3.6.1 after 1.3.6.1",
                false,
            ),
            ("1.x".into_oid().unwrap_err(), "invalid OID \"1.x\"", true),
            (
                Error::InvalidArgument("no OIDs"),
                "invalid argument: no OIDs",
                false,
            ),
            (
                Error::UnexpectedResponse("x"),
                "unexpected response: x",
                false,
            ),
            (
                Error::Report(ReportKind::WrongDigest),
                "agent report: wrong digest",
                false,
            ),
            (
                Error::Usm(UsmError::UserNameTooLong),
                "SNMPv3: user name longer",
                true,
            ),
        ];
        for (e, text, source) in cases {
            assert!(e.to_string().starts_with(text), "{e}");
            assert_eq!(e.source().is_some(), source, "{e}");
        }
    }

    #[test]
    fn into_oid() {
        let o = Oid::from([1, 3, 6, 1]);
        assert_eq!((&o).into_oid().unwrap(), o);
        assert_eq!(String::from("1.3.6.1").into_oid().unwrap(), o);
        assert_eq!((&[1u32, 3, 6, 1][..]).into_oid().unwrap(), o);
        assert_eq!([1u32, 3, 6, 1].into_oid().unwrap(), o);
        assert!(String::from("x").into_oid().is_err());
        assert!(oids_checked(["1.3", "7.1"]).is_err());
    }

    #[test]
    fn timeliness() {
        let at = |b, t| UsmParams {
            engine_boots: b,
            engine_time: t,
            ..UsmParams::default()
        };
        assert!(timely((5, 1000), &at(5, 1000)));
        assert!(timely((5, 1000), &at(5, 851)));
        assert!(!timely((5, 1000), &at(5, 849)));
        assert!(timely((5, 1000), &at(6, 0)));
        assert!(!timely((5, 1000), &at(4, 5000)));
        assert!(!timely((5, 1000), &at(i32::MAX as u32, 0)));
    }
}
