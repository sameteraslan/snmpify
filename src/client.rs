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
    community: Vec<u8>,
}

impl Community {
    /// SNMPv1 with a community.
    pub fn v1(community: impl AsRef<[u8]>) -> Self {
        Self {
            version: Version::V1,
            community: community.as_ref().to_vec(),
        }
    }

    /// SNMPv2c with a community.
    pub fn v2c(community: impl AsRef<[u8]>) -> Self {
        Self {
            version: Version::V2c,
            community: community.as_ref().to_vec(),
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
}

impl Usm {
    /// The user, with the default (empty) context.
    pub fn new(user: UsmUser) -> Self {
        Self {
            user,
            context_name: Vec::new(),
        }
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

/// What an answer must be to be accepted for a request.
enum Expect {
    Community {
        version: Version,
        community: Vec<u8>,
    },
    V3 {
        keys: Arc<LocalizedUser>,
        level: SecurityLevel,
        /// The engine boots and time the request was sent with.
        window: (u32, u32),
    },
}

enum Reply {
    Community(Pdu),
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
}

struct Shared {
    socket: UdpSocket,
    pending: Mutex<HashMap<i32, Waiter>>,
    next_id: AtomicU32,
    /// Privacy salts: must not repeat for a key, so a counter.
    next_salt: AtomicU64,
    check_source: bool,
}

impl Shared {
    fn take(&self, id: i32) -> Option<Waiter> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
    }
}

struct Transport {
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Transport {
    async fn bind(local: SocketAddr, check_source: bool) -> io::Result<Arc<Transport>> {
        let socket = UdpSocket::bind(local).await?;
        // Start request ids somewhere unpredictable, like net-snmp, so that a
        // restarted manager does not accept late answers to its predecessor.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32).rotate_left(16))
            .unwrap_or(1)
            ^ std::process::id();
        let shared = Arc::new(Shared {
            socket,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(seed),
            next_salt: AtomicU64::new(((seed as u64) << 32) ^ seed.rotate_left(7) as u64),
            check_source,
        });
        let task = tokio::spawn(receive(shared.clone()));
        Ok(Arc::new(Transport { shared, task }))
    }

    fn next_id(&self) -> i32 {
        (self.shared.next_id.fetch_add(1, Ordering::Relaxed) & 0x7FFF_FFFF) as i32
    }

    fn next_salt(&self) -> u64 {
        self.shared.next_salt.fetch_add(1, Ordering::Relaxed)
    }
}

async fn receive(shared: Arc<Shared>) {
    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, from) = match shared.socket.recv_from(&mut buf).await {
            Ok(x) => x,
            // ICMP port unreachable etc. are reported on later receives;
            // the request times out (and is retried) instead.
            Err(_) => continue,
        };
        let bytes = &buf[..n];
        // Not SNMP or malformed: ignore, the request may retry.
        let Ok(version) = peek_version(bytes) else {
            continue;
        };
        let (id, community) = if version == Version::V3 {
            let Some(id) = peek_msg_id(bytes) else {
                continue;
            };
            (id, None)
        } else {
            let Ok(msg) = CommunityMessage::decode(bytes) else {
                continue;
            };
            let AnyPdu::Pdu(pdu) = msg.pdu else { continue };
            (pdu.request_id, Some((msg.version, msg.community, pdu)))
        };
        let Some(w) = shared.take(id) else { continue };
        let reply = if shared.check_source && w.from != from {
            None
        } else {
            match (&w.expect, community) {
                (
                    Expect::Community {
                        version,
                        community: c,
                    },
                    Some((v, mc, pdu)),
                ) if *version == v && *c == mc => Some(Reply::Community(pdu)),
                (Expect::V3 { .. }, None) => accept_v3(&w.expect, bytes),
                _ => None,
            }
        };
        match reply {
            Some(r) => {
                let _ = w.tx.send(r);
            }
            None => {
                // Not our answer (spoofed, forged, another agent): keep waiting.
                shared
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id, w);
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
            transport: Transport::bind(local, true).await?,
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
        Ok(self.transport.shared.socket.local_addr()?)
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
            Credentials::Usm(usm) => Security::Usm(Arc::new(Session {
                usm,
                engine: Mutex::new(None),
                discovery: tokio::sync::Mutex::new(()),
            })),
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
            transport: Transport::bind(local, true).await?,
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
        let bytes = CommunityMessage::new(c.version, &c.community, pdu).encode();
        let expect = Expect::Community {
            version: c.version,
            community: c.community.clone(),
        };
        match self.exchange(id, &bytes, expect).await? {
            Reply::Community(pdu) => Ok(pdu),
            Reply::V3 { .. } => Err(Error::UnexpectedResponse("SNMPv3 answer")),
        }
    }

    /// Sends `bytes` until an answer for `id` passes `expect`, retrying on
    /// timeout.
    async fn exchange(&self, id: i32, bytes: &[u8], expect: Expect) -> Result<Reply> {
        let shared = &self.transport.shared;
        let (tx, mut rx) = oneshot::channel();
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
                },
            );
        let _guard = PendingGuard { shared, id };
        for _ in 0..=self.options.retries {
            shared.socket.send_to(bytes, self.target).await?;
            match tokio::time::timeout(self.options.timeout, &mut rx).await {
                Ok(Ok(reply)) => return Ok(reply),
                Ok(Err(_)) => return Err(Error::Timeout), // receive task gone
                Err(_) => continue,
            }
        }
        Err(Error::Timeout)
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
        Ok(self.get([oid.into_oid()?]).await?.remove(0).value)
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

    /// The whole subtree under `root` as a vector.
    pub async fn walk_all(&self, root: impl IntoOid) -> Result<Vec<VarBind>> {
        let mut w = self.walk(root)?;
        let mut out = Vec::new();
        while let Some(vb) = w.next().await {
            out.push(vb?);
        }
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
        if let Err(e) = self.fill().await {
            self.done = true;
            return Some(Err(e));
        }
        self.buf.pop_front().map(Ok)
    }

    async fn fill(&mut self) -> Result<()> {
        let c = &self.client;
        let vbs = if c.version() == Version::V1 {
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
            c.get_bulk(0, c.options.max_repetitions.max(1), [self.cursor.clone()])
                .await?
        };
        if vbs.is_empty() {
            self.done = true;
        }
        for vb in vbs {
            if vb.value == Value::EndOfMibView || !vb.oid.starts_with(&self.root) {
                self.done = true;
                break;
            }
            if vb.oid <= self.cursor {
                return Err(Error::NotIncreasing {
                    previous: Box::new(self.cursor.clone()),
                    next: Box::new(vb.oid),
                });
            }
            self.cursor = vb.oid.clone();
            self.buf.push_back(vb);
        }
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
