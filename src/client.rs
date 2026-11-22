//! Async SNMPv1/v2c client (tokio).
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

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::{
    AnyPdu, CommunityMessage, DecodeError, ErrorStatus, Oid, ParseOidError, Pdu, Value, VarBind,
    Version,
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
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Decode(e) => Some(e),
            Error::InvalidOid(e) => Some(e),
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

struct Waiter {
    from: SocketAddr,
    community: Vec<u8>,
    version: Version,
    tx: oneshot::Sender<Pdu>,
}

struct Shared {
    socket: UdpSocket,
    pending: Mutex<HashMap<i32, Waiter>>,
    next_id: AtomicU32,
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
            check_source,
        });
        let task = tokio::spawn(receive(shared.clone()));
        Ok(Arc::new(Transport { shared, task }))
    }

    fn next_id(&self) -> i32 {
        (self.shared.next_id.fetch_add(1, Ordering::Relaxed) & 0x7FFF_FFFF) as i32
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
        let Ok(msg) = CommunityMessage::decode(&buf[..n]) else {
            continue; // not SNMP or malformed: ignore, the request may retry
        };
        let AnyPdu::Pdu(pdu) = msg.pdu else { continue };
        let id = pdu.request_id;
        let Some(w) = shared.take(id) else { continue };
        let ok = (!shared.check_source || w.from == from)
            && w.version == msg.version
            && w.community == msg.community;
        if ok {
            let _ = w.tx.send(pdu);
        } else {
            // Not our answer (spoofed or another agent): keep waiting.
            shared
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id, w);
        }
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

    /// A client for one agent; cheap (no socket of its own).
    pub fn client(&self, target: SocketAddr, community: Community) -> Client {
        Client {
            transport: self.transport.clone(),
            target,
            community,
            options: self.options,
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A client for one agent. Cloning is cheap and clones share the socket.
#[derive(Clone)]
pub struct Client {
    transport: Arc<Transport>,
    target: SocketAddr,
    community: Community,
    options: Options,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("target", &self.target)
            .field("version", &self.community.version)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client with its own socket. `target` is `"host:port"` (port 161 is
    /// not implied).
    pub async fn connect(target: &str, community: Community) -> Result<Client> {
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
            community,
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
        self.community.version
    }

    /// Sends a PDU (its request id is replaced) and returns the response
    /// PDU as is, without interpreting the error status.
    pub async fn request(&self, mut pdu: Pdu) -> Result<Pdu> {
        let shared = &self.transport.shared;
        let id = self.transport.next_id();
        pdu.request_id = id;
        let bytes =
            CommunityMessage::new(self.community.version, &self.community.community, pdu).encode();
        let (tx, mut rx) = oneshot::channel();
        shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                id,
                Waiter {
                    from: self.target,
                    community: self.community.community.clone(),
                    version: self.community.version,
                    tx,
                },
            );
        let _guard = PendingGuard { shared, id };
        for _ in 0..=self.options.retries {
            shared.socket.send_to(&bytes, self.target).await?;
            match tokio::time::timeout(self.options.timeout, &mut rx).await {
                Ok(Ok(pdu)) => return Ok(pdu),
                Ok(Err(_)) => return Err(Error::Timeout), // receive task gone
                Err(_) => continue,
            }
        }
        Err(Error::Timeout)
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
        if self.community.version == Version::V1 {
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
        let vbs = if c.community.version == Version::V1 {
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
