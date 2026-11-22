//! An SNMP agent: answers Get, GetNext, GetBulk and Set (SNMPv1, v2c, v3)
//! from MIB handlers registered under subtrees.
//!
//! - [`MibHandler`]: what serves a subtree (get, get-next, two-phase set).
//! - [`MibTree`]: a ready handler holding values in memory: fixed,
//!   writable, or computed on each read.
//! - [`Agent`]: the UDP responder with communities, SNMPv3 users
//!   ([`LocalEngine`]) and read-only / read-write access.
//!
//! The same handlers serve as an AgentX subagent under net-snmp or
//! another master agent ([`agentx`](crate::agentx)).
//!
//! ```no_run
//! use snmpify::agent::{Access, Agent, MibTree};
//! use snmpify::Value;
//!
//! # async fn run() -> std::io::Result<()> {
//! let mib = MibTree::new();
//! mib.insert("1.3.6.1.4.1.99999.1.0".parse().unwrap(), Value::from("hello"));
//! mib.insert_writable("1.3.6.1.4.1.99999.2.0".parse().unwrap(), Value::Integer(5));
//! mib.insert_fn("1.3.6.1.4.1.99999.3.0".parse().unwrap(), || Value::Gauge32(42));
//!
//! let agent = Agent::bind("0.0.0.0:161")
//!     .await?
//!     .with_community("public", Access::ReadOnly)
//!     .with_community("private", Access::ReadWrite)
//!     .register("1.3.6.1.4.1.99999".parse().unwrap(), mib);
//! agent.run().await
//! # }
//! ```

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::ops::Bound;
use std::sync::{Arc, RwLock};

use tokio::net::{lookup_host, UdpSocket};

use crate::engine::{LocalEngine, Received};
use crate::usm::SecurityLevel;
use crate::v3::ReportKind;
use crate::{AnyPdu, CommunityMessage, ErrorStatus, Oid, Pdu, PduType, Value, VarBind, Version};

/// Serves the objects of one subtree.
///
/// Values are those of instances (`sysName.0`, `ifDescr.3`). Sets come in
/// two phases: every binding of a SetRequest is tested first, and only
/// if all pass are they committed (RFC 3416 §4.2.5).
pub trait MibHandler: Send + Sync {
    /// The value of an instance, or [`Value::NoSuchObject`] /
    /// [`Value::NoSuchInstance`].
    fn get(&self, oid: &Oid) -> Value;

    /// The first instance after `oid` (in this handler's subtree), with
    /// its value; `None` past the end.
    fn get_next(&self, oid: &Oid) -> Option<VarBind>;

    /// Whether `vb` may be set. Default: nothing is writable.
    fn test_set(&self, vb: &VarBind) -> Result<(), ErrorStatus> {
        let _ = vb;
        Err(ErrorStatus::NotWritable)
    }

    /// Sets `vb`, after every binding passed [`test_set`](Self::test_set).
    fn commit_set(&self, vb: &VarBind) -> Result<(), ErrorStatus> {
        let _ = vb;
        Err(ErrorStatus::CommitFailed)
    }
}

impl<T: MibHandler + ?Sized> MibHandler for Arc<T> {
    fn get(&self, oid: &Oid) -> Value {
        (**self).get(oid)
    }
    fn get_next(&self, oid: &Oid) -> Option<VarBind> {
        (**self).get_next(oid)
    }
    fn test_set(&self, vb: &VarBind) -> Result<(), ErrorStatus> {
        (**self).test_set(vb)
    }
    fn commit_set(&self, vb: &VarBind) -> Result<(), ErrorStatus> {
        (**self).commit_set(vb)
    }
}

type ValueFn = Arc<dyn Fn() -> Value + Send + Sync>;

#[derive(Clone)]
enum Entry {
    Fixed(Value),
    Writable(Value),
    Computed(ValueFn),
}

impl Entry {
    fn value(&self) -> Value {
        match self {
            Entry::Fixed(v) | Entry::Writable(v) => v.clone(),
            Entry::Computed(f) => f(),
        }
    }
}

/// Instances and their values in memory. Cloning shares the tree, so the
/// application can update values while an agent serves them.
#[derive(Clone, Default)]
pub struct MibTree {
    map: Arc<RwLock<BTreeMap<Oid, Entry>>>,
}

impl fmt::Debug for MibTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MibTree")
            .field("instances", &self.read().len())
            .finish()
    }
}

impl MibTree {
    /// An empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<Oid, Entry>> {
        self.map.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<Oid, Entry>> {
        self.map.write().unwrap_or_else(|e| e.into_inner())
    }

    /// A read-only instance (replaces any previous one).
    pub fn insert(&self, oid: Oid, value: impl Into<Value>) {
        self.write().insert(oid, Entry::Fixed(value.into()));
    }

    /// An instance managers may set (to a value of the same type).
    pub fn insert_writable(&self, oid: Oid, value: impl Into<Value>) {
        self.write().insert(oid, Entry::Writable(value.into()));
    }

    /// A read-only instance computed on every read (counters, uptime).
    pub fn insert_fn(&self, oid: Oid, f: impl Fn() -> Value + Send + Sync + 'static) {
        self.write().insert(oid, Entry::Computed(Arc::new(f)));
    }

    /// Removes an instance.
    pub fn remove(&self, oid: &Oid) -> bool {
        self.write().remove(oid).is_some()
    }

    /// The current value of an instance.
    pub fn value(&self, oid: &Oid) -> Option<Value> {
        self.read().get(oid).map(Entry::value)
    }

    /// The number of instances.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// The MIB-II system group (RFC 3418): sysDescr, sysObjectID,
    /// sysUpTime (from `uptime`, hundredths of a second), and writable
    /// sysContact, sysName, sysLocation; sysServices 72.
    pub fn with_system(
        self,
        descr: &str,
        object_id: Oid,
        name: &str,
        uptime: impl Fn() -> u32 + Send + Sync + 'static,
    ) -> Self {
        let sys = |n: u32| Oid::from([1, 3, 6, 1, 2, 1, 1, n, 0]);
        self.insert(sys(1), descr);
        self.insert(sys(2), Value::ObjectId(object_id));
        self.insert_fn(sys(3), move || Value::TimeTicks(uptime()));
        self.insert_writable(sys(4), "");
        self.insert_writable(sys(5), name);
        self.insert_writable(sys(6), "");
        self.insert(sys(7), Value::Integer(72));
        self
    }
}

impl MibHandler for MibTree {
    fn get(&self, oid: &Oid) -> Value {
        let map = self.read();
        if let Some(e) = map.get(oid) {
            return e.value();
        }
        // An object (the instance's parent) exists if some sibling
        // instance does: then it is the instance that is missing.
        let parent = &oid[..oid.len().saturating_sub(1)];
        let object_exists = map
            .range::<Oid, _>((Bound::Included(&Oid::from_slice(parent)), Bound::Unbounded))
            .next()
            .is_some_and(|(o, _)| o.starts_with(parent) && o.len() > parent.len());
        if object_exists {
            Value::NoSuchInstance
        } else {
            Value::NoSuchObject
        }
    }

    fn get_next(&self, oid: &Oid) -> Option<VarBind> {
        self.read()
            .range::<Oid, _>((Bound::Excluded(oid), Bound::Unbounded))
            .next()
            .map(|(o, e)| VarBind::new(o.clone(), e.value()))
    }

    fn test_set(&self, vb: &VarBind) -> Result<(), ErrorStatus> {
        match self.read().get(&vb.oid) {
            None => Err(ErrorStatus::NoCreation),
            Some(Entry::Writable(v)) if v.tag() == vb.value.tag() => Ok(()),
            Some(Entry::Writable(_)) => Err(ErrorStatus::WrongType),
            Some(_) => Err(ErrorStatus::NotWritable),
        }
    }

    fn commit_set(&self, vb: &VarBind) -> Result<(), ErrorStatus> {
        match self.write().get_mut(&vb.oid) {
            Some(Entry::Writable(v)) => {
                *v = vb.value.clone();
                Ok(())
            }
            _ => Err(ErrorStatus::CommitFailed),
        }
    }
}

/// Handlers by subtree; requests are routed to the deepest registration
/// containing the OID.
#[derive(Clone, Default)]
pub(crate) struct Registry {
    subtrees: Vec<(Oid, Arc<dyn MibHandler>)>,
}

impl Registry {
    pub(crate) fn register(&mut self, prefix: Oid, h: Arc<dyn MibHandler>) {
        self.subtrees.retain(|(p, _)| *p != prefix);
        self.subtrees.push((prefix, h));
        self.subtrees.sort_by(|a, b| a.0.cmp(&b.0));
    }

    pub(crate) fn prefixes(&self) -> impl Iterator<Item = &Oid> {
        self.subtrees.iter().map(|(p, _)| p)
    }

    fn owner(&self, oid: &Oid) -> Option<&(Oid, Arc<dyn MibHandler>)> {
        self.subtrees
            .iter()
            .filter(|(p, _)| oid.starts_with(p))
            .max_by_key(|(p, _)| p.len())
    }

    pub(crate) fn get(&self, oid: &Oid) -> Value {
        match self.owner(oid) {
            Some((_, h)) => h.get(oid),
            None => Value::NoSuchObject,
        }
    }

    /// The first instance after `oid` in any subtree.
    pub(crate) fn get_next(&self, oid: &Oid) -> Option<VarBind> {
        let mut best: Option<VarBind> = None;
        for (p, h) in &self.subtrees {
            // Sorted: a subtree starting after the best answer cannot beat it.
            if best.as_ref().is_some_and(|b| *p > b.oid) {
                break;
            }
            // A subtree entirely before `oid` has nothing after it.
            if *p < *oid && !oid.starts_with(p) {
                continue;
            }
            let mut cur = oid.clone();
            let found = loop {
                let Some(vb) = h.get_next(&cur) else {
                    break None;
                };
                if vb.oid < *p {
                    cur = vb.oid; // before the subtree (a shared handler)
                } else if !vb.oid.starts_with(p) {
                    break None; // past it
                } else if self.owner(&vb.oid).is_some_and(|(q, _)| q != p) {
                    cur = vb.oid; // a deeper registration answers for it
                } else {
                    break Some(vb);
                }
            };
            if let Some(vb) = found {
                if best.as_ref().is_none_or(|b| vb.oid < b.oid) {
                    best = Some(vb);
                }
            }
        }
        best
    }

    pub(crate) fn test_set(&self, vb: &VarBind) -> Result<(), ErrorStatus> {
        match self.owner(&vb.oid) {
            Some((_, h)) => h.test_set(vb),
            None => Err(ErrorStatus::NoCreation),
        }
    }

    pub(crate) fn commit_set(&self, vb: &VarBind) -> Result<(), ErrorStatus> {
        match self.owner(&vb.oid) {
            Some((_, h)) => h.commit_set(vb),
            None => Err(ErrorStatus::CommitFailed),
        }
    }
}

/// What a community or user may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Access {
    /// Get, GetNext, GetBulk.
    ReadOnly,
    /// Also Set.
    ReadWrite,
}

/// An SNMP agent on a UDP socket.
pub struct Agent {
    socket: UdpSocket,
    communities: HashMap<Vec<u8>, Access>,
    engine: Option<LocalEngine>,
    users: HashMap<Vec<u8>, (Access, SecurityLevel)>,
    registry: Registry,
}

impl fmt::Debug for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("local_addr", &self.socket.local_addr().ok())
            .field("subtrees", &self.registry.prefixes().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// The largest response sent when the request does not say (SNMPv1/v2c
/// requests have no msgMaxSize; this fits a UDP datagram).
const MAX_RESPONSE: usize = 65_507;

impl Agent {
    /// Binds an agent (`"0.0.0.0:161"`; port 161 needs privileges on most
    /// systems).
    pub async fn bind(addr: &str) -> io::Result<Agent> {
        let addr = lookup_host(addr).await?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "address does not resolve")
        })?;
        Ok(Agent {
            socket: UdpSocket::bind(addr).await?,
            communities: HashMap::new(),
            engine: None,
            users: HashMap::new(),
            registry: Registry::default(),
        })
    }

    /// Answers SNMPv1/v2c requests with this community.
    pub fn with_community(mut self, community: impl AsRef<[u8]>, access: Access) -> Self {
        self.communities.insert(community.as_ref().to_vec(), access);
        self
    }

    /// Answers SNMPv3 requests: the engine's users get read-only access at
    /// any level unless [`with_user_access`](Self::with_user_access) says
    /// otherwise.
    pub fn with_engine(mut self, engine: LocalEngine) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Access for an SNMPv3 user, and the lowest security level it may
    /// use (lower requests get authorizationError, like VACM).
    pub fn with_user_access(
        mut self,
        user: impl AsRef<[u8]>,
        access: Access,
        min_level: SecurityLevel,
    ) -> Self {
        self.users
            .insert(user.as_ref().to_vec(), (access, min_level));
        self
    }

    /// Serves `handler` under `prefix` (deeper registrations win).
    pub fn register(mut self, prefix: Oid, handler: impl MibHandler + 'static) -> Self {
        self.registry.register(prefix, Arc::new(handler));
        self
    }

    /// The local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The engine, if SNMPv3 is on.
    pub fn engine(&self) -> Option<&LocalEngine> {
        self.engine.as_ref()
    }

    /// Serves requests until a socket error.
    pub async fn run(&self) -> io::Result<()> {
        let mut buf = vec![0u8; 65_535];
        loop {
            let (n, from) = self.socket.recv_from(&mut buf).await?;
            if let Some(out) = self.handle(&buf[..n]) {
                self.socket.send_to(&out, from).await?;
            }
        }
    }

    /// Serves requests over TCP (RFC 3430) on `listener` as well, one task
    /// per connection, until accepting fails. Run it next to
    /// [`run`](Self::run) on a shared agent:
    ///
    /// ```no_run
    /// # use snmpify::agent::{Access, Agent};
    /// # async fn f() -> std::io::Result<()> {
    /// let agent = std::sync::Arc::new(Agent::bind("0.0.0.0:161").await?.with_community("public", Access::ReadOnly));
    /// let tcp = tokio::net::TcpListener::bind("0.0.0.0:161").await?;
    /// tokio::spawn(agent.clone().run_tcp(tcp));
    /// agent.run().await
    /// # }
    /// ```
    pub async fn run_tcp(self: Arc<Self>, listener: tokio::net::TcpListener) -> io::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                let _ = me.serve_stream(stream).await;
            });
        }
    }

    async fn serve_stream(&self, stream: tokio::net::TcpStream) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        stream.set_nodelay(true)?;
        let (mut read, mut write) = stream.into_split();
        while let Some(msg) = crate::tcp::read_message(&mut read).await? {
            if let Some(out) = self.handle(&msg) {
                write.write_all(&out).await?;
            }
        }
        Ok(())
    }

    /// The answer to one datagram, if any (for running the agent over
    /// another transport, or testing).
    pub fn handle(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        match crate::peek_version(bytes).ok()? {
            Version::V3 => self.handle_v3(bytes),
            _ => self.handle_community(bytes),
        }
    }

    fn handle_community(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let msg = CommunityMessage::decode(bytes).ok()?;
        // Unknown communities get no answer (RFC 1157 §4.1).
        let access = *self.communities.get(&msg.community)?;
        let AnyPdu::Pdu(pdu) = msg.pdu else {
            return None;
        };
        let limit = MAX_RESPONSE.saturating_sub(16 + msg.community.len());
        let resp = process(&self.registry, msg.version, pdu, access, limit)?;
        Some(CommunityMessage::new(msg.version, &msg.community, resp).encode())
    }

    fn handle_v3(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let engine = self.engine.as_ref()?;
        let req = match engine.receive(bytes) {
            Received::Message(r) => r,
            Received::Report(b) => return Some(b),
            Received::Drop(_) => return None,
        };
        if req.engine_id != engine.id() {
            return None; // a trap from another engine: not for an agent
        }
        if !req.context_name.is_empty() {
            let report = Pdu {
                pdu_type: PduType::Report,
                request_id: req.pdu.request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(
                    ReportKind::UnknownContext.oid(),
                    Value::Counter32(1),
                )],
            };
            return engine.respond(&req, report).ok();
        }
        let (access, min_level) = self
            .users
            .get(&req.user_name)
            .copied()
            .unwrap_or((Access::ReadOnly, SecurityLevel::NoAuthNoPriv));
        let limit = usize::try_from(req.max_size)
            .unwrap_or(MAX_RESPONSE)
            .min(MAX_RESPONSE)
            .saturating_sub(128 + req.user_name.len() + 48);
        let resp = if req.level < min_level {
            Some(error_response(&req.pdu, ErrorStatus::AuthorizationError, 0))
        } else {
            process(&self.registry, Version::V3, req.pdu.clone(), access, limit)
        }?;
        engine.respond(&req, resp).ok()
    }
}

fn error_response(req: &Pdu, status: ErrorStatus, index: usize) -> Pdu {
    Pdu {
        pdu_type: PduType::Response,
        request_id: req.request_id,
        error_status: status.code(),
        error_index: index as i32,
        varbinds: if req.pdu_type == PduType::GetBulk {
            Vec::new()
        } else {
            req.varbinds.clone()
        },
    }
}

/// SNMPv2 errors in SNMPv1 terms (RFC 3584 §4.4).
fn v1_status(s: ErrorStatus) -> ErrorStatus {
    use ErrorStatus::*;
    match s {
        NoAccess | NotWritable | NoCreation | InconsistentName | AuthorizationError => NoSuchName,
        WrongType | WrongLength | WrongEncoding | WrongValue | InconsistentValue => BadValue,
        ResourceUnavailable | CommitFailed | UndoFailed => GenErr,
        other => other,
    }
}

/// Answers one request PDU; `None` for PDUs an agent does not answer.
pub(crate) fn process(
    reg: &Registry,
    version: Version,
    req: Pdu,
    access: Access,
    limit: usize,
) -> Option<Pdu> {
    let v1 = version == Version::V1;
    let fail = |status: ErrorStatus, index: usize| {
        let s = if v1 { v1_status(status) } else { status };
        error_response(&req, s, index)
    };
    let next = |oid: &Oid| -> Option<VarBind> {
        let mut cur = oid.clone();
        loop {
            let vb = reg.get_next(&cur)?;
            // SNMPv1 has no Counter64: skip them (RFC 3584 §4.2.2.1).
            if v1 && matches!(vb.value, Value::Counter64(_)) {
                cur = vb.oid;
                continue;
            }
            return Some(vb);
        }
    };
    let resp = |varbinds| Pdu {
        pdu_type: PduType::Response,
        request_id: req.request_id,
        error_status: 0,
        error_index: 0,
        varbinds,
    };
    let out = match req.pdu_type {
        PduType::Get => {
            let mut vbs = Vec::with_capacity(req.varbinds.len());
            for (i, vb) in req.varbinds.iter().enumerate() {
                let v = reg.get(&vb.oid);
                if v1 && (v.is_exception() || matches!(v, Value::Counter64(_))) {
                    return Some(fail(ErrorStatus::NoSuchName, i + 1));
                }
                vbs.push(VarBind::new(vb.oid.clone(), v));
            }
            resp(vbs)
        }
        PduType::GetNext => {
            let mut vbs = Vec::with_capacity(req.varbinds.len());
            for (i, vb) in req.varbinds.iter().enumerate() {
                match next(&vb.oid) {
                    Some(n) => vbs.push(n),
                    None if v1 => return Some(fail(ErrorStatus::NoSuchName, i + 1)),
                    None => vbs.push(VarBind::new(vb.oid.clone(), Value::EndOfMibView)),
                }
            }
            resp(vbs)
        }
        PduType::GetBulk if !v1 => {
            let n = req.varbinds.len();
            let non_rep = (req.non_repeaters().max(0) as usize).min(n);
            let max_rep = req.max_repetitions().max(0) as usize;
            let mut vbs = Vec::new();
            for vb in &req.varbinds[..non_rep] {
                vbs.push(
                    next(&vb.oid)
                        .unwrap_or_else(|| VarBind::new(vb.oid.clone(), Value::EndOfMibView)),
                );
            }
            let mut cursors: Vec<Oid> = req.varbinds[non_rep..]
                .iter()
                .map(|vb| vb.oid.clone())
                .collect();
            // Stop early when the answer gets too big (RFC 3416 §4.2.3).
            let mut size = 0usize;
            'rows: for _ in 0..max_rep {
                if cursors.is_empty() {
                    break;
                }
                let mut all_end = true;
                for c in cursors.iter_mut() {
                    let vb =
                        next(c).unwrap_or_else(|| VarBind::new(c.clone(), Value::EndOfMibView));
                    if vb.value != Value::EndOfMibView {
                        all_end = false;
                    }
                    size += encoded_len(&vb);
                    if size > limit {
                        break 'rows;
                    }
                    *c = vb.oid.clone();
                    vbs.push(vb);
                }
                if all_end {
                    break;
                }
            }
            resp(vbs)
        }
        PduType::Set => {
            if access != Access::ReadWrite {
                return Some(fail(ErrorStatus::NoAccess, 1));
            }
            for (i, vb) in req.varbinds.iter().enumerate() {
                if let Err(s) = reg.test_set(vb) {
                    return Some(fail(s, i + 1));
                }
            }
            for (i, vb) in req.varbinds.iter().enumerate() {
                if let Err(s) = reg.commit_set(vb) {
                    return Some(fail(
                        if s == ErrorStatus::NoError {
                            ErrorStatus::CommitFailed
                        } else {
                            s
                        },
                        i + 1,
                    ));
                }
            }
            resp(req.varbinds.clone())
        }
        _ => return None,
    };
    // tooBig (RFC 3416 §4.2.1): the request's bindings are not returned.
    let total: usize = out.varbinds.iter().map(encoded_len).sum();
    if total > limit {
        return Some(Pdu {
            varbinds: Vec::new(),
            ..fail(ErrorStatus::TooBig, 0)
        });
    }
    Some(out)
}

/// An upper bound of a binding's encoded size.
fn encoded_len(vb: &VarBind) -> usize {
    let mut w = crate::ber::Writer::new();
    vb.encode(&mut w);
    w.mark()
}
