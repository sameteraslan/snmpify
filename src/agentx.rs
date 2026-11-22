//! AgentX (RFC 2741): serve [`MibHandler`]s as a subagent of a master
//! agent such as net-snmp's snmpd (`master agentx`). The master does the
//! SNMP side (communities, USM, VACM); the subagent answers for its
//! subtrees.
//!
//! ```no_run
//! use snmpify::agent::MibTree;
//! use snmpify::agentx::Subagent;
//! use snmpify::Value;
//!
//! # async fn run() -> std::io::Result<()> {
//! let mib = MibTree::new();
//! mib.insert("1.3.6.1.4.1.99999.1.0".parse().unwrap(), Value::from("from a subagent"));
//! let sub = Subagent::new("my subagent").register("1.3.6.1.4.1.99999".parse().unwrap(), mib);
//! let notifier = sub.notifier(); // traps through the master
//! sub.run_tcp("127.0.0.1:705").await
//! # }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::agent::{MibHandler, Registry};
use crate::notification::notification_varbinds;
use crate::{ErrorStatus, Oid, Value, VarBind};

/// AgentX PDU types (RFC 2741 §6.1).
#[allow(missing_docs)]
pub mod pdu_type {
    pub const OPEN: u8 = 1;
    pub const CLOSE: u8 = 2;
    pub const REGISTER: u8 = 3;
    pub const UNREGISTER: u8 = 4;
    pub const GET: u8 = 5;
    pub const GET_NEXT: u8 = 6;
    pub const GET_BULK: u8 = 7;
    pub const TEST_SET: u8 = 8;
    pub const COMMIT_SET: u8 = 9;
    pub const UNDO_SET: u8 = 10;
    pub const CLEANUP_SET: u8 = 11;
    pub const NOTIFY: u8 = 12;
    pub const PING: u8 = 13;
    pub const RESPONSE: u8 = 18;
}

const F_NON_DEFAULT_CONTEXT: u8 = 0x08;
const F_NETWORK_BYTE_ORDER: u8 = 0x10;
const HEADER: usize = 20;
/// Largest payload accepted from the master.
const MAX_PAYLOAD: usize = 1 << 20;

/// An AgentX packet: header fields and the raw payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// PDU type ([`pdu_type`]).
    pub pdu_type: u8,
    /// Header flags.
    pub flags: u8,
    /// `h.sessionID`.
    pub session_id: u32,
    /// `h.transactionID`.
    pub transaction_id: u32,
    /// `h.packetID`.
    pub packet_id: u32,
    /// The payload (after the header), in the packet's byte order.
    pub payload: Vec<u8>,
}

/// Malformed AgentX data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentxError(&'static str);

impl fmt::Display for AgentxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentX: {}", self.0)
    }
}

impl std::error::Error for AgentxError {}

impl From<AgentxError> for io::Error {
    fn from(e: AgentxError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// Reads AgentX payload fields in either byte order.
struct In<'a> {
    b: &'a [u8],
    pos: usize,
    be: bool,
}

impl<'a> In<'a> {
    fn new(b: &'a [u8], flags: u8) -> Self {
        In {
            b,
            pos: 0,
            be: flags & F_NETWORK_BYTE_ORDER != 0,
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], AgentxError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.b.len());
        let end = end.ok_or(AgentxError("truncated"))?;
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, AgentxError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AgentxError> {
        let a: [u8; 2] = self.take(2)?.try_into().unwrap_or_default();
        Ok(if self.be {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        })
    }

    fn u32(&mut self) -> Result<u32, AgentxError> {
        let a: [u8; 4] = self.take(4)?.try_into().unwrap_or_default();
        Ok(if self.be {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        })
    }

    fn u64(&mut self) -> Result<u64, AgentxError> {
        let hi = self.u32()? as u64;
        let lo = self.u32()? as u64;
        Ok(if self.be {
            (hi << 32) | lo
        } else {
            (lo << 32) | hi
        })
    }

    /// An Object Identifier (§5.1) and its `include` flag.
    fn oid(&mut self) -> Result<(Oid, bool), AgentxError> {
        let n = self.u8()? as usize;
        let prefix = self.u8()?;
        let include = self.u8()? != 0;
        self.u8()?;
        if n > 128 {
            return Err(AgentxError("OID too long"));
        }
        let mut arcs = Vec::with_capacity(n + 5);
        if prefix != 0 {
            arcs.extend_from_slice(&[1, 3, 6, 1, prefix as u32]);
        }
        for _ in 0..n {
            arcs.push(self.u32()?);
        }
        Ok((Oid::from(arcs), include))
    }

    /// An Octet String (§5.3), padded to 4 bytes.
    fn octets(&mut self) -> Result<Vec<u8>, AgentxError> {
        let n = self.u32()? as usize;
        if n > MAX_PAYLOAD {
            return Err(AgentxError("string too long"));
        }
        let v = self.take(n)?.to_vec();
        self.take((4 - n % 4) % 4)?;
        Ok(v)
    }

    fn varbind(&mut self) -> Result<VarBind, AgentxError> {
        let t = self.u16()?;
        self.u16()?;
        let (oid, _) = self.oid()?;
        let value = match t {
            2 => Value::Integer(self.u32()? as i32),
            4 => Value::OctetString(self.octets()?),
            5 => Value::Null,
            6 => Value::ObjectId(self.oid()?.0),
            64 => {
                let a: [u8; 4] = self
                    .octets()?
                    .try_into()
                    .map_err(|_| AgentxError("IpAddress is not 4 bytes"))?;
                Value::IpAddress(a.into())
            }
            65 => Value::Counter32(self.u32()?),
            66 => Value::Gauge32(self.u32()?),
            67 => Value::TimeTicks(self.u32()?),
            68 => Value::Opaque(self.octets()?),
            70 => Value::Counter64(self.u64()?),
            128 => Value::NoSuchObject,
            129 => Value::NoSuchInstance,
            130 => Value::EndOfMibView,
            _ => return Err(AgentxError("unknown value type")),
        };
        Ok(VarBind::new(oid, value))
    }

    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }
}

/// Writes AgentX payload fields in network byte order.
#[derive(Default)]
struct Out(Vec<u8>);

impl Out {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn oid(&mut self, o: &[u32], include: bool) {
        // The 1.3.6.1.x prefix compression of §5.1.
        let (prefix, rest) = match o {
            [1, 3, 6, 1, p, rest @ ..] if *p > 0 && *p < 256 => (*p as u8, rest),
            _ => (0, o),
        };
        self.u8(rest.len() as u8);
        self.u8(prefix);
        self.u8(include as u8);
        self.u8(0);
        for &a in rest {
            self.u32(a);
        }
    }

    fn octets(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
        self.0.resize(self.0.len() + (4 - b.len() % 4) % 4, 0);
    }

    fn varbind(&mut self, vb: &VarBind) {
        let t: u16 = match &vb.value {
            Value::Integer(_) => 2,
            Value::OctetString(_) => 4,
            Value::Null => 5,
            Value::ObjectId(_) => 6,
            Value::IpAddress(_) => 64,
            Value::Counter32(_) => 65,
            Value::Gauge32(_) => 66,
            Value::TimeTicks(_) => 67,
            Value::Opaque(_) => 68,
            Value::Counter64(_) => 70,
            Value::NoSuchObject => 128,
            Value::NoSuchInstance => 129,
            Value::EndOfMibView => 130,
        };
        self.u16(t);
        self.u16(0);
        self.oid(&vb.oid, false);
        match &vb.value {
            Value::Integer(v) => self.u32(*v as u32),
            Value::OctetString(b) | Value::Opaque(b) => self.octets(b),
            Value::ObjectId(o) => self.oid(o, false),
            Value::IpAddress(a) => self.octets(&a.octets()),
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => self.u32(*v),
            Value::Counter64(v) => {
                self.u32((v >> 32) as u32);
                self.u32(*v as u32);
            }
            _ => {}
        }
    }
}

impl Packet {
    /// The wire form (always network byte order).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER + self.payload.len());
        b.extend_from_slice(&[1, self.pdu_type, self.flags | F_NETWORK_BYTE_ORDER, 0]);
        b.extend_from_slice(&self.session_id.to_be_bytes());
        b.extend_from_slice(&self.transaction_id.to_be_bytes());
        b.extend_from_slice(&self.packet_id.to_be_bytes());
        b.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.payload);
        b
    }

    /// Parses a header; returns the packet without payload and the
    /// payload length.
    pub fn decode_header(h: &[u8; HEADER]) -> Result<(Packet, usize), AgentxError> {
        if h[0] != 1 {
            return Err(AgentxError("unsupported version"));
        }
        let mut r = In::new(&h[4..], h[2]);
        let session_id = r.u32()?;
        let transaction_id = r.u32()?;
        let packet_id = r.u32()?;
        let len = r.u32()? as usize;
        if len > MAX_PAYLOAD || len % 4 != 0 {
            return Err(AgentxError("bad payload length"));
        }
        Ok((
            Packet {
                pdu_type: h[1],
                flags: h[2],
                session_id,
                transaction_id,
                packet_id,
                payload: Vec::new(),
            },
            len,
        ))
    }
}

async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Packet> {
    let mut h = [0u8; HEADER];
    r.read_exact(&mut h).await?;
    let (mut p, len) = Packet::decode_header(&h)?;
    p.payload = vec![0; len];
    r.read_exact(&mut p.payload).await?;
    Ok(p)
}

/// A Response PDU payload (§6.2.16).
fn response(uptime: u32, error: u16, index: u16, varbinds: &[VarBind]) -> Vec<u8> {
    let mut o = Out::default();
    o.u32(uptime);
    o.u16(error);
    o.u16(index);
    for vb in varbinds {
        o.varbind(vb);
    }
    o.0
}

/// Search ranges of Get/GetNext/GetBulk, after the optional context.
fn ranges(r: &mut In<'_>) -> Result<Vec<(Oid, bool, Oid)>, AgentxError> {
    let mut v = Vec::new();
    while !r.done() {
        let (start, include) = r.oid()?;
        let (end, _) = r.oid()?;
        v.push((start, include, end));
    }
    Ok(v)
}

/// Sends notifications through the master agent (AgentX Notify).
#[derive(Clone)]
pub struct Notifier {
    tx: mpsc::UnboundedSender<Vec<VarBind>>,
    start: Instant,
}

impl fmt::Debug for Notifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notifier").finish_non_exhaustive()
    }
}

impl Notifier {
    /// Queues a notification (sysUpTime.0, snmpTrapOID.0, `varbinds`);
    /// the master sends it to its trap destinations. Fails if the
    /// subagent has stopped.
    pub fn notify(&self, trap_oid: Oid, varbinds: Vec<VarBind>) -> io::Result<()> {
        let uptime = (self.start.elapsed().as_millis() / 10) as u32;
        self.tx
            .send(notification_varbinds(uptime, trap_oid, varbinds))
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "subagent stopped"))
    }
}

/// An AgentX subagent.
pub struct Subagent {
    descr: String,
    id: Oid,
    timeout: u8,
    registry: Registry,
    notify_tx: mpsc::UnboundedSender<Vec<VarBind>>,
    notify_rx: mpsc::UnboundedReceiver<Vec<VarBind>>,
    start: Instant,
}

impl fmt::Debug for Subagent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subagent")
            .field("descr", &self.descr)
            .field("subtrees", &self.registry.prefixes().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Subagent {
    /// A subagent with a description (shown by the master).
    pub fn new(descr: impl Into<String>) -> Self {
        let (notify_tx, notify_rx) = mpsc::unbounded_channel();
        Subagent {
            descr: descr.into(),
            id: Oid::from_slice(&[]),
            timeout: 0,
            registry: Registry::default(),
            notify_tx,
            notify_rx,
            start: Instant::now(),
        }
    }

    /// The subagent's object identifier (sysObjectID-like); default none.
    pub fn with_id(mut self, id: Oid) -> Self {
        self.id = id;
        self
    }

    /// How long the master waits for answers, in seconds (0: its default).
    pub fn with_timeout(mut self, seconds: u8) -> Self {
        self.timeout = seconds;
        self
    }

    /// Serves `handler` under `prefix`; registered with the master on
    /// connect.
    pub fn register(mut self, prefix: Oid, handler: impl MibHandler + 'static) -> Self {
        self.registry.register(prefix, Arc::new(handler));
        self
    }

    /// A handle for sending notifications through the master.
    pub fn notifier(&self) -> Notifier {
        Notifier {
            tx: self.notify_tx.clone(),
            start: self.start,
        }
    }

    /// Connects to the master over TCP (net-snmp:
    /// `agentXSocket tcp:localhost:705`) and serves until the master closes
    /// the session.
    pub async fn run_tcp(self, addr: &str) -> io::Result<()> {
        let s = tokio::net::TcpStream::connect(addr).await?;
        s.set_nodelay(true)?;
        self.run(s).await
    }

    /// Connects to the master over a Unix socket (net-snmp's default
    /// `/var/agentx/master`).
    #[cfg(unix)]
    pub async fn run_unix(self, path: impl AsRef<std::path::Path>) -> io::Result<()> {
        self.run(tokio::net::UnixStream::connect(path).await?).await
    }

    /// Serves over an established connection to the master.
    pub async fn run<S: AsyncRead + AsyncWrite + Send + 'static>(
        mut self,
        stream: S,
    ) -> io::Result<()> {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut packet_id = 0u32;
        let mut next_packet = || {
            packet_id = packet_id.wrapping_add(1);
            packet_id
        };
        // Open the session.
        let mut o = Out::default();
        o.u8(self.timeout);
        o.0.extend_from_slice(&[0, 0, 0]);
        o.oid(&self.id, false);
        o.octets(self.descr.as_bytes());
        let open_id = next_packet();
        wr.write_all(
            &Packet {
                pdu_type: pdu_type::OPEN,
                flags: 0,
                session_id: 0,
                transaction_id: 0,
                packet_id: open_id,
                payload: o.0,
            }
            .encode(),
        )
        .await?;
        let resp = read_packet(&mut rd).await?;
        check_response(&resp, "Open")?;
        let session = resp.session_id;
        // Register every subtree.
        let prefixes: Vec<Oid> = self.registry.prefixes().cloned().collect();
        for p in &prefixes {
            let mut o = Out::default();
            o.0.extend_from_slice(&[self.timeout, 127, 0, 0]);
            o.oid(p, false);
            wr.write_all(
                &Packet {
                    pdu_type: pdu_type::REGISTER,
                    flags: 0,
                    session_id: session,
                    transaction_id: 0,
                    packet_id: next_packet(),
                    payload: o.0,
                }
                .encode(),
            )
            .await?;
            check_response(&read_packet(&mut rd).await?, "Register")?;
        }
        // Serve. A reader task feeds packets so writes (answers,
        // notifications) never wait on a half-read packet.
        let (ptx, mut prx) = mpsc::channel::<io::Result<Packet>>(64);
        let reader = tokio::spawn(async move {
            loop {
                let r = read_packet(&mut rd).await;
                let stop = r.is_err();
                if ptx.send(r).await.is_err() || stop {
                    break;
                }
            }
        });
        let mut pending: HashMap<u32, Vec<VarBind>> = HashMap::new();
        let result = loop {
            tokio::select! {
                p = prx.recv() => {
                    let p = match p {
                        Some(Ok(p)) => p,
                        Some(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break Ok(()),
                        Some(Err(e)) => break Err(e),
                        None => break Ok(()),
                    };
                    if p.pdu_type == pdu_type::CLOSE {
                        break Ok(());
                    }
                    if let Some(answer) = self.answer(&p, &mut pending)? {
                        wr.write_all(&answer.encode()).await?;
                    }
                }
                Some(vbs) = self.notify_rx.recv() => {
                    let mut o = Out::default();
                    for vb in &vbs {
                        o.varbind(vb);
                    }
                    wr.write_all(&Packet {
                        pdu_type: pdu_type::NOTIFY,
                        flags: 0,
                        session_id: session,
                        transaction_id: 0,
                        packet_id: next_packet(),
                        payload: o.0,
                    }.encode()).await?;
                }
            }
        };
        reader.abort();
        result
    }

    fn uptime(&self) -> u32 {
        (self.start.elapsed().as_millis() / 10) as u32
    }

    /// The answer to a request from the master (None: no answer due).
    fn answer(
        &self,
        p: &Packet,
        pending: &mut HashMap<u32, Vec<VarBind>>,
    ) -> io::Result<Option<Packet>> {
        let mut r = In::new(&p.payload, p.flags);
        if p.flags & F_NON_DEFAULT_CONTEXT != 0
            && matches!(
                p.pdu_type,
                pdu_type::GET | pdu_type::GET_NEXT | pdu_type::GET_BULK | pdu_type::TEST_SET
            )
        {
            r.octets()?; // contexts are not distinguished
        }
        let reg = &self.registry;
        let (error, index, vbs): (ErrorStatus, usize, Vec<VarBind>) = match p.pdu_type {
            pdu_type::GET => {
                let vbs = ranges(&mut r)?
                    .into_iter()
                    .map(|(start, _, _)| {
                        let v = reg.get(&start);
                        VarBind::new(start, v)
                    })
                    .collect();
                (ErrorStatus::NoError, 0, vbs)
            }
            pdu_type::GET_NEXT => {
                let vbs = ranges(&mut r)?
                    .into_iter()
                    .map(|(start, include, end)| self.next_in(&start, include, &end))
                    .collect();
                (ErrorStatus::NoError, 0, vbs)
            }
            pdu_type::GET_BULK => {
                let non_rep = r.u16()? as usize;
                let max_rep = r.u16()? as usize;
                let rs = ranges(&mut r)?;
                let non_rep = non_rep.min(rs.len());
                let mut vbs: Vec<VarBind> = rs[..non_rep]
                    .iter()
                    .map(|(s, i, e)| self.next_in(s, *i, e))
                    .collect();
                let mut cur: Vec<(Oid, bool, Oid)> = rs[non_rep..].to_vec();
                for _ in 0..max_rep {
                    if cur.is_empty() {
                        break;
                    }
                    let mut all_end = true;
                    for c in cur.iter_mut() {
                        let vb = self.next_in(&c.0, c.1, &c.2);
                        if vb.value != Value::EndOfMibView {
                            all_end = false;
                        }
                        c.0 = vb.oid.clone();
                        c.1 = false;
                        vbs.push(vb);
                    }
                    if all_end {
                        break;
                    }
                }
                (ErrorStatus::NoError, 0, vbs)
            }
            pdu_type::TEST_SET => {
                let mut vbs = Vec::new();
                while !r.done() {
                    vbs.push(r.varbind()?);
                }
                let fail = vbs
                    .iter()
                    .enumerate()
                    .find_map(|(i, vb)| reg.test_set(vb).err().map(|e| (e, i + 1)));
                match fail {
                    Some((e, i)) => (e, i, Vec::new()),
                    None => {
                        pending.insert(p.transaction_id, vbs);
                        (ErrorStatus::NoError, 0, Vec::new())
                    }
                }
            }
            pdu_type::COMMIT_SET => {
                let vbs = pending.get(&p.transaction_id).cloned().unwrap_or_default();
                let fail = vbs
                    .iter()
                    .enumerate()
                    .find_map(|(i, vb)| reg.commit_set(vb).err().map(|e| (e, i + 1)));
                match fail {
                    Some((_, i)) => (ErrorStatus::CommitFailed, i, Vec::new()),
                    None => (ErrorStatus::NoError, 0, Vec::new()),
                }
            }
            pdu_type::UNDO_SET => {
                pending.remove(&p.transaction_id);
                (ErrorStatus::NoError, 0, Vec::new())
            }
            pdu_type::CLEANUP_SET => {
                // No response is sent for CleanupSet (§7.2.4.4).
                pending.remove(&p.transaction_id);
                return Ok(None);
            }
            // Responses to our Notify and anything unknown: nothing to say.
            _ => return Ok(None),
        };
        Ok(Some(Packet {
            pdu_type: pdu_type::RESPONSE,
            flags: 0,
            session_id: p.session_id,
            transaction_id: p.transaction_id,
            packet_id: p.packet_id,
            payload: response(self.uptime(), error.code() as u16, index as u16, &vbs),
        }))
    }

    /// GetNext within a search range (§7.2.3.2).
    fn next_in(&self, start: &Oid, include: bool, end: &Oid) -> VarBind {
        if include {
            let v = self.registry.get(start);
            if !v.is_exception() {
                return VarBind::new(start.clone(), v);
            }
        }
        match self.registry.get_next(start) {
            Some(vb) if end.is_empty() || vb.oid < *end => vb,
            _ => VarBind::new(start.clone(), Value::EndOfMibView),
        }
    }
}

fn check_response(p: &Packet, what: &'static str) -> io::Result<()> {
    if p.pdu_type != pdu_type::RESPONSE {
        return Err(AgentxError("expected a Response").into());
    }
    let mut r = In::new(&p.payload, p.flags);
    r.u32()?;
    let error = r.u16()?;
    if error != 0 {
        return Err(io::Error::other(format!(
            "AgentX {what} refused by the master (error {error})"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_prefix_compression_and_values_round_trip() {
        let vbs = vec![
            VarBind::new([1, 3, 6, 1, 2, 1, 1, 5, 0], Value::from("name")),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 1], Value::Integer(-7)),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 2], Value::Counter64(1 << 40 | 5)),
            VarBind::new(
                [1, 2, 840],
                Value::ObjectId(Oid::from([1, 3, 6, 1, 6, 3, 1])),
            ),
            VarBind::new(
                [1, 3, 6, 1, 4, 1, 99999, 3],
                Value::IpAddress([10, 0, 0, 1].into()),
            ),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 4], Value::TimeTicks(9)),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 5], Value::Opaque(vec![1, 2, 3])),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 6], Value::Counter32(1)),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 7], Value::Gauge32(2)),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 8], Value::Null),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 9], Value::NoSuchObject),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 10], Value::NoSuchInstance),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 11], Value::EndOfMibView),
        ];
        let mut o = Out::default();
        for vb in &vbs {
            o.varbind(vb);
        }
        assert_eq!(o.0.len() % 4, 0);
        // sysName.0: 4 sub-ids after the 1.3.6.1.2 prefix.
        assert_eq!(&o.0[4..8], &[4, 2, 0, 0]);
        let mut r = In::new(&o.0, F_NETWORK_BYTE_ORDER);
        let back: Vec<VarBind> =
            std::iter::from_fn(|| (!r.done()).then(|| r.varbind().unwrap())).collect();
        assert_eq!(back, vbs);
    }

    #[test]
    fn little_endian_and_header() {
        // An OID in little-endian order: 2 sub-ids, prefix 4 (enterprises).
        let le = [2, 4, 1, 0, 0x9f, 0x86, 0x01, 0x00, 7, 0, 0, 0];
        let (o, include) = In::new(&le, 0).oid().unwrap();
        assert_eq!(o.to_string(), "1.3.6.1.4.99999.7");
        assert!(include);
        let p = Packet {
            pdu_type: pdu_type::PING,
            flags: 0,
            session_id: 5,
            transaction_id: 6,
            packet_id: 7,
            payload: vec![0; 8],
        };
        let b = p.encode();
        let h: [u8; HEADER] = b[..HEADER].try_into().unwrap();
        let (q, len) = Packet::decode_header(&h).unwrap();
        assert_eq!(
            (q.session_id, q.transaction_id, q.packet_id, len),
            (5, 6, 7, 8)
        );
        let mut bad = h;
        bad[0] = 2;
        assert!(Packet::decode_header(&bad).is_err());
        let mut odd = h;
        odd[19] = 3;
        assert!(Packet::decode_header(&odd).is_err());
        assert!(In::new(&[1, 0], 0).u32().is_err());
        assert!(In::new(&[200, 0, 0, 0], 0).oid().is_err());
        assert!(In::new(&[0, 0xff, 0, 0, 0, 0], 0).varbind().is_err());
        assert!(!AgentxError("x").to_string().is_empty());
    }

    fn sub() -> Subagent {
        let mib = crate::agent::MibTree::new();
        mib.insert("1.3.6.1.4.1.9.1.0".parse().unwrap(), 1);
        mib.insert("1.3.6.1.4.1.9.2.0".parse().unwrap(), 2);
        mib.insert_writable("1.3.6.1.4.1.9.3.0".parse().unwrap(), 3);
        Subagent::new("t").register("1.3.6.1.4.1.9".parse().unwrap(), mib)
    }

    fn packet(t: u8, flags: u8, tid: u32, payload: Vec<u8>) -> Packet {
        Packet {
            pdu_type: t,
            flags: flags | F_NETWORK_BYTE_ORDER,
            session_id: 1,
            transaction_id: tid,
            packet_id: 9,
            payload,
        }
    }

    fn answer_vbs(s: &Subagent, p: &Packet) -> (u16, u16, Vec<VarBind>) {
        let mut pending = HashMap::new();
        let a = s.answer(p, &mut pending).unwrap().unwrap();
        assert_eq!((a.pdu_type, a.packet_id), (pdu_type::RESPONSE, 9));
        let mut r = In::new(&a.payload, F_NETWORK_BYTE_ORDER);
        r.u32().unwrap();
        let (e, i) = (r.u16().unwrap(), r.u16().unwrap());
        let mut v = Vec::new();
        while !r.done() {
            v.push(r.varbind().unwrap());
        }
        (e, i, v)
    }

    #[test]
    fn answers_every_request() {
        let s = sub();
        let o = |x: &str| x.parse::<Oid>().unwrap();
        // GetBulk with a context: 1 non-repeater, 2 repetitions.
        let mut b = Out::default();
        b.octets(b"ctx");
        b.u16(1);
        b.u16(2);
        for (start, include) in [("1.3.6.1.4.1.9.1.0", true), ("1.3.6.1.4.1.9", false)] {
            b.oid(&o(start), include);
            b.oid(&[], false);
        }
        let (e, _, v) = answer_vbs(
            &s,
            &packet(pdu_type::GET_BULK, F_NON_DEFAULT_CONTEXT, 1, b.0),
        );
        assert_eq!(e, 0);
        let names: Vec<String> = v.iter().map(|vb| vb.oid.to_string()).collect();
        assert_eq!(
            names,
            [
                "1.3.6.1.4.1.9.1.0",
                "1.3.6.1.4.1.9.1.0",
                "1.3.6.1.4.1.9.2.0"
            ]
        );
        // GetNext bounded by an end: endOfMibView.
        let mut b = Out::default();
        b.oid(&o("1.3.6.1.4.1.9.1.0"), false);
        b.oid(&o("1.3.6.1.4.1.9.2"), false);
        let (_, _, v) = answer_vbs(&s, &packet(pdu_type::GET_NEXT, 0, 2, b.0));
        assert_eq!(v[0].value, Value::EndOfMibView);
        // TestSet failing, then succeeding; Commit; Undo; Cleanup.
        let set = |val: Value| {
            let mut b = Out::default();
            b.varbind(&VarBind::new(o("1.3.6.1.4.1.9.3.0"), val));
            b.0
        };
        let (e, i, _) = answer_vbs(&s, &packet(pdu_type::TEST_SET, 0, 3, set(Value::from("x"))));
        assert_eq!((e, i), (ErrorStatus::WrongType.code() as u16, 1));
        let mut pending = HashMap::new();
        let t = packet(pdu_type::TEST_SET, 0, 4, set(Value::Integer(7)));
        assert!(s.answer(&t, &mut pending).unwrap().is_some());
        assert!(pending.contains_key(&4));
        let c = packet(pdu_type::COMMIT_SET, 0, 4, vec![]);
        assert!(s.answer(&c, &mut pending).unwrap().is_some());
        assert_eq!(s.registry.get(&o("1.3.6.1.4.1.9.3.0")), Value::Integer(7));
        let u = packet(pdu_type::UNDO_SET, 0, 4, vec![]);
        assert!(s.answer(&u, &mut pending).unwrap().is_some());
        let cl = packet(pdu_type::CLEANUP_SET, 0, 4, vec![]);
        assert!(s.answer(&cl, &mut pending).unwrap().is_none());
        assert!(pending.is_empty());
        // Commit of a value that can no longer be set.
        pending.insert(5, vec![VarBind::new(o("1.3.6.1.4.1.9.1.0"), 1)]);
        let c = packet(pdu_type::COMMIT_SET, 0, 5, vec![]);
        let a = s.answer(&c, &mut pending).unwrap().unwrap();
        assert_eq!(
            &a.payload[4..6],
            &(ErrorStatus::CommitFailed.code() as u16).to_be_bytes()
        );
        // Unknown PDUs and responses get nothing; truncated ones an error.
        assert!(s
            .answer(&packet(pdu_type::RESPONSE, 0, 6, vec![]), &mut pending)
            .unwrap()
            .is_none());
        assert!(s
            .answer(&packet(pdu_type::GET, 0, 7, vec![1, 2]), &mut pending)
            .is_err());
        // Little-endian 16- and 64-bit fields.
        let mut le = In::new(&[1, 0, 2, 0, 0, 0, 1, 0, 0, 0], 0);
        assert_eq!(le.u16().unwrap(), 1);
        assert_eq!(le.u64().unwrap(), (1 << 32) | 2);
        assert!(format!("{s:?}").contains("subtrees"));
        assert!(format!("{:?}", s.notifier()).contains("Notifier"));
        // Response checks.
        let ok = packet(pdu_type::RESPONSE, 0, 0, response(0, 0, 0, &[]));
        assert!(check_response(&ok, "Open").is_ok());
        let refused = packet(pdu_type::RESPONSE, 0, 0, response(0, 263, 0, &[]));
        assert!(check_response(&refused, "Register")
            .unwrap_err()
            .to_string()
            .contains("263"));
        assert!(check_response(&packet(pdu_type::GET, 0, 0, vec![]), "Open").is_err());
    }

    #[tokio::test]
    async fn session_over_a_pipe() {
        // A fake master on an in-memory pipe: Open, Register, Get, Close.
        let (a, mut m) = tokio::io::duplex(4096);
        let s = sub();
        let n = s.notifier();
        let task = tokio::spawn(s.run(a));
        let open = read_packet(&mut m).await.unwrap();
        assert_eq!(open.pdu_type, pdu_type::OPEN);
        let reply = |p: &Packet, session| Packet {
            pdu_type: pdu_type::RESPONSE,
            flags: 0,
            session_id: session,
            transaction_id: p.transaction_id,
            packet_id: p.packet_id,
            payload: response(0, 0, 0, &[]),
        };
        m.write_all(&reply(&open, 42).encode()).await.unwrap();
        let reg = read_packet(&mut m).await.unwrap();
        assert_eq!((reg.pdu_type, reg.session_id), (pdu_type::REGISTER, 42));
        m.write_all(&reply(&reg, 42).encode()).await.unwrap();
        n.notify("1.3.6.1.4.1.9.0.1".parse().unwrap(), vec![])
            .unwrap();
        let notify = read_packet(&mut m).await.unwrap();
        assert_eq!(notify.pdu_type, pdu_type::NOTIFY);
        let mut b = Out::default();
        b.oid(&[1, 3, 6, 1, 4, 1, 9, 2, 0], false);
        b.oid(&[], false);
        m.write_all(&packet(pdu_type::GET, 0, 1, b.0).encode())
            .await
            .unwrap();
        let r = read_packet(&mut m).await.unwrap();
        assert_eq!(r.pdu_type, pdu_type::RESPONSE);
        m.write_all(&packet(pdu_type::CLOSE, 0, 0, vec![1, 0, 0, 0]).encode())
            .await
            .unwrap();
        task.await.unwrap().unwrap();
        assert!(n.notify("1.3".parse().unwrap(), vec![]).is_err());
    }

    #[tokio::test]
    async fn refused_open_and_closed_pipes() {
        let (a, mut m) = tokio::io::duplex(4096);
        let task = tokio::spawn(sub().run(a));
        let open = read_packet(&mut m).await.unwrap();
        let mut refused = Packet {
            pdu_type: pdu_type::RESPONSE,
            flags: 0,
            session_id: 0,
            transaction_id: 0,
            packet_id: open.packet_id,
            payload: response(0, 256, 0, &[]),
        };
        m.write_all(&refused.encode()).await.unwrap();
        assert!(task.await.unwrap().is_err());
        // The master hangs up after registration: a clean end.
        let (a, mut m) = tokio::io::duplex(4096);
        let task = tokio::spawn(sub().run(a));
        let open = read_packet(&mut m).await.unwrap();
        refused.payload = response(0, 0, 0, &[]);
        refused.packet_id = open.packet_id;
        m.write_all(&refused.encode()).await.unwrap();
        let reg = read_packet(&mut m).await.unwrap();
        refused.packet_id = reg.packet_id;
        m.write_all(&refused.encode()).await.unwrap();
        drop(m);
        assert!(task.await.unwrap().is_ok());
    }
}
