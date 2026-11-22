//! Python bindings of snmpify (`snmpify._snmpify`). The Python package
//! (python/snmpify) adds the value types and exceptions.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pyo3::exceptions::{PyStopAsyncIteration, PyStopIteration};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyByteArray, PyBytes, PyDict, PyList, PyString, PyTuple, PyType};
use pyo3_async_runtimes::tokio::future_into_py;

use snmpify::agent::{Access, MibTree};
use snmpify::client::{self, Community, Credentials, Options, Usm};
use snmpify::engine::LocalEngine;
use snmpify::notification::{self, NotificationKind, Sender};
use snmpify::usm::{AuthProtocol, PrivProtocol, SecurityLevel};
use snmpify::v3::ReportKind;
use snmpify::{Oid, Value, VarBind, Version};

fn rt() -> &'static tokio::runtime::Runtime {
    pyo3_async_runtimes::tokio::get_runtime()
}

// ---------------------------------------------------------------------------
// Exceptions and value types from the Python side of the package
// ---------------------------------------------------------------------------

static SNMP_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static TIMEOUT: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static AGENT_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static REPORT_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static INVALID: PyOnceLock<Py<PyType>> = PyOnceLock::new();

fn raise<A: for<'a> pyo3::call::PyCallArgs<'a>>(
    py: Python<'_>,
    cell: &'static PyOnceLock<Py<PyType>>,
    name: &str,
    args: A,
) -> PyErr {
    match cell
        .import(py, "snmpify.exceptions", name)
        .and_then(|cls| cls.call1(args))
    {
        Ok(v) => PyErr::from_value(v),
        Err(e) => e,
    }
}

fn invalid(py: Python<'_>, msg: impl Into<String>) -> PyErr {
    raise(py, &INVALID, "InvalidArgument", (msg.into(),))
}

fn report_name(k: &ReportKind) -> String {
    match k {
        ReportKind::UnsupportedSecurityLevel => "unsupportedSecurityLevel".into(),
        ReportKind::NotInTimeWindow => "notInTimeWindow".into(),
        ReportKind::UnknownUserName => "unknownUserName".into(),
        ReportKind::UnknownEngineId => "unknownEngineID".into(),
        ReportKind::WrongDigest => "wrongDigest".into(),
        ReportKind::DecryptionError => "decryptionError".into(),
        ReportKind::UnknownContext => "unknownContext".into(),
        ReportKind::UnavailableContext => "unavailableContext".into(),
        other => other.to_string(),
    }
}

fn err_with(py: Python<'_>, e: client::Error) -> PyErr {
    let msg = e.to_string();
    match e {
        client::Error::Timeout => raise(py, &TIMEOUT, "SnmpTimeout", (msg,)),
        client::Error::Snmp { status, index, oid } => raise(
            py,
            &AGENT_ERROR,
            "AgentError",
            (msg, status.to_string(), index, oid.map(|o| o.to_string())),
        ),
        client::Error::Report(k) => raise(py, &REPORT_ERROR, "ReportError", (msg, report_name(&k))),
        client::Error::InvalidOid(_) | client::Error::InvalidArgument(_) => invalid(py, msg),
        _ => raise(py, &SNMP_ERROR, "SnmpError", (msg,)),
    }
}

fn err(e: client::Error) -> PyErr {
    Python::attach(|py| err_with(py, e))
}

fn io_err(e: std::io::Error) -> PyErr {
    Python::attach(|py| raise(py, &SNMP_ERROR, "SnmpError", (e.to_string(),)))
}

macro_rules! types {
    ($($cell:ident $name:literal),*) => { $(static $cell: PyOnceLock<Py<PyType>> = PyOnceLock::new();)* };
}
types!(T_COUNTER32 "Counter32", T_GAUGE32 "Gauge32", T_TIMETICKS "TimeTicks", T_COUNTER64 "Counter64", T_IP "IpAddress", T_OID "ObjectId", T_OPAQUE "Opaque");
static EXCEPTIONS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

fn ty<'py>(
    py: Python<'py>,
    cell: &'static PyOnceLock<Py<PyType>>,
    name: &str,
) -> PyResult<&'py Bound<'py, PyType>> {
    cell.import(py, "snmpify._types", name)
}

/// The three exception singletons (NO_SUCH_OBJECT …).
fn exception_value(py: Python<'_>, v: &Value) -> PyResult<Py<PyAny>> {
    let names = EXCEPTIONS.get_or_try_init(py, || -> PyResult<Py<PyAny>> {
        let m = py.import("snmpify._types")?;
        Ok(PyTuple::new(
            py,
            [
                m.getattr("NO_SUCH_OBJECT")?,
                m.getattr("NO_SUCH_INSTANCE")?,
                m.getattr("END_OF_MIB_VIEW")?,
            ],
        )?
        .into_any()
        .unbind())
    })?;
    let i = match v {
        Value::NoSuchObject => 0,
        Value::NoSuchInstance => 1,
        _ => 2,
    };
    Ok(names.bind(py).get_item(i)?.unbind())
}

fn to_py(py: Python<'_>, v: &Value) -> PyResult<Py<PyAny>> {
    Ok(match v {
        Value::Integer(n) => n.into_pyobject(py)?.into_any().unbind(),
        Value::OctetString(b) => PyBytes::new(py, b).into_any().unbind(),
        Value::Null => py.None(),
        Value::ObjectId(o) => ty(py, &T_OID, "ObjectId")?
            .call1((o.to_string(),))?
            .unbind(),
        Value::IpAddress(a) => ty(py, &T_IP, "IpAddress")?
            .call1((a.to_string(),))?
            .unbind(),
        Value::Counter32(n) => ty(py, &T_COUNTER32, "Counter32")?.call1((*n,))?.unbind(),
        Value::Gauge32(n) => ty(py, &T_GAUGE32, "Gauge32")?.call1((*n,))?.unbind(),
        Value::TimeTicks(n) => ty(py, &T_TIMETICKS, "TimeTicks")?.call1((*n,))?.unbind(),
        Value::Opaque(b) => ty(py, &T_OPAQUE, "Opaque")?
            .call1((PyBytes::new(py, b),))?
            .unbind(),
        Value::Counter64(n) => ty(py, &T_COUNTER64, "Counter64")?.call1((*n,))?.unbind(),
        _ => exception_value(py, v)?,
    })
}

fn from_py(v: &Bound<'_, PyAny>) -> PyResult<Value> {
    let py = v.py();
    let range = |what: &str| invalid(py, format!("value out of range for {what}"));
    let u32_of = |what: &str| v.extract::<u32>().map_err(|_| range(what));
    if v.is_none() {
        return Ok(Value::Null);
    }
    if v.is_instance(ty(py, &T_COUNTER32, "Counter32")?)? {
        return Ok(Value::Counter32(u32_of("Counter32")?));
    }
    if v.is_instance(ty(py, &T_GAUGE32, "Gauge32")?)? {
        return Ok(Value::Gauge32(u32_of("Gauge32")?));
    }
    if v.is_instance(ty(py, &T_TIMETICKS, "TimeTicks")?)? {
        return Ok(Value::TimeTicks(u32_of("TimeTicks")?));
    }
    if v.is_instance(ty(py, &T_COUNTER64, "Counter64")?)? {
        return Ok(Value::Counter64(
            v.extract::<u64>().map_err(|_| range("Counter64"))?,
        ));
    }
    if v.is_instance(ty(py, &T_IP, "IpAddress")?)? {
        let s: String = v.extract()?;
        let a: Ipv4Addr = s
            .parse()
            .map_err(|_| invalid(py, format!("invalid IpAddress {s:?}")))?;
        return Ok(Value::IpAddress(a));
    }
    if v.is_instance(ty(py, &T_OID, "ObjectId")?)? {
        return Ok(Value::ObjectId(parse_oid(py, &v.extract::<String>()?)?));
    }
    if v.is_instance(ty(py, &T_OPAQUE, "Opaque")?)? {
        return Ok(Value::Opaque(v.extract::<Vec<u8>>()?));
    }
    if v.is_instance_of::<pyo3::types::PyBool>() {
        return Err(invalid(
            py,
            "booleans are not SNMP values; use 1 / 2 (TruthValue)",
        ));
    }
    if v.is_instance_of::<pyo3::types::PyInt>() {
        return Ok(Value::Integer(
            v.extract::<i32>().map_err(|_| range("INTEGER"))?,
        ));
    }
    if let Ok(s) = v.cast::<PyString>() {
        return Ok(Value::OctetString(s.extract::<String>()?.into_bytes()));
    }
    if let Ok(b) = v.cast::<PyBytes>() {
        return Ok(Value::OctetString(b.as_bytes().to_vec()));
    }
    if let Ok(b) = v.cast::<PyByteArray>() {
        return Ok(Value::OctetString(b.to_vec()));
    }
    Err(invalid(
        py,
        format!("cannot send a {} as an SNMP value", v.get_type().name()?),
    ))
}

fn parse_oid(py: Python<'_>, s: &str) -> PyResult<Oid> {
    let o: Oid = s
        .trim()
        .trim_start_matches('.')
        .parse()
        .map_err(|_| invalid(py, format!("invalid OID {s:?}")))?;
    Ok(o)
}

fn oids(py: Python<'_>, v: &Bound<'_, PyAny>) -> PyResult<Vec<Oid>> {
    if let Ok(s) = v.extract::<String>() {
        return Ok(vec![parse_oid(py, &s)?]);
    }
    v.try_iter()?
        .map(|x| parse_oid(py, &x?.extract::<String>()?))
        .collect()
}

/// `(oid, value)`.
fn pair(py: Python<'_>, vb: &VarBind) -> PyResult<Py<PyAny>> {
    let oid = vb.oid.to_string().into_pyobject(py)?.into_any();
    Ok(
        PyTuple::new(py, [oid, to_py(py, &vb.value)?.into_bound(py)])?
            .into_any()
            .unbind(),
    )
}

fn varbinds_to_py(py: Python<'_>, vbs: &[VarBind]) -> PyResult<Py<PyAny>> {
    let items = vbs
        .iter()
        .map(|vb| pair(py, vb))
        .collect::<PyResult<Vec<_>>>()?;
    Ok(PyList::new(py, items)?.into_any().unbind())
}

fn varbinds_from_py(py: Python<'_>, v: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<VarBind>> {
    let Some(v) = v else { return Ok(Vec::new()) };
    let iter: Vec<Bound<'_, PyAny>> = if let Ok(d) = v.cast::<PyDict>() {
        d.items().iter().collect()
    } else {
        v.try_iter()?.collect::<PyResult<_>>()?
    };
    iter.into_iter()
        .map(|item| {
            let (oid, value): (String, Bound<'_, PyAny>) = item.extract()?;
            Ok(VarBind::new(parse_oid(py, &oid)?, from_py(&value)?))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// UsmUser
// ---------------------------------------------------------------------------

fn auth_protocol(py: Python<'_>, s: &str) -> PyResult<AuthProtocol> {
    Ok(
        match s.to_ascii_uppercase().replace(['-', '_'], "").as_str() {
            "MD5" => AuthProtocol::Md5,
            "SHA" | "SHA1" => AuthProtocol::Sha1,
            "SHA224" => AuthProtocol::Sha224,
            "SHA256" => AuthProtocol::Sha256,
            "SHA384" => AuthProtocol::Sha384,
            "SHA512" => AuthProtocol::Sha512,
            _ => {
                return Err(invalid(
                    py,
                    format!("unknown authentication protocol {s:?}"),
                ))
            }
        },
    )
}

fn priv_protocol(py: Python<'_>, s: &str) -> PyResult<PrivProtocol> {
    Ok(
        match s.to_ascii_uppercase().replace(['-', '_'], "").as_str() {
            "DES" => PrivProtocol::Des,
            "AES" | "AES128" => PrivProtocol::Aes128,
            "AES192" => PrivProtocol::Aes192,
            "AES256" => PrivProtocol::Aes256,
            "AES192C" => PrivProtocol::Aes192Cisco,
            "AES256C" => PrivProtocol::Aes256Cisco,
            "3DES" | "DES3" | "3DESEDE" | "TDES" => PrivProtocol::Des3,
            _ => return Err(invalid(py, format!("unknown privacy protocol {s:?}"))),
        },
    )
}

/// An SNMPv3 user. ``auth`` and ``privacy`` are ``(protocol, password)``
/// pairs: protocols MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512 and DES,
/// AES (128), AES-192, AES-256, AES-192-C, AES-256-C (Cisco's key
/// extension). Passwords are hashed into keys once.
#[pyclass(frozen, module = "snmpify")]
struct UsmUser {
    inner: snmpify::usm::UsmUser,
}

#[pymethods]
impl UsmUser {
    #[new]
    #[pyo3(signature = (name, auth=None, privacy=None))]
    fn new(
        py: Python<'_>,
        name: &str,
        auth: Option<(String, String)>,
        privacy: Option<(String, String)>,
    ) -> PyResult<Self> {
        let usm_err = |e: snmpify::usm::UsmError| invalid(py, e.to_string());
        let mut u = snmpify::usm::UsmUser::new(name);
        if let Some((p, pw)) = auth {
            let p = auth_protocol(py, &p)?;
            u = py.detach(|| u.with_auth(p, pw)).map_err(usm_err)?;
        }
        if let Some((p, pw)) = privacy {
            let p = priv_protocol(py, &p)?;
            u = py.detach(|| u.with_privacy(p, pw)).map_err(usm_err)?;
        }
        Ok(UsmUser { inner: u })
    }

    /// The user name.
    #[getter]
    fn name(&self) -> String {
        String::from_utf8_lossy(self.inner.name()).into_owned()
    }

    /// "noAuthNoPriv", "authNoPriv" or "authPriv".
    #[getter]
    fn level(&self) -> &'static str {
        level_name(self.inner.level())
    }

    fn __repr__(&self) -> String {
        format!("UsmUser({:?}, {})", self.name(), self.level())
    }
}

fn level_name(l: SecurityLevel) -> &'static str {
    match l {
        SecurityLevel::NoAuthNoPriv => "noAuthNoPriv",
        SecurityLevel::AuthNoPriv => "authNoPriv",
        SecurityLevel::AuthPriv => "authPriv",
    }
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

fn credentials(
    py: Python<'_>,
    community: &str,
    version: &str,
    user: Option<&UsmUser>,
    context: Option<&str>,
) -> PyResult<Credentials> {
    Ok(match user {
        Some(u) => {
            let mut usm = Usm::new(u.inner.clone());
            if let Some(c) = context {
                usm = usm.with_context(c);
            }
            usm.into()
        }
        None => match version {
            "1" | "v1" => Community::v1(community).into(),
            "2c" | "v2c" | "2" => Community::v2c(community).into(),
            _ => {
                return Err(invalid(
                    py,
                    format!("version {version:?}: use \"1\" or \"2c\" (v3: pass user=)"),
                ))
            }
        },
    })
}

fn options(py: Python<'_>, timeout: f64, retries: u32, max_repetitions: u32) -> PyResult<Options> {
    if !(timeout > 0.0 && timeout.is_finite()) {
        return Err(invalid(py, "timeout must be a positive number of seconds"));
    }
    Ok(Options {
        timeout: Duration::from_secs_f64(timeout),
        retries,
        max_repetitions,
    })
}

#[allow(clippy::too_many_arguments)]
fn connect(
    py: Python<'_>,
    target: &str,
    community: &str,
    version: &str,
    user: Option<&UsmUser>,
    context: Option<&str>,
    timeout: f64,
    retries: u32,
    max_repetitions: u32,
    tcp: bool,
) -> PyResult<client::Client> {
    let creds = credentials(py, community, version, user, context)?;
    let options = options(py, timeout, retries, max_repetitions)?;
    let target = with_port(target);
    py.detach(|| {
        rt().block_on(async {
            if tcp {
                client::Client::connect_tcp(&target, creds).await
            } else {
                client::Client::connect(&target, creds).await
            }
        })
    })
    .map(|c| c.with_options(options))
    .map_err(|e| err_with(py, e))
}

/// Many agents over one UDP socket: clients made by a manager share its
/// socket (polling thousands of agents costs one socket). At most
/// ``max_in_flight`` requests are outstanding at once; more wait.
#[pyclass(frozen, module = "snmpify")]
struct Manager {
    inner: client::Manager,
}

#[pymethods]
impl Manager {
    #[new]
    #[pyo3(signature = (local="0.0.0.0:0", *, timeout=1.0, retries=2, max_repetitions=25, max_in_flight=64))]
    fn new(
        py: Python<'_>,
        local: &str,
        timeout: f64,
        retries: u32,
        max_repetitions: u32,
        max_in_flight: usize,
    ) -> PyResult<Self> {
        let opts = options(py, timeout, retries, max_repetitions)?;
        let local = local.to_string();
        let m = py
            .detach(|| rt().block_on(client::Manager::bind(&local)))
            .map_err(|e| err_with(py, e))?;
        Ok(Manager {
            inner: m.with_options(opts).with_max_in_flight(max_in_flight),
        })
    }

    /// An :class:`AsyncClient` for one agent on the manager's socket.
    #[pyo3(signature = (target, community="public", version="2c", *, user=None, context=None))]
    fn client(
        &self,
        py: Python<'_>,
        target: &str,
        community: &str,
        version: &str,
        user: Option<PyRef<'_, UsmUser>>,
        context: Option<&str>,
    ) -> PyResult<AsyncClient> {
        Ok(AsyncClient {
            inner: self.make(py, target, community, version, user.as_deref(), context)?,
        })
    }

    /// A blocking :class:`Client` for one agent on the manager's socket.
    #[pyo3(signature = (target, community="public", version="2c", *, user=None, context=None))]
    fn blocking_client(
        &self,
        py: Python<'_>,
        target: &str,
        community: &str,
        version: &str,
        user: Option<PyRef<'_, UsmUser>>,
        context: Option<&str>,
    ) -> PyResult<Client> {
        Ok(Client {
            inner: self.make(py, target, community, version, user.as_deref(), context)?,
        })
    }

    /// The local address of the socket.
    #[getter]
    fn address(&self, py: Python<'_>) -> PyResult<String> {
        self.inner
            .local_addr()
            .map(|a| a.to_string())
            .map_err(|e| err_with(py, e))
    }
}

impl Manager {
    fn make(
        &self,
        py: Python<'_>,
        target: &str,
        community: &str,
        version: &str,
        user: Option<&UsmUser>,
        context: Option<&str>,
    ) -> PyResult<client::Client> {
        use std::net::ToSocketAddrs;
        let creds = credentials(py, community, version, user, context)?;
        let t = with_port(target);
        let addr = t
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .ok_or_else(|| invalid(py, format!("target {target:?} does not resolve")))?;
        Ok(self.inner.client(addr, creds))
    }
}

/// `host` → `host:161`, a bare IPv6 address → `[addr]:161`.
fn with_port(t: &str) -> String {
    if t.parse::<std::net::SocketAddr>().is_ok() {
        t.to_string()
    } else if t.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{t}]:161")
    } else if t.contains(':') {
        t.to_string()
    } else {
        format!("{t}:161")
    }
}

fn version_name(v: Version) -> &'static str {
    match v {
        Version::V1 => "1",
        Version::V2c => "2c",
        Version::V3 => "3",
    }
}

/// A blocking SNMP client for one agent (v1, v2c, or v3 with ``user=``).
///
/// ``target`` is ``"host"`` or ``"host:port"`` (port 161 by default).
/// Values come back as Python values: ``int``, ``bytes``, and the SNMP
/// types of :mod:`snmpify` (``Counter32`` …). The GIL is released while
/// waiting, so threads can share a client.
#[pyclass(frozen, module = "snmpify")]
struct Client {
    inner: client::Client,
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (target, community="public", version="2c", *, user=None, context=None, timeout=1.0, retries=2, max_repetitions=25, tcp=false))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        target: &str,
        community: &str,
        version: &str,
        user: Option<PyRef<'_, UsmUser>>,
        context: Option<&str>,
        timeout: f64,
        retries: u32,
        max_repetitions: u32,
        tcp: bool,
    ) -> PyResult<Self> {
        let inner = connect(
            py,
            target,
            community,
            version,
            user.as_deref(),
            context,
            timeout,
            retries,
            max_repetitions,
            tcp,
        )?;
        Ok(Client { inner })
    }

    /// "1", "2c" or "3".
    #[getter]
    fn version(&self) -> &'static str {
        version_name(self.inner.version())
    }

    /// The agent's address.
    #[getter]
    fn target(&self) -> String {
        self.inner.target().to_string()
    }

    /// SNMPv3: the agent's engine id once discovered.
    #[getter]
    fn engine_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.engine_id().map(|e| PyBytes::new(py, &e))
    }

    /// The value of one OID.
    fn get(&self, py: Python<'_>, oid: &str) -> PyResult<Py<PyAny>> {
        let (c, o) = (self.inner.clone(), parse_oid(py, oid)?);
        let v = py
            .detach(|| rt().block_on(c.get_one(o)))
            .map_err(|e| err_with(py, e))?;
        to_py(py, &v)
    }

    /// Several OIDs in one request: ``[(oid, value), …]``.
    fn get_many(&self, py: Python<'_>, oids_: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let (c, o) = (self.inner.clone(), oids(py, oids_)?);
        let v = py
            .detach(|| rt().block_on(c.get(o)))
            .map_err(|e| err_with(py, e))?;
        varbinds_to_py(py, &v)
    }

    /// GetNext: the next object after each OID.
    fn get_next(&self, py: Python<'_>, oids_: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let (c, o) = (self.inner.clone(), oids(py, oids_)?);
        let v = py
            .detach(|| rt().block_on(c.get_next(o)))
            .map_err(|e| err_with(py, e))?;
        varbinds_to_py(py, &v)
    }

    /// GetBulk (v2c, v3).
    #[pyo3(signature = (oids, non_repeaters=0, max_repetitions=10))]
    fn get_bulk(
        &self,
        py: Python<'_>,
        oids: &Bound<'_, PyAny>,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> PyResult<Py<PyAny>> {
        let (c, o) = (self.inner.clone(), self::oids(py, oids)?);
        let v = py
            .detach(|| rt().block_on(c.get_bulk(non_repeaters, max_repetitions, o)))
            .map_err(|e| err_with(py, e))?;
        varbinds_to_py(py, &v)
    }

    /// Set: ``[(oid, value), …]`` or ``{oid: value}``.
    fn set(&self, py: Python<'_>, varbinds: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let (c, vbs) = (self.inner.clone(), varbinds_from_py(py, Some(varbinds))?);
        let v = py
            .detach(|| rt().block_on(c.set(vbs)))
            .map_err(|e| err_with(py, e))?;
        varbinds_to_py(py, &v)
    }

    /// The subtree under ``oid`` as an iterator of ``(oid, value)``
    /// (GetBulk in v2c/v3, GetNext in v1).
    fn walk(&self, py: Python<'_>, oid: &str) -> PyResult<Walk> {
        let w = self
            .inner
            .walk(parse_oid(py, oid)?)
            .map_err(|e| err_with(py, e))?;
        Ok(Walk {
            inner: Mutex::new(w),
        })
    }

    /// Sends a trap (v2c, v3): ``trap_oid`` then ``varbinds``.
    #[pyo3(signature = (trap_oid, varbinds=None))]
    fn trap(
        &self,
        py: Python<'_>,
        trap_oid: &str,
        varbinds: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let (c, o, vbs) = (
            self.inner.clone(),
            parse_oid(py, trap_oid)?,
            varbinds_from_py(py, varbinds)?,
        );
        py.detach(|| rt().block_on(c.trap(o, vbs)))
            .map_err(|e| err_with(py, e))
    }

    /// Sends an inform (v2c, v3) and waits for the acknowledgement.
    #[pyo3(signature = (trap_oid, varbinds=None))]
    fn inform(
        &self,
        py: Python<'_>,
        trap_oid: &str,
        varbinds: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let (c, o, vbs) = (
            self.inner.clone(),
            parse_oid(py, trap_oid)?,
            varbinds_from_py(py, varbinds)?,
        );
        let v = py
            .detach(|| rt().block_on(c.inform(o, vbs)))
            .map_err(|e| err_with(py, e))?;
        varbinds_to_py(py, &v)
    }

    fn __repr__(&self) -> String {
        format!("Client({:?}, version={:?})", self.target(), self.version())
    }
}

/// A blocking walk.
#[pyclass(module = "snmpify")]
struct Walk {
    inner: Mutex<client::Walk>,
}

#[pymethods]
impl Walk {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let item = py.detach(|| {
            let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            rt().block_on(w.next())
        });
        match item {
            Some(Ok(vb)) => pair(py, &vb),
            Some(Err(e)) => Err(err_with(py, e)),
            None => Err(PyStopIteration::new_err(())),
        }
    }
}

/// The asyncio client: the methods of :class:`Client` as coroutines, and
/// ``walk`` as an async iterator.
#[pyclass(frozen, module = "snmpify")]
struct AsyncClient {
    inner: client::Client,
}

#[pymethods]
impl AsyncClient {
    #[new]
    #[pyo3(signature = (target, community="public", version="2c", *, user=None, context=None, timeout=1.0, retries=2, max_repetitions=25, tcp=false))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        target: &str,
        community: &str,
        version: &str,
        user: Option<PyRef<'_, UsmUser>>,
        context: Option<&str>,
        timeout: f64,
        retries: u32,
        max_repetitions: u32,
        tcp: bool,
    ) -> PyResult<Self> {
        let inner = connect(
            py,
            target,
            community,
            version,
            user.as_deref(),
            context,
            timeout,
            retries,
            max_repetitions,
            tcp,
        )?;
        Ok(AsyncClient { inner })
    }

    #[getter]
    fn version(&self) -> &'static str {
        version_name(self.inner.version())
    }

    #[getter]
    fn target(&self) -> String {
        self.inner.target().to_string()
    }

    #[getter]
    fn engine_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.engine_id().map(|e| PyBytes::new(py, &e))
    }

    fn get<'py>(&self, py: Python<'py>, oid: &str) -> PyResult<Bound<'py, PyAny>> {
        let (c, o) = (self.inner.clone(), parse_oid(py, oid)?);
        future_into_py(py, async move {
            let v = c.get_one(o).await.map_err(err)?;
            Python::attach(|py| to_py(py, &v))
        })
    }

    fn get_many<'py>(
        &self,
        py: Python<'py>,
        oids_: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (c, o) = (self.inner.clone(), oids(py, oids_)?);
        future_into_py(py, async move {
            let v = c.get(o).await.map_err(err)?;
            Python::attach(|py| varbinds_to_py(py, &v))
        })
    }

    fn get_next<'py>(
        &self,
        py: Python<'py>,
        oids_: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (c, o) = (self.inner.clone(), oids(py, oids_)?);
        future_into_py(py, async move {
            let v = c.get_next(o).await.map_err(err)?;
            Python::attach(|py| varbinds_to_py(py, &v))
        })
    }

    #[pyo3(signature = (oids, non_repeaters=0, max_repetitions=10))]
    fn get_bulk<'py>(
        &self,
        py: Python<'py>,
        oids: &Bound<'py, PyAny>,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (c, o) = (self.inner.clone(), self::oids(py, oids)?);
        future_into_py(py, async move {
            let v = c
                .get_bulk(non_repeaters, max_repetitions, o)
                .await
                .map_err(err)?;
            Python::attach(|py| varbinds_to_py(py, &v))
        })
    }

    fn set<'py>(
        &self,
        py: Python<'py>,
        varbinds: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (c, vbs) = (self.inner.clone(), varbinds_from_py(py, Some(varbinds))?);
        future_into_py(py, async move {
            let v = c.set(vbs).await.map_err(err)?;
            Python::attach(|py| varbinds_to_py(py, &v))
        })
    }

    /// ``async for oid, value in client.walk(oid)``.
    fn walk(&self, py: Python<'_>, oid: &str) -> PyResult<AsyncWalk> {
        let w = self
            .inner
            .walk(parse_oid(py, oid)?)
            .map_err(|e| err_with(py, e))?;
        Ok(AsyncWalk {
            inner: Arc::new(tokio::sync::Mutex::new(w)),
        })
    }

    #[pyo3(signature = (trap_oid, varbinds=None))]
    fn trap<'py>(
        &self,
        py: Python<'py>,
        trap_oid: &str,
        varbinds: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (c, o, vbs) = (
            self.inner.clone(),
            parse_oid(py, trap_oid)?,
            varbinds_from_py(py, varbinds)?,
        );
        future_into_py(py, async move { c.trap(o, vbs).await.map_err(err) })
    }

    #[pyo3(signature = (trap_oid, varbinds=None))]
    fn inform<'py>(
        &self,
        py: Python<'py>,
        trap_oid: &str,
        varbinds: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (c, o, vbs) = (
            self.inner.clone(),
            parse_oid(py, trap_oid)?,
            varbinds_from_py(py, varbinds)?,
        );
        future_into_py(py, async move {
            let v = c.inform(o, vbs).await.map_err(err)?;
            Python::attach(|py| varbinds_to_py(py, &v))
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "AsyncClient({:?}, version={:?})",
            self.target(),
            self.version()
        )
    }
}

/// An asynchronous walk.
#[pyclass(frozen, module = "snmpify")]
struct AsyncWalk {
    inner: Arc<tokio::sync::Mutex<client::Walk>>,
}

#[pymethods]
impl AsyncWalk {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let w = self.inner.clone();
        future_into_py(py, async move {
            let item = w.lock().await.next().await;
            match item {
                Some(Ok(vb)) => Python::attach(|py| pair(py, &vb)),
                Some(Err(e)) => Err(err(e)),
                None => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

/// A received trap or inform, in SNMPv2 form.
#[pyclass(frozen, module = "snmpify")]
struct Notification {
    inner: notification::Notification,
}

#[pymethods]
impl Notification {
    /// "trap" or "inform".
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner.kind {
            NotificationKind::Trap => "trap",
            NotificationKind::Inform => "inform",
        }
    }

    /// The sender's address.
    #[getter]
    fn source(&self) -> String {
        self.inner.source.to_string()
    }

    /// "1", "2c" or "3".
    #[getter]
    fn version(&self) -> &'static str {
        version_name(self.inner.version)
    }

    /// The community (v1, v2c).
    #[getter]
    fn community<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        match &self.inner.sender {
            Sender::Community(c) => Some(PyBytes::new(py, c)),
            _ => None,
        }
    }

    /// The SNMPv3 user.
    #[getter]
    fn user(&self) -> Option<String> {
        match &self.inner.sender {
            Sender::Usm { user, .. } => Some(String::from_utf8_lossy(user).into_owned()),
            _ => None,
        }
    }

    /// The SNMPv3 security level.
    #[getter]
    fn level(&self) -> Option<&'static str> {
        match &self.inner.sender {
            Sender::Usm { level, .. } => Some(level_name(*level)),
            _ => None,
        }
    }

    /// snmpTrapOID.0.
    #[getter]
    fn trap_oid(&self) -> String {
        self.inner.trap_oid.to_string()
    }

    /// sysUpTime.0 of the sender, hundredths of a second.
    #[getter]
    fn uptime(&self) -> Option<u32> {
        self.inner.uptime
    }

    /// The bindings after sysUpTime.0 and snmpTrapOID.0.
    #[getter]
    fn varbinds(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        varbinds_to_py(py, &self.inner.varbinds)
    }

    fn __repr__(&self) -> String {
        format!(
            "Notification({} {} from {})",
            self.kind(),
            self.trap_oid(),
            self.source()
        )
    }
}

/// Receives traps and informs (informs are acknowledged).
///
/// ``communities`` lists the accepted v1/v2c communities (``None``: any);
/// ``users`` the SNMPv3 users, with ``engine_id`` the receiver's engine
/// id for informs (random if not given).
#[pyclass(frozen, module = "snmpify")]
struct NotificationReceiver {
    inner: Arc<tokio::sync::Mutex<notification::NotificationReceiver>>,
    addr: String,
}

#[pymethods]
impl NotificationReceiver {
    #[new]
    #[pyo3(signature = (address="0.0.0.0:162", communities=Some(vec!["public".to_string()]), users=Vec::new(), engine_id=None))]
    fn new(
        py: Python<'_>,
        address: &str,
        communities: Option<Vec<String>>,
        users: Vec<PyRef<'_, UsmUser>>,
        engine_id: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let mut engine = LocalEngine::new(engine_id.unwrap_or_else(LocalEngine::generate_id));
        let has_users = !users.is_empty();
        for u in &users {
            engine = engine.with_user(u.inner.clone());
        }
        let addr = address.to_string();
        let mut r = py
            .detach(|| rt().block_on(notification::NotificationReceiver::bind(&addr)))
            .map_err(io_err)?;
        match communities {
            None => r = r.with_any_community(),
            Some(cs) => {
                for c in cs {
                    r = r.with_community(c);
                }
            }
        }
        if has_users {
            r = r.with_engine(engine);
        }
        let addr = r.local_addr().map_err(io_err)?.to_string();
        Ok(NotificationReceiver {
            inner: Arc::new(tokio::sync::Mutex::new(r)),
            addr,
        })
    }

    /// The local address.
    #[getter]
    fn address(&self) -> String {
        self.addr.clone()
    }

    /// The next notification (blocking), or ``None`` after ``timeout``
    /// seconds.
    #[pyo3(signature = (timeout=None))]
    fn recv(&self, py: Python<'_>, timeout: Option<f64>) -> PyResult<Option<Notification>> {
        let r = self.inner.clone();
        let got = py.detach(|| {
            rt().block_on(async move {
                let mut r = r.lock().await;
                match timeout {
                    None => r.recv().await.map(Some),
                    Some(t) => {
                        match tokio::time::timeout(Duration::from_secs_f64(t.max(0.0)), r.recv())
                            .await
                        {
                            Ok(x) => x.map(Some),
                            Err(_) => Ok(None),
                        }
                    }
                }
            })
        });
        Ok(got.map_err(io_err)?.map(|n| Notification { inner: n }))
    }

    /// The next notification (a coroutine).
    fn recv_async<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let r = self.inner.clone();
        future_into_py(py, async move {
            let n = r.lock().await.recv().await.map_err(io_err)?;
            Ok(Notification { inner: n })
        })
    }

    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.recv_async(py)
    }

    fn __repr__(&self) -> String {
        format!("NotificationReceiver({:?})", self.addr)
    }
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

/// An SNMP agent serving values set from Python.
///
/// ``communities`` maps community → ``"ro"`` / ``"rw"``; ``users`` is a
/// list of ``(UsmUser, "ro" | "rw")``. Values: :meth:`set` (fixed or
/// writable) and :meth:`set_callback` (computed on every read).
#[pyclass(frozen, module = "snmpify")]
struct Agent {
    mib: MibTree,
    running: Mutex<Option<tokio::task::JoinHandle<std::io::Result<()>>>>,
    config: Mutex<Option<snmpify::agent::Agent>>,
    addr: String,
}

fn access(py: Python<'_>, s: &str) -> PyResult<Access> {
    match s {
        "ro" | "read-only" => Ok(Access::ReadOnly),
        "rw" | "read-write" => Ok(Access::ReadWrite),
        _ => Err(invalid(py, format!("access {s:?}: use \"ro\" or \"rw\""))),
    }
}

#[pymethods]
impl Agent {
    #[new]
    #[pyo3(signature = (address="0.0.0.0:161", communities=None, users=Vec::new(), engine_id=None))]
    fn new(
        py: Python<'_>,
        address: &str,
        communities: Option<HashMap<String, String>>,
        users: Vec<(PyRef<'_, UsmUser>, String)>,
        engine_id: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let addr = address.to_string();
        let mut a = py
            .detach(|| rt().block_on(snmpify::agent::Agent::bind(&addr)))
            .map_err(io_err)?;
        let communities = communities
            .unwrap_or_else(|| HashMap::from([("public".to_string(), "ro".to_string())]));
        for (c, acc) in communities {
            a = a.with_community(c, access(py, &acc)?);
        }
        if !users.is_empty() {
            let mut engine = LocalEngine::new(engine_id.unwrap_or_else(LocalEngine::generate_id));
            for (u, acc) in &users {
                engine = engine.with_user(u.inner.clone());
                a = a.with_user_access(
                    u.inner.name(),
                    access(py, acc)?,
                    SecurityLevel::NoAuthNoPriv,
                );
            }
            a = a.with_engine(engine);
        }
        let mib = MibTree::new();
        let a = a.register(Oid::from([1u32, 3]), mib.clone());
        let addr = a.local_addr().map_err(io_err)?.to_string();
        Ok(Agent {
            mib,
            running: Mutex::new(None),
            config: Mutex::new(Some(a)),
            addr,
        })
    }

    /// The local address.
    #[getter]
    fn address(&self) -> String {
        self.addr.clone()
    }

    /// Serves ``value`` at ``oid`` (an instance, such as ``…​.0``);
    /// ``writable`` lets managers set it (to the same type).
    #[pyo3(signature = (oid, value, writable=false))]
    fn set(
        &self,
        py: Python<'_>,
        oid: &str,
        value: &Bound<'_, PyAny>,
        writable: bool,
    ) -> PyResult<()> {
        let (o, v) = (parse_oid(py, oid)?, from_py(value)?);
        if writable {
            self.mib.insert_writable(o, v);
        } else {
            self.mib.insert(o, v);
        }
        Ok(())
    }

    /// Serves ``callback()``'s result at ``oid`` on every read.
    fn set_callback(&self, py: Python<'_>, oid: &str, callback: Py<PyAny>) -> PyResult<()> {
        let o = parse_oid(py, oid)?;
        self.mib.insert_fn(o, move || {
            Python::attach(|py| {
                callback
                    .call0(py)
                    .and_then(|v| from_py(v.bind(py)))
                    .unwrap_or_else(|e| {
                        e.print(py);
                        Value::NoSuchInstance
                    })
            })
        });
        Ok(())
    }

    /// The current value at ``oid`` (after sets from managers), or ``None``.
    fn get(&self, py: Python<'_>, oid: &str) -> PyResult<Option<Py<PyAny>>> {
        let o = parse_oid(py, oid)?;
        self.mib.value(&o).map(|v| to_py(py, &v)).transpose()
    }

    /// Stops serving ``oid``.
    fn remove(&self, py: Python<'_>, oid: &str) -> PyResult<bool> {
        Ok(self.mib.remove(&parse_oid(py, oid)?))
    }

    /// Starts answering requests in the background.
    fn start(&self, py: Python<'_>) -> PyResult<()> {
        let Some(a) = self.config.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return Err(invalid(py, "the agent was already started"));
        };
        // The socket belongs to this runtime: serve on it.
        let task = rt().spawn(async move { a.run().await });
        *self.running.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        Ok(())
    }

    /// Stops the agent.
    fn stop(&self) {
        if let Some(t) = self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            t.abort();
        }
    }

    fn __enter__<'py>(slf: PyRef<'py, Self>, py: Python<'py>) -> PyResult<PyRef<'py, Self>> {
        if slf
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none()
        {
            slf.start(py)?;
        }
        Ok(slf)
    }

    #[pyo3(signature = (*_args))]
    fn __exit__(&self, _args: &Bound<'_, PyTuple>) {
        self.stop();
    }

    fn __repr__(&self) -> String {
        format!("Agent({:?}, {} values)", self.addr, self.mib.len())
    }
}

// ---------------------------------------------------------------------------
// MIBs
// ---------------------------------------------------------------------------

/// MIB modules: OID names and readable values.
#[pyclass(frozen, module = "snmpify")]
struct Mib {
    inner: Mutex<snmpify::mib::Mib>,
}

impl Mib {
    fn lock(&self) -> std::sync::MutexGuard<'_, snmpify::mib::Mib> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn mib_err(py: Python<'_>, e: snmpify::mib::MibError) -> PyErr {
    invalid(py, e.to_string())
}

#[pymethods]
impl Mib {
    /// An empty MIB set; ``standard=True`` loads the built-in standard
    /// modules (SNMPv2-MIB, IF-MIB, HOST-RESOURCES-MIB …).
    #[new]
    #[pyo3(signature = (standard=true))]
    fn new(standard: bool) -> Self {
        Mib {
            inner: Mutex::new(if standard {
                snmpify::mib::Mib::standard()
            } else {
                snmpify::mib::Mib::new()
            }),
        }
    }

    /// Loads a MIB file; returns the module names.
    fn load_file(&self, py: Python<'_>, path: std::path::PathBuf) -> PyResult<Vec<String>> {
        self.lock().load_file(path).map_err(|e| mib_err(py, e))
    }

    /// Loads MIB text.
    fn load_str(&self, py: Python<'_>, text: &str) -> PyResult<Vec<String>> {
        self.lock().load_str(text).map_err(|e| mib_err(py, e))
    }

    /// Loads every MIB in a directory; returns (modules, failed files).
    fn load_dir(
        &self,
        py: Python<'_>,
        path: std::path::PathBuf,
    ) -> PyResult<(Vec<String>, Vec<String>)> {
        let r = self.lock().load_dir(path).map_err(|e| mib_err(py, e))?;
        Ok((
            r.loaded,
            r.failed
                .into_iter()
                .map(|(f, e)| format!("{f}: {e}"))
                .collect(),
        ))
    }

    /// The OID of a name: ``"IF-MIB::ifDescr.3"``, ``"sysName.0"``.
    fn resolve(&self, py: Python<'_>, name: &str) -> PyResult<String> {
        self.lock()
            .resolve(name)
            .map(|o| o.to_string())
            .map_err(|e| mib_err(py, e))
    }

    /// The name of an OID: ``"IF-MIB::ifDescr.3"``.
    fn name(&self, py: Python<'_>, oid: &str) -> PyResult<String> {
        Ok(self.lock().name(&parse_oid(py, oid)?))
    }

    /// ``"name = value"`` with enum labels and display hints.
    fn format(&self, py: Python<'_>, oid: &str, value: &Bound<'_, PyAny>) -> PyResult<String> {
        Ok(self
            .lock()
            .format(&VarBind::new(parse_oid(py, oid)?, from_py(value)?)))
    }

    /// The value alone, formatted for ``oid``.
    fn format_value(
        &self,
        py: Python<'_>,
        oid: &str,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<String> {
        Ok(self
            .lock()
            .format_value(&parse_oid(py, oid)?, &from_py(value)?))
    }

    /// What the MIB says about a name: a dict (module, name, oid, kind,
    /// syntax, access, status, enums, units) or ``None``.
    fn object(&self, py: Python<'_>, name: &str) -> PyResult<Option<Py<PyAny>>> {
        let m = self.lock();
        let Some(o) = m.object(name) else {
            return Ok(None);
        };
        let d = PyDict::new(py);
        d.set_item("module", &o.module)?;
        d.set_item("name", &o.name)?;
        d.set_item("oid", o.oid.to_string())?;
        d.set_item("kind", format!("{:?}", o.kind).to_lowercase())?;
        d.set_item("syntax", &o.type_name)?;
        d.set_item("base", o.base.map(|b| format!("{b:?}")))?;
        d.set_item("access", o.access.map(|a| format!("{a:?}")))?;
        d.set_item("status", o.status.map(|s| format!("{s:?}").to_lowercase()))?;
        d.set_item(
            "enums",
            o.enums
                .iter()
                .map(|(n, l)| (*n, l.clone()))
                .collect::<Vec<_>>(),
        )?;
        d.set_item("index", &o.index)?;
        d.set_item("units", &o.units)?;
        d.set_item("display_hint", &o.display_hint)?;
        Ok(Some(d.into_any().unbind()))
    }

    /// The loaded module names.
    #[getter]
    fn modules(&self) -> Vec<String> {
        self.lock().modules().to_vec()
    }

    fn __repr__(&self) -> String {
        format!("Mib({} modules)", self.lock().modules().len())
    }
}

#[pymodule]
fn _snmpify(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Client>()?;
    m.add_class::<AsyncClient>()?;
    m.add_class::<Manager>()?;
    m.add_class::<Walk>()?;
    m.add_class::<AsyncWalk>()?;
    m.add_class::<UsmUser>()?;
    m.add_class::<Notification>()?;
    m.add_class::<NotificationReceiver>()?;
    m.add_class::<Agent>()?;
    m.add_class::<Mib>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
