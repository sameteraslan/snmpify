//! The C API of snmpify (include/snmpify.h). Every function catches
//! panics; errors are a status code plus a thread-local message
//! (`snmpify_last_error`). Handles are opaque and freed by their `_free`
//! function; strings returned as `const char *` belong to the handle they
//! came from.
#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types)]

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::net::Ipv4Addr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Mutex;
use std::time::Duration;

use snmpify::agent::{Access, MibTree};
use snmpify::blocking::{self, runtime};
use snmpify::client::{self, Community, Credentials, Options, Usm};
use snmpify::engine::LocalEngine;
use snmpify::notification::{NotificationKind, Sender};
use snmpify::usm::{AuthProtocol, PrivProtocol, SecurityLevel, UsmUser};
use snmpify::{ErrorStatus, Oid, Value, VarBind, Version};

// ---------------------------------------------------------------------------
// Status codes and errors
// ---------------------------------------------------------------------------

/// Result codes (mirrors `snmpify_status` in snmpify.h).
pub type snmpify_status = c_int;
pub const SNMPIFY_OK: c_int = 0;
pub const SNMPIFY_ERR_TIMEOUT: c_int = 1;
pub const SNMPIFY_ERR_AGENT: c_int = 2;
pub const SNMPIFY_ERR_REPORT: c_int = 3;
pub const SNMPIFY_ERR_INVALID_ARGUMENT: c_int = 4;
pub const SNMPIFY_ERR_IO: c_int = 5;
pub const SNMPIFY_ERR_PROTOCOL: c_int = 6;
pub const SNMPIFY_END: c_int = 7;
pub const SNMPIFY_ERR_PANIC: c_int = 8;

thread_local! {
    static LAST: RefCell<(CString, c_int, u32)> = RefCell::new((CString::default(), 0, 0));
}

fn set_error(msg: impl Into<String>, status: c_int, index: u32) {
    let s = CString::new(msg.into().replace('\0', " ")).unwrap_or_default();
    LAST.with(|l| *l.borrow_mut() = (s, status, index));
}

fn clear_error() {
    LAST.with(|l| *l.borrow_mut() = (CString::default(), 0, 0));
}

fn client_error(e: client::Error) -> snmpify_status {
    let msg = e.to_string();
    match e {
        client::Error::Timeout => {
            set_error(msg, 0, 0);
            SNMPIFY_ERR_TIMEOUT
        }
        client::Error::Snmp { status, index, .. } => {
            set_error(msg, status.code(), index);
            SNMPIFY_ERR_AGENT
        }
        client::Error::Report(_) => {
            set_error(msg, 0, 0);
            SNMPIFY_ERR_REPORT
        }
        client::Error::InvalidOid(_) | client::Error::InvalidArgument(_) => {
            set_error(msg, 0, 0);
            SNMPIFY_ERR_INVALID_ARGUMENT
        }
        client::Error::Io(_) => {
            set_error(msg, 0, 0);
            SNMPIFY_ERR_IO
        }
        _ => {
            set_error(msg, 0, 0);
            SNMPIFY_ERR_PROTOCOL
        }
    }
}

fn invalid(msg: impl Into<String>) -> snmpify_status {
    set_error(msg, 0, 0);
    SNMPIFY_ERR_INVALID_ARGUMENT
}

fn io(e: std::io::Error) -> snmpify_status {
    set_error(e.to_string(), 0, 0);
    SNMPIFY_ERR_IO
}

/// Runs `f`, turning a panic into SNMPIFY_ERR_PANIC.
fn guard(f: impl FnOnce() -> snmpify_status) -> snmpify_status {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(_) => {
            set_error("internal error (panic) in snmpify", 0, 0);
            SNMPIFY_ERR_PANIC
        }
    }
}

/// Like `guard` for constructors: NULL on error or panic.
fn guard_ptr<T>(f: impl FnOnce() -> Result<T, snmpify_status>) -> *mut T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => {
            clear_error();
            Box::into_raw(Box::new(v))
        }
        Ok(Err(_)) => ptr::null_mut(),
        Err(_) => {
            set_error("internal error (panic) in snmpify", 0, 0);
            ptr::null_mut()
        }
    }
}

/// The message of the last error on this thread ("" if none). Valid until
/// the next snmpify call on this thread.
#[no_mangle]
pub extern "C" fn snmpify_last_error() -> *const c_char {
    LAST.with(|l| l.borrow().0.as_ptr())
}

/// After SNMPIFY_ERR_AGENT: the agent's error-status (RFC 3416 code).
#[no_mangle]
pub extern "C" fn snmpify_last_error_status() -> c_int {
    LAST.with(|l| l.borrow().1)
}

/// After SNMPIFY_ERR_AGENT: the 1-based index of the failing binding.
#[no_mangle]
pub extern "C" fn snmpify_last_error_index() -> u32 {
    LAST.with(|l| l.borrow().2)
}

/// The name of an error-status code ("noSuchName" …), static.
#[no_mangle]
pub extern "C" fn snmpify_error_status_name(code: c_int) -> *const c_char {
    static NAMES: std::sync::OnceLock<Vec<CString>> = std::sync::OnceLock::new();
    let names = NAMES.get_or_init(|| {
        (0..19)
            .map(|c| CString::new(ErrorStatus::from_code(c).to_string()).unwrap_or_default())
            .collect()
    });
    names
        .get(code as usize)
        .map_or(c"unknown".as_ptr(), |s| s.as_ptr())
}

/// The library version, static.
#[no_mangle]
pub extern "C" fn snmpify_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

// ---------------------------------------------------------------------------
// Strings in and out
// ---------------------------------------------------------------------------

unsafe fn str_arg<'a>(p: *const c_char, what: &str) -> Result<&'a str, snmpify_status> {
    if p.is_null() {
        return Err(invalid(format!("{what} is NULL")));
    }
    CStr::from_ptr(p)
        .to_str()
        .map_err(|_| invalid(format!("{what} is not UTF-8")))
}

unsafe fn opt_str<'a>(p: *const c_char, what: &str) -> Result<Option<&'a str>, snmpify_status> {
    if p.is_null() {
        Ok(None)
    } else {
        str_arg(p, what).map(Some)
    }
}

fn oid_arg(s: &str) -> Result<Oid, snmpify_status> {
    s.trim()
        .trim_start_matches('.')
        .parse()
        .map_err(|_| invalid(format!("invalid OID {s:?}")))
}

unsafe fn oid_list(oids: *const *const c_char, n: usize) -> Result<Vec<Oid>, snmpify_status> {
    if oids.is_null() && n > 0 {
        return Err(invalid("oids is NULL"));
    }
    (0..n)
        .map(|i| oid_arg(str_arg(*oids.add(i), "oid")?))
        .collect()
}

/// Copies `s` into `buf` (NUL-terminated, truncated to `len`); returns the
/// length `s` needs including the NUL.
unsafe fn copy_out(s: &str, buf: *mut c_char, len: usize) -> usize {
    if !buf.is_null() && len > 0 {
        let n = s.len().min(len - 1);
        ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), n);
        *buf.add(n) = 0;
    }
    s.len() + 1
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Value types: the BER tags (mirrors `snmpify_type`).
pub type snmpify_type = c_int;

/// A value to send (set, traps, agent values).
#[repr(C)]
pub struct snmpify_value {
    /// SNMPIFY_INTEGER, SNMPIFY_OCTET_STRING, …
    pub type_: snmpify_type,
    /// INTEGER.
    pub integer: i64,
    /// Counter32, Gauge32, TimeTicks, Counter64.
    pub uinteger: u64,
    /// OCTET STRING / Opaque bytes.
    pub bytes: *const u8,
    /// Length of `bytes`.
    pub len: usize,
    /// OBJECT IDENTIFIER or IpAddress in dotted form.
    pub text: *const c_char,
}

unsafe fn value_in(v: &snmpify_value) -> Result<Value, snmpify_status> {
    let bytes = || -> Result<Vec<u8>, snmpify_status> {
        if v.len == 0 {
            Ok(Vec::new())
        } else if v.bytes.is_null() {
            Err(invalid("value bytes are NULL"))
        } else {
            Ok(std::slice::from_raw_parts(v.bytes, v.len).to_vec())
        }
    };
    let u32_of =
        |what: &str| u32::try_from(v.uinteger).map_err(|_| invalid(format!("{what} out of range")));
    Ok(match v.type_ {
        0x02 => {
            Value::Integer(i32::try_from(v.integer).map_err(|_| invalid("INTEGER out of range"))?)
        }
        0x04 => Value::OctetString(bytes()?),
        0x05 => Value::Null,
        0x06 => Value::ObjectId(oid_arg(str_arg(v.text, "OBJECT IDENTIFIER value")?)?),
        0x40 => {
            let s = str_arg(v.text, "IpAddress value")?;
            Value::IpAddress(
                s.parse::<Ipv4Addr>()
                    .map_err(|_| invalid(format!("invalid IpAddress {s:?}")))?,
            )
        }
        0x41 => Value::Counter32(u32_of("Counter32")?),
        0x42 => Value::Gauge32(u32_of("Gauge32")?),
        0x43 => Value::TimeTicks(u32_of("TimeTicks")?),
        0x44 => Value::Opaque(bytes()?),
        0x46 => Value::Counter64(v.uinteger),
        t => return Err(invalid(format!("unknown value type 0x{t:02x}"))),
    })
}

/// A set binding: an OID and a value.
#[repr(C)]
pub struct snmpify_varbind {
    pub oid: *const c_char,
    pub value: snmpify_value,
}

unsafe fn varbinds_in(
    vbs: *const snmpify_varbind,
    n: usize,
) -> Result<Vec<VarBind>, snmpify_status> {
    if vbs.is_null() && n > 0 {
        return Err(invalid("varbinds is NULL"));
    }
    (0..n)
        .map(|i| {
            let vb = &*vbs.add(i);
            Ok(VarBind::new(
                oid_arg(str_arg(vb.oid, "oid")?)?,
                value_in(&vb.value)?,
            ))
        })
        .collect()
}

/// Received bindings, read through the `snmpify_result_*` functions.
pub struct snmpify_result {
    items: Vec<(CString, Value, CString)>,
}

impl snmpify_result {
    fn new(vbs: Vec<VarBind>) -> Self {
        let cs = |s: String| CString::new(s).unwrap_or_default();
        snmpify_result {
            items: vbs
                .into_iter()
                .map(|vb| {
                    let text = match &vb.value {
                        Value::OctetString(b) | Value::Opaque(b) => {
                            String::from_utf8_lossy(b).into_owned()
                        }
                        v => v.to_string(),
                    };
                    (cs(vb.oid.to_string()), vb.value, cs(text))
                })
                .collect(),
        }
    }

    fn item(&self, i: usize) -> Option<&(CString, Value, CString)> {
        self.items.get(i)
    }
}

unsafe fn result_out(out: *mut *mut snmpify_result, vbs: Vec<VarBind>) -> snmpify_status {
    if out.is_null() {
        return invalid("out is NULL");
    }
    *out = Box::into_raw(Box::new(snmpify_result::new(vbs)));
    clear_error();
    SNMPIFY_OK
}

/// The number of bindings.
#[no_mangle]
pub unsafe extern "C" fn snmpify_result_len(r: *const snmpify_result) -> usize {
    r.as_ref().map_or(0, |r| r.items.len())
}

/// The OID of binding `i`, dotted (NULL if out of range).
#[no_mangle]
pub unsafe extern "C" fn snmpify_result_oid(r: *const snmpify_result, i: usize) -> *const c_char {
    r.as_ref()
        .and_then(|r| r.item(i))
        .map_or(ptr::null(), |x| x.0.as_ptr())
}

/// The type of binding `i` (a BER tag; -1 if out of range).
#[no_mangle]
pub unsafe extern "C" fn snmpify_result_type(r: *const snmpify_result, i: usize) -> snmpify_type {
    r.as_ref()
        .and_then(|r| r.item(i))
        .map_or(-1, |x| x.1.tag() as c_int)
}

/// Binding `i` as a signed number (INTEGER, and the unsigned types).
#[no_mangle]
pub unsafe extern "C" fn snmpify_result_int(r: *const snmpify_result, i: usize) -> i64 {
    r.as_ref()
        .and_then(|r| r.item(i))
        .and_then(|x| x.1.as_i64())
        .unwrap_or(0)
}

/// Binding `i` as an unsigned number (Counter32/64, Gauge32, TimeTicks).
#[no_mangle]
pub unsafe extern "C" fn snmpify_result_uint(r: *const snmpify_result, i: usize) -> u64 {
    r.as_ref()
        .and_then(|r| r.item(i))
        .and_then(|x| x.1.as_u64())
        .unwrap_or(0)
}

/// The bytes of an OCTET STRING / Opaque / IpAddress binding.
#[no_mangle]
pub unsafe extern "C" fn snmpify_result_bytes(
    r: *const snmpify_result,
    i: usize,
    len: *mut usize,
) -> *const u8 {
    let b: Option<&[u8]> = r.as_ref().and_then(|r| r.item(i)).and_then(|x| match &x.1 {
        Value::OctetString(b) | Value::Opaque(b) => Some(b.as_slice()),
        _ => None,
    });
    if !len.is_null() {
        *len = b.map_or(0, |b| b.len());
    }
    b.map_or(ptr::null(), |b| b.as_ptr())
}

/// Binding `i` as text: strings as is (invalid UTF-8 replaced), numbers
/// in decimal, OIDs dotted, exceptions as "No Such Object …".
#[no_mangle]
pub unsafe extern "C" fn snmpify_result_text(r: *const snmpify_result, i: usize) -> *const c_char {
    r.as_ref()
        .and_then(|r| r.item(i))
        .map_or(ptr::null(), |x| x.2.as_ptr())
}

/// Frees a result.
#[no_mangle]
pub unsafe extern "C" fn snmpify_result_free(r: *mut snmpify_result) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

// ---------------------------------------------------------------------------
// Users and clients
// ---------------------------------------------------------------------------

pub struct snmpify_user(UsmUser);

/// An SNMPv3 user. Protocols (NULL for none): "MD5", "SHA", "SHA-224",
/// "SHA-256", "SHA-384", "SHA-512"; "DES", "AES", "AES-192", "AES-256".
/// Passwords need 8 characters or more. NULL on error.
#[no_mangle]
pub unsafe extern "C" fn snmpify_user_new(
    name: *const c_char,
    auth_protocol: *const c_char,
    auth_password: *const c_char,
    priv_protocol: *const c_char,
    priv_password: *const c_char,
) -> *mut snmpify_user {
    guard_ptr(|| {
        let mut u = UsmUser::new(str_arg(name, "name")?);
        if let Some(p) = opt_str(auth_protocol, "auth_protocol")? {
            let p = match p.to_ascii_uppercase().replace(['-', '_'], "").as_str() {
                "MD5" => AuthProtocol::Md5,
                "SHA" | "SHA1" => AuthProtocol::Sha1,
                "SHA224" => AuthProtocol::Sha224,
                "SHA256" => AuthProtocol::Sha256,
                "SHA384" => AuthProtocol::Sha384,
                "SHA512" => AuthProtocol::Sha512,
                _ => return Err(invalid(format!("unknown authentication protocol {p:?}"))),
            };
            u = u
                .with_auth(p, str_arg(auth_password, "auth_password")?)
                .map_err(|e| invalid(e.to_string()))?;
        }
        if let Some(p) = opt_str(priv_protocol, "priv_protocol")? {
            let p = match p.to_ascii_uppercase().replace(['-', '_'], "").as_str() {
                "DES" => PrivProtocol::Des,
                "AES" | "AES128" => PrivProtocol::Aes128,
                "AES192" => PrivProtocol::Aes192,
                "AES256" => PrivProtocol::Aes256,
                _ => return Err(invalid(format!("unknown privacy protocol {p:?}"))),
            };
            u = u
                .with_privacy(p, str_arg(priv_password, "priv_password")?)
                .map_err(|e| invalid(e.to_string()))?;
        }
        Ok(snmpify_user(u))
    })
}

/// Frees a user (clients made with it keep working).
#[no_mangle]
pub unsafe extern "C" fn snmpify_user_free(u: *mut snmpify_user) {
    if !u.is_null() {
        drop(Box::from_raw(u));
    }
}

pub struct snmpify_client(blocking::Client);

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

fn connect(target: &str, c: Credentials) -> Result<snmpify_client, snmpify_status> {
    blocking::Client::connect(&with_port(target), c)
        .map(snmpify_client)
        .map_err(client_error)
}

/// A v1 (`version` 1) or v2c (`version` 2) client; `target` is "host" or
/// "host:port" (161 by default). NULL on error.
#[no_mangle]
pub unsafe extern "C" fn snmpify_client_new(
    target: *const c_char,
    community: *const c_char,
    version: c_int,
) -> *mut snmpify_client {
    guard_ptr(|| {
        let community = str_arg(community, "community")?;
        let c = match version {
            1 => Community::v1(community),
            2 => Community::v2c(community),
            _ => {
                return Err(invalid(
                    "version must be 1 or 2 (SNMPv3: snmpify_client_new_v3)",
                ))
            }
        };
        connect(str_arg(target, "target")?, c.into())
    })
}

/// An SNMPv3 client; `context` may be NULL. NULL on error.
#[no_mangle]
pub unsafe extern "C" fn snmpify_client_new_v3(
    target: *const c_char,
    user: *const snmpify_user,
    context: *const c_char,
) -> *mut snmpify_client {
    guard_ptr(|| {
        let user = user.as_ref().ok_or_else(|| invalid("user is NULL"))?;
        let mut usm = Usm::new(user.0.clone());
        if let Some(c) = opt_str(context, "context")? {
            usm = usm.with_context(c);
        }
        connect(str_arg(target, "target")?, usm.into())
    })
}

/// Timeout per attempt (ms), retries, and bindings per GetBulk in walks.
#[no_mangle]
pub unsafe extern "C" fn snmpify_client_set_options(
    c: *mut snmpify_client,
    timeout_ms: u32,
    retries: u32,
    max_repetitions: u32,
) -> snmpify_status {
    guard(|| {
        let Some(c) = c.as_mut() else {
            return invalid("client is NULL");
        };
        if timeout_ms == 0 {
            return invalid("timeout_ms must be positive");
        }
        c.0 = c.0.clone().with_options(Options {
            timeout: Duration::from_millis(timeout_ms as u64),
            retries,
            max_repetitions: max_repetitions.max(1),
        });
        SNMPIFY_OK
    })
}

/// Frees a client.
#[no_mangle]
pub unsafe extern "C" fn snmpify_client_free(c: *mut snmpify_client) {
    if !c.is_null() {
        drop(Box::from_raw(c));
    }
}

unsafe fn client<'a>(c: *const snmpify_client) -> Result<&'a blocking::Client, snmpify_status> {
    c.as_ref()
        .map(|c| &c.0)
        .ok_or_else(|| invalid("client is NULL"))
}

fn done(r: Result<snmpify_status, snmpify_status>) -> snmpify_status {
    r.unwrap_or_else(|e| e)
}

/// GetRequest for `n` OIDs (dotted strings).
#[no_mangle]
pub unsafe extern "C" fn snmpify_get(
    c: *const snmpify_client,
    oids: *const *const c_char,
    n: usize,
    out: *mut *mut snmpify_result,
) -> snmpify_status {
    guard(|| {
        done((|| {
            Ok(result_out(
                out,
                client(c)?.get(oid_list(oids, n)?).map_err(client_error)?,
            ))
        })())
    })
}

/// GetNextRequest.
#[no_mangle]
pub unsafe extern "C" fn snmpify_get_next(
    c: *const snmpify_client,
    oids: *const *const c_char,
    n: usize,
    out: *mut *mut snmpify_result,
) -> snmpify_status {
    guard(|| {
        done((|| {
            Ok(result_out(
                out,
                client(c)?
                    .get_next(oid_list(oids, n)?)
                    .map_err(client_error)?,
            ))
        })())
    })
}

/// GetBulkRequest (v2c, v3).
#[no_mangle]
pub unsafe extern "C" fn snmpify_get_bulk(
    c: *const snmpify_client,
    oids: *const *const c_char,
    n: usize,
    non_repeaters: u32,
    max_repetitions: u32,
    out: *mut *mut snmpify_result,
) -> snmpify_status {
    guard(|| {
        done((|| {
            let v = client(c)?
                .get_bulk(non_repeaters, max_repetitions, oid_list(oids, n)?)
                .map_err(client_error)?;
            Ok(result_out(out, v))
        })())
    })
}

/// SetRequest; `out` (may be NULL) receives the agent's bindings.
#[no_mangle]
pub unsafe extern "C" fn snmpify_set(
    c: *const snmpify_client,
    vbs: *const snmpify_varbind,
    n: usize,
    out: *mut *mut snmpify_result,
) -> snmpify_status {
    guard(|| {
        done((|| {
            let v = client(c)?.set(varbinds_in(vbs, n)?).map_err(client_error)?;
            if out.is_null() {
                clear_error();
                return Ok(SNMPIFY_OK);
            }
            Ok(result_out(out, v))
        })())
    })
}

/// The whole subtree under `root` (GetBulk in v2c/v3, GetNext in v1).
#[no_mangle]
pub unsafe extern "C" fn snmpify_walk_all(
    c: *const snmpify_client,
    root: *const c_char,
    out: *mut *mut snmpify_result,
) -> snmpify_status {
    guard(|| {
        done((|| {
            let v = client(c)?
                .walk_all(oid_arg(str_arg(root, "root")?)?)
                .map_err(client_error)?;
            Ok(result_out(out, v))
        })())
    })
}

/// A walk read one binding at a time.
pub struct snmpify_walk(Mutex<blocking::Walk>);

/// Starts a walk; read it with snmpify_walk_next. NULL on error.
#[no_mangle]
pub unsafe extern "C" fn snmpify_walk_new(
    c: *const snmpify_client,
    root: *const c_char,
) -> *mut snmpify_walk {
    guard_ptr(|| {
        let w = client(c)?
            .walk(oid_arg(str_arg(root, "root")?)?)
            .map_err(client_error)?;
        Ok(snmpify_walk(Mutex::new(w)))
    })
}

/// The next binding as a one-binding result; SNMPIFY_END at the end.
#[no_mangle]
pub unsafe extern "C" fn snmpify_walk_next(
    w: *mut snmpify_walk,
    out: *mut *mut snmpify_result,
) -> snmpify_status {
    guard(|| {
        let Some(w) = w.as_ref() else {
            return invalid("walk is NULL");
        };
        let next = w.0.lock().unwrap_or_else(|e| e.into_inner()).next();
        match next {
            Some(Ok(vb)) => result_out(out, vec![vb]),
            Some(Err(e)) => client_error(e),
            None => {
                clear_error();
                SNMPIFY_END
            }
        }
    })
}

/// Frees a walk.
#[no_mangle]
pub unsafe extern "C" fn snmpify_walk_free(w: *mut snmpify_walk) {
    if !w.is_null() {
        drop(Box::from_raw(w));
    }
}

/// Sends a trap (v2c, v3): `trap_oid`, then `n` bindings.
#[no_mangle]
pub unsafe extern "C" fn snmpify_trap(
    c: *const snmpify_client,
    trap_oid: *const c_char,
    vbs: *const snmpify_varbind,
    n: usize,
) -> snmpify_status {
    guard(|| {
        done((|| {
            client(c)?
                .trap(
                    oid_arg(str_arg(trap_oid, "trap_oid")?)?,
                    varbinds_in(vbs, n)?,
                )
                .map_err(client_error)?;
            clear_error();
            Ok(SNMPIFY_OK)
        })())
    })
}

/// Sends an inform (v2c, v3) and waits for the acknowledgement.
#[no_mangle]
pub unsafe extern "C" fn snmpify_inform(
    c: *const snmpify_client,
    trap_oid: *const c_char,
    vbs: *const snmpify_varbind,
    n: usize,
) -> snmpify_status {
    guard(|| {
        done((|| {
            client(c)?
                .inform(
                    oid_arg(str_arg(trap_oid, "trap_oid")?)?,
                    varbinds_in(vbs, n)?,
                )
                .map_err(client_error)?;
            clear_error();
            Ok(SNMPIFY_OK)
        })())
    })
}

// ---------------------------------------------------------------------------
// Notification receiver
// ---------------------------------------------------------------------------

pub struct snmpify_receiver {
    inner: blocking::NotificationReceiver,
    addr: CString,
}

/// Receives traps and informs on `address` ("0.0.0.0:162"): v1/v2c with
/// one of `communities` (`n_communities` 0: any community), v3 with one of
/// `users`. NULL on error.
#[no_mangle]
pub unsafe extern "C" fn snmpify_receiver_new(
    address: *const c_char,
    communities: *const *const c_char,
    n_communities: usize,
    users: *const *const snmpify_user,
    n_users: usize,
) -> *mut snmpify_receiver {
    guard_ptr(|| {
        let addr = str_arg(address, "address")?;
        let mut r = runtime()
            .block_on(snmpify::notification::NotificationReceiver::bind(addr))
            .map_err(io)?;
        if n_communities == 0 {
            r = r.with_any_community();
        }
        for i in 0..n_communities {
            if communities.is_null() {
                return Err(invalid("communities is NULL"));
            }
            r = r.with_community(str_arg(*communities.add(i), "community")?);
        }
        if n_users > 0 {
            if users.is_null() {
                return Err(invalid("users is NULL"));
            }
            let mut e = LocalEngine::new(LocalEngine::generate_id());
            for i in 0..n_users {
                let u = (*users.add(i))
                    .as_ref()
                    .ok_or_else(|| invalid("user is NULL"))?;
                e = e.with_user(u.0.clone());
            }
            r = r.with_engine(e);
        }
        let a = r.local_addr().map_err(io)?.to_string();
        Ok(snmpify_receiver {
            inner: blocking::NotificationReceiver::from_async(r),
            addr: CString::new(a).unwrap_or_default(),
        })
    })
}

/// The receiver's address ("127.0.0.1:40000").
#[no_mangle]
pub unsafe extern "C" fn snmpify_receiver_address(r: *const snmpify_receiver) -> *const c_char {
    r.as_ref().map_or(ptr::null(), |r| r.addr.as_ptr())
}

pub struct snmpify_notification {
    kind: CString,
    version: c_int,
    source: CString,
    trap_oid: CString,
    sender: CString,
    uptime: u32,
    varbinds: snmpify_result,
}

/// The next notification (informs are acknowledged), waiting at most
/// `timeout_ms` (0: forever); SNMPIFY_ERR_TIMEOUT if none came.
#[no_mangle]
pub unsafe extern "C" fn snmpify_receiver_recv(
    r: *mut snmpify_receiver,
    timeout_ms: u32,
    out: *mut *mut snmpify_notification,
) -> snmpify_status {
    guard(|| {
        let Some(r) = r.as_mut() else {
            return invalid("receiver is NULL");
        };
        if out.is_null() {
            return invalid("out is NULL");
        }
        let t = (timeout_ms > 0).then(|| Duration::from_millis(timeout_ms as u64));
        match r.inner.recv(t) {
            Ok(Some(n)) => {
                let cs = |s: String| CString::new(s).unwrap_or_default();
                let sender = match &n.sender {
                    Sender::Community(c) => String::from_utf8_lossy(c).into_owned(),
                    Sender::Usm { user, .. } => String::from_utf8_lossy(user).into_owned(),
                };
                *out = Box::into_raw(Box::new(snmpify_notification {
                    kind: cs(match n.kind {
                        NotificationKind::Trap => "trap".into(),
                        NotificationKind::Inform => "inform".into(),
                    }),
                    version: match n.version {
                        Version::V1 => 1,
                        Version::V2c => 2,
                        Version::V3 => 3,
                    },
                    source: cs(n.source.to_string()),
                    trap_oid: cs(n.trap_oid.to_string()),
                    sender: cs(sender),
                    uptime: n.uptime.unwrap_or(0),
                    varbinds: snmpify_result::new(n.varbinds),
                }));
                clear_error();
                SNMPIFY_OK
            }
            Ok(None) => {
                set_error("no notification before the timeout", 0, 0);
                SNMPIFY_ERR_TIMEOUT
            }
            Err(e) => io(e),
        }
    })
}

/// Frees a receiver.
#[no_mangle]
pub unsafe extern "C" fn snmpify_receiver_free(r: *mut snmpify_receiver) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

/// "trap" or "inform".
#[no_mangle]
pub unsafe extern "C" fn snmpify_notification_kind(
    n: *const snmpify_notification,
) -> *const c_char {
    n.as_ref().map_or(ptr::null(), |n| n.kind.as_ptr())
}

/// 1, 2 (v2c) or 3.
#[no_mangle]
pub unsafe extern "C" fn snmpify_notification_version(n: *const snmpify_notification) -> c_int {
    n.as_ref().map_or(0, |n| n.version)
}

/// The sender's address.
#[no_mangle]
pub unsafe extern "C" fn snmpify_notification_source(
    n: *const snmpify_notification,
) -> *const c_char {
    n.as_ref().map_or(ptr::null(), |n| n.source.as_ptr())
}

/// The community (v1/v2c) or user name (v3).
#[no_mangle]
pub unsafe extern "C" fn snmpify_notification_sender(
    n: *const snmpify_notification,
) -> *const c_char {
    n.as_ref().map_or(ptr::null(), |n| n.sender.as_ptr())
}

/// snmpTrapOID.0.
#[no_mangle]
pub unsafe extern "C" fn snmpify_notification_trap_oid(
    n: *const snmpify_notification,
) -> *const c_char {
    n.as_ref().map_or(ptr::null(), |n| n.trap_oid.as_ptr())
}

/// sysUpTime.0 of the sender (hundredths of a second).
#[no_mangle]
pub unsafe extern "C" fn snmpify_notification_uptime(n: *const snmpify_notification) -> u32 {
    n.as_ref().map_or(0, |n| n.uptime)
}

/// The bindings after sysUpTime.0 and snmpTrapOID.0 (owned by `n`).
#[no_mangle]
pub unsafe extern "C" fn snmpify_notification_varbinds(
    n: *const snmpify_notification,
) -> *const snmpify_result {
    n.as_ref().map_or(ptr::null(), |n| &n.varbinds as *const _)
}

/// Frees a notification.
#[no_mangle]
pub unsafe extern "C" fn snmpify_notification_free(n: *mut snmpify_notification) {
    if !n.is_null() {
        drop(Box::from_raw(n));
    }
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

pub struct snmpify_agent {
    config: Option<snmpify::agent::Agent>,
    engine: Option<LocalEngine>,
    users: Vec<(Vec<u8>, Access)>,
    mib: MibTree,
    running: Option<blocking::RunningAgent>,
    addr: CString,
}

/// An agent bound to `address` ("0.0.0.0:161"); add communities, users and
/// values, then snmpify_agent_start. NULL on error.
#[no_mangle]
pub unsafe extern "C" fn snmpify_agent_new(address: *const c_char) -> *mut snmpify_agent {
    guard_ptr(|| {
        let a = runtime()
            .block_on(snmpify::agent::Agent::bind(str_arg(address, "address")?))
            .map_err(io)?;
        let addr = a.local_addr().map_err(io)?.to_string();
        Ok(snmpify_agent {
            config: Some(a),
            engine: None,
            users: Vec::new(),
            mib: MibTree::new(),
            running: None,
            addr: CString::new(addr).unwrap_or_default(),
        })
    })
}

unsafe fn agent_cfg<'a>(a: *mut snmpify_agent) -> Result<&'a mut snmpify_agent, snmpify_status> {
    let a = a.as_mut().ok_or_else(|| invalid("agent is NULL"))?;
    if a.config.is_none() {
        return Err(invalid("the agent is already started"));
    }
    Ok(a)
}

/// Answers v1/v2c requests with `community`; `writable` allows sets.
#[no_mangle]
pub unsafe extern "C" fn snmpify_agent_add_community(
    a: *mut snmpify_agent,
    community: *const c_char,
    writable: c_int,
) -> snmpify_status {
    guard(|| {
        done((|| {
            let a = agent_cfg(a)?;
            let c = str_arg(community, "community")?;
            let access = if writable != 0 {
                Access::ReadWrite
            } else {
                Access::ReadOnly
            };
            a.config = a.config.take().map(|cfg| cfg.with_community(c, access));
            Ok(SNMPIFY_OK)
        })())
    })
}

/// Answers SNMPv3 requests from `user`; `writable` allows sets.
#[no_mangle]
pub unsafe extern "C" fn snmpify_agent_add_user(
    a: *mut snmpify_agent,
    user: *const snmpify_user,
    writable: c_int,
) -> snmpify_status {
    guard(|| {
        done((|| {
            let a = agent_cfg(a)?;
            let u = user.as_ref().ok_or_else(|| invalid("user is NULL"))?;
            let e = a
                .engine
                .take()
                .unwrap_or_else(|| LocalEngine::new(LocalEngine::generate_id()));
            a.engine = Some(e.with_user(u.0.clone()));
            let access = if writable != 0 {
                Access::ReadWrite
            } else {
                Access::ReadOnly
            };
            a.users.push((u.0.name().to_vec(), access));
            Ok(SNMPIFY_OK)
        })())
    })
}

/// Serves a value at an instance OID; `writable` lets managers set it.
#[no_mangle]
pub unsafe extern "C" fn snmpify_agent_set(
    a: *mut snmpify_agent,
    vb: *const snmpify_varbind,
    writable: c_int,
) -> snmpify_status {
    guard(|| {
        done((|| {
            let a = a.as_mut().ok_or_else(|| invalid("agent is NULL"))?;
            let vb = varbinds_in(vb, 1)?.remove(0);
            if writable != 0 {
                a.mib.insert_writable(vb.oid, vb.value);
            } else {
                a.mib.insert(vb.oid, vb.value);
            }
            Ok(SNMPIFY_OK)
        })())
    })
}

/// Fills `out` with the current value; return 0 on success.
pub type snmpify_value_fn =
    unsafe extern "C" fn(ctx: *mut c_void, out: *mut snmpify_value) -> c_int;

struct Ctx(*mut c_void);
// The caller promises (snmpify.h) that ctx may be used from another thread.
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

/// Serves `callback`'s value at `oid` on every read (called on an snmpify
/// thread; strings it returns must stay valid until the next call).
#[no_mangle]
pub unsafe extern "C" fn snmpify_agent_set_callback(
    a: *mut snmpify_agent,
    oid: *const c_char,
    callback: Option<snmpify_value_fn>,
    ctx: *mut c_void,
) -> snmpify_status {
    guard(|| {
        done((|| {
            let a = a.as_mut().ok_or_else(|| invalid("agent is NULL"))?;
            let oid = oid_arg(str_arg(oid, "oid")?)?;
            let cb = callback.ok_or_else(|| invalid("callback is NULL"))?;
            let ctx = Ctx(ctx);
            a.mib.insert_fn(oid, move || {
                let ctx = &ctx;
                let mut v = snmpify_value {
                    type_: 0x05,
                    integer: 0,
                    uinteger: 0,
                    bytes: ptr::null(),
                    len: 0,
                    text: ptr::null(),
                };
                if cb(ctx.0, &mut v) != 0 {
                    return Value::NoSuchInstance;
                }
                value_in(&v).unwrap_or(Value::NoSuchInstance)
            });
            Ok(SNMPIFY_OK)
        })())
    })
}

/// The current value at `oid` (after managers' sets) as a one-binding
/// result; SNMPIFY_ERR_INVALID_ARGUMENT if nothing is there.
#[no_mangle]
pub unsafe extern "C" fn snmpify_agent_get(
    a: *const snmpify_agent,
    oid: *const c_char,
    out: *mut *mut snmpify_result,
) -> snmpify_status {
    guard(|| {
        done((|| {
            let a = a.as_ref().ok_or_else(|| invalid("agent is NULL"))?;
            let oid = oid_arg(str_arg(oid, "oid")?)?;
            let v = a
                .mib
                .value(&oid)
                .ok_or_else(|| invalid("no value at this OID"))?;
            Ok(result_out(out, vec![VarBind::new(oid, v)]))
        })())
    })
}

/// Starts answering in the background.
#[no_mangle]
pub unsafe extern "C" fn snmpify_agent_start(a: *mut snmpify_agent) -> snmpify_status {
    guard(|| {
        done((|| {
            let a = agent_cfg(a)?;
            let mut cfg = a.config.take().expect("checked");
            if let Some(e) = a.engine.take() {
                cfg = cfg.with_engine(e);
                for (u, acc) in &a.users {
                    cfg = cfg.with_user_access(u, *acc, SecurityLevel::NoAuthNoPriv);
                }
            }
            cfg = cfg.register(Oid::from([1u32, 3]), a.mib.clone());
            a.running = Some(blocking::RunningAgent::start(cfg).map_err(io)?);
            Ok(SNMPIFY_OK)
        })())
    })
}

/// The agent's address ("127.0.0.1:40000").
#[no_mangle]
pub unsafe extern "C" fn snmpify_agent_address(a: *const snmpify_agent) -> *const c_char {
    a.as_ref().map_or(ptr::null(), |a| a.addr.as_ptr())
}

/// Stops and frees an agent.
#[no_mangle]
pub unsafe extern "C" fn snmpify_agent_free(a: *mut snmpify_agent) {
    if !a.is_null() {
        drop(Box::from_raw(a));
    }
}

// ---------------------------------------------------------------------------
// MIBs
// ---------------------------------------------------------------------------

pub struct snmpify_mib(Mutex<snmpify::mib::Mib>);

/// The standard MIB modules (built in).
#[no_mangle]
pub extern "C" fn snmpify_mib_standard() -> *mut snmpify_mib {
    guard_ptr(|| Ok(snmpify_mib(Mutex::new(snmpify::mib::Mib::standard()))))
}

/// Loads a MIB file.
#[no_mangle]
pub unsafe extern "C" fn snmpify_mib_load_file(
    m: *mut snmpify_mib,
    path: *const c_char,
) -> snmpify_status {
    guard(|| {
        done((|| {
            let m = m.as_ref().ok_or_else(|| invalid("mib is NULL"))?;
            let p = str_arg(path, "path")?;
            m.0.lock()
                .unwrap_or_else(|e| e.into_inner())
                .load_file(p)
                .map_err(|e| invalid(e.to_string()))?;
            Ok(SNMPIFY_OK)
        })())
    })
}

/// The OID of `name` ("IF-MIB::ifDescr.3") into `buf`; returns the length
/// needed with the NUL, 0 if the name is unknown.
#[no_mangle]
pub unsafe extern "C" fn snmpify_mib_resolve(
    m: *const snmpify_mib,
    name: *const c_char,
    buf: *mut c_char,
    len: usize,
) -> usize {
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<usize, snmpify_status> {
        let m = m.as_ref().ok_or_else(|| invalid("mib is NULL"))?;
        let o =
            m.0.lock()
                .unwrap_or_else(|e| e.into_inner())
                .resolve(str_arg(name, "name")?)
                .map_err(|e| invalid(e.to_string()))?;
        Ok(copy_out(&o.to_string(), buf, len))
    }));
    match r {
        Ok(Ok(n)) => n,
        _ => 0,
    }
}

/// The name of `oid` ("IF-MIB::ifDescr.3") into `buf`; returns the length
/// needed with the NUL (0 on error).
#[no_mangle]
pub unsafe extern "C" fn snmpify_mib_name(
    m: *const snmpify_mib,
    oid: *const c_char,
    buf: *mut c_char,
    len: usize,
) -> usize {
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<usize, snmpify_status> {
        let m = m.as_ref().ok_or_else(|| invalid("mib is NULL"))?;
        let o = oid_arg(str_arg(oid, "oid")?)?;
        Ok(copy_out(
            &m.0.lock().unwrap_or_else(|e| e.into_inner()).name(&o),
            buf,
            len,
        ))
    }));
    r.ok().and_then(Result::ok).unwrap_or(0)
}

/// Binding `i` of `r` as "name = value" (enum labels, display hints) into
/// `buf`; returns the length needed with the NUL (0 on error).
#[no_mangle]
pub unsafe extern "C" fn snmpify_mib_format(
    m: *const snmpify_mib,
    r: *const snmpify_result,
    i: usize,
    buf: *mut c_char,
    len: usize,
) -> usize {
    let res = catch_unwind(AssertUnwindSafe(|| -> Option<usize> {
        let m = m.as_ref()?;
        let (oid, value, _) = r.as_ref()?.item(i)?;
        let oid: Oid = oid.to_str().ok()?.parse().ok()?;
        let s =
            m.0.lock()
                .unwrap_or_else(|e| e.into_inner())
                .format(&VarBind::new(oid, value.clone()));
        Some(copy_out(&s, buf, len))
    }));
    res.ok().flatten().unwrap_or(0)
}

/// Frees a MIB set.
#[no_mangle]
pub unsafe extern "C" fn snmpify_mib_free(m: *mut snmpify_mib) {
    if !m.is_null() {
        drop(Box::from_raw(m));
    }
}
