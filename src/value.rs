//! Variable values and variable bindings.

use std::fmt;
use std::net::Ipv4Addr;

use crate::ber::{decode_signed, decode_unsigned, tag, Reader, Writer};
use crate::error::{DecodeError, DecodeErrorKind};
use crate::oid::Oid;

/// The value of a variable (SMIv2 types, RFC 2578, plus the v2 exceptions).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Value {
    /// INTEGER / Integer32.
    Integer(i32),
    /// OCTET STRING (also DisplayString, MAC addresses, …).
    OctetString(Vec<u8>),
    /// NULL: the value in a request.
    Null,
    /// OBJECT IDENTIFIER.
    ObjectId(Oid),
    /// IpAddress.
    IpAddress(Ipv4Addr),
    /// Counter32.
    Counter32(u32),
    /// Gauge32 / Unsigned32.
    Gauge32(u32),
    /// TimeTicks: hundredths of a second.
    TimeTicks(u32),
    /// Opaque: arbitrary BER, kept as bytes.
    Opaque(Vec<u8>),
    /// Counter64.
    Counter64(u64),
    /// v2 exception: no such object.
    NoSuchObject,
    /// v2 exception: no such instance.
    NoSuchInstance,
    /// v2 exception: end of the MIB view (end of a walk).
    EndOfMibView,
}

impl Value {
    /// Whether this is one of the v2 exceptions (noSuchObject,
    /// noSuchInstance, endOfMibView).
    pub fn is_exception(&self) -> bool {
        matches!(
            self,
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView
        )
    }

    /// The value as an integer, for every numeric type.
    pub fn as_i64(&self) -> Option<i64> {
        Some(match *self {
            Value::Integer(v) => v as i64,
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => v as i64,
            Value::Counter64(v) => i64::try_from(v).ok()?,
            _ => return None,
        })
    }

    /// The value as an unsigned integer, for every non-negative numeric value.
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Value::Integer(v) => u64::try_from(v).ok(),
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => Some(v as u64),
            Value::Counter64(v) => Some(v),
            _ => None,
        }
    }

    /// The bytes of an OCTET STRING or Opaque.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::OctetString(b) | Value::Opaque(b) => Some(b),
            _ => None,
        }
    }

    /// An OCTET STRING as text, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::OctetString(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }

    /// The BER tag of this value.
    pub fn tag(&self) -> u8 {
        match self {
            Value::Integer(_) => tag::INTEGER,
            Value::OctetString(_) => tag::OCTET_STRING,
            Value::Null => tag::NULL,
            Value::ObjectId(_) => tag::OBJECT_IDENTIFIER,
            Value::IpAddress(_) => tag::IP_ADDRESS,
            Value::Counter32(_) => tag::COUNTER32,
            Value::Gauge32(_) => tag::GAUGE32,
            Value::TimeTicks(_) => tag::TIMETICKS,
            Value::Opaque(_) => tag::OPAQUE,
            Value::Counter64(_) => tag::COUNTER64,
            Value::NoSuchObject => tag::NO_SUCH_OBJECT,
            Value::NoSuchInstance => tag::NO_SUCH_INSTANCE,
            Value::EndOfMibView => tag::END_OF_MIB_VIEW,
        }
    }

    pub(crate) fn encode(&self, w: &mut Writer) {
        match self {
            Value::Integer(v) => w.integer(*v as i64),
            Value::OctetString(b) => w.octets(b),
            Value::Null => w.empty(tag::NULL),
            Value::ObjectId(o) => w.oid(o),
            Value::IpAddress(a) => w.bytes(tag::IP_ADDRESS, &a.octets()),
            Value::Counter32(v) => w.unsigned(tag::COUNTER32, *v as u64),
            Value::Gauge32(v) => w.unsigned(tag::GAUGE32, *v as u64),
            Value::TimeTicks(v) => w.unsigned(tag::TIMETICKS, *v as u64),
            Value::Opaque(b) => w.bytes(tag::OPAQUE, b),
            Value::Counter64(v) => w.unsigned(tag::COUNTER64, *v),
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => {
                w.empty(self.tag())
            }
        }
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Value, DecodeError> {
        let at = r.position();
        let (t, inner) = r.read_any()?;
        let c = inner.rest();
        let e = |k| DecodeError::new(k, at);
        let u32_of = |c: &[u8]| decode_unsigned(c, 32).map(|v| v as u32).map_err(e);
        Ok(match t {
            tag::INTEGER => {
                let v = decode_signed(c).map_err(e)?;
                Value::Integer(i32::try_from(v).map_err(|_| e(DecodeErrorKind::IntegerOverflow))?)
            }
            tag::OCTET_STRING => Value::OctetString(c.to_vec()),
            tag::NULL => {
                if !c.is_empty() {
                    return Err(e(DecodeErrorKind::InvalidNull));
                }
                Value::Null
            }
            tag::OBJECT_IDENTIFIER => Value::ObjectId(Oid::from_ber(c).map_err(e)?),
            tag::IP_ADDRESS => {
                let o: [u8; 4] = c
                    .try_into()
                    .map_err(|_| e(DecodeErrorKind::InvalidIpAddress))?;
                Value::IpAddress(Ipv4Addr::from(o))
            }
            tag::COUNTER32 => Value::Counter32(u32_of(c)?),
            tag::GAUGE32 | tag::UINTEGER32 => Value::Gauge32(u32_of(c)?),
            tag::TIMETICKS => Value::TimeTicks(u32_of(c)?),
            tag::OPAQUE => Value::Opaque(c.to_vec()),
            tag::COUNTER64 => Value::Counter64(decode_unsigned(c, 64).map_err(e)?),
            tag::NO_SUCH_OBJECT => Value::NoSuchObject,
            tag::NO_SUCH_INSTANCE => Value::NoSuchInstance,
            tag::END_OF_MIB_VIEW => Value::EndOfMibView,
            other => return Err(e(DecodeErrorKind::UnknownValueTag(other))),
        })
    }
}

impl fmt::Display for Value {
    /// Formats like net-snmp's `snmpget -Oqv` where it is unambiguous:
    /// text for printable strings, hex otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Integer(v) => write!(f, "{v}"),
            Value::OctetString(b) => match std::str::from_utf8(b) {
                Ok(s)
                    if s.chars()
                        .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') =>
                {
                    f.write_str(s)
                }
                _ => {
                    for (i, x) in b.iter().enumerate() {
                        if i > 0 {
                            f.write_str(" ")?;
                        }
                        write!(f, "{x:02X}")?;
                    }
                    Ok(())
                }
            },
            Value::Null => f.write_str("NULL"),
            Value::ObjectId(o) => write!(f, "{o}"),
            Value::IpAddress(a) => write!(f, "{a}"),
            Value::Counter32(v) | Value::Gauge32(v) => write!(f, "{v}"),
            Value::TimeTicks(v) => {
                let (s, cs) = (v / 100, v % 100);
                write!(
                    f,
                    "{}:{:02}:{:02}:{:02}.{:02}",
                    s / 86400,
                    s / 3600 % 24,
                    s / 60 % 60,
                    s % 60,
                    cs
                )
            }
            Value::Opaque(b) => write!(f, "Opaque({} bytes)", b.len()),
            Value::Counter64(v) => write!(f, "{v}"),
            Value::NoSuchObject => {
                f.write_str("No Such Object available on this agent at this OID")
            }
            Value::NoSuchInstance => f.write_str("No Such Instance currently exists at this OID"),
            Value::EndOfMibView => f.write_str("No more variables left in this MIB View"),
        }
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Integer(v)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::OctetString(v.as_bytes().to_vec())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::OctetString(v.into_bytes())
    }
}
impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::OctetString(v)
    }
}
impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Self {
        Value::OctetString(v.to_vec())
    }
}
impl From<Oid> for Value {
    fn from(v: Oid) -> Self {
        Value::ObjectId(v)
    }
}
impl From<Ipv4Addr> for Value {
    fn from(v: Ipv4Addr) -> Self {
        Value::IpAddress(v)
    }
}

/// A variable binding: an OID and its value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VarBind {
    /// The variable's name.
    pub oid: Oid,
    /// Its value ([`Value::Null`] in requests).
    pub value: Value,
}

impl VarBind {
    /// A binding.
    pub fn new(oid: impl Into<Oid>, value: impl Into<Value>) -> Self {
        Self {
            oid: oid.into(),
            value: value.into(),
        }
    }

    /// A binding with a NULL value, as used in Get/GetNext/GetBulk requests.
    pub fn null(oid: impl Into<Oid>) -> Self {
        Self {
            oid: oid.into(),
            value: Value::Null,
        }
    }

    pub(crate) fn encode(&self, w: &mut Writer) {
        let m = w.mark();
        self.value.encode(w);
        w.oid(&self.oid);
        w.wrap(m, tag::SEQUENCE);
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<VarBind, DecodeError> {
        let mut s = r.read_sequence()?;
        let at = s.position();
        let oid = Oid::from_ber(s.read_tagged(tag::OBJECT_IDENTIFIER)?.rest())
            .map_err(|k| DecodeError::new(k, at))?;
        let value = Value::decode(&mut s)?;
        s.finish()?;
        Ok(VarBind { oid, value })
    }
}

impl fmt::Display for VarBind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.oid, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(v: Value) {
        let mut w = Writer::new();
        v.encode(&mut w);
        let b = w.finish();
        let mut r = Reader::new(&b);
        assert_eq!(Value::decode(&mut r).unwrap(), v);
        assert!(r.is_empty());
    }

    #[test]
    fn every_type_round_trips() {
        for v in [
            Value::Integer(0),
            Value::Integer(-42),
            Value::Integer(i32::MAX),
            Value::OctetString(b"Linux router 6.1".to_vec()),
            Value::OctetString(vec![]),
            Value::Null,
            Value::ObjectId("1.3.6.1.4.1.8072.3.2.10".parse().unwrap()),
            Value::IpAddress(Ipv4Addr::new(192, 168, 1, 254)),
            Value::Counter32(u32::MAX),
            Value::Gauge32(1_000_000_000),
            Value::TimeTicks(123_456),
            Value::Opaque(vec![0x9F, 0x78, 0x04, 0x3F, 0x80, 0, 0]),
            Value::Counter64(u64::MAX),
            Value::NoSuchObject,
            Value::NoSuchInstance,
            Value::EndOfMibView,
        ] {
            round_trip(v);
        }
    }

    #[test]
    fn display() {
        assert_eq!(Value::TimeTicks(8_640_123).to_string(), "1:00:00:01.23");
        assert_eq!(
            Value::OctetString(vec![0, 0x1B, 0xFF]).to_string(),
            "00 1B FF"
        );
        assert_eq!(Value::from("eth0").to_string(), "eth0");
        let vb = VarBind::new([1, 3, 6, 1, 2, 1, 1, 5, 0], "router");
        assert_eq!(vb.to_string(), "1.3.6.1.2.1.1.5.0 = router");
    }

    #[test]
    fn rejects_bad_values() {
        let kind = |b: &[u8]| Value::decode(&mut Reader::new(b)).unwrap_err().kind;
        assert_eq!(
            kind(&[0x40, 0x03, 1, 2, 3]),
            DecodeErrorKind::InvalidIpAddress
        );
        assert_eq!(kind(&[0x05, 0x01, 0]), DecodeErrorKind::InvalidNull);
        assert_eq!(
            kind(&[0x41, 0x05, 1, 0, 0, 0, 0]),
            DecodeErrorKind::IntegerOverflow
        );
        assert_eq!(kind(&[0x99, 0x00]), DecodeErrorKind::UnknownValueTag(0x99));
    }
}
