//! Zero-copy views of received messages: the bindings read in place,
//! without allocating. [`community_pdu`] parses an SNMPv1/v2c message's
//! headers and returns a [`PduRef`] whose [`Varbinds`] iterator yields
//! [`VarBindRef`]s borrowing from the message.
//!
//! ```
//! use snmpify::view::{community_pdu, ValueRef};
//! use snmpify::{CommunityMessage, Pdu, PduType, VarBind, Version};
//!
//! let bytes = CommunityMessage::new(Version::V2c, "public", Pdu {
//!     pdu_type: PduType::Response, request_id: 1, error_status: 0, error_index: 0,
//!     varbinds: vec![VarBind::new([1, 3, 6, 1, 2, 1, 1, 5, 0], "router-1")],
//! }).encode();
//! let (version, community, pdu) = community_pdu(&bytes)?;
//! assert_eq!((version, community), (Version::V2c, &b"public"[..]));
//! for vb in pdu.varbinds {
//!     let vb = vb?;
//!     assert_eq!(vb.oid.to_oid().unwrap().to_string(), "1.3.6.1.2.1.1.5.0");
//!     assert_eq!(vb.value, ValueRef::OctetString(b"router-1"));
//! }
//! # Ok::<(), snmpify::DecodeError>(())
//! ```

use std::cmp::Ordering;
use std::net::Ipv4Addr;

use crate::ber::{decode_signed, decode_unsigned, tag, Reader};
use crate::error::{DecodeError, DecodeErrorKind};
use crate::pdu::{PduType, Version};
use crate::{Oid, Value, VarBind};

/// An OBJECT IDENTIFIER in its BER form (contents octets), not decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OidRef<'a>(&'a [u8]);

/// Sub-identifiers of a BER OID, decoded one at a time (the first two
/// arcs are one sub-identifier).
#[inline]
fn subids(b: &[u8]) -> impl Iterator<Item = Option<u64>> + '_ {
    let mut i = 0;
    std::iter::from_fn(move || {
        if i >= b.len() {
            return None;
        }
        let mut v = 0u64;
        loop {
            let Some(&x) = b.get(i) else {
                return Some(None); // unterminated
            };
            i += 1;
            v = (v << 7) | (x & 0x7F) as u64;
            if x < 0x80 {
                return Some(Some(v));
            }
            if v > u32::MAX as u64 {
                return Some(None);
            }
        }
    })
}

impl<'a> OidRef<'a> {
    /// The BER contents octets.
    pub fn as_ber(&self) -> &'a [u8] {
        self.0
    }

    /// The decoded OID.
    pub fn to_oid(&self) -> Result<Oid, DecodeErrorKind> {
        Oid::from_ber(self.0)
    }

    /// Whether this OID is under `prefix` (or equal to it), given as BER
    /// contents ([`Oid`] → `ber_contents`): encodings of sub-identifiers
    /// are prefix-free, so the bytes say it.
    #[inline]
    pub fn starts_with_ber(&self, prefix: &[u8]) -> bool {
        self.0.starts_with(prefix)
    }

    /// Compares in OID (MIB tree) order with another BER OID. Byte order
    /// is not OID order (sub-identifiers have different lengths), so this
    /// walks the sub-identifiers.
    #[inline]
    pub fn cmp_ber(&self, other: &[u8]) -> Ordering {
        let (mut a, mut b) = (subids(self.0), subids(other));
        loop {
            match (a.next(), b.next()) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some(x), Some(y)) => match x.cmp(&y) {
                    Ordering::Equal => {}
                    o => return o,
                },
            }
        }
    }
}

/// A value read in place (strings borrow from the message).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ValueRef<'a> {
    Integer(i32),
    OctetString(&'a [u8]),
    Null,
    ObjectId(OidRef<'a>),
    IpAddress(Ipv4Addr),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(&'a [u8]),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl ValueRef<'_> {
    /// The owned [`Value`].
    pub fn to_value(&self) -> Result<Value, DecodeErrorKind> {
        Ok(match *self {
            ValueRef::Integer(v) => Value::Integer(v),
            ValueRef::OctetString(b) => Value::OctetString(b.to_vec()),
            ValueRef::Null => Value::Null,
            ValueRef::ObjectId(o) => Value::ObjectId(o.to_oid()?),
            ValueRef::IpAddress(a) => Value::IpAddress(a),
            ValueRef::Counter32(v) => Value::Counter32(v),
            ValueRef::Gauge32(v) => Value::Gauge32(v),
            ValueRef::TimeTicks(v) => Value::TimeTicks(v),
            ValueRef::Opaque(b) => Value::Opaque(b.to_vec()),
            ValueRef::Counter64(v) => Value::Counter64(v),
            ValueRef::NoSuchObject => Value::NoSuchObject,
            ValueRef::NoSuchInstance => Value::NoSuchInstance,
            ValueRef::EndOfMibView => Value::EndOfMibView,
        })
    }

    /// Whether this is a v2 exception (noSuchObject, noSuchInstance,
    /// endOfMibView).
    pub fn is_exception(&self) -> bool {
        matches!(
            self,
            ValueRef::NoSuchObject | ValueRef::NoSuchInstance | ValueRef::EndOfMibView
        )
    }

    /// Numbers of every numeric type.
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            ValueRef::Integer(v) => u64::try_from(v).ok(),
            ValueRef::Counter32(v) | ValueRef::Gauge32(v) | ValueRef::TimeTicks(v) => {
                Some(v as u64)
            }
            ValueRef::Counter64(v) => Some(v),
            _ => None,
        }
    }

    /// OCTET STRING / Opaque bytes.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match *self {
            ValueRef::OctetString(b) | ValueRef::Opaque(b) => Some(b),
            _ => None,
        }
    }

    #[inline]
    fn decode<'a>(r: &mut Reader<'a>) -> Result<ValueRef<'a>, DecodeError> {
        let at = r.position();
        let (t, inner) = r.read_any()?;
        let c = inner.rest();
        let e = |k| DecodeError::new(k, at);
        let u32_of = |c: &[u8]| decode_unsigned(c, 32).map(|v| v as u32).map_err(e);
        Ok(match t {
            tag::INTEGER => {
                let v = decode_signed(c).map_err(e)?;
                ValueRef::Integer(
                    i32::try_from(v).map_err(|_| e(DecodeErrorKind::IntegerOverflow))?,
                )
            }
            tag::OCTET_STRING => ValueRef::OctetString(c),
            tag::NULL if c.is_empty() => ValueRef::Null,
            tag::NULL => return Err(e(DecodeErrorKind::InvalidNull)),
            tag::OBJECT_IDENTIFIER => ValueRef::ObjectId(OidRef(c)),
            tag::IP_ADDRESS => {
                let o: [u8; 4] = c
                    .try_into()
                    .map_err(|_| e(DecodeErrorKind::InvalidIpAddress))?;
                ValueRef::IpAddress(Ipv4Addr::from(o))
            }
            tag::COUNTER32 => ValueRef::Counter32(u32_of(c)?),
            tag::GAUGE32 | tag::UINTEGER32 => ValueRef::Gauge32(u32_of(c)?),
            tag::TIMETICKS => ValueRef::TimeTicks(u32_of(c)?),
            tag::OPAQUE => ValueRef::Opaque(c),
            tag::COUNTER64 => ValueRef::Counter64(decode_unsigned(c, 64).map_err(e)?),
            tag::NO_SUCH_OBJECT => ValueRef::NoSuchObject,
            tag::NO_SUCH_INSTANCE => ValueRef::NoSuchInstance,
            tag::END_OF_MIB_VIEW => ValueRef::EndOfMibView,
            other => return Err(e(DecodeErrorKind::UnknownValueTag(other))),
        })
    }
}

/// A binding read in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VarBindRef<'a> {
    /// The name.
    pub oid: OidRef<'a>,
    /// The value.
    pub value: ValueRef<'a>,
}

impl VarBindRef<'_> {
    /// The owned [`VarBind`].
    pub fn to_owned(&self) -> Result<VarBind, DecodeErrorKind> {
        Ok(VarBind {
            oid: self.oid.to_oid()?,
            value: self.value.to_value()?,
        })
    }
}

/// The bindings of a PDU, decoded one by one as they are read.
#[derive(Clone, Copy, Debug)]
pub struct Varbinds<'a> {
    list: Reader<'a>,
    failed: bool,
}

impl<'a> Iterator for Varbinds<'a> {
    type Item = Result<VarBindRef<'a>, DecodeError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.list.is_empty() {
            return None;
        }
        let r = (|| {
            let mut s = self.list.read_sequence()?;
            let oid = OidRef(s.read_tagged(tag::OBJECT_IDENTIFIER)?.rest());
            let value = ValueRef::decode(&mut s)?;
            s.finish()?;
            Ok(VarBindRef { oid, value })
        })();
        self.failed = r.is_err();
        Some(r)
    }
}

/// A PDU read in place.
#[derive(Clone, Copy, Debug)]
pub struct PduRef<'a> {
    /// The PDU kind.
    pub pdu_type: PduType,
    /// The request id.
    pub request_id: i32,
    /// Error status (non-repeaters for GetBulk).
    pub error_status: i32,
    /// Error index (max-repetitions for GetBulk).
    pub error_index: i32,
    /// The bindings.
    pub varbinds: Varbinds<'a>,
}

/// Reads a standard PDU (not a v1 trap) in place.
pub fn pdu<'a>(r: &mut Reader<'a>) -> Result<PduRef<'a>, DecodeError> {
    pdu_ref(r)
}

fn pdu_ref<'a>(r: &mut Reader<'a>) -> Result<PduRef<'a>, DecodeError> {
    let at = r.position();
    let (t, mut body) = r.read_any()?;
    let pdu_type =
        PduType::from_tag(t).ok_or_else(|| DecodeError::new(DecodeErrorKind::UnknownPdu(t), at))?;
    let request_id = body.read_i32()?;
    let error_status = body.read_i32()?;
    let error_index = body.read_i32()?;
    let list = body.read_sequence()?;
    body.finish()?;
    Ok(PduRef {
        pdu_type,
        request_id,
        error_status,
        error_index,
        varbinds: Varbinds {
            list,
            failed: false,
        },
    })
}

/// Reads an SNMPv1/v2c message's headers in place: version, community
/// and the PDU (its bindings are decoded as they are iterated).
pub fn community_pdu(bytes: &[u8]) -> Result<(Version, &[u8], PduRef<'_>), DecodeError> {
    let mut outer = Reader::new(bytes);
    let mut r = outer.read_sequence()?;
    outer.finish()?;
    let at = r.position();
    let code = r.read_i32()?;
    let version = match Version::from_code(code) {
        Some(v @ (Version::V1 | Version::V2c)) => v,
        _ => return Err(DecodeError::new(DecodeErrorKind::UnknownVersion(code), at)),
    };
    let community = r.read_octets()?;
    let p = pdu_ref(&mut r)?;
    r.finish()?;
    Ok((version, community, p))
}

/// The BER contents of an OID (for [`OidRef::starts_with_ber`] and
/// [`OidRef::cmp_ber`]).
pub fn ber_contents(oid: &Oid) -> Vec<u8> {
    let mut w = crate::ber::Writer::new();
    w.oid(oid);
    let full = w.finish();
    // Skip the tag and the length.
    let skip = if full[1] < 0x80 {
        2
    } else {
        2 + (full[1] & 0x7F) as usize
    };
    full[skip..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommunityMessage, Pdu};

    fn message() -> Vec<u8> {
        let vbs = vec![
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 1], Value::Integer(-5)),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 2], "text"),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 3], Value::Null),
            VarBind::new(
                [1, 3, 6, 1, 4, 1, 99999, 4],
                Value::ObjectId(Oid::from([1, 3, 6, 200000])),
            ),
            VarBind::new(
                [1, 3, 6, 1, 4, 1, 99999, 5],
                Value::IpAddress([10, 0, 0, 1].into()),
            ),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 6], Value::Counter32(7)),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 7], Value::Gauge32(8)),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 8], Value::TimeTicks(9)),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 9], Value::Opaque(vec![1])),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 10], Value::Counter64(1 << 40)),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 11], Value::NoSuchObject),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 12], Value::NoSuchInstance),
            VarBind::new([1, 3, 6, 1, 4, 1, 99999, 13], Value::EndOfMibView),
        ];
        CommunityMessage::new(
            Version::V2c,
            "public",
            Pdu {
                pdu_type: PduType::Response,
                request_id: 42,
                error_status: 0,
                error_index: 0,
                varbinds: vbs,
            },
        )
        .encode()
    }

    #[test]
    fn same_as_the_owned_decoder() {
        let b = message();
        let owned = CommunityMessage::decode(&b).unwrap();
        let crate::AnyPdu::Pdu(p) = owned.pdu else {
            panic!()
        };
        let (v, c, r) = community_pdu(&b).unwrap();
        assert_eq!(
            (v, c, r.request_id, r.pdu_type),
            (Version::V2c, &b"public"[..], 42, PduType::Response)
        );
        let refs: Vec<VarBind> = r.varbinds.map(|x| x.unwrap().to_owned().unwrap()).collect();
        assert_eq!(refs, p.varbinds);
        let first = community_pdu(&b)
            .unwrap()
            .2
            .varbinds
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(first.value.as_u64(), None);
        assert!(!first.value.is_exception());
        let vals: Vec<ValueRef<'_>> = community_pdu(&b)
            .unwrap()
            .2
            .varbinds
            .map(|x| x.unwrap().value)
            .collect();
        assert_eq!(vals[1].as_bytes(), Some(&b"text"[..]));
        assert_eq!(vals[5].as_u64(), Some(7));
        assert!(vals[12].is_exception());
        // Every truncation fails cleanly, and iteration stops after an error.
        for n in 0..b.len() {
            if let Ok((_, _, p)) = community_pdu(&b[..n]) {
                assert!(p.varbinds.count() <= 13);
            }
        }
        assert!(community_pdu(
            &crate::CommunityMessage::new(Version::V1, "x", Pdu::get(1, [[1u32, 3]])).encode()
        )
        .is_ok());
        let v3 = [0x30, 0x03, 0x02, 0x01, 0x03];
        assert!(community_pdu(&v3).is_err());
    }

    #[test]
    fn order_and_prefixes_in_ber() {
        let enc = |s: &str| ber_contents(&s.parse().unwrap());
        let cases = [
            ("1.3.6.1.2", "1.3.6.1.2", Ordering::Equal),
            ("1.3.6.1.2", "1.3.6.1.2.1", Ordering::Less),
            ("1.3.6.1.127", "1.3.6.1.128", Ordering::Less),
            // 16256 (FF 00) < 16384 (81 80 00) although FF > 81.
            ("1.3.6.16256", "1.3.6.16384", Ordering::Less),
            (
                "1.3.6.1.4.1.99999.2",
                "1.3.6.1.4.1.99999.1.7",
                Ordering::Greater,
            ),
            ("2.999.1", "1.3.6", Ordering::Greater),
        ];
        for (a, b, o) in cases {
            assert_eq!(OidRef(&enc(a)).cmp_ber(&enc(b)), o, "{a} {b}");
            let (x, y): (Oid, Oid) = (a.parse().unwrap(), b.parse().unwrap());
            assert_eq!(x.cmp(&y), o, "owned {a} {b}");
        }
        assert!(OidRef(&enc("1.3.6.1.4.1.99999.1.2")).starts_with_ber(&enc("1.3.6.1.4.1.99999.1")));
        assert!(!OidRef(&enc("1.3.6.1.4.1.99999.10")).starts_with_ber(&enc("1.3.6.1.4.1.99999.1")));
        assert_eq!(OidRef(&enc("1.3.6.1")).as_ber(), &enc("1.3.6.1")[..]);
        // Unterminated sub-identifiers compare as invalid (None).
        assert_ne!(
            OidRef(&[0x2b, 0x86]).cmp_ber(&[0x2b, 0x06]),
            Ordering::Equal
        );
        let mut r = Reader::new(&[0xA2, 0x03, 0x02, 0x01, 0x01]);
        assert!(pdu(&mut r).is_err());
    }
}
