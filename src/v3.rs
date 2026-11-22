//! SNMPv3 messages (RFC 3412) with User-based Security Model parameters
//! (RFC 3414): the wire format only.
//!
//! Authentication and encryption, which need keys, are in
//! [`usm`](crate::usm) (feature `v3`). This module encodes and decodes the
//! message as it is on the wire: header, security parameters, and the
//! scoped PDU either in plaintext or still encrypted.
//!
//! ```
//! use snmpify::v3::{ScopedPdu, ScopedPduData, UsmParams, V3Message, flags};
//! use snmpify::Pdu;
//!
//! // The engine discovery probe of RFC 3414 §4: no user, no engine id.
//! let probe = V3Message {
//!     msg_id: 1,
//!     max_size: 65507,
//!     flags: flags::REPORTABLE,
//!     usm: UsmParams::default(),
//!     data: ScopedPduData::Plaintext(ScopedPdu::new(Vec::new(), Vec::new(), Pdu::get(1, Vec::<snmpify::Oid>::new()))),
//! };
//! let bytes = probe.encode();
//! assert_eq!(V3Message::decode(&bytes).unwrap(), probe);
//! ```

use std::ops::Range;

use crate::ber::{tag, Reader, Writer};
use crate::error::{DecodeError, DecodeErrorKind};
use crate::oid::Oid;
use crate::pdu::{AnyPdu, CommunityMessage, Pdu, Version};

/// Bits of `msgFlags`.
pub mod flags {
    /// authFlag: the message is authenticated.
    pub const AUTH: u8 = 0x01;
    /// privFlag: the scoped PDU is encrypted (needs [`AUTH`]).
    pub const PRIV: u8 = 0x02;
    /// reportableFlag: the receiver may answer with a Report PDU.
    pub const REPORTABLE: u8 = 0x04;
}

/// The User-based Security Model (`msgSecurityModel` 3).
pub const USM_SECURITY_MODEL: i32 = 3;

/// The largest message a UDP datagram over IPv4 can carry, the usual
/// `msgMaxSize`.
pub const DEFAULT_MAX_SIZE: i32 = 65_507;

/// `UsmSecurityParameters` (RFC 3414 §2.4), carried in
/// `msgSecurityParameters`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsmParams {
    /// `msgAuthoritativeEngineID`: the agent's engine id for requests to it.
    pub engine_id: Vec<u8>,
    /// `msgAuthoritativeEngineBoots` (0 ..= 2^31 - 1).
    pub engine_boots: u32,
    /// `msgAuthoritativeEngineTime`, seconds (0 ..= 2^31 - 1).
    pub engine_time: u32,
    /// `msgUserName` (at most 32 octets).
    pub user_name: Vec<u8>,
    /// `msgAuthenticationParameters`: the truncated HMAC, or empty.
    pub auth_params: Vec<u8>,
    /// `msgPrivacyParameters`: the encryption salt, or empty.
    pub priv_params: Vec<u8>,
}

/// A scoped PDU: context and PDU (RFC 3412 §6.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedPdu {
    /// `contextEngineID`; usually the agent's engine id.
    pub context_engine_id: Vec<u8>,
    /// `contextName`; usually empty.
    pub context_name: Vec<u8>,
    /// The PDU (never an SNMPv1 trap).
    pub pdu: Pdu,
}

impl ScopedPdu {
    /// A scoped PDU.
    pub fn new(
        context_engine_id: impl Into<Vec<u8>>,
        context_name: impl Into<Vec<u8>>,
        pdu: Pdu,
    ) -> Self {
        Self {
            context_engine_id: context_engine_id.into(),
            context_name: context_name.into(),
            pdu,
        }
    }

    pub(crate) fn encode_into(&self, w: &mut Writer) {
        let m = w.mark();
        self.pdu.encode(w);
        w.octets(&self.context_name);
        w.octets(&self.context_engine_id);
        w.wrap(m, tag::SEQUENCE);
    }

    /// The BER encoding (the plaintext that privacy encrypts).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.pdu.varbinds.len() * 24);
        self.encode_into(&mut w);
        w.finish()
    }

    /// Decodes one scoped PDU that must fill `bytes` exactly.
    pub fn decode(bytes: &[u8]) -> Result<ScopedPdu, DecodeError> {
        let mut r = Reader::new(bytes);
        let s = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(s)
    }

    /// Decodes a scoped PDU followed by padding (DES pads the plaintext to
    /// whole blocks; RFC 3414 §8.1.1.2 lets the receiver ignore it).
    #[cfg_attr(not(feature = "v3"), allow(dead_code))]
    pub(crate) fn decode_padded(bytes: &[u8]) -> Result<ScopedPdu, DecodeError> {
        Self::decode_from(&mut Reader::new(bytes))
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<ScopedPdu, DecodeError> {
        let mut s = r.read_sequence()?;
        let context_engine_id = s.read_octets()?.to_vec();
        let context_name = s.read_octets()?.to_vec();
        let at = s.position();
        let pdu = match AnyPdu::decode(&mut s)? {
            AnyPdu::Pdu(p) => p,
            AnyPdu::TrapV1(_) => {
                return Err(DecodeError::new(
                    DecodeErrorKind::UnknownPdu(tag::TRAP_V1),
                    at,
                ))
            }
        };
        s.finish()?;
        Ok(ScopedPdu {
            context_engine_id,
            context_name,
            pdu,
        })
    }
}

/// `msgData`: the scoped PDU, in plaintext or encrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopedPduData {
    /// Not encrypted.
    Plaintext(ScopedPdu),
    /// `encryptedPDU`: the ciphertext of an encoded [`ScopedPdu`].
    Encrypted(Vec<u8>),
}

/// An SNMPv3 message with USM security parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3Message {
    /// `msgID`: matches a response to its request (not the request id).
    pub msg_id: i32,
    /// `msgMaxSize`: the largest message the sender can receive.
    pub max_size: i32,
    /// `msgFlags`, see [`flags`].
    pub flags: u8,
    /// The USM security parameters.
    pub usm: UsmParams,
    /// The scoped PDU.
    pub data: ScopedPduData,
}

impl V3Message {
    /// The BER encoding, as is (no authentication or encryption is done
    /// here; see [`usm`](crate::usm)).
    pub fn encode(&self) -> Vec<u8> {
        self.encode_with_auth_range().0
    }

    /// The encoding and where the contents of `msgAuthenticationParameters`
    /// are in it (the bytes the HMAC covers zeroed and then replaces).
    pub(crate) fn encode_with_auth_range(&self) -> (Vec<u8>, Range<usize>) {
        let hint = match &self.data {
            ScopedPduData::Plaintext(s) => 64 + s.pdu.varbinds.len() * 24,
            ScopedPduData::Encrypted(c) => c.len(),
        };
        let mut w = Writer::with_capacity(96 + hint + self.usm.user_name.len());
        let m = w.mark();
        match &self.data {
            ScopedPduData::Plaintext(s) => s.encode_into(&mut w),
            ScopedPduData::Encrypted(c) => w.octets(c),
        }
        // msgSecurityParameters: an OCTET STRING holding the USM SEQUENCE.
        let sp = w.mark();
        let seq = w.mark();
        let u = &self.usm;
        w.octets(&u.priv_params);
        let auth_end = w.mark(); // reversed: contents start after this
        w.octets(&u.auth_params);
        w.octets(&u.user_name);
        w.integer(u.engine_time as i64);
        w.integer(u.engine_boots as i64);
        w.octets(&u.engine_id);
        w.wrap(seq, tag::SEQUENCE);
        w.wrap(sp, tag::OCTET_STRING);
        // msgGlobalData
        let h = w.mark();
        w.integer(USM_SECURITY_MODEL as i64);
        w.octets(&[self.flags]);
        w.integer(self.max_size as i64);
        w.integer(self.msg_id as i64);
        w.wrap(h, tag::SEQUENCE);
        w.integer(Version::V3.code() as i64);
        w.wrap(m, tag::SEQUENCE);
        let total = w.mark();
        // In the reversed buffer the contents occupy
        // [auth_end, auth_end + len); flip to normal order.
        let start = total - auth_end - u.auth_params.len();
        (w.finish(), start..start + u.auth_params.len())
    }

    /// Decodes an SNMPv3 message with USM parameters. Other versions give
    /// [`DecodeErrorKind::UnknownVersion`], other security models
    /// [`DecodeErrorKind::UnsupportedSecurityModel`].
    pub fn decode(bytes: &[u8]) -> Result<V3Message, DecodeError> {
        Ok(Self::decode_with_auth_range(bytes)?.0)
    }

    pub(crate) fn decode_with_auth_range(
        bytes: &[u8],
    ) -> Result<(V3Message, Range<usize>), DecodeError> {
        let mut outer = Reader::new(bytes);
        let mut r = outer.read_sequence()?;
        outer.finish()?;
        let at = r.position();
        let code = r.read_i32()?;
        if code != Version::V3.code() {
            return Err(DecodeError::new(DecodeErrorKind::UnknownVersion(code), at));
        }
        // msgGlobalData
        let mut h = r.read_sequence()?;
        let at = h.position();
        let msg_id = non_negative(h.read_i32()?, at)?;
        let at = h.position();
        let max_size = non_negative(h.read_i32()?, at)?;
        let at = h.position();
        let flags = match h.read_octets()? {
            [f] if f & flags::PRIV == 0 || f & flags::AUTH != 0 => *f,
            _ => return Err(DecodeError::new(DecodeErrorKind::InvalidMsgFlags, at)),
        };
        let at = h.position();
        let model = h.read_i32()?;
        h.finish()?;
        if model != USM_SECURITY_MODEL {
            return Err(DecodeError::new(
                DecodeErrorKind::UnsupportedSecurityModel(model),
                at,
            ));
        }
        // msgSecurityParameters
        let mut sp = r.read_tagged(tag::OCTET_STRING)?;
        let mut u = sp.read_sequence()?;
        sp.finish()?;
        let engine_id = u.read_octets()?.to_vec();
        let at = u.position();
        let engine_boots = non_negative(u.read_i32()?, at)? as u32;
        let at = u.position();
        let engine_time = non_negative(u.read_i32()?, at)? as u32;
        let user_name = u.read_octets()?.to_vec();
        let auth = u.read_tagged(tag::OCTET_STRING)?;
        let auth_range = auth.position()..auth.position() + auth.rest().len();
        let auth_params = auth.rest().to_vec();
        let priv_params = u.read_octets()?.to_vec();
        u.finish()?;
        // msgData
        let data = if r.peek_tag()? == tag::OCTET_STRING {
            ScopedPduData::Encrypted(r.read_octets()?.to_vec())
        } else {
            ScopedPduData::Plaintext(ScopedPdu::decode_from(&mut r)?)
        };
        r.finish()?;
        Ok((
            V3Message {
                msg_id,
                max_size,
                flags,
                usm: UsmParams {
                    engine_id,
                    engine_boots,
                    engine_time,
                    user_name,
                    auth_params,
                    priv_params,
                },
                data,
            },
            auth_range,
        ))
    }
}

fn non_negative(v: i32, at: usize) -> Result<i32, DecodeError> {
    if v < 0 {
        Err(DecodeError::new(DecodeErrorKind::IntegerOverflow, at))
    } else {
        Ok(v)
    }
}

/// The msgID of an SNMPv3 message, decoding only the header.
#[cfg_attr(not(feature = "client"), allow(dead_code))]
pub(crate) fn peek_msg_id(bytes: &[u8]) -> Option<i32> {
    let mut r = Reader::new(bytes).read_sequence().ok()?;
    if r.read_i32().ok()? != Version::V3.code() {
        return None;
    }
    r.read_sequence().ok()?.read_i32().ok()
}

/// Any SNMP message: community-based (v1, v2c) or SNMPv3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// SNMPv1 or v2c.
    Community(CommunityMessage),
    /// SNMPv3.
    V3(V3Message),
}

impl Message {
    /// Decodes a message of any version.
    pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        match crate::pdu::peek_version(bytes)? {
            Version::V3 => Ok(Message::V3(V3Message::decode(bytes)?)),
            _ => Ok(Message::Community(CommunityMessage::decode(bytes)?)),
        }
    }

    /// The BER encoding.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::Community(m) => m.encode(),
            Message::V3(m) => m.encode(),
        }
    }
}

/// What a Report PDU reports: the counter in its first binding
/// (RFC 3414 §5 `usmStats`, RFC 3412 §5 `snmpMPDStats`, RFC 3413).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportKind {
    /// usmStatsUnsupportedSecLevels: the user may not use this level.
    UnsupportedSecurityLevel,
    /// usmStatsNotInTimeWindows: engine boots/time out of the window
    /// (the report carries the current values).
    NotInTimeWindow,
    /// usmStatsUnknownUserNames.
    UnknownUserName,
    /// usmStatsUnknownEngineIDs: the answer to engine discovery.
    UnknownEngineId,
    /// usmStatsWrongDigests: wrong authentication key or protocol.
    WrongDigest,
    /// usmStatsDecryptionErrors: wrong privacy key or protocol.
    DecryptionError,
    /// snmpUnknownSecurityModels.
    UnknownSecurityModel,
    /// snmpInvalidMsgs.
    InvalidMessage,
    /// snmpUnknownPDUHandlers.
    UnknownPduHandler,
    /// snmpUnavailableContexts.
    UnavailableContext,
    /// snmpUnknownContexts.
    UnknownContext,
    /// Another counter.
    Other(Oid),
}

impl ReportKind {
    /// The kind for a report's first binding (the counter's instance OID).
    pub fn from_oid(oid: &Oid) -> ReportKind {
        const USM_STATS: [u32; 9] = [1, 3, 6, 1, 6, 3, 15, 1, 1];
        const MPD_STATS: [u32; 9] = [1, 3, 6, 1, 6, 3, 11, 2, 1];
        const TARGET: [u32; 9] = [1, 3, 6, 1, 6, 3, 12, 1, 0];
        let a = oid.as_slice();
        if a.len() == 11 && a[10] == 0 {
            let (prefix, n) = (&a[..9], a[9]);
            if prefix == USM_STATS {
                match n {
                    1 => return ReportKind::UnsupportedSecurityLevel,
                    2 => return ReportKind::NotInTimeWindow,
                    3 => return ReportKind::UnknownUserName,
                    4 => return ReportKind::UnknownEngineId,
                    5 => return ReportKind::WrongDigest,
                    6 => return ReportKind::DecryptionError,
                    _ => {}
                }
            } else if prefix == MPD_STATS {
                match n {
                    1 => return ReportKind::UnknownSecurityModel,
                    2 => return ReportKind::InvalidMessage,
                    3 => return ReportKind::UnknownPduHandler,
                    _ => {}
                }
            }
        }
        // snmpUnavailableContexts / snmpUnknownContexts: 1.3.6.1.6.3.12.1.{4,5}.0
        if a.len() == 10 && a[..8] == TARGET[..8] && a[9] == 0 {
            match a[8] {
                4 => return ReportKind::UnavailableContext,
                5 => return ReportKind::UnknownContext,
                _ => {}
            }
        }
        ReportKind::Other(oid.clone())
    }

    /// The counter's instance OID (for agents sending reports).
    pub fn oid(&self) -> Oid {
        let usm = |n| Oid::from([1, 3, 6, 1, 6, 3, 15, 1, 1, n, 0]);
        let mpd = |n| Oid::from([1, 3, 6, 1, 6, 3, 11, 2, 1, n, 0]);
        match self {
            ReportKind::UnsupportedSecurityLevel => usm(1),
            ReportKind::NotInTimeWindow => usm(2),
            ReportKind::UnknownUserName => usm(3),
            ReportKind::UnknownEngineId => usm(4),
            ReportKind::WrongDigest => usm(5),
            ReportKind::DecryptionError => usm(6),
            ReportKind::UnknownSecurityModel => mpd(1),
            ReportKind::InvalidMessage => mpd(2),
            ReportKind::UnknownPduHandler => mpd(3),
            ReportKind::UnavailableContext => Oid::from([1, 3, 6, 1, 6, 3, 12, 1, 4, 0]),
            ReportKind::UnknownContext => Oid::from([1, 3, 6, 1, 6, 3, 12, 1, 5, 0]),
            ReportKind::Other(o) => o.clone(),
        }
    }
}

impl std::fmt::Display for ReportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReportKind::UnsupportedSecurityLevel => "unsupported security level",
            ReportKind::NotInTimeWindow => "not in time window",
            ReportKind::UnknownUserName => "unknown user name",
            ReportKind::UnknownEngineId => "unknown engine id",
            ReportKind::WrongDigest => "wrong digest (authentication key or protocol)",
            ReportKind::DecryptionError => "decryption error (privacy key or protocol)",
            ReportKind::UnknownSecurityModel => "unknown security model",
            ReportKind::InvalidMessage => "invalid message",
            ReportKind::UnknownPduHandler => "unknown PDU handler",
            ReportKind::UnavailableContext => "unavailable context",
            ReportKind::UnknownContext => "unknown context",
            ReportKind::Other(o) => return write!(f, "report {o}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::{Value, VarBind};

    fn sample(data: ScopedPduData) -> V3Message {
        V3Message {
            msg_id: 0x1234_5678,
            max_size: DEFAULT_MAX_SIZE,
            flags: flags::AUTH | flags::REPORTABLE,
            usm: UsmParams {
                engine_id: vec![0x80, 0, 0x1f, 0x88, 0x80, 1, 2, 3, 4],
                engine_boots: 7,
                engine_time: 123_456,
                user_name: b"admin".to_vec(),
                auth_params: vec![0xAA; 12],
                priv_params: vec![],
            },
            data,
        }
    }

    fn scoped() -> ScopedPdu {
        ScopedPdu::new(
            vec![0x80, 0, 0x1f, 0x88, 0x80, 1, 2, 3, 4],
            b"ctx".to_vec(),
            Pdu::get(42, [[1u32, 3, 6, 1, 2, 1, 1, 5, 0]]),
        )
    }

    #[test]
    fn round_trip_and_auth_range() {
        for data in [
            ScopedPduData::Plaintext(scoped()),
            ScopedPduData::Encrypted(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        ] {
            let m = sample(data);
            let (bytes, range) = m.encode_with_auth_range();
            assert_eq!(&bytes[range.clone()], &[0xAA; 12]);
            let (d, r2) = V3Message::decode_with_auth_range(&bytes).unwrap();
            assert_eq!(d, m);
            assert_eq!(r2, range);
            assert_eq!(peek_msg_id(&bytes), Some(0x1234_5678));
            assert_eq!(Message::decode(&bytes).unwrap(), Message::V3(m.clone()));
            assert_eq!(Message::V3(m).encode(), bytes);
        }
    }

    #[test]
    fn auth_range_with_long_lengths() {
        // A big message (multi-byte lengths everywhere) and a 48-byte MAC.
        let mut m = sample(ScopedPduData::Plaintext(ScopedPdu::new(
            Vec::new(),
            Vec::new(),
            Pdu::set(
                1,
                (0..200)
                    .map(|i| VarBind::new([1, 3, 6, 1, 4, 1, i], Value::from("x".repeat(40))))
                    .collect(),
            ),
        )));
        m.usm.auth_params = vec![0x55; 48];
        let (bytes, range) = m.encode_with_auth_range();
        assert!(bytes.len() > 10_000);
        assert_eq!(&bytes[range.clone()], &[0x55; 48]);
        assert_eq!(V3Message::decode_with_auth_range(&bytes).unwrap().1, range);
        // Empty auth params: an empty range at the right place.
        m.usm.auth_params.clear();
        let (bytes, range) = m.encode_with_auth_range();
        assert!(range.is_empty());
        assert_eq!(V3Message::decode_with_auth_range(&bytes).unwrap().1, range);
    }

    #[test]
    fn netsnmp_discovery_probe_bytes() {
        // What net-snmp 5.9's `snmpget -v3 -u x` sends first, captured:
        // empty engine id and user, an empty GetRequest.
        let probe = [
            0x30, 0x3e, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x21, 0x4b, 0x89, 0xa8, 0x02,
            0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e,
            0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00,
            0x30, 0x14, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0e, 0x02, 0x04, 0x35, 0x5a, 0xa7, 0x6f,
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];
        let m = V3Message::decode(&probe).unwrap();
        assert_eq!(m.msg_id, 0x214B_89A8);
        assert_eq!(m.max_size, 65507);
        assert_eq!(m.flags, flags::REPORTABLE);
        assert_eq!(m.usm, UsmParams::default());
        let ScopedPduData::Plaintext(s) = &m.data else {
            panic!()
        };
        assert!(s.pdu.varbinds.is_empty());
        assert_eq!(s.pdu.request_id, 0x355A_A76F);
        assert_eq!(m.encode(), probe);
    }

    #[test]
    fn rejects_bad_headers() {
        let good = sample(ScopedPduData::Plaintext(scoped())).encode();
        let kind = |b: &[u8]| V3Message::decode(b).unwrap_err().kind;
        // Version 1 message.
        let v1 = CommunityMessage::new(Version::V1, "public", Pdu::get(1, [[1u32, 3]])).encode();
        assert_eq!(kind(&v1), DecodeErrorKind::UnknownVersion(0));
        // Priv without auth.
        let mut m = sample(ScopedPduData::Encrypted(vec![0; 8]));
        m.flags = flags::PRIV;
        assert_eq!(kind(&m.encode()), DecodeErrorKind::InvalidMsgFlags);
        // Version 2 and security model 2.
        let mut b = good.clone();
        b[4] = 2;
        assert_eq!(kind(&b), DecodeErrorKind::UnknownVersion(2));
        let f = [
            0x04,
            0x01,
            flags::AUTH | flags::REPORTABLE,
            0x02,
            0x01,
            0x03,
        ];
        let i = good.windows(6).position(|w| w == f).unwrap();
        let mut b = good.clone();
        b[i + 5] = 2;
        assert_eq!(kind(&b), DecodeErrorKind::UnsupportedSecurityModel(2));
        // Negative boots.
        let mut m = sample(ScopedPduData::Plaintext(scoped()));
        m.usm.engine_boots = u32::MAX;
        assert_eq!(kind(&m.encode()), DecodeErrorKind::IntegerOverflow);
        // Truncated anywhere: an error, never a panic.
        for n in 0..good.len() {
            assert!(V3Message::decode(&good[..n]).is_err());
        }
        assert_eq!(peek_msg_id(&v1), None);
        assert_eq!(peek_msg_id(&[0x30]), None);
    }

    #[test]
    fn scoped_pdu_padding_and_traps() {
        let s = scoped();
        let mut b = s.encode();
        assert_eq!(ScopedPdu::decode(&b).unwrap(), s);
        b.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            ScopedPdu::decode(&b).unwrap_err().kind,
            DecodeErrorKind::TrailingData
        );
        assert_eq!(ScopedPdu::decode_padded(&b).unwrap(), s);
        // A v1 trap cannot be in a scoped PDU.
        let trap = crate::pdu::TrapV1Pdu {
            enterprise: Oid::from([1, 3, 6, 1]),
            agent_addr: [127, 0, 0, 1].into(),
            generic_trap: 0,
            specific_trap: 0,
            timestamp: 0,
            varbinds: vec![],
        };
        let mut w = Writer::new();
        let m = w.mark();
        AnyPdu::TrapV1(trap).encode(&mut w);
        w.octets(b"");
        w.octets(b"");
        w.wrap(m, tag::SEQUENCE);
        assert_eq!(
            ScopedPdu::decode(&w.finish()).unwrap_err().kind,
            DecodeErrorKind::UnknownPdu(tag::TRAP_V1)
        );
    }

    #[test]
    fn report_kinds() {
        let all = [
            ReportKind::UnsupportedSecurityLevel,
            ReportKind::NotInTimeWindow,
            ReportKind::UnknownUserName,
            ReportKind::UnknownEngineId,
            ReportKind::WrongDigest,
            ReportKind::DecryptionError,
            ReportKind::UnknownSecurityModel,
            ReportKind::InvalidMessage,
            ReportKind::UnknownPduHandler,
            ReportKind::UnavailableContext,
            ReportKind::UnknownContext,
        ];
        for k in all {
            assert_eq!(ReportKind::from_oid(&k.oid()), k);
            assert!(!k.to_string().is_empty());
        }
        assert_eq!(
            ReportKind::from_oid(&"1.3.6.1.6.3.15.1.1.4.0".parse().unwrap()),
            ReportKind::UnknownEngineId
        );
        for o in [
            "1.3.6.1.6.3.15.1.1.9.0",
            "1.3.6.1.6.3.15.1.1.4",
            "1.3.6.1.6.3.11.2.1.9.0",
            "1.3.6.1.6.3.12.1.9.0",
            "1.3.6",
        ] {
            let oid: Oid = o.parse().unwrap();
            let k = ReportKind::from_oid(&oid);
            assert_eq!(k, ReportKind::Other(oid.clone()));
            assert_eq!(k.oid(), oid);
            assert_eq!(k.to_string(), format!("report {o}"));
        }
    }
}
