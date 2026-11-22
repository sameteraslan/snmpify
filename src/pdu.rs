//! PDUs (RFC 3416, RFC 1157) and community-based messages (SNMPv1, v2c).

use std::fmt;
use std::net::Ipv4Addr;

use crate::ber::{decode_unsigned, tag, Reader, Writer};
use crate::error::{DecodeError, DecodeErrorKind};
use crate::oid::Oid;
use crate::value::VarBind;

/// SNMP version, as encoded in a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// SNMPv1 (encoded as 0).
    V1,
    /// SNMPv2c (encoded as 1).
    V2c,
    /// SNMPv3 (encoded as 3).
    V3,
}

impl Version {
    /// The value in the message's version field.
    pub fn code(self) -> i32 {
        match self {
            Version::V1 => 0,
            Version::V2c => 1,
            Version::V3 => 3,
        }
    }

    /// The version for a message's version field.
    pub fn from_code(c: i32) -> Option<Version> {
        Some(match c {
            0 => Version::V1,
            1 => Version::V2c,
            3 => Version::V3,
            _ => return None,
        })
    }
}

/// The kind of a (non-v1-trap) PDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PduType {
    /// GetRequest-PDU.
    Get,
    /// GetNextRequest-PDU.
    GetNext,
    /// Response-PDU (GetResponse in v1).
    Response,
    /// SetRequest-PDU.
    Set,
    /// GetBulkRequest-PDU (v2c/v3).
    GetBulk,
    /// InformRequest-PDU (v2c/v3).
    Inform,
    /// SNMPv2-Trap-PDU (v2c/v3).
    TrapV2,
    /// Report-PDU (v3).
    Report,
}

impl PduType {
    /// The PDU's BER tag.
    pub fn tag(self) -> u8 {
        match self {
            PduType::Get => tag::GET_REQUEST,
            PduType::GetNext => tag::GET_NEXT_REQUEST,
            PduType::Response => tag::RESPONSE,
            PduType::Set => tag::SET_REQUEST,
            PduType::GetBulk => tag::GET_BULK_REQUEST,
            PduType::Inform => tag::INFORM_REQUEST,
            PduType::TrapV2 => tag::TRAP_V2,
            PduType::Report => tag::REPORT,
        }
    }

    pub(crate) fn from_tag(t: u8) -> Option<PduType> {
        Some(match t {
            tag::GET_REQUEST => PduType::Get,
            tag::GET_NEXT_REQUEST => PduType::GetNext,
            tag::RESPONSE => PduType::Response,
            tag::SET_REQUEST => PduType::Set,
            tag::GET_BULK_REQUEST => PduType::GetBulk,
            tag::INFORM_REQUEST => PduType::Inform,
            tag::TRAP_V2 => PduType::TrapV2,
            tag::REPORT => PduType::Report,
            _ => return None,
        })
    }
}

/// The error-status of a response (RFC 3416 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum ErrorStatus {
    NoError,
    TooBig,
    NoSuchName,
    BadValue,
    ReadOnly,
    GenErr,
    NoAccess,
    WrongType,
    WrongLength,
    WrongEncoding,
    WrongValue,
    NoCreation,
    InconsistentValue,
    ResourceUnavailable,
    CommitFailed,
    UndoFailed,
    AuthorizationError,
    NotWritable,
    InconsistentName,
    /// A code outside RFC 3416.
    Other(i32),
}

impl ErrorStatus {
    const NAMES: [ErrorStatus; 19] = [
        ErrorStatus::NoError,
        ErrorStatus::TooBig,
        ErrorStatus::NoSuchName,
        ErrorStatus::BadValue,
        ErrorStatus::ReadOnly,
        ErrorStatus::GenErr,
        ErrorStatus::NoAccess,
        ErrorStatus::WrongType,
        ErrorStatus::WrongLength,
        ErrorStatus::WrongEncoding,
        ErrorStatus::WrongValue,
        ErrorStatus::NoCreation,
        ErrorStatus::InconsistentValue,
        ErrorStatus::ResourceUnavailable,
        ErrorStatus::CommitFailed,
        ErrorStatus::UndoFailed,
        ErrorStatus::AuthorizationError,
        ErrorStatus::NotWritable,
        ErrorStatus::InconsistentName,
    ];

    /// The status for a code.
    pub fn from_code(c: i32) -> ErrorStatus {
        usize::try_from(c)
            .ok()
            .and_then(|i| Self::NAMES.get(i).copied())
            .unwrap_or(ErrorStatus::Other(c))
    }

    /// The code on the wire.
    pub fn code(self) -> i32 {
        match self {
            ErrorStatus::Other(c) => c,
            s => Self::NAMES.iter().position(|&n| n == s).unwrap() as i32,
        }
    }
}

impl fmt::Display for ErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorStatus::Other(c) => write!(f, "error-status {c}"),
            s => {
                // noError, tooBig, … as in the RFC.
                let d = format!("{s:?}");
                let mut c = d.chars();
                let first = c.next().unwrap().to_ascii_lowercase();
                write!(f, "{first}{}", c.as_str())
            }
        }
    }
}

/// A request, response, inform, v2 trap or report PDU.
///
/// For GetBulk, `error_status` and `error_index` carry non-repeaters and
/// max-repetitions; use [`Pdu::get_bulk`], [`Pdu::non_repeaters`] and
/// [`Pdu::max_repetitions`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    /// The PDU kind.
    pub pdu_type: PduType,
    /// Matches a response to its request.
    pub request_id: i32,
    /// Error status (non-repeaters for GetBulk).
    pub error_status: i32,
    /// Index (1-based) of the failing binding (max-repetitions for GetBulk).
    pub error_index: i32,
    /// The variable bindings.
    pub varbinds: Vec<VarBind>,
}

impl Pdu {
    fn request<I: Into<Oid>>(
        pdu_type: PduType,
        request_id: i32,
        oids: impl IntoIterator<Item = I>,
    ) -> Pdu {
        Pdu {
            pdu_type,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds: oids.into_iter().map(VarBind::null).collect(),
        }
    }

    /// A GetRequest for `oids`.
    pub fn get<I: Into<Oid>>(request_id: i32, oids: impl IntoIterator<Item = I>) -> Pdu {
        Self::request(PduType::Get, request_id, oids)
    }

    /// A GetNextRequest for `oids`.
    pub fn get_next<I: Into<Oid>>(request_id: i32, oids: impl IntoIterator<Item = I>) -> Pdu {
        Self::request(PduType::GetNext, request_id, oids)
    }

    /// A GetBulkRequest: the first `non_repeaters` OIDs get one successor,
    /// the others up to `max_repetitions` each.
    pub fn get_bulk<I: Into<Oid>>(
        request_id: i32,
        non_repeaters: i32,
        max_repetitions: i32,
        oids: impl IntoIterator<Item = I>,
    ) -> Pdu {
        let mut p = Self::request(PduType::GetBulk, request_id, oids);
        p.error_status = non_repeaters;
        p.error_index = max_repetitions;
        p
    }

    /// A SetRequest.
    pub fn set(request_id: i32, varbinds: Vec<VarBind>) -> Pdu {
        Pdu {
            pdu_type: PduType::Set,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds,
        }
    }

    /// The error status of a response.
    pub fn status(&self) -> ErrorStatus {
        ErrorStatus::from_code(self.error_status)
    }

    /// Non-repeaters of a GetBulk.
    pub fn non_repeaters(&self) -> i32 {
        self.error_status
    }

    /// Max-repetitions of a GetBulk.
    pub fn max_repetitions(&self) -> i32 {
        self.error_index
    }

    pub(crate) fn encode(&self, w: &mut Writer) {
        let m = w.mark();
        let l = w.mark();
        for vb in self.varbinds.iter().rev() {
            vb.encode(w);
        }
        w.wrap(l, tag::SEQUENCE);
        w.integer(self.error_index as i64);
        w.integer(self.error_status as i64);
        w.integer(self.request_id as i64);
        w.wrap(m, self.pdu_type.tag());
    }

    fn decode_body(pdu_type: PduType, mut r: Reader<'_>) -> Result<Pdu, DecodeError> {
        let request_id = r.read_i32()?;
        let error_status = r.read_i32()?;
        let error_index = r.read_i32()?;
        let varbinds = decode_varbinds(&mut r)?;
        r.finish()?;
        Ok(Pdu {
            pdu_type,
            request_id,
            error_status,
            error_index,
            varbinds,
        })
    }
}

fn decode_varbinds(r: &mut Reader<'_>) -> Result<Vec<VarBind>, DecodeError> {
    let mut list = r.read_sequence()?;
    // Count first (headers only) so the vector is allocated once.
    let mut probe = list;
    let mut count = 0;
    while !probe.is_empty() {
        probe.read_any()?;
        count += 1;
    }
    let mut v = Vec::with_capacity(count);
    while !list.is_empty() {
        v.push(VarBind::decode(&mut list)?);
    }
    Ok(v)
}

/// An SNMPv1 Trap-PDU (RFC 1157).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrapV1Pdu {
    /// sysObjectID of the sender.
    pub enterprise: Oid,
    /// Address of the sender.
    pub agent_addr: Ipv4Addr,
    /// coldStart(0) … enterpriseSpecific(6).
    pub generic_trap: i32,
    /// Enterprise-specific code.
    pub specific_trap: i32,
    /// sysUpTime of the sender, in hundredths of a second.
    pub timestamp: u32,
    /// The variable bindings.
    pub varbinds: Vec<VarBind>,
}

impl TrapV1Pdu {
    fn encode(&self, w: &mut Writer) {
        let m = w.mark();
        let l = w.mark();
        for vb in self.varbinds.iter().rev() {
            vb.encode(w);
        }
        w.wrap(l, tag::SEQUENCE);
        w.unsigned(tag::TIMETICKS, self.timestamp as u64);
        w.integer(self.specific_trap as i64);
        w.integer(self.generic_trap as i64);
        w.bytes(tag::IP_ADDRESS, &self.agent_addr.octets());
        w.oid(&self.enterprise);
        w.wrap(m, tag::TRAP_V1);
    }

    fn decode_body(mut r: Reader<'_>) -> Result<TrapV1Pdu, DecodeError> {
        let at = r.position();
        let enterprise = Oid::from_ber(r.read_tagged(tag::OBJECT_IDENTIFIER)?.rest())
            .map_err(|k| DecodeError::new(k, at))?;
        let at = r.position();
        let addr: [u8; 4] = r
            .read_tagged(tag::IP_ADDRESS)?
            .rest()
            .try_into()
            .map_err(|_| DecodeError::new(DecodeErrorKind::InvalidIpAddress, at))?;
        let generic_trap = r.read_i32()?;
        let specific_trap = r.read_i32()?;
        let at = r.position();
        let timestamp = decode_unsigned(r.read_tagged(tag::TIMETICKS)?.rest(), 32)
            .map_err(|k| DecodeError::new(k, at))? as u32;
        let varbinds = decode_varbinds(&mut r)?;
        r.finish()?;
        Ok(TrapV1Pdu {
            enterprise,
            agent_addr: Ipv4Addr::from(addr),
            generic_trap,
            specific_trap,
            timestamp,
            varbinds,
        })
    }
}

/// Any PDU: the standard format or a v1 trap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyPdu {
    /// Get, GetNext, Response, Set, GetBulk, Inform, TrapV2, Report.
    Pdu(Pdu),
    /// An SNMPv1 trap.
    TrapV1(TrapV1Pdu),
}

impl AnyPdu {
    pub(crate) fn encode(&self, w: &mut Writer) {
        match self {
            AnyPdu::Pdu(p) => p.encode(w),
            AnyPdu::TrapV1(t) => t.encode(w),
        }
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<AnyPdu, DecodeError> {
        let at = r.position();
        let (t, body) = r.read_any()?;
        if t == tag::TRAP_V1 {
            return Ok(AnyPdu::TrapV1(TrapV1Pdu::decode_body(body)?));
        }
        let ty = PduType::from_tag(t)
            .ok_or_else(|| DecodeError::new(DecodeErrorKind::UnknownPdu(t), at))?;
        Ok(AnyPdu::Pdu(Pdu::decode_body(ty, body)?))
    }
}

impl From<Pdu> for AnyPdu {
    fn from(p: Pdu) -> Self {
        AnyPdu::Pdu(p)
    }
}

impl From<TrapV1Pdu> for AnyPdu {
    fn from(p: TrapV1Pdu) -> Self {
        AnyPdu::TrapV1(p)
    }
}

/// An SNMPv1 or v2c message: version, community and PDU.
///
/// ```
/// use snmpify::{CommunityMessage, Pdu, Version};
///
/// let req = CommunityMessage::new(Version::V2c, "public", Pdu::get(1, [[1, 3, 6, 1, 2, 1, 1, 1, 0]]));
/// let bytes = req.encode();
/// assert_eq!(CommunityMessage::decode(&bytes).unwrap(), req);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommunityMessage {
    /// [`Version::V1`] or [`Version::V2c`].
    pub version: Version,
    /// The community string.
    pub community: Vec<u8>,
    /// The PDU.
    pub pdu: AnyPdu,
}

impl CommunityMessage {
    /// A message.
    pub fn new(version: Version, community: impl AsRef<[u8]>, pdu: impl Into<AnyPdu>) -> Self {
        Self {
            version,
            community: community.as_ref().to_vec(),
            pdu: pdu.into(),
        }
    }

    /// The BER encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.community.len() + self.varbind_hint() * 24);
        self.encode_into(&mut w);
        w.finish()
    }

    fn varbind_hint(&self) -> usize {
        match &self.pdu {
            AnyPdu::Pdu(p) => p.varbinds.len(),
            AnyPdu::TrapV1(t) => t.varbinds.len(),
        }
    }

    pub(crate) fn encode_into(&self, w: &mut Writer) {
        let m = w.mark();
        self.pdu.encode(w);
        w.octets(&self.community);
        w.integer(self.version.code() as i64);
        w.wrap(m, tag::SEQUENCE);
    }

    /// Decodes a v1 or v2c message. SNMPv3 messages give
    /// [`DecodeErrorKind::UnknownVersion`]`(3)`.
    pub fn decode(bytes: &[u8]) -> Result<CommunityMessage, DecodeError> {
        let mut outer = Reader::new(bytes);
        let mut r = outer.read_sequence()?;
        outer.finish()?;
        let at = r.position();
        let code = r.read_i32()?;
        let version = match Version::from_code(code) {
            Some(v @ (Version::V1 | Version::V2c)) => v,
            _ => return Err(DecodeError::new(DecodeErrorKind::UnknownVersion(code), at)),
        };
        let community = r.read_octets()?.to_vec();
        let pdu = AnyPdu::decode(&mut r)?;
        r.finish()?;
        Ok(CommunityMessage {
            version,
            community,
            pdu,
        })
    }
}

/// Encodes a community message without copying the community.
pub(crate) fn encode_community(version: Version, community: &[u8], pdu: &Pdu) -> Vec<u8> {
    let mut w = Writer::with_capacity(48 + community.len() + pdu.varbinds.len() * 24);
    let m = w.mark();
    pdu.encode(&mut w);
    w.octets(community);
    w.integer(version.code() as i64);
    w.wrap(m, tag::SEQUENCE);
    w.finish()
}

/// The version of an encoded message, without decoding the rest.
pub fn peek_version(bytes: &[u8]) -> Result<Version, DecodeError> {
    let mut r = Reader::new(bytes).read_sequence()?;
    let at = r.position();
    let code = r.read_i32()?;
    Version::from_code(code)
        .ok_or_else(|| DecodeError::new(DecodeErrorKind::UnknownVersion(code), at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;

    const SYS_DESCR: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 1, 0];

    #[test]
    fn get_request_bytes() {
        // snmpget -v2c -c public host 1.3.6.1.2.1.1.1.0 with request-id 0x1234
        let msg = CommunityMessage::new(Version::V2c, "public", Pdu::get(0x1234, [SYS_DESCR]));
        let expected = [
            0x30, 0x27, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xA0,
            0x1A, 0x02, 0x02, 0x12, 0x34, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30,
            0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ];
        assert_eq!(msg.encode(), expected);
        assert_eq!(CommunityMessage::decode(&expected).unwrap(), msg);
        assert_eq!(peek_version(&expected).unwrap(), Version::V2c);
    }

    #[test]
    fn response_round_trip() {
        let pdu = Pdu {
            pdu_type: PduType::Response,
            request_id: -7,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(SYS_DESCR, "Linux snmpd"),
                VarBind::new([1, 3, 6, 1, 2, 1, 1, 3, 0], Value::TimeTicks(4242)),
                VarBind::new([1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1], Value::Counter32(99)),
                VarBind::new(
                    [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1],
                    Value::Counter64(1 << 40),
                ),
                VarBind::new([1, 3, 6, 1, 9, 9], Value::EndOfMibView),
            ],
        };
        let msg = CommunityMessage::new(Version::V1, b"s3cr\xE9t", pdu);
        assert_eq!(CommunityMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn bulk_and_trap_v1() {
        let bulk = Pdu::get_bulk(
            5,
            1,
            25,
            [[1, 3, 6, 1, 2, 1, 1, 3], [1, 3, 6, 1, 2, 1, 2, 2]],
        );
        assert_eq!((bulk.non_repeaters(), bulk.max_repetitions()), (1, 25));
        let m = CommunityMessage::new(Version::V2c, "public", bulk);
        assert_eq!(CommunityMessage::decode(&m.encode()).unwrap(), m);

        let trap = TrapV1Pdu {
            enterprise: "1.3.6.1.4.1.8072.3.2.10".parse().unwrap(),
            agent_addr: Ipv4Addr::new(10, 0, 0, 1),
            generic_trap: 6,
            specific_trap: 17,
            timestamp: 12345,
            varbinds: vec![VarBind::new([1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1], 42)],
        };
        let m = CommunityMessage::new(Version::V1, "public", trap);
        assert_eq!(CommunityMessage::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn error_status_names() {
        assert_eq!(ErrorStatus::from_code(2), ErrorStatus::NoSuchName);
        assert_eq!(ErrorStatus::NotWritable.code(), 17);
        assert_eq!(ErrorStatus::from_code(99), ErrorStatus::Other(99));
        assert_eq!(ErrorStatus::NoSuchName.to_string(), "noSuchName");
        assert_eq!(ErrorStatus::Other(-1).to_string(), "error-status -1");
    }

    #[test]
    fn rejects_bad_messages() {
        let good = CommunityMessage::new(Version::V2c, "public", Pdu::get(1, [SYS_DESCR])).encode();
        // Every truncation fails cleanly.
        for n in 0..good.len() {
            assert!(CommunityMessage::decode(&good[..n]).is_err(), "{n}");
        }
        let mut extra = good.clone();
        extra.push(0);
        assert_eq!(
            CommunityMessage::decode(&extra).unwrap_err().kind,
            DecodeErrorKind::TrailingData
        );
        let mut v3 = good.clone();
        v3[4] = 3;
        assert_eq!(
            CommunityMessage::decode(&v3).unwrap_err().kind,
            DecodeErrorKind::UnknownVersion(3)
        );
        let mut bad_pdu = good;
        bad_pdu[13] = 0xAF;
        assert_eq!(
            CommunityMessage::decode(&bad_pdu).unwrap_err().kind,
            DecodeErrorKind::UnknownPdu(0xAF)
        );
    }

    #[test]
    fn trap_v2_inform_and_other_status() {
        for t in [PduType::TrapV2, PduType::Inform, PduType::Report] {
            let p = Pdu {
                pdu_type: t,
                ..Pdu::get(9, [SYS_DESCR])
            };
            let m = CommunityMessage::new(Version::V2c, "c", p);
            assert_eq!(CommunityMessage::decode(&m.encode()).unwrap(), m);
        }
        assert_eq!(ErrorStatus::from_code(99), ErrorStatus::Other(99));
        assert_eq!(ErrorStatus::Other(99).code(), 99);
        assert_eq!(ErrorStatus::Other(99).to_string(), "error-status 99");
    }

    #[test]
    fn rejects_bad_v1_traps() {
        // enterprise, agent-addr, generic, specific, timestamp, varbinds
        let trap = |oid: &[u8], addr: &[u8], ticks: &[u8]| {
            let mut w = Writer::new();
            let m = w.mark();
            let t = w.mark();
            let l = w.mark();
            w.wrap(l, tag::SEQUENCE);
            w.bytes(tag::TIMETICKS, ticks);
            w.integer(0);
            w.integer(1);
            w.bytes(tag::IP_ADDRESS, addr);
            w.bytes(tag::OBJECT_IDENTIFIER, oid);
            w.wrap(t, tag::TRAP_V1);
            w.octets(b"public");
            w.integer(0);
            w.wrap(m, tag::SEQUENCE);
            w.finish()
        };
        let kind = |b: Vec<u8>| CommunityMessage::decode(&b).unwrap_err().kind;
        let good = trap(&[0x2B, 6, 1], &[10, 0, 0, 1], &[5]);
        assert!(CommunityMessage::decode(&good).is_ok());
        assert_eq!(
            kind(trap(&[0x2B, 0x80, 1], &[10, 0, 0, 1], &[5])),
            DecodeErrorKind::InvalidOid
        );
        assert_eq!(
            kind(trap(&[0x2B, 6, 1], &[10, 0, 1], &[5])),
            DecodeErrorKind::InvalidIpAddress
        );
        assert_eq!(
            kind(trap(&[0x2B, 6, 1], &[10, 0, 0, 1], &[1, 0, 0, 0, 0, 0])),
            DecodeErrorKind::IntegerOverflow
        );
    }
}
