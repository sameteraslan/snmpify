//! Error types.

use std::fmt;

/// Why a message could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The input ended inside an element.
    UnexpectedEnd,
    /// Indefinite lengths are not allowed in SNMP.
    IndefiniteLength,
    /// A length of more than 4 bytes.
    LengthTooLarge,
    /// A multi-byte tag (never used by SNMP).
    UnsupportedTag(u8),
    /// Another tag was expected here.
    UnexpectedTag {
        /// The tag that was expected.
        expected: u8,
        /// The tag that was found.
        found: u8,
    },
    /// An INTEGER without contents.
    EmptyInteger,
    /// An integer that does not fit its type.
    IntegerOverflow,
    /// A NULL with contents.
    InvalidNull,
    /// A malformed OBJECT IDENTIFIER.
    InvalidOid,
    /// An IpAddress that is not 4 bytes.
    InvalidIpAddress,
    /// An unknown value tag in a variable binding.
    UnknownValueTag(u8),
    /// An unknown PDU tag.
    UnknownPdu(u8),
    /// An SNMP version other than 1, 2c or 3.
    UnknownVersion(i32),
    /// Bytes after the end of the message or element.
    TrailingData,
    /// SNMPv3 `msgFlags` that are not one octet, or privacy without
    /// authentication.
    InvalidMsgFlags,
    /// An SNMPv3 security model other than USM (3).
    UnsupportedSecurityModel(i32),
}

impl fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeErrorKind::*;
        match self {
            UnexpectedEnd => f.write_str("unexpected end of data"),
            IndefiniteLength => f.write_str("indefinite length"),
            LengthTooLarge => f.write_str("length too large"),
            UnsupportedTag(t) => write!(f, "unsupported tag 0x{t:02X}"),
            UnexpectedTag { expected, found } => {
                write!(f, "expected tag 0x{expected:02X}, found 0x{found:02X}")
            }
            EmptyInteger => f.write_str("empty integer"),
            IntegerOverflow => f.write_str("integer out of range"),
            InvalidNull => f.write_str("NULL with contents"),
            InvalidOid => f.write_str("invalid object identifier"),
            InvalidIpAddress => f.write_str("IpAddress is not 4 bytes"),
            UnknownValueTag(t) => write!(f, "unknown value tag 0x{t:02X}"),
            UnknownPdu(t) => write!(f, "unknown PDU tag 0x{t:02X}"),
            UnknownVersion(v) => write!(f, "unknown SNMP version {v}"),
            TrailingData => f.write_str("trailing data"),
            InvalidMsgFlags => f.write_str("invalid msgFlags"),
            UnsupportedSecurityModel(m) => write!(f, "unsupported security model {m}"),
        }
    }
}

/// A decoding error and the byte offset where it happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError {
    /// What went wrong.
    pub kind: DecodeErrorKind,
    /// Offset in the decoded buffer.
    pub offset: usize,
}

impl DecodeError {
    pub(crate) fn new(kind: DecodeErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.offset)
    }
}

impl std::error::Error for DecodeError {}

/// An OID string that could not be parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseOidError(pub(crate) String);

impl fmt::Display for ParseOidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid OID {:?}", self.0)
    }
}

impl std::error::Error for ParseOidError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_its_own_message() {
        use DecodeErrorKind::*;
        let kinds = [
            UnexpectedEnd,
            IndefiniteLength,
            LengthTooLarge,
            UnsupportedTag(0x1F),
            UnexpectedTag {
                expected: 0x30,
                found: 0x02,
            },
            EmptyInteger,
            IntegerOverflow,
            InvalidNull,
            InvalidOid,
            InvalidIpAddress,
            UnknownValueTag(0x99),
            UnknownPdu(0xAF),
            UnknownVersion(7),
            TrailingData,
            InvalidMsgFlags,
            UnsupportedSecurityModel(4),
        ];
        let mut seen = std::collections::HashSet::new();
        for k in kinds {
            let s = DecodeError::new(k, 12).to_string();
            assert!(s.ends_with(" at byte 12"), "{s}");
            assert!(seen.insert(s), "{k:?}");
        }
        assert!(seen
            .iter()
            .any(|s| s.contains("0x30") && s.contains("0x02")));
        assert!(seen.iter().any(|s| s.contains("security model 4")));
        let e = ParseOidError("1.x".into());
        assert_eq!(e.to_string(), "invalid OID \"1.x\"");
    }
}
