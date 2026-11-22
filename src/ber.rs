//! BER (Basic Encoding Rules) as used by SNMP: definite lengths only,
//! single-byte tags (every SNMP tag fits in one byte).
//!
//! [`Reader`] decodes without copying: it hands out sub-slices of the input.
//! [`Writer`] encodes back to front, so a constructed value's length is known
//! when its header is written and nested values are never moved or copied.

use crate::error::{DecodeError, DecodeErrorKind};

/// Universal and SNMP application tags.
#[allow(missing_docs)] // the names are the ASN.1 / RFC 2578 type names
pub mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;
    // Application (RFC 2578)
    pub const IP_ADDRESS: u8 = 0x40;
    pub const COUNTER32: u8 = 0x41;
    pub const GAUGE32: u8 = 0x42;
    pub const TIMETICKS: u8 = 0x43;
    pub const OPAQUE: u8 = 0x44;
    pub const NSAP_ADDRESS: u8 = 0x45;
    pub const COUNTER64: u8 = 0x46;
    pub const UINTEGER32: u8 = 0x47;
    // Context-specific primitive: exceptions in a v2 response (RFC 3416)
    pub const NO_SUCH_OBJECT: u8 = 0x80;
    pub const NO_SUCH_INSTANCE: u8 = 0x81;
    pub const END_OF_MIB_VIEW: u8 = 0x82;
    // Context-specific constructed: PDUs
    pub const GET_REQUEST: u8 = 0xA0;
    pub const GET_NEXT_REQUEST: u8 = 0xA1;
    pub const RESPONSE: u8 = 0xA2;
    pub const SET_REQUEST: u8 = 0xA3;
    pub const TRAP_V1: u8 = 0xA4;
    pub const GET_BULK_REQUEST: u8 = 0xA5;
    pub const INFORM_REQUEST: u8 = 0xA6;
    pub const TRAP_V2: u8 = 0xA7;
    pub const REPORT: u8 = 0xA8;
}

/// Zero-copy BER decoder over a byte slice.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Offset of `buf` in the original message, for error positions.
    base: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            base: 0,
        }
    }

    /// Whether every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Absolute offset of the next byte.
    pub fn position(&self) -> usize {
        self.base + self.pos
    }

    fn err(&self, kind: DecodeErrorKind) -> DecodeError {
        DecodeError::new(kind, self.position())
    }

    /// The tag of the next element, without consuming it.
    pub fn peek_tag(&self) -> Result<u8, DecodeError> {
        self.buf
            .get(self.pos)
            .copied()
            .ok_or_else(|| self.err(DecodeErrorKind::UnexpectedEnd))
    }

    /// Reads one TLV and returns its tag and contents.
    pub fn read_any(&mut self) -> Result<(u8, Reader<'a>), DecodeError> {
        let start = self.pos;
        let tag = self.peek_tag()?;
        if tag & 0x1F == 0x1F {
            return Err(self.err(DecodeErrorKind::UnsupportedTag(tag)));
        }
        let mut p = self.pos + 1;
        let first = *self
            .buf
            .get(p)
            .ok_or_else(|| DecodeError::new(DecodeErrorKind::UnexpectedEnd, self.base + p))?;
        p += 1;
        let len = if first < 0x80 {
            first as usize
        } else if first == 0x80 {
            return Err(DecodeError::new(
                DecodeErrorKind::IndefiniteLength,
                self.base + p - 1,
            ));
        } else {
            let n = (first & 0x7F) as usize;
            if n > 4 {
                return Err(DecodeError::new(
                    DecodeErrorKind::LengthTooLarge,
                    self.base + p - 1,
                ));
            }
            let bytes = self
                .buf
                .get(p..p + n)
                .ok_or_else(|| DecodeError::new(DecodeErrorKind::UnexpectedEnd, self.base + p))?;
            p += n;
            bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
        };
        let end = p
            .checked_add(len)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| DecodeError::new(DecodeErrorKind::UnexpectedEnd, self.base + start))?;
        let inner = Reader {
            buf: &self.buf[p..end],
            pos: 0,
            base: self.base + p,
        };
        self.pos = end;
        Ok((tag, inner))
    }

    /// Reads one TLV that must have the tag `expected`.
    pub fn read_tagged(&mut self, expected: u8) -> Result<Reader<'a>, DecodeError> {
        let at = self.position();
        let (t, inner) = self.read_any()?;
        if t != expected {
            return Err(DecodeError::new(
                DecodeErrorKind::UnexpectedTag { expected, found: t },
                at,
            ));
        }
        Ok(inner)
    }

    /// The remaining bytes.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }

    /// Reads a SEQUENCE and returns a reader over its contents.
    pub fn read_sequence(&mut self) -> Result<Reader<'a>, DecodeError> {
        self.read_tagged(tag::SEQUENCE)
    }

    /// Reads an INTEGER that fits in an `i32` (SNMP's Integer32).
    pub fn read_i32(&mut self) -> Result<i32, DecodeError> {
        let at = self.position();
        let r = self.read_tagged(tag::INTEGER)?;
        let v = decode_signed(r.rest()).map_err(|k| DecodeError::new(k, at))?;
        i32::try_from(v).map_err(|_| DecodeError::new(DecodeErrorKind::IntegerOverflow, at))
    }

    /// Reads an OCTET STRING.
    pub fn read_octets(&mut self) -> Result<&'a [u8], DecodeError> {
        Ok(self.read_tagged(tag::OCTET_STRING)?.rest())
    }

    /// Reads a NULL.
    pub fn read_null(&mut self) -> Result<(), DecodeError> {
        let at = self.position();
        let r = self.read_tagged(tag::NULL)?;
        if !r.rest().is_empty() {
            return Err(DecodeError::new(DecodeErrorKind::InvalidNull, at));
        }
        Ok(())
    }

    /// Fails unless every byte was consumed.
    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(self.err(DecodeErrorKind::TrailingData))
        }
    }
}

/// Decodes a two's-complement big-endian integer of 1–8 content bytes
/// (9 when the first is a 0x00 sign pad).
pub fn decode_signed(bytes: &[u8]) -> Result<i64, DecodeErrorKind> {
    if bytes.is_empty() {
        return Err(DecodeErrorKind::EmptyInteger);
    }
    if bytes.len() > 8 {
        return Err(DecodeErrorKind::IntegerOverflow);
    }
    let mut v: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        v = (v << 8) | b as i64;
    }
    Ok(v)
}

/// Decodes an unsigned integer (Counter32/Gauge32/TimeTicks/Counter64).
/// Accepts a leading 0x00 pad and, like net-snmp, a value encoded as a
/// negative number by a sloppy agent (taken modulo 2^bits).
pub fn decode_unsigned(bytes: &[u8], bits: u32) -> Result<u64, DecodeErrorKind> {
    if bytes.is_empty() {
        return Err(DecodeErrorKind::EmptyInteger);
    }
    let digits = if bytes.len() > 1 && bytes[0] == 0 {
        &bytes[1..]
    } else {
        bytes
    };
    if digits.len() > (bits / 8) as usize {
        return Err(DecodeErrorKind::IntegerOverflow);
    }
    // Without a 0x00 pad, a set top bit means the agent sent a negative
    // number: sign-extend, then keep `bits` bits.
    let mut v: u64 = if digits[0] & 0x80 != 0 && digits.len() == bytes.len() {
        u64::MAX
    } else {
        0
    };
    for &b in digits {
        v = (v << 8) | b as u64;
    }
    if bits < 64 {
        v &= (1u64 << bits) - 1;
    }
    Ok(v)
}

/// Back-to-front BER encoder.
///
/// Elements are written **in reverse order**: write the last element of a
/// sequence first. [`finish`](Self::finish) returns the encoding in normal
/// order. Constructed values: remember [`mark`](Self::mark), write the
/// contents (reversed), then call [`wrap`](Self::wrap) with the tag.
#[derive(Default, Debug)]
pub struct Writer {
    /// Bytes in reverse order.
    rev: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty writer with room for `n` bytes.
    pub fn with_capacity(n: usize) -> Self {
        Self {
            rev: Vec::with_capacity(n),
        }
    }

    /// Current length; pass it to [`wrap`](Self::wrap).
    pub fn mark(&self) -> usize {
        self.rev.len()
    }

    fn push_len(&mut self, len: usize) {
        if len < 0x80 {
            self.rev.push(len as u8);
        } else {
            let mut n = 0u8;
            let mut l = len;
            while l > 0 {
                self.rev.push(l as u8);
                l >>= 8;
                n += 1;
            }
            self.rev.push(0x80 | n);
        }
    }

    /// Writes the header of a value whose contents were written since `mark`.
    pub fn wrap(&mut self, mark: usize, tag: u8) {
        let len = self.rev.len() - mark;
        self.push_len(len);
        self.rev.push(tag);
    }

    /// Writes raw contents bytes (in normal order) with a tag.
    pub fn bytes(&mut self, tag: u8, data: &[u8]) {
        self.rev.extend(data.iter().rev());
        self.push_len(data.len());
        self.rev.push(tag);
    }

    /// Writes a signed integer with the given tag (minimal encoding).
    pub fn signed(&mut self, tag: u8, v: i64) {
        let m = self.mark();
        let mut v = v;
        loop {
            let b = v as u8;
            self.rev.push(b);
            v >>= 8;
            // Stop when the remaining value is pure sign extension of `b`.
            if (v == 0 && b & 0x80 == 0) || (v == -1 && b & 0x80 != 0) {
                break;
            }
        }
        self.wrap(m, tag);
    }

    /// Writes an unsigned integer with the given tag (minimal encoding,
    /// 0x00 pad when the top bit is set).
    pub fn unsigned(&mut self, tag: u8, v: u64) {
        let m = self.mark();
        let mut v = v;
        loop {
            let b = v as u8;
            self.rev.push(b);
            v >>= 8;
            if v == 0 {
                if b & 0x80 != 0 {
                    self.rev.push(0);
                }
                break;
            }
        }
        self.wrap(m, tag);
    }

    /// Writes an INTEGER.
    pub fn integer(&mut self, v: i64) {
        self.signed(tag::INTEGER, v);
    }

    /// Writes an OCTET STRING.
    pub fn octets(&mut self, data: &[u8]) {
        self.bytes(tag::OCTET_STRING, data);
    }

    /// Writes a NULL (or another empty primitive, e.g. noSuchObject).
    pub fn empty(&mut self, tag: u8) {
        self.rev.push(0);
        self.rev.push(tag);
    }

    /// Writes OID sub-identifiers as contents with the given tag.
    pub fn oid(&mut self, arcs: &[u32]) {
        let m = self.mark();
        if arcs.len() >= 2 {
            for &a in arcs[2..].iter().rev() {
                self.base128(a as u64);
            }
            self.base128(arcs[0] as u64 * 40 + arcs[1] as u64);
        } else if let Some(&a) = arcs.first() {
            self.base128(a as u64 * 40);
        }
        self.wrap(m, tag::OBJECT_IDENTIFIER);
    }

    fn base128(&mut self, mut v: u64) {
        self.rev.push((v & 0x7F) as u8);
        v >>= 7;
        while v > 0 {
            self.rev.push(0x80 | (v & 0x7F) as u8);
            v >>= 7;
        }
    }

    /// The encoding, in normal order.
    pub fn finish(mut self) -> Vec<u8> {
        self.rev.reverse();
        self.rev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        f(&mut w);
        w.finish()
    }

    #[test]
    fn integers_are_minimal() {
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x02, 0x01, 0x00]),
            (127, &[0x02, 0x01, 0x7F]),
            (128, &[0x02, 0x02, 0x00, 0x80]),
            (256, &[0x02, 0x02, 0x01, 0x00]),
            (-1, &[0x02, 0x01, 0xFF]),
            (-128, &[0x02, 0x01, 0x80]),
            (-129, &[0x02, 0x02, 0xFF, 0x7F]),
            (i32::MAX as i64, &[0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF]),
            (i32::MIN as i64, &[0x02, 0x04, 0x80, 0x00, 0x00, 0x00]),
        ];
        for &(v, bytes) in cases {
            assert_eq!(enc(|w| w.integer(v)), bytes, "{v}");
            let mut r = Reader::new(bytes);
            assert_eq!(r.read_i32().unwrap() as i64, v);
        }
    }

    #[test]
    fn unsigned_round_trip() {
        for v in [0u64, 1, 127, 128, 255, 256, 0xFFFF_FFFF, u64::MAX] {
            let b = enc(|w| w.unsigned(tag::COUNTER64, v));
            let mut r = Reader::new(&b);
            let (t, inner) = r.read_any().unwrap();
            assert_eq!(t, tag::COUNTER64);
            assert_eq!(decode_unsigned(inner.rest(), 64).unwrap(), v);
        }
        assert_eq!(
            enc(|w| w.unsigned(tag::COUNTER32, 0xFFFF_FFFF)),
            [0x41, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        // An agent that encodes 4294967295 as -1 still decodes as u32::MAX.
        assert_eq!(decode_unsigned(&[0xFF], 32).unwrap(), 0xFFFF_FFFF);
        assert!(decode_unsigned(&[1, 0, 0, 0, 0], 32).is_err());
    }

    #[test]
    fn long_lengths() {
        let data = vec![0xAB; 300];
        let b = enc(|w| w.octets(&data));
        assert_eq!(&b[..4], &[0x04, 0x82, 0x01, 0x2C]);
        let mut r = Reader::new(&b);
        assert_eq!(r.read_octets().unwrap(), &data[..]);
        assert!(r.is_empty());
    }

    #[test]
    fn nested_sequence() {
        let b = enc(|w| {
            let m = w.mark();
            w.octets(b"public"); // written last-first
            w.integer(1);
            w.wrap(m, tag::SEQUENCE);
        });
        assert_eq!(
            b,
            [0x30, 0x0B, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c']
        );
    }

    #[test]
    fn rejects_malformed() {
        use DecodeErrorKind::*;
        let kind = |b: &[u8]| Reader::new(b).read_any().unwrap_err().kind;
        assert_eq!(kind(&[]), UnexpectedEnd);
        assert_eq!(kind(&[0x04]), UnexpectedEnd);
        assert_eq!(kind(&[0x04, 0x05, 1, 2]), UnexpectedEnd);
        assert_eq!(kind(&[0x30, 0x80, 0, 0]), IndefiniteLength);
        assert_eq!(kind(&[0x04, 0x85, 1, 1, 1, 1, 1]), LengthTooLarge);
        assert_eq!(kind(&[0x1F, 0x01, 0x00]), UnsupportedTag(0x1F));
        assert_eq!(
            Reader::new(&[0x02, 0x00]).read_i32().unwrap_err().kind,
            EmptyInteger
        );
        assert_eq!(
            Reader::new(&[0x02, 0x05, 1, 0, 0, 0, 0])
                .read_i32()
                .unwrap_err()
                .kind,
            IntegerOverflow
        );
        // A huge declared length does not overflow.
        assert_eq!(kind(&[0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]), UnexpectedEnd);
    }

    #[test]
    fn null_and_short_oids() {
        let mut r = Reader::new(&[0x05, 0x00, 0x05, 0x01, 0x00]);
        assert!(r.read_null().is_ok());
        assert_eq!(
            r.read_null().unwrap_err().kind,
            DecodeErrorKind::InvalidNull
        );
        let mut r = Reader::new(&[0x02, 0x01, 0x00]);
        assert!(matches!(
            r.read_null().unwrap_err().kind,
            DecodeErrorKind::UnexpectedTag { .. }
        ));
        // One arc and none: encoded as the first sub-identifier alone.
        assert_eq!(enc(|w| w.oid(&[2])), [0x06, 0x01, 80]);
        assert_eq!(enc(|w| w.oid(&[])), [0x06, 0x00]);
    }
}
