//! Object identifiers.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str::FromStr;

use crate::error::{DecodeErrorKind, ParseOidError};

const INLINE: usize = 15;

/// An OBJECT IDENTIFIER such as `1.3.6.1.2.1.1.1.0`.
///
/// Up to 15 arcs are stored inline (no allocation), which covers nearly
/// every OID in practice. Derefs to `[u32]`; ordered lexicographically like
/// the MIB tree (the order of a walk).
///
/// ```
/// use snmpify::Oid;
/// let sys_descr: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
/// let system = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]);
/// assert!(sys_descr.starts_with(&system));
/// assert_eq!(sys_descr.to_string(), "1.3.6.1.2.1.1.1.0");
/// ```
#[derive(Clone)]
pub struct Oid(Repr);

#[derive(Clone)]
enum Repr {
    Inline { len: u8, arcs: [u32; INLINE] },
    Heap(Box<[u32]>),
}

impl Oid {
    /// An OID from its arcs. Does not validate them; see [`Oid::is_valid`].
    pub fn from_slice(arcs: &[u32]) -> Self {
        if arcs.len() <= INLINE {
            let mut a = [0; INLINE];
            a[..arcs.len()].copy_from_slice(arcs);
            Oid(Repr::Inline {
                len: arcs.len() as u8,
                arcs: a,
            })
        } else {
            Oid(Repr::Heap(arcs.into()))
        }
    }

    /// The arcs.
    pub fn as_slice(&self) -> &[u32] {
        match &self.0 {
            Repr::Inline { len, arcs } => &arcs[..*len as usize],
            Repr::Heap(b) => b,
        }
    }

    /// Whether the OID can be encoded: at least two arcs, the first 0–2 and
    /// the second below 40 when the first is 0 or 1.
    pub fn is_valid(&self) -> bool {
        let a = self.as_slice();
        a.len() >= 2 && a[0] <= 2 && (a[0] == 2 || a[1] < 40)
    }

    /// Whether `prefix` is a prefix of this OID (or equal to it).
    pub fn starts_with(&self, prefix: &[u32]) -> bool {
        self.as_slice().starts_with(prefix)
    }

    /// This OID with `arcs` appended, e.g. a table column plus an index.
    pub fn child(&self, arcs: &[u32]) -> Oid {
        let mut v = Vec::with_capacity(self.len() + arcs.len());
        v.extend_from_slice(self);
        v.extend_from_slice(arcs);
        Oid::from_slice(&v)
    }

    /// Decodes the contents of a BER OBJECT IDENTIFIER.
    pub fn from_ber(bytes: &[u8]) -> Result<Oid, DecodeErrorKind> {
        if bytes.is_empty() {
            return Err(DecodeErrorKind::InvalidOid);
        }
        /// One sub-identifier: one byte in the common case, else base 128.
        #[inline(always)]
        fn subid(bytes: &[u8], i: &mut usize) -> Result<u64, DecodeErrorKind> {
            let b = bytes[*i];
            *i += 1;
            if b < 0x80 {
                return Ok(b as u64);
            }
            if b == 0x80 {
                return Err(DecodeErrorKind::InvalidOid); // non-minimal
            }
            let mut v = (b & 0x7F) as u64;
            loop {
                let b = *bytes.get(*i).ok_or(DecodeErrorKind::InvalidOid)?; // unterminated
                *i += 1;
                v = (v << 7) | (b & 0x7F) as u64;
                if v > u32::MAX as u64 + 80 {
                    return Err(DecodeErrorKind::InvalidOid);
                }
                if b < 0x80 {
                    return Ok(v);
                }
            }
        }
        let mut arcs = [0u32; INLINE];
        let mut n = 0usize;
        let mut heap: Vec<u32> = Vec::new();
        let mut i = 0;
        let first = subid(bytes, &mut i)?;
        let (x, y) = match first {
            0..=39 => (0, first),
            40..=79 => (1, first - 40),
            _ => (2, first - 80),
        };
        arcs[0] = x;
        arcs[1] = u32::try_from(y).map_err(|_| DecodeErrorKind::InvalidOid)?;
        n += 2;
        while i < bytes.len() {
            let a =
                u32::try_from(subid(bytes, &mut i)?).map_err(|_| DecodeErrorKind::InvalidOid)?;
            if n < INLINE {
                arcs[n] = a;
            } else {
                if heap.is_empty() {
                    heap.extend_from_slice(&arcs);
                }
                heap.push(a);
            }
            n += 1;
        }
        Ok(if n <= INLINE {
            Oid(Repr::Inline { len: n as u8, arcs })
        } else {
            Oid(Repr::Heap(heap.into()))
        })
    }
}

impl Deref for Oid {
    type Target = [u32];
    fn deref(&self) -> &[u32] {
        self.as_slice()
    }
}

impl AsRef<[u32]> for Oid {
    fn as_ref(&self) -> &[u32] {
        self.as_slice()
    }
}

impl From<&[u32]> for Oid {
    fn from(a: &[u32]) -> Self {
        Oid::from_slice(a)
    }
}

impl<const N: usize> From<[u32; N]> for Oid {
    fn from(a: [u32; N]) -> Self {
        Oid::from_slice(&a)
    }
}

impl From<Vec<u32>> for Oid {
    fn from(a: Vec<u32>) -> Self {
        Oid::from_slice(&a)
    }
}

impl PartialEq for Oid {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for Oid {}

impl PartialOrd for Oid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Oid {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl Hash for Oid {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.as_slice().hash(h)
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, a) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{a}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({self})")
    }
}

impl FromStr for Oid {
    type Err = ParseOidError;
    /// Parses dotted decimal, with or without a leading dot.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.strip_prefix('.').unwrap_or(s);
        if t.is_empty() {
            return Err(ParseOidError(s.into()));
        }
        let arcs: Result<Vec<u32>, _> = t.split('.').map(str::parse::<u32>).collect();
        let oid = Oid::from(arcs.map_err(|_| ParseOidError(s.into()))?);
        if !oid.is_valid() {
            return Err(ParseOidError(s.into()));
        }
        Ok(oid)
    }
}

impl TryFrom<&str> for Oid {
    type Error = ParseOidError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::{Reader, Writer};

    fn ber(arcs: &[u32]) -> Vec<u8> {
        let mut w = Writer::new();
        w.oid(arcs);
        w.finish()
    }

    #[test]
    fn known_encodings() {
        assert_eq!(
            ber(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            [0x06, 0x08, 0x2B, 6, 1, 2, 1, 1, 1, 0]
        );
        // 2.999.3 (X.690 example) and large arcs.
        assert_eq!(ber(&[2, 999, 3]), [0x06, 0x03, 0x88, 0x37, 0x03]);
        assert_eq!(
            ber(&[1, 3, 6, 1, 4, 1, 2636]),
            [0x06, 0x07, 0x2B, 6, 1, 4, 1, 0x94, 0x4C]
        );
        assert_eq!(ber(&[0, 0]), [0x06, 0x01, 0x00]);
    }

    #[test]
    fn round_trips() {
        for arcs in [
            vec![1, 3, 6, 1, 2, 1, 1, 1, 0],
            vec![0, 0],
            vec![2, 999, 3],
            vec![1, 3, 6, 1, 4, 1, u32::MAX, 0, 127, 128, 16383, 16384],
            (0..40)
                .map(|i| [1, 3][..].get(i).copied().unwrap_or(i as u32 * 1000))
                .collect(),
        ] {
            let b = ber(&arcs);
            let mut r = Reader::new(&b);
            let (_, inner) = r.read_any().unwrap();
            let oid = Oid::from_ber(inner.rest()).unwrap();
            assert_eq!(oid.as_slice(), &arcs[..]);
            assert_eq!(oid.to_string().parse::<Oid>().unwrap(), oid);
        }
    }

    #[test]
    fn rejects_bad_ber() {
        for bad in [
            &[][..],
            &[0x80, 0x01],
            &[0x2B, 0x86],
            &[0x8F, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
        ] {
            assert_eq!(
                Oid::from_ber(bad),
                Err(DecodeErrorKind::InvalidOid),
                "{bad:02X?}"
            );
        }
    }

    #[test]
    fn parsing_and_order() {
        assert_eq!(".1.3.6".parse::<Oid>().unwrap(), Oid::from([1, 3, 6]));
        for bad in ["", ".", "1", "3.1", "1.40", "1..2", "1.x", "1.3.4294967296"] {
            assert!(bad.parse::<Oid>().is_err(), "{bad}");
        }
        let mut v: Vec<Oid> = ["1.3.6.1.2", "1.3.6.1.10", "1.3.6.1.2.1", "1.3.6"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        v.sort();
        let s: Vec<String> = v.iter().map(Oid::to_string).collect();
        assert_eq!(s, ["1.3.6", "1.3.6.1.2", "1.3.6.1.2.1", "1.3.6.1.10"]);
        let long = Oid::from((0..20).collect::<Vec<u32>>());
        assert_eq!(long.len(), 20);
        assert_eq!(Oid::from([1, 3]).child(&[6, 1]), Oid::from([1, 3, 6, 1]));
    }

    #[test]
    fn trait_impls() {
        use std::collections::HashSet;
        let a: Oid = "1.3.6.1.2".try_into().unwrap();
        let b = Oid::from(&[1u32, 3, 6, 1, 2][..]);
        assert_eq!(a, b);
        assert_eq!(AsRef::<[u32]>::as_ref(&a), &[1, 3, 6, 1, 2]);
        assert_eq!(format!("{a:?}"), "Oid(1.3.6.1.2)");
        let set: HashSet<Oid> = [a.clone(), b, Oid::from(vec![1, 3])].into_iter().collect();
        assert_eq!(set.len(), 2);
        assert!(Oid::try_from("1..2").is_err());
        // A long OID (heap storage) behaves the same.
        let long: Vec<u32> = (0..40).collect();
        let l = Oid::from(long.clone());
        assert_eq!(l.as_slice(), &long[..]);
        assert!(set.contains(&a) && !set.contains(&l));
    }
}
