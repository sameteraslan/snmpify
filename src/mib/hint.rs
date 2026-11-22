//! DISPLAY-HINT formatting (RFC 2579 §3.1).

/// Formats octets with an OCTET STRING display hint, e.g. `"1x:"`
/// (MAC addresses), `"255a"` (DisplayString), `"2d-1d-1d,1d:1d:1d.1d"`
/// (DateAndTime). An invalid hint shows the octets in hex.
///
/// ```
/// use snmpify::mib::format_octets;
/// assert_eq!(format_octets("1x:", &[0, 0x1b, 0x21, 0x3a, 0xc6, 0x08]), "00:1b:21:3a:c6:08");
/// assert_eq!(format_octets("1d.1d.1d.1d", &[192, 0, 2, 1]), "192.0.2.1");
/// ```
pub fn format_octets(hint: &str, data: &[u8]) -> String {
    let Some(specs) = parse_octet_hint(hint) else {
        return hex(data);
    };
    let mut out = String::new();
    let mut d = data;
    let mut k = 0;
    while !d.is_empty() {
        let s = &specs[k.min(specs.len() - 1)];
        k += 1;
        let repeat = if s.star {
            let n = d[0] as usize;
            d = &d[1..];
            n
        } else {
            1
        };
        for r in 0..repeat {
            if d.is_empty() {
                break;
            }
            let n = s.len.min(d.len());
            let (chunk, rest) = d.split_at(n);
            d = rest;
            match s.fmt {
                'a' | 't' => out.push_str(&String::from_utf8_lossy(chunk)),
                f => {
                    let v = chunk.iter().fold(0u128, |a, &b| (a << 8) | b as u128);
                    match f {
                        'd' => out.push_str(&v.to_string()),
                        'o' => out.push_str(&format!("{v:o}")),
                        _ => out.push_str(&format!("{v:0w$x}", w = chunk.len() * 2)),
                    }
                }
            }
            let last_of_repeat = r + 1 == repeat;
            if !d.is_empty() {
                if let Some(sep) = s.sep {
                    if !(s.star && last_of_repeat && s.term.is_some()) {
                        out.push(sep);
                    }
                }
            }
            if s.star && last_of_repeat {
                if let Some(t) = s.term {
                    if !d.is_empty() {
                        out.push(t);
                    }
                }
            }
        }
    }
    out
}

struct Spec {
    star: bool,
    len: usize,
    fmt: char,
    sep: Option<char>,
    term: Option<char>,
}

fn parse_octet_hint(h: &str) -> Option<Vec<Spec>> {
    let c: Vec<char> = h.chars().collect();
    let mut i = 0;
    let mut v = Vec::new();
    while i < c.len() {
        let star = c[i] == '*';
        if star {
            i += 1;
        }
        let start = i;
        while i < c.len() && c[i].is_ascii_digit() {
            i += 1;
        }
        let len: usize = c[start..i].iter().collect::<String>().parse().ok()?;
        let fmt = *c.get(i)?;
        if !"dxoat".contains(fmt) || len == 0 {
            return None;
        }
        i += 1;
        let is_sep = |ch: char| !ch.is_ascii_digit() && ch != '*';
        let sep = c.get(i).copied().filter(|&ch| is_sep(ch));
        if sep.is_some() {
            i += 1;
        }
        let term = if star {
            let t = c.get(i).copied().filter(|&ch| is_sep(ch));
            if t.is_some() {
                i += 1;
            }
            t
        } else {
            None
        };
        v.push(Spec {
            star,
            len,
            fmt,
            sep,
            term,
        });
    }
    (!v.is_empty()).then_some(v)
}

fn hex(d: &[u8]) -> String {
    d.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Formats an integer with an INTEGER display hint: `d-2` (two decimals),
/// `x`, `o`, `b`, `d`.
///
/// ```
/// use snmpify::mib::format_integer;
/// assert_eq!(format_integer("d-2", 1234), "12.34");
/// assert_eq!(format_integer("x", 255), "ff");
/// ```
pub fn format_integer(hint: &str, v: i64) -> String {
    match hint.chars().next() {
        Some('x') => format!("{v:x}"),
        Some('o') => format!("{v:o}"),
        Some('b') => format!("{v:b}"),
        Some('d') => {
            let places: usize = hint
                .strip_prefix("d-")
                .and_then(|p| p.parse().ok())
                .unwrap_or(0);
            if places == 0 {
                return v.to_string();
            }
            let neg = v < 0;
            let digits = format!("{:0w$}", v.unsigned_abs(), w = places + 1);
            let (int, frac) = digits.split_at(digits.len() - places);
            format!("{}{int}.{frac}", if neg { "-" } else { "" })
        }
        _ => v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octet_hints() {
        // DateAndTime (SNMPv2-TC): 2019-11-05,13:30:15.0,+1:0
        let dt = [0x07, 0xe3, 11, 5, 13, 30, 15, 0, b'+', 1, 0];
        assert_eq!(
            format_octets("2d-1d-1d,1d:1d:1d.1d,1a1d:1d", &dt),
            "2019-11-5,13:30:15.0,+1:0"
        );
        assert_eq!(format_octets("255a", b"eth0"), "eth0");
        assert_eq!(format_octets("255t", "naïve".as_bytes()), "naïve");
        assert_eq!(format_octets("1o", &[8, 9]), "1011");
        // Repeat with a terminator: a count byte, then that many items.
        assert_eq!(format_octets("*1d.;", &[3, 1, 2, 3, 2, 4, 5]), "1.2.3;4.5");
        // The last spec repeats.
        assert_eq!(format_octets("1d.", &[10, 0, 0, 1]), "10.0.0.1");
        assert_eq!(format_octets("2x", &[0xab, 0xcd, 0x01]), "abcd01");
        // Invalid hints: hex.
        for h in ["", "x", "1q", "0d", "1"] {
            assert_eq!(format_octets(h, &[1, 2]), "01 02", "{h}");
        }
        assert_eq!(format_octets("1x:", &[]), "");
    }

    #[test]
    fn integer_hints() {
        assert_eq!(format_integer("d-2", 1234), "12.34");
        assert_eq!(format_integer("d-2", -5), "-0.05");
        assert_eq!(format_integer("d-0", 5), "5");
        assert_eq!(format_integer("d", 5), "5");
        assert_eq!(format_integer("o", 8), "10");
        assert_eq!(format_integer("b", 5), "101");
        assert_eq!(format_integer("q", 5), "5");
    }
}
