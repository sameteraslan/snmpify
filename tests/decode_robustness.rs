//! The decoder on random and mutated input (a stable-Rust complement to
//! the cargo-fuzz target in fuzz/): it never panics, and what decodes
//! survives a re-encode.

use snmpify::{CommunityMessage, Pdu, PduType, Value, VarBind, Version};

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

fn check(data: &[u8]) {
    let _ = snmpify::peek_version(data);
    if let Ok(msg) = CommunityMessage::decode(data) {
        assert_eq!(CommunityMessage::decode(&msg.encode()).unwrap(), msg);
    }
}

fn sample() -> Vec<u8> {
    let pdu = Pdu {
        pdu_type: PduType::Response,
        request_id: 77,
        error_status: 0,
        error_index: 0,
        varbinds: vec![
            VarBind::new([1, 3, 6, 1, 2, 1, 1, 1, 0], "Linux"),
            VarBind::new([1, 3, 6, 1, 2, 1, 1, 3, 0], Value::TimeTicks(5)),
            VarBind::new([1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1], Value::Counter64(9)),
            VarBind::new(
                [1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 10, 0, 0, 1],
                Value::IpAddress([10, 0, 0, 1].into()),
            ),
        ],
    };
    CommunityMessage::new(Version::V2c, "public", pdu).encode()
}

#[test]
fn random_bytes() {
    let mut rng = Rng(0x5EED);
    for _ in 0..20_000 {
        let len = (rng.next() % 200) as usize;
        let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        check(&data);
    }
}

#[test]
fn mutated_messages() {
    let good = sample();
    let mut rng = Rng(42);
    for _ in 0..50_000 {
        let mut m = good.clone();
        for _ in 0..1 + rng.next() % 4 {
            let i = (rng.next() as usize) % m.len();
            match rng.next() % 3 {
                0 => m[i] = rng.next() as u8,
                1 => m[i] ^= 1 << (rng.next() % 8),
                _ => {
                    m.truncate(i);
                    if m.is_empty() {
                        break;
                    }
                }
            }
        }
        check(&m);
    }
}
