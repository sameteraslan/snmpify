//! The decoder on random and mutated input (a stable-Rust complement to
//! the cargo-fuzz targets in fuzz/): it never panics, and what decodes
//! survives a re-encode. SNMPv3 messages also go through USM `open` with
//! every protocol: never a panic, and never accepted once altered.

use snmpify::usm::{AuthProtocol, LocalizedUser, PrivProtocol, SecurityLevel, UsmUser};
use snmpify::v3::{flags, Message, ScopedPdu, ScopedPduData, UsmParams, V3Message};
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
    if let Ok(msg) = Message::decode(data) {
        assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
    }
}

const ENGINE: &[u8] = &[0x80, 0, 0x1f, 0x88, 0x80, 9, 9, 9, 9];

fn v3_users() -> Vec<LocalizedUser> {
    let mut v = Vec::new();
    for a in [AuthProtocol::Md5, AuthProtocol::Sha512] {
        let u = UsmUser::new("u").with_auth(a, "auth-pass").unwrap();
        v.push(u.localize(ENGINE));
        for p in PrivProtocol::ALL {
            v.push(
                u.clone()
                    .with_privacy(p, "priv-pass")
                    .unwrap()
                    .localize(ENGINE),
            );
        }
    }
    v
}

fn v3_sample(keys: &LocalizedUser) -> Vec<u8> {
    let msg = V3Message {
        msg_id: 4242,
        max_size: 65507,
        flags: flags::REPORTABLE,
        usm: UsmParams {
            engine_boots: 2,
            engine_time: 300,
            ..UsmParams::default()
        },
        data: ScopedPduData::Plaintext(ScopedPdu::new(ENGINE, Vec::new(), sample_pdu())),
    };
    keys.seal(msg, 17).unwrap()
}

fn sample_pdu() -> Pdu {
    Pdu {
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
    }
}

fn sample() -> Vec<u8> {
    CommunityMessage::new(Version::V2c, "public", sample_pdu()).encode()
}

fn mutate(rng: &mut Rng, good: &[u8]) -> Vec<u8> {
    let mut m = good.to_vec();
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
    m
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
        check(&mutate(&mut rng, &good));
    }
}

#[test]
fn mutated_v3_messages() {
    let mut rng = Rng(7);
    for keys in v3_users() {
        let good = v3_sample(&keys);
        assert!(keys.open(&good).is_ok());
        for _ in 0..4_000 {
            let m = mutate(&mut rng, &good);
            check(&m);
            if m != good {
                // Altered messages never verify at the user's level (with
                // the auth flag cleared they open as unauthenticated,
                // which the client refuses).
                if let Ok(o) = keys.open(&m) {
                    assert!(
                        SecurityLevel::from_flags(o.flags) < keys.level(),
                        "{keys:?}\n{}\n{}",
                        hexs(&good),
                        hexs(&m)
                    );
                }
            }
        }
    }
}

#[test]
fn random_v3_shaped_bytes() {
    // A valid v3 header followed by noise: exercises the USM decoder.
    let keys = v3_users();
    let good = v3_sample(&keys[1]);
    let mut rng = Rng(99);
    for _ in 0..20_000 {
        let cut = (rng.next() as usize) % good.len();
        let mut m = good[..cut].to_vec();
        let extra = (rng.next() % 64) as usize;
        m.extend((0..extra).map(|_| rng.next() as u8));
        check(&m);
        for k in &keys {
            let _ = k.open(&m);
        }
    }
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
