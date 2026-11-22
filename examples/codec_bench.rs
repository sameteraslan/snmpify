//! Codec throughput: a Response with 50 interface-table bindings (a typical
//! GetBulk answer), encoded and decoded repeatedly; then the same PDU as
//! an SNMPv3 message, sealed and opened with each USM protocol, and the
//! cost of making keys from passwords.
//!
//!     cargo run --release --example codec_bench

use std::hint::black_box;
use std::time::Instant;

use snmpify::usm::{AuthProtocol, PrivProtocol, UsmUser};
use snmpify::v3::{ScopedPdu, ScopedPduData, UsmParams, V3Message};
use snmpify::{AnyPdu, CommunityMessage, Pdu, PduType, Value, VarBind, Version};

fn per_op(n: u32, mut f: impl FnMut()) -> f64 {
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    t.elapsed().as_secs_f64() / n as f64
}

fn main() {
    let varbinds: Vec<VarBind> = (1..=50)
        .map(|i| {
            let oid = [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6 + (i % 4), i];
            let value = match i % 4 {
                0 => Value::Counter64(1_000_000_000 * i as u64),
                1 => Value::from(format!("GigabitEthernet0/{i}")),
                2 => Value::Gauge32(1000),
                _ => Value::Counter32(i * 7919),
            };
            VarBind::new(oid, value)
        })
        .collect();
    let msg = CommunityMessage::new(
        Version::V2c,
        "public",
        Pdu {
            pdu_type: PduType::Response,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds,
        },
    );
    let bytes = msg.encode();
    let n = 200_000;

    let t = Instant::now();
    for _ in 0..n {
        black_box(black_box(&msg).encode());
    }
    let enc = t.elapsed().as_secs_f64() / n as f64;

    let t = Instant::now();
    for _ in 0..n {
        black_box(CommunityMessage::decode(black_box(&bytes)).unwrap());
    }
    let dec = t.elapsed().as_secs_f64() / n as f64;

    println!(
        "{} bytes, 50 varbinds: encode {:.2} µs ({:.0} ns/varbind), decode {:.2} µs ({:.0} ns/varbind, {:.0} MB/s)",
        bytes.len(),
        enc * 1e6,
        enc * 1e9 / 50.0,
        dec * 1e6,
        dec * 1e9 / 50.0,
        bytes.len() as f64 / dec / 1e6
    );

    // SNMPv3: the same PDU, sealed (encrypt + HMAC) and opened (verify +
    // decrypt).
    let AnyPdu::Pdu(pdu) = msg.pdu else {
        unreachable!()
    };
    let engine = [0x80, 0x00, 0x1f, 0x88, 0x80, 1, 2, 3, 4];
    let v3 = V3Message {
        msg_id: 1,
        max_size: 65507,
        flags: 0,
        usm: UsmParams {
            engine_boots: 1,
            engine_time: 1000,
            ..UsmParams::default()
        },
        data: ScopedPduData::Plaintext(ScopedPdu::new(engine, Vec::new(), pdu)),
    };
    println!("SNMPv3, same PDU:        seal      open");
    let mut combos = vec![(None, None)];
    for a in [
        AuthProtocol::Md5,
        AuthProtocol::Sha1,
        AuthProtocol::Sha256,
        AuthProtocol::Sha512,
    ] {
        combos.push((Some(a), None));
    }
    for p in PrivProtocol::ALL {
        combos.push((Some(AuthProtocol::Sha1), Some(p)));
    }
    combos.push((Some(AuthProtocol::Sha256), Some(PrivProtocol::Aes256)));
    for (a, p) in combos {
        let mut u = UsmUser::new("bench");
        if let Some(a) = a {
            u = u.with_auth(a, "auth-password").unwrap();
        }
        if let Some(p) = p {
            u = u.with_privacy(p, "priv-password").unwrap();
        }
        let keys = u.localize(&engine);
        let sealed = keys.seal(v3.clone(), 0).unwrap();
        let n = 50_000;
        let mut salt = 0;
        let seal = per_op(n, || {
            salt += 1;
            black_box(keys.seal(black_box(v3.clone()), salt).unwrap());
        });
        let open = per_op(n, || {
            black_box(keys.open(black_box(&sealed)).unwrap());
        });
        let label = match (a, p) {
            (None, _) => "noAuthNoPriv".to_string(),
            (Some(a), None) => format!("{a}"),
            (Some(a), Some(p)) => format!("{a} + {p}"),
        };
        println!("  {label:<20} {:6.2} µs {:6.2} µs", seal * 1e6, open * 1e6);
    }

    // Master keys: the slow, once-per-user step (1 MB hashed).
    for a in [
        AuthProtocol::Md5,
        AuthProtocol::Sha1,
        AuthProtocol::Sha256,
        AuthProtocol::Sha512,
    ] {
        let ku = per_op(20, || {
            black_box(a.password_to_key(black_box(b"auth-password")).unwrap());
        });
        let k = a.password_to_key(b"auth-password").unwrap();
        let loc = per_op(100_000, || {
            black_box(a.localize(black_box(&k), black_box(&engine)));
        });
        println!(
            "  {a:<8} password to key {:.2} ms, localize {:.2} µs",
            ku * 1e3,
            loc * 1e6
        );
    }
}
