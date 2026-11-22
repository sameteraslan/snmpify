//! Codec throughput: a Response with 50 interface-table bindings (a typical
//! GetBulk answer), encoded and decoded repeatedly.
//!
//!     cargo run --release --example codec_bench

use std::hint::black_box;
use std::time::Instant;

use snmpify::{CommunityMessage, Pdu, PduType, Value, VarBind, Version};

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
}
