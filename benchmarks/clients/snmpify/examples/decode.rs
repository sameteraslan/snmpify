//! Cost of decoding a 25-binding GetBulk answer: owned vs walking it in place.
use snmpify::ber::{tag, Reader};
use snmpify::{CommunityMessage, Pdu, PduType, Value, VarBind, Version};
use std::time::Instant;

fn main() {
    let vbs: Vec<VarBind> = (1..=25u32)
        .map(|i| {
            VarBind::new(
                [1, 3, 6, 1, 4, 1, 99999, 1, 1, 1, i],
                format!("interface-{i:05}-description"),
            )
        })
        .collect();
    let msg = CommunityMessage::new(
        Version::V2c,
        "public",
        Pdu {
            pdu_type: PduType::Response,
            request_id: 7,
            error_status: 0,
            error_index: 0,
            varbinds: vbs,
        },
    )
    .encode();
    let n = 400_000;
    let t = Instant::now();
    let mut k = 0;
    for _ in 0..n {
        k += CommunityMessage::decode(std::hint::black_box(&msg))
            .map(|m| matches!(m.pdu, snmpify::AnyPdu::Pdu(_)) as usize)
            .unwrap();
    }
    println!(
        "owned decode:  {:.0} ns/msg ({k})",
        t.elapsed().as_nanos() as f64 / n as f64
    );
    let t = Instant::now();
    let mut c = 0usize;
    for _ in 0..n {
        let mut r = Reader::new(std::hint::black_box(&msg));
        let mut m = r.read_sequence().unwrap();
        m.read_i32().unwrap();
        m.read_octets().unwrap();
        let (_, mut p) = m.read_any().unwrap();
        p.read_i32().unwrap();
        p.read_i32().unwrap();
        p.read_i32().unwrap();
        let mut l = p.read_sequence().unwrap();
        while !l.is_empty() {
            let mut vb = l.read_sequence().unwrap();
            let o = vb.read_tagged(tag::OBJECT_IDENTIFIER).unwrap();
            let (_, v) = vb.read_any().unwrap();
            c += o.rest().len() + v.rest().len();
        }
    }
    println!(
        "in place:      {:.0} ns/msg ({c})",
        t.elapsed().as_nanos() as f64 / n as f64
    );
    let _ = Value::Null;
}
