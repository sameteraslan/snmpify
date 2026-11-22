//! Where does the walk's CPU go? Client vs a bare encode/send/recv/decode loop.
use std::time::Instant;

use snmpify::client::{Client, Community, Options};
use snmpify::{AnyPdu, CommunityMessage, Oid, Pdu, Value, Version};

fn cpu_ns() -> u64 {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("schedstat")).ok())
        .map(|s| s.split_whitespace().next().unwrap().parse::<u64>().unwrap())
        .sum()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let n = 100;
    let c = Client::connect("127.0.0.1:16100", Community::v2c("public")).await.unwrap().with_options(Options {
        max_repetitions: 25,
        ..Options::default()
    });
    c.walk_all("1.3.6.1.4.1.99999.1").await.unwrap();
    let (c0, t0) = (cpu_ns(), Instant::now());
    for _ in 0..n {
        c.walk_all("1.3.6.1.4.1.99999.1").await.unwrap();
    }
    println!("client: {:.1} ms CPU, {:.1} ms wall", (cpu_ns() - c0) as f64 / 1e6, t0.elapsed().as_secs_f64() * 1e3);
    let (c0, t0) = (cpu_ns(), Instant::now());
    let mut k = 0;
    for _ in 0..n {
        k += c.walk_with("1.3.6.1.4.1.99999.1", |vb| { std::hint::black_box(vb); }).await.unwrap();
    }
    println!("view:   {:.1} ms CPU, {:.1} ms wall ({k})", (cpu_ns() - c0) as f64 / 1e6, t0.elapsed().as_secs_f64() * 1e3);

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect("127.0.0.1:16100").await.unwrap();
    let root: Oid = "1.3.6.1.4.1.99999.1".parse().unwrap();
    let mut buf = vec![0u8; 65535];
    let (c0, t0) = (cpu_ns(), Instant::now());
    let mut items = 0;
    for _ in 0..n {
        let mut cur = root.clone();
        'w: loop {
            let req = CommunityMessage::new(Version::V2c, "public", Pdu::get_bulk(1, 0, 25, [cur.clone()])).encode();
            sock.send(&req).await.unwrap();
            let len = sock.recv(&mut buf).await.unwrap();
            let m = CommunityMessage::decode(&buf[..len]).unwrap();
            let AnyPdu::Pdu(p) = m.pdu else { panic!() };
            for vb in p.varbinds {
                if vb.value == Value::EndOfMibView || !vb.oid.starts_with(&root) {
                    break 'w;
                }
                cur = vb.oid;
                items += 1;
            }
        }
    }
    println!("raw:    {:.1} ms CPU, {:.1} ms wall ({items})", (cpu_ns() - c0) as f64 / 1e6, t0.elapsed().as_secs_f64() * 1e3);
}
