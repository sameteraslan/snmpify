//! csnmp (SNMPv2c only).
use std::time::{Duration, Instant};

use csnmp::{ObjectIdentifier, Snmp2cClient};

include!("../../common.rs");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let a = args();
    let oid = |s: &str| s.parse::<ObjectIdentifier>().unwrap();
    let ip: std::net::IpAddr = a.host.parse().unwrap();
    let connect = |port: u16| {
        Snmp2cClient::new(
            (ip, port).into(),
            b"public".to_vec(),
            Some("0.0.0.0:0".parse().unwrap()),
            Some(Duration::from_secs(1)),
            2,
        )
    };
    let t = Instant::now();
    match a.scenario.as_str() {
        "walk" => {
            let c = connect(a.port).await.unwrap();
            let mut n = 0;
            for _ in 0..a.n {
                n += c.walk_bulk(oid(TABLE), MAX_REP).await.unwrap().len();
            }
            report(n, t.elapsed().as_secs_f64() * 1e3, &mut []);
        }
        "get" => {
            let c = connect(a.port).await.unwrap();
            let o = oid(SYS_NAME);
            let mut lat = Vec::with_capacity(a.n);
            for _ in 0..a.n {
                let s = Instant::now();
                c.get(o).await.unwrap();
                lat.push(s.elapsed().as_secs_f64() * 1e6);
            }
            report(a.n, t.elapsed().as_secs_f64() * 1e3, &mut lat);
        }
        "poll" => {
            // One client (socket) per agent, all at once.
            let o = oid(SYS_NAME);
            let tasks: Vec<_> = (1..=a.n as u16)
                .map(|k| {
                    let c = connect(a.port + k);
                    tokio::spawn(async move {
                        match c.await {
                            Ok(c) => c.get(o).await.is_ok(),
                            Err(_) => false,
                        }
                    })
                })
                .collect();
            let mut ok = 0;
            for t in tasks {
                ok += t.await.unwrap() as usize;
            }
            report(ok, t.elapsed().as_secs_f64() * 1e3, &mut []);
        }
        "idle" => report(0, 0.0, &mut []),
        _ => unsupported(),
    }
}
