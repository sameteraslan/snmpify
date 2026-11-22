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
        "getnext" | "bulk" | "set" => {
            let community: &[u8] = if a.scenario == "set" {
                b"private"
            } else {
                b"public"
            };
            let c = Snmp2cClient::new(
                (ip, a.port).into(),
                community.to_vec(),
                Some("0.0.0.0:0".parse().unwrap()),
                Some(Duration::from_secs(1)),
                2,
            )
            .await
            .unwrap();
            let (name, table, w) = (oid(SYS_NAME), oid(TABLE), oid(WRITABLE));
            let mut lat = Vec::with_capacity(a.n);
            let mut items = 0;
            for i in 0..a.n {
                let s = Instant::now();
                items += match a.scenario.as_str() {
                    "getnext" => {
                        c.get_next(name).await.unwrap();
                        1
                    }
                    "bulk" => c
                        .get_bulk(&[table], 0, BULK_REP)
                        .await
                        .unwrap()
                        .values
                        .len(),
                    _ => {
                        c.set(
                            w,
                            csnmp::ObjectValue::String(format!("value {i}").into_bytes()),
                        )
                        .await
                        .unwrap();
                        1
                    }
                };
                lat.push(s.elapsed().as_secs_f64() * 1e6);
            }
            report(items, t.elapsed().as_secs_f64() * 1e3, &mut lat);
        }
        "trap" | "inform" => {
            let c = connect(a.port - 1).await.unwrap();
            let bindings = || {
                vec![
                    (oid("1.3.6.1.2.1.1.3.0"), csnmp::ObjectValue::TimeTicks(0)),
                    (
                        oid("1.3.6.1.6.3.1.1.4.1.0"),
                        csnmp::ObjectValue::ObjectId(oid(LINK_DOWN)),
                    ),
                    (oid("1.3.6.1.2.1.2.2.1.1.7"), csnmp::ObjectValue::Integer(7)),
                ]
                .into_iter()
            };
            let mut lat = Vec::with_capacity(a.n);
            for _ in 0..a.n {
                let s = Instant::now();
                if a.scenario == "trap" {
                    c.trap(bindings()).await.unwrap();
                } else {
                    c.inform(bindings()).await.unwrap();
                }
                lat.push(s.elapsed().as_secs_f64() * 1e6);
            }
            report(a.n, t.elapsed().as_secs_f64() * 1e3, &mut lat);
        }
        "idle" => report(0, 0.0, &mut []),
        _ => unsupported(),
    }
}
