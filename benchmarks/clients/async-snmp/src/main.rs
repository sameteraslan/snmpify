//! async-snmp.
use std::time::{Duration, Instant};

use async_snmp::transport::UdpTransport;
use async_snmp::v3::{AuthProtocol, PrivProtocol};
use async_snmp::{Auth, Client, ClientBuilder, Oid, UsmConfig, Value};

include!("../../common.rs");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let a = args();
    let oid = |s: &str| Oid::parse(s).unwrap();
    let t = Instant::now();
    match a.scenario.as_str() {
        "walk" | "walk3" => {
            let auth: Auth = if a.scenario == "walk" {
                Auth::v2c("public")
            } else {
                UsmConfig::new(bytes::Bytes::from_static(b"bench"))
                    .auth_priv(
                        AuthProtocol::Sha1,
                        "bench-auth-pass",
                        PrivProtocol::Aes128,
                        "bench-priv-pass",
                    )
                    .unwrap()
                    .into()
            };
            let c = Client::builder((a.host.as_str(), a.port), auth)
                .connect()
                .await
                .unwrap();
            let mut n = 0;
            for _ in 0..a.n {
                let mut w = c.bulk_walk(oid(TABLE), MAX_REP).unwrap();
                while let Some(vb) = w.next().await {
                    vb.unwrap();
                    n += 1;
                }
            }
            report(n, t.elapsed().as_secs_f64() * 1e3, &mut []);
        }
        "get" => {
            let c = Client::builder((a.host.as_str(), a.port), Auth::v2c("public"))
                .connect()
                .await
                .unwrap();
            let o = oid(SYS_NAME);
            let mut lat = Vec::with_capacity(a.n);
            for _ in 0..a.n {
                let s = Instant::now();
                c.get(&o).await.unwrap();
                lat.push(s.elapsed().as_secs_f64() * 1e6);
            }
            report(a.n, t.elapsed().as_secs_f64() * 1e3, &mut lat);
        }
        "poll" => {
            // A shared UDP transport for every target (its mass-polling mode).
            let transport = UdpTransport::bind("0.0.0.0:0").await.unwrap();
            let ip: std::net::IpAddr = a.host.parse().unwrap();
            let o = oid(SYS_NAME);
            let tasks: Vec<_> = (1..=a.n as u16)
                .map(|k| {
                    let h = transport.handle((ip, a.port + k).into()).unwrap();
                    let c = ClientBuilder::new(Auth::v2c("public"))
                        .request_timeout(Duration::from_secs(1))
                        .build_with_transport(h)
                        .unwrap();
                    let o = o.clone();
                    tokio::spawn(async move { c.get(&o).await.is_ok() })
                })
                .collect();
            let mut ok = 0;
            for t in tasks {
                ok += t.await.unwrap() as usize;
            }
            report(ok, t.elapsed().as_secs_f64() * 1e3, &mut []);
        }
        "getnext" | "bulk" | "set" => {
            let community = if a.scenario == "set" {
                "private"
            } else {
                "public"
            };
            let c = Client::builder((a.host.as_str(), a.port), Auth::v2c(community))
                .connect()
                .await
                .unwrap();
            let (name, table, w) = (oid(SYS_NAME), oid(TABLE), oid(WRITABLE));
            let mut lat = Vec::with_capacity(a.n);
            let mut items = 0;
            for i in 0..a.n {
                let s = Instant::now();
                items += match a.scenario.as_str() {
                    "getnext" => c.get_next(&name).await.unwrap().varbinds.len(),
                    "bulk" => c
                        .get_bulk(std::slice::from_ref(&table), 0, BULK_REP)
                        .await
                        .unwrap()
                        .len(),
                    _ => c
                        .set(
                            &w,
                            Value::OctetString(bytes::Bytes::from(format!("value {i}"))),
                        )
                        .await
                        .unwrap()
                        .varbinds
                        .len(),
                };
                lat.push(s.elapsed().as_secs_f64() * 1e6);
            }
            report(items, t.elapsed().as_secs_f64() * 1e3, &mut lat);
        }
        "trap" | "inform" => {
            let c = Client::builder((a.host.as_str(), a.port - 1), Auth::v2c("public"))
                .connect()
                .await
                .unwrap();
            let trap_oid = oid(LINK_DOWN);
            let vbs = vec![async_snmp::VarBind::new(
                oid("1.3.6.1.2.1.2.2.1.1.7"),
                Value::Integer(7),
            )];
            let mut lat = Vec::with_capacity(a.n);
            for _ in 0..a.n {
                let s = Instant::now();
                if a.scenario == "trap" {
                    c.send_trap(&trap_oid, 0, vbs.clone()).await.unwrap();
                } else {
                    c.send_inform(&trap_oid, 0, vbs.clone()).await.unwrap();
                }
                lat.push(s.elapsed().as_secs_f64() * 1e6);
            }
            report(a.n, t.elapsed().as_secs_f64() * 1e3, &mut lat);
        }
        "idle" => report(0, 0.0, &mut []),
        _ => unsupported(),
    }
    let _ = Value::Null;
}
