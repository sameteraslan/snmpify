//! snmpify (Rust).
use std::time::Instant;

use snmpify::client::{Client, Community, Manager, Options};
use snmpify::usm::{AuthProtocol, PrivProtocol, UsmUser};

include!("../../common.rs");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let a = args();
    let target = format!("{}:{}", a.host, a.port);
    let opts = Options {
        max_repetitions: MAX_REP,
        ..Options::default()
    };
    let t = Instant::now();
    match a.scenario.as_str() {
        "walk" | "walk3" => {
            let c = if a.scenario == "walk" {
                Client::connect(&target, Community::v2c("public")).await.unwrap()
            } else {
                let u = UsmUser::new("bench")
                    .with_auth(AuthProtocol::Sha1, "bench-auth-pass")
                    .unwrap()
                    .with_privacy(PrivProtocol::Aes128, "bench-priv-pass")
                    .unwrap();
                Client::connect(&target, u).await.unwrap()
            }
            .with_options(opts);
            let mut n = 0;
            for _ in 0..a.n {
                n += c.walk_all(TABLE).await.unwrap().len();
            }
            report(n, t.elapsed().as_secs_f64() * 1e3, &mut []);
        }
        "get" => {
            let c = Client::connect(&target, Community::v2c("public")).await.unwrap();
            let mut lat = Vec::with_capacity(a.n);
            for _ in 0..a.n {
                let s = Instant::now();
                c.get_one(SYS_NAME).await.unwrap();
                lat.push(s.elapsed().as_secs_f64() * 1e6);
            }
            report(a.n, t.elapsed().as_secs_f64() * 1e3, &mut lat);
        }
        "poll" => {
            // Every agent at once over one socket.
            let m = Manager::bind("0.0.0.0:0").await.unwrap().with_options(opts);
            let ip: std::net::IpAddr = a.host.parse().unwrap();
            let tasks: Vec<_> = (1..=a.n as u16)
                .map(|k| {
                    let c = m.client((ip, a.port + k).into(), Community::v2c("public"));
                    tokio::spawn(async move { c.get_one(SYS_NAME).await.is_ok() })
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
