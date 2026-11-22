//! snmp2 (async session).
use std::time::{Duration, Instant};

use snmp2::{v3, AsyncSession, Oid, Value};

include!("../../common.rs");

fn oid(s: &str) -> Oid<'static> {
    let arcs: Vec<u64> = s.split('.').map(|x| x.parse().unwrap()).collect();
    Oid::from(arcs.as_slice()).unwrap().to_owned()
}

async fn walk(s: &mut AsyncSession) -> usize {
    let root = oid(TABLE);
    let mut cur = root.clone();
    let mut n = 0;
    'walk: loop {
        let pdu = tokio::time::timeout(Duration::from_secs(2), s.getbulk(&[&cur], 0, MAX_REP))
            .await
            .unwrap()
            .unwrap();
        let mut last = None;
        for (name, value) in pdu.varbinds {
            if matches!(value, Value::EndOfMibView) || !name.starts_with(&root) {
                break 'walk;
            }
            n += 1;
            last = Some(name.to_owned());
        }
        match last {
            Some(l) => cur = l,
            None => break,
        }
    }
    n
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let a = args();
    let target = format!("{}:{}", a.host, a.port);
    let t = Instant::now();
    match a.scenario.as_str() {
        "walk" | "walk3" => {
            let mut s = if a.scenario == "walk" {
                AsyncSession::new_v2c(&target, b"public", 0).await.unwrap()
            } else {
                let sec = v3::Security::new(b"bench", b"bench-auth-pass")
                    .with_auth_protocol(v3::AuthProtocol::Sha1)
                    .with_auth(v3::Auth::AuthPriv {
                        cipher: v3::Cipher::Aes128,
                        privacy_password: b"bench-priv-pass".to_vec(),
                    });
                let mut s = AsyncSession::new_v3(&target, 0, sec).await.unwrap();
                s.init().await.unwrap();
                s
            };
            let mut n = 0;
            for _ in 0..a.n {
                n += walk(&mut s).await;
            }
            report(n, t.elapsed().as_secs_f64() * 1e3, &mut []);
        }
        "get" => {
            let mut s = AsyncSession::new_v2c(&target, b"public", 0).await.unwrap();
            let o = oid(SYS_NAME);
            let mut lat = Vec::with_capacity(a.n);
            for _ in 0..a.n {
                let st = Instant::now();
                tokio::time::timeout(Duration::from_secs(1), s.get(&o)).await.unwrap().unwrap();
                lat.push(st.elapsed().as_secs_f64() * 1e6);
            }
            report(a.n, t.elapsed().as_secs_f64() * 1e3, &mut lat);
        }
        "poll" => {
            // One session (socket) per agent, all at once; timeouts are the
            // caller's (no retries).
            let tasks: Vec<_> = (1..=a.n as u16)
                .map(|k| {
                    let target = format!("{}:{}", a.host, a.port + k);
                    tokio::spawn(async move {
                        let Ok(mut s) = AsyncSession::new_v2c(&target, b"public", 0).await else {
                            return false;
                        };
                        let o = oid(SYS_NAME);
                        matches!(tokio::time::timeout(Duration::from_secs(1), s.get(&o)).await, Ok(Ok(_)))
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
