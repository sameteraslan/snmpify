//! The agent and the AgentX subagent with net-snmp. Skipped unless
//! `SNMPIFY_AGENTX` is set (snmpd's AgentX port, see tools/snmpd):
//!
//! ```sh
//! docker run -d --rm --name snmpify-snmpd -p 127.0.0.1:1161:161/udp \
//!   -p 127.0.0.1:1705:705/tcp snmpify-snmpd
//! SNMPIFY_AGENT=127.0.0.1:1161 SNMPIFY_AGENTX=127.0.0.1:1705 cargo test --test netsnmp_agent
//! ```
//!
//! - net-snmp's snmpget / snmpbulkwalk / snmpset (run in the container)
//!   against snmpify's agent, v2c and v3.
//! - snmpify as an AgentX subagent of snmpd: queried and set through
//!   snmpd, and a notification sent through it.

use std::process::Command;
use std::time::Duration;

use snmpify::agent::{Access, Agent, MibTree};
use snmpify::agentx::Subagent;
use snmpify::client::{Client, Community};
use snmpify::engine::LocalEngine;
use snmpify::notification::NotificationReceiver;
use snmpify::usm::{AuthProtocol, PrivProtocol, UsmUser};
use snmpify::{Oid, Value, VarBind};

fn oid(s: &str) -> Oid {
    s.parse().unwrap()
}

fn netsnmp(args: &[&str]) -> (bool, String) {
    let out = Command::new("docker")
        .args(["exec", "snmpify-snmpd"])
        .args(args)
        .output()
        .expect("docker");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

fn enabled() -> Option<(String, String)> {
    Some((
        std::env::var("SNMPIFY_AGENTX").ok()?,
        std::env::var("SNMPIFY_AGENT").ok()?,
    ))
}

#[tokio::test]
async fn netsnmp_tools_against_the_agent() {
    if enabled().is_none() {
        eprintln!("SNMPIFY_AGENTX not set; skipped");
        return;
    }
    let host = std::env::var("SNMPIFY_DOCKER_HOST").unwrap_or_else(|_| "172.17.0.1".into());
    let mib = MibTree::new().with_system(
        "snmpify agent",
        oid("1.3.6.1.4.1.99999"),
        "rust-agent",
        || 100,
    );
    for i in 1..=50u32 {
        mib.insert(
            oid(&format!("1.3.6.1.4.1.99999.1.{i}")),
            Value::Counter64(u64::from(i) << 33),
        );
    }
    mib.insert_writable(oid("1.3.6.1.4.1.99999.2.0"), "before");
    let user = UsmUser::new("agentuser")
        .with_auth(AuthProtocol::Sha512, "agent-auth-pass")
        .unwrap()
        .with_privacy(PrivProtocol::Aes256, "agent-priv-pass")
        .unwrap();
    let agent = Agent::bind(&format!("{host}:0"))
        .await
        .unwrap()
        .with_community("public", Access::ReadOnly)
        .with_community("private", Access::ReadWrite)
        .with_engine(LocalEngine::new(LocalEngine::generate_id()).with_user(user))
        .with_user_access(
            "agentuser",
            Access::ReadWrite,
            snmpify::usm::SecurityLevel::AuthPriv,
        )
        .register(oid("1.3.6.1.2.1.1"), mib.clone())
        .register(oid("1.3.6.1.4.1.99999"), mib.clone());
    let target = agent.local_addr().unwrap().to_string();
    // The same agent over TCP.
    let agent = std::sync::Arc::new(agent);
    let tcp = tokio::net::TcpListener::bind(&format!("{host}:0"))
        .await
        .unwrap();
    let tcp_target = format!("tcp:{}", tcp.local_addr().unwrap());
    tokio::spawn(agent.clone().run_tcp(tcp));
    tokio::spawn(async move { agent.run().await });
    let v3 = [
        "-v3",
        "-u",
        "agentuser",
        "-l",
        "authPriv",
        "-a",
        "SHA-512",
        "-A",
        "agent-auth-pass",
        "-x",
        "AES-256",
        "-X",
        "agent-priv-pass",
    ];
    let t = target.clone();
    let tt = tcp_target.clone();
    let results = tokio::task::spawn_blocking(move || {
        let mut r = Vec::new();
        for auth in [&["-v2c", "-c", "public"][..], &v3[..]] {
            let run = |cmd: &str, rest: &[&str]| {
                let mut a = vec![cmd, "-On", "-r1", "-t2"];
                a.extend_from_slice(auth);
                a.push(&t);
                a.extend_from_slice(rest);
                netsnmp(&a)
            };
            r.push(run("snmpget", &["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"]));
            r.push(run("snmpbulkwalk", &["1.3.6.1.4.1.99999.1"]));
            r.push(run("snmpgetnext", &["1.3.6.1.4.1.99999.1.50"]));
        }
        let mut w = vec!["snmpset", "-On", "-r1", "-t2"];
        w.extend_from_slice(&v3);
        w.extend_from_slice(&[&t, "1.3.6.1.4.1.99999.2.0", "s", "after"]);
        r.push(netsnmp(&w));
        r.push(netsnmp(&[
            "snmpset",
            "-r1",
            "-t2",
            "-v2c",
            "-c",
            "public",
            &t,
            "1.3.6.1.4.1.99999.2.0",
            "s",
            "x",
        ]));
        // net-snmp over TCP.
        r.push(netsnmp(&[
            "snmpget",
            "-On",
            "-v2c",
            "-c",
            "public",
            &tt,
            "1.3.6.1.2.1.1.5.0",
        ]));
        let mut w3 = vec!["snmpbulkwalk", "-On"];
        w3.extend_from_slice(&v3);
        w3.extend_from_slice(&[&tt, "1.3.6.1.4.1.99999.1"]);
        r.push(netsnmp(&w3));
        r
    })
    .await
    .unwrap();
    for (i, (ok, out)) in results.iter().enumerate().take(6) {
        assert!(ok, "command {i}: {out}");
    }
    for get in [&results[0].1, &results[3].1] {
        assert!(get.contains("STRING: \"rust-agent\""), "{get}");
        assert!(get.contains("Timeticks: (100)"), "{get}");
    }
    for walk in [&results[1].1, &results[4].1] {
        assert_eq!(
            walk.lines().filter(|l| l.contains("Counter64")).count(),
            50,
            "{walk}"
        );
        assert!(
            walk.contains(".1.3.6.1.4.1.99999.1.50 = Counter64: 429496729600"),
            "{walk}"
        );
    }
    for next in [&results[2].1, &results[5].1] {
        assert!(next.contains(".1.3.6.1.4.1.99999.2.0"), "{next}");
    }
    assert!(results[6].0, "{}", results[6].1);
    assert_eq!(
        mib.value(&oid("1.3.6.1.4.1.99999.2.0")),
        Some(Value::from("after"))
    );
    assert!(
        !results[7].0 && results[7].1.contains("noAccess"),
        "{}",
        results[7].1
    );
    assert!(
        results[8].0 && results[8].1.contains("STRING: \"rust-agent\""),
        "{}",
        results[8].1
    );
    assert_eq!(
        results[9]
            .1
            .lines()
            .filter(|l| l.contains("Counter64"))
            .count(),
        50,
        "{}",
        results[9].1
    );
}

#[tokio::test]
async fn agentx_subagent_under_snmpd() {
    let Some((agentx, snmpd)) = enabled() else {
        eprintln!("SNMPIFY_AGENTX not set; skipped");
        return;
    };
    // snmpd sends traps to the docker host, port 11620 (snmpd.conf).
    let host = std::env::var("SNMPIFY_DOCKER_HOST").unwrap_or_else(|_| "172.17.0.1".into());
    let mut rx = NotificationReceiver::bind(&format!("{host}:11620"))
        .await
        .unwrap()
        .with_community("public");

    let mib = MibTree::new();
    mib.insert(oid("1.3.6.1.4.1.99998.1.0"), "from the subagent");
    mib.insert(oid("1.3.6.1.4.1.99998.2.0"), Value::Counter64(1 << 50));
    mib.insert_writable(oid("1.3.6.1.4.1.99998.3.0"), Value::Integer(1));
    for i in 1..=20u32 {
        mib.insert(oid(&format!("1.3.6.1.4.1.99998.4.{i}")), Value::Gauge32(i));
    }
    let sub = Subagent::new("snmpify test subagent")
        .with_id(oid("1.3.6.1.4.1.99998"))
        .with_timeout(5)
        .register(oid("1.3.6.1.4.1.99998"), mib.clone());
    let notifier = sub.notifier();
    let run = tokio::spawn(async move { sub.run_tcp(&agentx).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!run.is_finished(), "{:?}", run.await);

    let c = Client::connect(&snmpd, Community::v2c("public"))
        .await
        .unwrap();
    assert_eq!(
        c.get_one("1.3.6.1.4.1.99998.1.0").await.unwrap(),
        Value::from("from the subagent")
    );
    assert_eq!(
        c.get_one("1.3.6.1.4.1.99998.2.0").await.unwrap(),
        Value::Counter64(1 << 50)
    );
    assert_eq!(
        c.get_one("1.3.6.1.4.1.99998.9.0").await.unwrap(),
        Value::NoSuchObject
    );
    let rows = c.walk_all("1.3.6.1.4.1.99998.4").await.unwrap();
    assert_eq!(rows.len(), 20);
    assert_eq!(rows[19].value, Value::Gauge32(20));
    let all = c.walk_all("1.3.6.1.4.1.99998").await.unwrap();
    assert_eq!(all.len(), 23);
    // Set through snmpd: test and commit go to the subagent.
    let w = Client::connect(&snmpd, Community::v2c("private"))
        .await
        .unwrap();
    w.set(vec![VarBind::new(oid("1.3.6.1.4.1.99998.3.0"), 42)])
        .await
        .unwrap();
    assert_eq!(
        mib.value(&oid("1.3.6.1.4.1.99998.3.0")),
        Some(Value::Integer(42))
    );
    assert!(w
        .set(vec![VarBind::new(oid("1.3.6.1.4.1.99998.1.0"), "x")])
        .await
        .is_err());
    assert!(w
        .set(vec![VarBind::new(
            oid("1.3.6.1.4.1.99998.3.0"),
            "wrong type"
        )])
        .await
        .is_err());
    assert_eq!(
        mib.value(&oid("1.3.6.1.4.1.99998.3.0")),
        Some(Value::Integer(42))
    );

    // A notification through the master.
    notifier
        .notify(
            oid("1.3.6.1.4.1.99998.0.1"),
            vec![VarBind::new(oid("1.3.6.1.4.1.99998.1.0"), "alert")],
        )
        .unwrap();
    let n = loop {
        let n = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the notification")
            .unwrap();
        // snmpd's own coldStart / other traps may come first.
        if n.trap_oid == oid("1.3.6.1.4.1.99998.0.1") {
            break n;
        }
    };
    assert!(n
        .varbinds
        .contains(&VarBind::new(oid("1.3.6.1.4.1.99998.1.0"), "alert")));
    run.abort();
}
