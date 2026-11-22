//! Notifications between snmpify and net-snmp, both ways. Skipped unless
//! `SNMPIFY_TRAPD` is set:
//!
//! ```sh
//! docker build -t snmpify-snmpd tools/snmpd
//! docker run -d --rm --name snmpify-snmpd -p 127.0.0.1:1161:161/udp snmpify-snmpd
//! docker run -d --rm --name snmpify-snmptrapd -p 127.0.0.1:1162:162/udp \
//!   --entrypoint /usr/sbin/snmptrapd snmpify-snmpd -f -Lo -C -c /etc/snmp/snmptrapd.conf
//! SNMPIFY_TRAPD=127.0.0.1:1162 cargo test --test netsnmp_notifications
//! ```
//!
//! - snmpify → snmptrapd: traps and informs in v1, v2c and v3; checked in
//!   snmptrapd's log (`docker logs snmpify-snmptrapd`).
//! - net-snmp's snmptrap / snmpinform (run in the snmpify-snmpd container)
//!   → snmpify's receiver, reached from the container at the docker
//!   bridge address (`SNMPIFY_DOCKER_HOST`, default 172.17.0.1).

use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;

use snmpify::client::{Client, Community, Usm};
use snmpify::engine::LocalEngine;
use snmpify::notification::{trap_v1, NotificationKind, NotificationReceiver, Sender};
use snmpify::usm::{AuthProtocol, PrivProtocol, SecurityLevel, UsmUser};
use snmpify::{Oid, Value, VarBind, Version};

const LINK_DOWN: &str = "1.3.6.1.6.3.1.1.5.3";
const SYS_NAME: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 5, 0];
/// "testsend": the trap sender engine id snmptrapd.conf knows.
const SENDER_ENGINE: &[u8] = b"\x80\x00\x00\x00\x05testsend";

fn trapd() -> Option<String> {
    std::env::var("SNMPIFY_TRAPD").ok()
}

fn trap_user() -> UsmUser {
    UsmUser::new("trapuser")
        .with_auth(AuthProtocol::Sha256, "trap-auth-pass")
        .unwrap()
        .with_privacy(PrivProtocol::Aes128, "trap-priv-pass")
        .unwrap()
}

fn trapd_log() -> String {
    let out = Command::new("docker")
        .args(["logs", "snmpify-snmptrapd"])
        .output()
        .expect("docker");
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

fn marker(what: &str) -> String {
    format!("{what}-{}", std::process::id())
}

#[tokio::test]
async fn snmpify_notifications_reach_snmptrapd() {
    let Some(addr) = trapd() else {
        eprintln!("SNMPIFY_TRAPD not set; skipped");
        return;
    };
    let mark = |m: &str| vec![VarBind::new(SYS_NAME, Value::from(marker(m)))];
    let v2 = Client::connect(&addr, Community::v2c("public"))
        .await
        .unwrap();
    v2.trap(LINK_DOWN, mark("v2c-trap")).await.unwrap();
    v2.inform(LINK_DOWN, mark("v2c-inform")).await.unwrap();
    let v1 = Client::connect(&addr, Community::v1("public"))
        .await
        .unwrap();
    v1.trap_v1(trap_v1(
        Oid::from([1, 3, 6, 1, 4, 1, 99999]),
        Ipv4Addr::new(192, 0, 2, 1),
        6,
        17,
        100,
        mark("v1-trap"),
    ))
    .await
    .unwrap();
    // v3: traps from the engine id snmptrapd knows, informs to its engine.
    let v3 = Client::connect(&addr, Usm::new(trap_user()).with_engine_id(SENDER_ENGINE))
        .await
        .unwrap();
    v3.trap(LINK_DOWN, mark("v3-trap")).await.unwrap();
    v3.inform(LINK_DOWN, mark("v3-inform")).await.unwrap();
    // Not accepted: another community, a wrong password.
    let bad = Client::connect(&addr, Community::v2c("wrong"))
        .await
        .unwrap();
    bad.trap(LINK_DOWN, mark("bad-community")).await.unwrap();
    let wrong = UsmUser::new("trapuser")
        .with_auth(AuthProtocol::Sha256, "not-the-password")
        .unwrap();
    let w = Client::connect(&addr, Usm::new(wrong).with_engine_id(SENDER_ENGINE))
        .await
        .unwrap();
    w.trap(LINK_DOWN, mark("bad-password")).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    let log = trapd_log();
    for m in ["v2c-trap", "v2c-inform", "v1-trap", "v3-trap", "v3-inform"] {
        assert!(log.contains(&marker(m)), "{m} missing from:\n{log}");
    }
    for m in ["bad-community", "bad-password"] {
        assert!(!log.contains(&marker(m)), "{m} accepted:\n{log}");
    }
}

/// Runs a net-snmp command in the snmpd container.
fn netsnmp(args: &[&str]) -> std::process::Output {
    Command::new("docker")
        .args(["exec", "snmpify-snmpd"])
        .args(args)
        .output()
        .expect("docker")
}

#[tokio::test]
async fn netsnmp_notifications_reach_snmpify() {
    if trapd().is_none() {
        eprintln!("SNMPIFY_TRAPD not set; skipped");
        return;
    }
    let host = std::env::var("SNMPIFY_DOCKER_HOST").unwrap_or_else(|_| "172.17.0.1".into());
    let engine = LocalEngine::new(LocalEngine::generate_id()).with_user(trap_user());
    let mut rx = NotificationReceiver::bind(&format!("{host}:0"))
        .await
        .unwrap()
        .with_community("public")
        .with_engine(engine);
    let target = rx.local_addr().unwrap().to_string();
    let auth = [
        "-u",
        "trapuser",
        "-l",
        "authPriv",
        "-a",
        "SHA-256",
        "-A",
        "trap-auth-pass",
        "-x",
        "AES",
        "-X",
        "trap-priv-pass",
    ];
    let sends: Vec<Vec<String>> = vec![
        vec![
            "snmptrap",
            "-v1",
            "-c",
            "public",
            &target,
            "1.3.6.1.4.1.99999",
            "192.0.2.7",
            "6",
            "5",
            "4242",
        ],
        vec!["snmptrap", "-v2c", "-c", "public", &target, "", LINK_DOWN],
        vec!["snmpinform", "-v2c", "-c", "public", &target, "", LINK_DOWN],
        [
            &["snmptrap", "-v3", "-e", "0x8000000005aabbccdd"][..],
            &auth,
            &[&target, "", LINK_DOWN],
        ]
        .concat(),
        [&["snmpinform", "-v3"][..], &auth, &[&target, "", LINK_DOWN]].concat(),
    ]
    .into_iter()
    .map(|v| v.into_iter().map(String::from).collect())
    .collect();
    let task = tokio::task::spawn_blocking(move || {
        sends
            .iter()
            .map(|args| {
                let mut full = args.clone();
                full.extend(["1.3.6.1.2.1.1.5.0".into(), "s".into(), args[1].clone()]);
                let a: Vec<&str> = full.iter().map(String::as_str).collect();
                let out = netsnmp(&a);
                (
                    a.join(" "),
                    out.status.success(),
                    String::from_utf8_lossy(&out.stderr).into_owned(),
                )
            })
            .collect::<Vec<_>>()
    });
    let mut got = Vec::new();
    while got.len() < 5 {
        match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
            Ok(n) => got.push(n.unwrap()),
            Err(_) => break,
        }
    }
    for (cmd, ok, err) in task.await.unwrap() {
        assert!(ok, "{cmd}: {err}");
    }
    assert_eq!(got.len(), 5, "{got:#?}");
    let v1 = &got[0];
    assert_eq!(v1.version, Version::V1);
    assert_eq!(v1.trap_oid.to_string(), "1.3.6.1.4.1.99999.0.5");
    assert_eq!(v1.uptime, Some(4242));
    assert_eq!(
        v1.v1.as_ref().unwrap().agent_addr,
        Ipv4Addr::new(192, 0, 2, 7)
    );
    for (n, (version, kind)) in got.iter().skip(1).zip([
        (Version::V2c, NotificationKind::Trap),
        (Version::V2c, NotificationKind::Inform),
        (Version::V3, NotificationKind::Trap),
        (Version::V3, NotificationKind::Inform),
    ]) {
        assert_eq!((n.version, n.kind), (version, kind), "{n:?}");
        assert_eq!(n.trap_oid.to_string(), LINK_DOWN);
        assert_eq!(n.varbinds.len(), 1);
        if version == Version::V3 {
            let Sender::Usm { level, .. } = &n.sender else {
                panic!()
            };
            assert_eq!(*level, SecurityLevel::AuthPriv);
        }
    }
}
