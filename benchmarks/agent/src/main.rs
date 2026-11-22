//! The agent the benchmarks query: snmpify's agent (fast, so the clients
//! are what is measured).
//!
//!     bench-agent BIND_IP BASE_PORT N_POLL
//!
//! - BASE_PORT: the system group and a 10 000-object table under
//!   1.3.6.1.4.1.99999.1 (5000 rows × an OCTET STRING and a Counter64),
//!   community "public", SNMPv3 user "bench" (SHA, AES; passwords
//!   "bench-auth-pass" / "bench-priv-pass").
//! - BASE_PORT+1 … BASE_PORT+N_POLL: one small agent each (mass polling).
//! - BASE_PORT-1: a notification receiver (community "public", user
//!   "bench") that takes traps and acknowledges informs.
//! - A writable OCTET STRING at 1.3.6.1.4.1.99999.3.0 (community
//!   "private").
//!
//! Prints READY when everything listens.

use snmpify::agent::{Access, Agent, MibTree};
use snmpify::engine::LocalEngine;
use snmpify::notification::NotificationReceiver;
use snmpify::usm::{AuthProtocol, PrivProtocol, SecurityLevel, UsmUser};
use snmpify::{Oid, Value};

fn oid(s: &str) -> Oid {
    s.parse().unwrap()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ip = args.get(1).map(String::as_str).unwrap_or("127.0.0.1");
    let base: u16 = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(16100);
    let n_poll: u16 = args.get(3).and_then(|p| p.parse().ok()).unwrap_or(1000);

    let mib = MibTree::new().with_system(
        "snmpify bench agent",
        oid("1.3.6.1.4.1.99999"),
        "bench",
        || 100,
    );
    for i in 1..=5000u32 {
        mib.insert(
            oid(&format!("1.3.6.1.4.1.99999.1.1.1.{i}")),
            format!("interface-{i:05}-description"),
        );
        mib.insert(
            oid(&format!("1.3.6.1.4.1.99999.1.1.2.{i}")),
            Value::Counter64(u64::from(i) * 1_000_003),
        );
    }
    // Something after the table, as on real agents: walks end by leaving
    // the subtree, not at the end of the MIB view.
    mib.insert(oid("1.3.6.1.4.1.99999.2.0"), "after the table");
    mib.insert_writable(oid("1.3.6.1.4.1.99999.3.0"), "writable");
    let user = UsmUser::new("bench")
        .with_auth(AuthProtocol::Sha1, "bench-auth-pass")
        .unwrap()
        .with_privacy(PrivProtocol::Aes128, "bench-priv-pass")
        .unwrap();
    let main_agent = Agent::bind(&format!("{ip}:{base}"))
        .await
        .unwrap()
        .with_community("public", Access::ReadOnly)
        .with_community("private", Access::ReadWrite)
        .with_engine(LocalEngine::new(LocalEngine::generate_id()).with_user(user.clone()))
        .with_user_access("bench", Access::ReadOnly, SecurityLevel::AuthPriv)
        .register(oid("1.3.6.1.2.1.1"), mib.clone())
        .register(oid("1.3.6.1.4.1.99999"), mib);
    tokio::spawn(async move { main_agent.run().await });

    let small = MibTree::new().with_system(
        "snmpify bench agent",
        oid("1.3.6.1.4.1.99999"),
        "poll",
        || 100,
    );
    for k in 1..=n_poll {
        let a = Agent::bind(&format!("{ip}:{}", base + k))
            .await
            .unwrap()
            .with_community("public", Access::ReadOnly)
            .register(oid("1.3.6.1.2.1.1"), small.clone());
        tokio::spawn(async move { a.run().await });
    }
    let mut rx = NotificationReceiver::bind(&format!("{ip}:{}", base - 1))
        .await
        .unwrap()
        .with_community("public")
        .with_engine(LocalEngine::new(LocalEngine::generate_id()).with_user(user));
    tokio::spawn(async move { while rx.recv().await.is_ok() {} });
    println!("READY");
    std::future::pending::<()>().await;
}
