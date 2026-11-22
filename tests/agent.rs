//! The agent, queried with the client: v1, v2c, v3, routing, sets,
//! errors, access control.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use snmpify::agent::{Access, Agent, MibHandler, MibTree};
use snmpify::client::{Client, Community, Error, Options, Usm};
use snmpify::engine::LocalEngine;
use snmpify::usm::{AuthProtocol, PrivProtocol, SecurityLevel, UsmUser};
use snmpify::v3::ReportKind;
use snmpify::{ErrorStatus, Oid, Value, VarBind};

const ENT: &str = "1.3.6.1.4.1.99999";

fn oid(s: &str) -> Oid {
    s.parse().unwrap()
}

fn alice() -> UsmUser {
    UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "alice-auth")
        .unwrap()
        .with_privacy(PrivProtocol::Aes128, "alice-priv")
        .unwrap()
}

fn bob() -> UsmUser {
    UsmUser::new("bob")
        .with_auth(AuthProtocol::Md5, "bob-auth-pass")
        .unwrap()
}

/// Counts reads: a handler of its own under 1.3.6.1.4.1.99999.9.
struct Counter(AtomicU32);

impl MibHandler for Counter {
    fn get(&self, oid: &Oid) -> Value {
        if oid.to_string() == format!("{ENT}.9.1.0") {
            Value::Counter32(self.0.fetch_add(1, Ordering::SeqCst))
        } else {
            Value::NoSuchObject
        }
    }
    fn get_next(&self, oid: &Oid) -> Option<VarBind> {
        let me = oid_(&format!("{ENT}.9.1.0"));
        (*oid < me).then(|| VarBind::new(me.clone(), self.get(&me)))
    }
}

fn oid_(s: &str) -> Oid {
    s.parse().unwrap()
}

struct Fixture {
    addr: String,
    mib: MibTree,
}

async fn agent() -> Fixture {
    let mib = MibTree::new().with_system("snmpify test agent", oid(ENT), "agent-1", || 4242);
    mib.insert(oid(&format!("{ENT}.1.0")), "hello");
    mib.insert_writable(oid(&format!("{ENT}.2.0")), Value::Integer(5));
    mib.insert(oid(&format!("{ENT}.3.1")), Value::Counter64(1 << 40));
    mib.insert(oid(&format!("{ENT}.3.2")), Value::Gauge32(7));
    // A table of 30 rows.
    for i in 1..=30u32 {
        mib.insert(
            oid(&format!("{ENT}.4.1.{i}")),
            Value::from(format!("row {i}")),
        );
    }
    let engine = LocalEngine::new(LocalEngine::generate_id())
        .with_user(alice())
        .with_user(bob());
    let agent = Agent::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_community("public", Access::ReadOnly)
        .with_community("private", Access::ReadWrite)
        .with_engine(engine)
        .with_user_access("alice", Access::ReadWrite, SecurityLevel::AuthPriv)
        .register(oid("1.3.6.1.2.1.1"), mib.clone())
        .register(oid(ENT), mib.clone())
        .register(oid(&format!("{ENT}.9")), Counter(AtomicU32::new(0)));
    assert!(format!("{agent:?}").contains("subtrees"));
    assert!(agent.engine().is_some());
    let addr = agent.local_addr().unwrap().to_string();
    tokio::spawn(async move { agent.run().await });
    Fixture { addr, mib }
}

async fn client(f: &Fixture, c: impl Into<snmpify::client::Credentials>) -> Client {
    Client::connect(&f.addr, c)
        .await
        .unwrap()
        .with_options(Options {
            timeout: Duration::from_millis(300),
            retries: 1,
            max_repetitions: 7,
        })
}

#[tokio::test]
async fn get_next_bulk_walk_in_every_version() {
    let f = agent().await;
    for c in [
        client(&f, Community::v1("public")).await,
        client(&f, Community::v2c("public")).await,
        client(&f, alice()).await,
        client(&f, bob()).await,
    ] {
        let v = c.version();
        assert_eq!(
            c.get_one("1.3.6.1.2.1.1.5.0").await.unwrap(),
            Value::from("agent-1"),
            "{v:?}"
        );
        assert_eq!(
            c.get_one("1.3.6.1.2.1.1.3.0").await.unwrap(),
            Value::TimeTicks(4242)
        );
        let next = c.get_next([format!("{ENT}.1.0").as_str()]).await.unwrap();
        assert_eq!(next[0].oid, oid(&format!("{ENT}.2.0")));
        // The table, with GetBulk (GetNext in v1).
        let rows = c.walk_all(format!("{ENT}.4").as_str()).await.unwrap();
        assert_eq!(rows.len(), 30, "{v:?}");
        // The whole agent: system group, enterprise subtree, the counter
        // handler — in order, nothing twice.
        let all = c.walk_all("1.3.6.1").await.unwrap();
        assert!(all.windows(2).all(|w| w[0].oid < w[1].oid));
        let counter = all
            .iter()
            .filter(|vb| vb.oid.to_string() == format!("{ENT}.9.1.0"))
            .count();
        assert_eq!(counter, 1);
        if v == snmpify::Version::V1 {
            // No Counter64 in v1: skipped by walks, noSuchName for Get.
            assert!(!all.iter().any(|vb| matches!(vb.value, Value::Counter64(_))));
            assert!(matches!(
                c.get_one(format!("{ENT}.3.1").as_str()).await,
                Err(Error::Snmp {
                    status: ErrorStatus::NoSuchName,
                    index: 1,
                    ..
                })
            ));
            assert!(matches!(
                c.get_one(format!("{ENT}.7.0").as_str()).await,
                Err(Error::Snmp {
                    status: ErrorStatus::NoSuchName,
                    ..
                })
            ));
        } else {
            assert!(all.iter().any(|vb| matches!(vb.value, Value::Counter64(_))));
            let vbs = c
                .get([
                    format!("{ENT}.7.0"),
                    format!("{ENT}.1.1"),
                    "1.3.6.1.2.1.1.5.0".into(),
                ])
                .await
                .unwrap();
            assert_eq!(vbs[0].value, Value::NoSuchObject);
            assert_eq!(vbs[1].value, Value::NoSuchInstance);
            let bulk = c
                .get_bulk(1, 3, ["1.3.6.1.2.1.1.4", &format!("{ENT}.4.1.28")])
                .await
                .unwrap();
            assert_eq!(bulk[0].oid, oid("1.3.6.1.2.1.1.4.0"));
            assert_eq!(bulk[1].oid, oid(&format!("{ENT}.4.1.29")));
            assert_eq!(bulk[2].oid, oid(&format!("{ENT}.4.1.30")));
            // Past the last object: endOfMibView.
            let end = c.get_next(["1.3.6.1.9"]).await.unwrap();
            assert_eq!(end[0].value, Value::EndOfMibView);
        }
    }
}

#[tokio::test]
async fn sets_and_access() {
    let f = agent().await;
    let target = oid(&format!("{ENT}.2.0"));
    let rw = client(&f, Community::v2c("private")).await;
    rw.set(vec![VarBind::new(target.clone(), 9)]).await.unwrap();
    assert_eq!(f.mib.value(&target), Some(Value::Integer(9)));
    let fail = |r: Result<Vec<VarBind>, Error>| match r {
        Err(Error::Snmp { status, index, .. }) => (status, index),
        r => panic!("{r:?}"),
    };
    // Wrong type, read-only, missing: nothing is set (two phases).
    assert_eq!(
        fail(
            rw.set(vec![
                VarBind::new(target.clone(), 1),
                VarBind::new(target.clone(), "x")
            ])
            .await
        ),
        (ErrorStatus::WrongType, 2)
    );
    assert_eq!(f.mib.value(&target), Some(Value::Integer(9)));
    assert_eq!(
        fail(
            rw.set(vec![VarBind::new(oid(&format!("{ENT}.1.0")), "x")])
                .await
        ),
        (ErrorStatus::NotWritable, 1)
    );
    assert_eq!(
        fail(
            rw.set(vec![VarBind::new(oid(&format!("{ENT}.8.0")), 1)])
                .await
        ),
        (ErrorStatus::NoCreation, 1)
    );
    assert_eq!(
        fail(rw.set(vec![VarBind::new(oid("1.3.6.1.6.1.0"), 1)]).await),
        (ErrorStatus::NoCreation, 1)
    );
    assert_eq!(
        fail(
            rw.set(vec![VarBind::new(
                oid(&format!("{ENT}.9.1.0")),
                Value::Counter32(1)
            )])
            .await
        ),
        (ErrorStatus::NotWritable, 1)
    );
    // Read-only community: noAccess; in v1 the same errors become
    // noSuchName / badValue (RFC 3584).
    let ro = client(&f, Community::v2c("public")).await;
    assert_eq!(
        fail(ro.set(vec![VarBind::new(target.clone(), 1)]).await),
        (ErrorStatus::NoAccess, 1)
    );
    let v1 = client(&f, Community::v1("private")).await;
    assert_eq!(
        fail(v1.set(vec![VarBind::new(target.clone(), "x")]).await),
        (ErrorStatus::BadValue, 1)
    );
    assert_eq!(
        fail(
            v1.set(vec![VarBind::new(oid(&format!("{ENT}.1.0")), "x")])
                .await
        ),
        (ErrorStatus::NoSuchName, 1)
    );
    v1.set(vec![VarBind::new(target.clone(), 11)])
        .await
        .unwrap();
    // SNMPv3: alice may write (authPriv), bob only read.
    let a = client(&f, alice()).await;
    a.set(vec![VarBind::new(target.clone(), 12)]).await.unwrap();
    assert_eq!(f.mib.value(&target), Some(Value::Integer(12)));
    let b = client(&f, bob()).await;
    assert_eq!(
        fail(b.set(vec![VarBind::new(target.clone(), 1)]).await),
        (ErrorStatus::NoAccess, 1)
    );
    // alice below authPriv: authorizationError.
    let low = UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "alice-auth")
        .unwrap();
    let l = client(&f, low).await;
    assert!(matches!(
        l.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Snmp {
            status: ErrorStatus::AuthorizationError,
            ..
        })
    ));
}

#[tokio::test]
async fn refusals() {
    let f = agent().await;
    // Unknown community: no answer.
    let c = client(&f, Community::v2c("nope")).await;
    assert!(matches!(
        c.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Timeout)
    ));
    // Unknown user, wrong password: reports.
    let c = client(&f, UsmUser::new("mallory")).await;
    assert!(matches!(
        c.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Report(ReportKind::UnknownUserName))
    ));
    let wrong = UsmUser::new("bob")
        .with_auth(AuthProtocol::Md5, "wrong-password")
        .unwrap();
    let c = client(&f, wrong).await;
    assert!(matches!(
        c.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Report(ReportKind::WrongDigest))
    ));
    // A context the agent does not have.
    let c = client(&f, Usm::new(bob()).with_context("vlan-9")).await;
    assert!(matches!(
        c.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Report(ReportKind::UnknownContext))
    ));
}

#[tokio::test]
async fn too_big_and_bulk_truncation() {
    let mib = MibTree::new();
    for i in 0..400u32 {
        mib.insert(oid(&format!("{ENT}.1.{i}")), Value::from("x".repeat(200)));
    }
    let agent = Agent::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_community("public", Access::ReadOnly)
        .register(oid(ENT), mib);
    // handle() directly: no socket needed.
    let get = |pdu| snmpify::CommunityMessage::new(snmpify::Version::V2c, "public", pdu).encode();
    let ask_all: Vec<Oid> = (0..400u32).map(|i| oid(&format!("{ENT}.1.{i}"))).collect();
    let out = agent.handle(&get(snmpify::Pdu::get(1, ask_all))).unwrap();
    let r = snmpify::CommunityMessage::decode(&out).unwrap();
    let snmpify::AnyPdu::Pdu(p) = r.pdu else {
        panic!()
    };
    assert_eq!(p.status(), ErrorStatus::TooBig);
    assert!(p.varbinds.is_empty());
    // GetBulk is cut to what fits instead.
    let out = agent
        .handle(&get(snmpify::Pdu::get_bulk(2, 0, 1000, [oid(ENT)])))
        .unwrap();
    assert!(out.len() <= 65_507);
    let snmpify::AnyPdu::Pdu(p) = snmpify::CommunityMessage::decode(&out).unwrap().pdu else {
        panic!()
    };
    assert_eq!(p.status(), ErrorStatus::NoError);
    assert!(
        p.varbinds.len() > 100 && p.varbinds.len() < 400,
        "{}",
        p.varbinds.len()
    );
    // Not answered: garbage, responses, traps, unknown versions, v3
    // without an engine.
    assert!(agent.handle(b"junk").is_none());
    let mut resp = snmpify::Pdu::get(3, [oid(ENT)]);
    resp.pdu_type = snmpify::PduType::Response;
    assert!(agent.handle(&get(resp)).is_none());
    let v1_bulk = snmpify::CommunityMessage::new(
        snmpify::Version::V1,
        "public",
        snmpify::Pdu::get_bulk(4, 0, 5, [oid(ENT)]),
    );
    assert!(agent.handle(&v1_bulk.encode()).is_none());
    let probe = snmpify::v3::V3Message {
        msg_id: 1,
        max_size: 65507,
        flags: snmpify::v3::flags::REPORTABLE,
        usm: Default::default(),
        data: snmpify::v3::ScopedPduData::Plaintext(snmpify::v3::ScopedPdu::new(
            Vec::new(),
            Vec::new(),
            snmpify::Pdu::get(1, Vec::<Oid>::new()),
        )),
    };
    assert!(agent.handle(&probe.encode()).is_none());
}

#[test]
fn mib_tree_basics() {
    let t = MibTree::new();
    assert!(t.is_empty());
    t.insert(oid("1.3.6.1.4.1.1.1.0"), 1);
    t.insert_fn(oid("1.3.6.1.4.1.1.2.0"), || Value::Gauge32(3));
    assert_eq!(t.len(), 2);
    assert_eq!(t.get(&oid("1.3.6.1.4.1.1.2.0")), Value::Gauge32(3));
    assert_eq!(t.get(&oid("1.3.6.1.4.1.1.2.1")), Value::NoSuchInstance);
    assert_eq!(t.get(&oid("1.3.6.1.4.1.1.3.0")), Value::NoSuchObject);
    assert_eq!(
        t.get_next(&oid("1.3.6.1.4.1.1.1.0")).unwrap().oid,
        oid("1.3.6.1.4.1.1.2.0")
    );
    assert!(t.get_next(&oid("1.3.6.1.4.1.1.2.0")).is_none());
    assert!(t
        .test_set(&VarBind::new(oid("1.3.6.1.4.1.1.2.0"), Value::Gauge32(1)))
        .is_err());
    assert!(t
        .commit_set(&VarBind::new(oid("1.3.6.1.4.1.1.1.0"), 1))
        .is_err());
    assert!(t.remove(&oid("1.3.6.1.4.1.1.1.0")));
    assert!(!t.remove(&oid("1.3.6.1.4.1.1.1.0")));
    assert!(format!("{t:?}").contains("1"));
    // A handler with the defaults: nothing writable.
    struct ReadOnly;
    impl MibHandler for ReadOnly {
        fn get(&self, _: &Oid) -> Value {
            Value::Integer(1)
        }
        fn get_next(&self, _: &Oid) -> Option<VarBind> {
            None
        }
    }
    let h: Arc<dyn MibHandler> = Arc::new(ReadOnly);
    let vb = VarBind::new(oid("1.3"), 1);
    assert_eq!(h.test_set(&vb), Err(ErrorStatus::NotWritable));
    assert_eq!(h.commit_set(&vb), Err(ErrorStatus::CommitFailed));
    assert_eq!(h.get(&oid("1.3")), Value::Integer(1));
    assert!(h.get_next(&oid("1.3")).is_none());
}

#[tokio::test]
async fn over_tcp() {
    let mib = MibTree::new().with_system("tcp agent", oid(ENT), "tcp-1", || 1);
    for i in 1..=300u32 {
        mib.insert(oid(&format!("{ENT}.1.{i}")), Value::from("x".repeat(100)));
    }
    let engine = LocalEngine::new(LocalEngine::generate_id()).with_user(alice());
    let agent = Arc::new(
        Agent::bind("127.0.0.1:0")
            .await
            .unwrap()
            .with_community("public", Access::ReadOnly)
            .with_engine(engine)
            .register(oid("1.3.6.1.2.1.1"), mib.clone())
            .register(oid(ENT), mib),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(agent.clone().run_tcp(listener));
    for c in [
        Client::connect_tcp(&addr, Community::v2c("public"))
            .await
            .unwrap(),
        Client::connect_tcp(&addr, alice()).await.unwrap(),
    ] {
        assert_eq!(
            c.get_one("1.3.6.1.2.1.1.5.0").await.unwrap(),
            Value::from("tcp-1")
        );
        // Messages of many kilobytes, back to back on the stream.
        let rows = c.walk_all(format!("{ENT}.1").as_str()).await.unwrap();
        assert_eq!(rows.len(), 300);
        // Concurrent requests share the connection.
        let row = format!("{ENT}.1.7");
        let (a, b) = tokio::join!(c.get_one("1.3.6.1.2.1.1.5.0"), c.get_one(row.as_str()));
        assert!(a.is_ok() && b.is_ok());
    }
    // A wrong community gets no answer: the whole budget, then a timeout.
    let c = Client::connect_tcp(&addr, Community::v2c("nope"))
        .await
        .unwrap()
        .with_options(Options {
            timeout: Duration::from_millis(100),
            retries: 1,
            max_repetitions: 10,
        });
    let t = std::time::Instant::now();
    assert!(matches!(
        c.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Timeout)
    ));
    assert!(t.elapsed() >= Duration::from_millis(200));
    // Nothing listening, and a connection the agent closes.
    let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = free.local_addr().unwrap().to_string();
    drop(free);
    assert!(matches!(
        Client::connect_tcp(&dead, Community::v2c("public")).await,
        Err(Error::Io(_))
    ));
    let closer = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let caddr = closer.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (s, _) = closer.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(s);
    });
    let c = Client::connect_tcp(&caddr, Community::v2c("public"))
        .await
        .unwrap();
    assert!(matches!(
        c.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Io(_))
    ));
    assert!(matches!(
        c.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Io(_))
    ));
}
