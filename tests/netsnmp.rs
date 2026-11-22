//! Interoperability with net-snmp's snmpd (tools/snmpd), using only the
//! codec and a std UDP socket. Skipped unless `SNMPIFY_AGENT` is set:
//!
//! ```sh
//! docker build -t snmpify-snmpd tools/snmpd
//! docker run -d --rm --name snmpify-snmpd -p 127.0.0.1:1161:161/udp snmpify-snmpd
//! SNMPIFY_AGENT=127.0.0.1:1161 cargo test --test netsnmp
//! ```

use std::net::UdpSocket;
use std::time::Duration;

use snmpify::{AnyPdu, CommunityMessage, ErrorStatus, Oid, Pdu, PduType, Value, VarBind, Version};

const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const SYS_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";
const SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
const SYS_CONTACT: &str = "1.3.6.1.2.1.1.4.0";
/// sysContact is the agent's only writable object: tests that set it and
/// read it back take turns.
static SYS_CONTACT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
const SYS_SERVICES: &str = "1.3.6.1.2.1.1.7.0";
const IF_TABLE: &str = "1.3.6.1.2.1.2.2";

fn oid(s: &str) -> Oid {
    s.parse().unwrap()
}

struct Agent {
    socket: UdpSocket,
    next_id: i32,
}

impl Agent {
    fn connect() -> Option<Agent> {
        let addr = std::env::var("SNMPIFY_AGENT").ok()?;
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(addr).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        Some(Agent {
            socket,
            next_id: 1000,
        })
    }

    fn id(&mut self) -> i32 {
        self.next_id += 1;
        self.next_id
    }

    fn send(&mut self, version: Version, community: &str, pdu: Pdu) -> Pdu {
        let id = pdu.request_id;
        let req = CommunityMessage::new(version, community, pdu).encode();
        self.socket.send(&req).unwrap();
        let mut buf = vec![0u8; 65535];
        let n = self
            .socket
            .recv(&mut buf)
            .expect("no answer from the agent");
        let msg = CommunityMessage::decode(&buf[..n]).unwrap();
        assert_eq!(msg.version, version);
        assert_eq!(msg.community, community.as_bytes());
        let AnyPdu::Pdu(pdu) = msg.pdu else {
            panic!("not a response: {:?}", msg.pdu)
        };
        assert_eq!(pdu.pdu_type, PduType::Response);
        assert_eq!(pdu.request_id, id);
        pdu
    }
}

macro_rules! agent {
    () => {
        match Agent::connect() {
            Some(a) => a,
            None => {
                eprintln!("SNMPIFY_AGENT not set; skipped");
                return;
            }
        }
    };
}

#[test]
fn get_every_system_type() {
    let mut a = agent!();
    for version in [Version::V1, Version::V2c] {
        let id = a.id();
        let r = a.send(
            version,
            "public",
            Pdu::get(
                id,
                [SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_NAME, SYS_SERVICES].map(oid),
            ),
        );
        assert_eq!(r.status(), ErrorStatus::NoError);
        let v: Vec<&Value> = r.varbinds.iter().map(|vb| &vb.value).collect();
        assert!(v[0].as_str().unwrap().starts_with("Linux"), "{:?}", v[0]);
        assert_eq!(v[1], &Value::ObjectId(oid("1.3.6.1.4.1.8072.3.2.10")));
        assert!(matches!(v[2], Value::TimeTicks(_)));
        assert_eq!(v[3], &Value::from("snmpify-agent"));
        assert_eq!(v[4], &Value::Integer(72));
    }
}

#[test]
fn missing_objects() {
    let mut a = agent!();
    let missing = oid("1.3.6.1.2.1.1.99.0");
    // v2c: an exception value per binding.
    let id = a.id();
    let r = a.send(Version::V2c, "public", Pdu::get(id, [missing.clone()]));
    assert_eq!(r.status(), ErrorStatus::NoError);
    assert_eq!(r.varbinds[0].value, Value::NoSuchObject);
    let id = a.id();
    let r = a.send(
        Version::V2c,
        "public",
        Pdu::get(id, [oid("1.3.6.1.2.1.1.5.1")]),
    );
    assert_eq!(r.varbinds[0].value, Value::NoSuchInstance);
    // v1: noSuchName for the whole PDU.
    let id = a.id();
    let r = a.send(Version::V1, "public", Pdu::get(id, [missing]));
    assert_eq!(r.status(), ErrorStatus::NoSuchName);
    assert_eq!(r.error_index, 1);
}

#[test]
fn get_next_walks_in_order_to_the_end() {
    let mut a = agent!();
    let mut cur = oid("1.3.6.1.2.1.1");
    let mut seen = Vec::new();
    loop {
        let id = a.id();
        let r = a.send(Version::V2c, "public", Pdu::get_next(id, [cur.clone()]));
        let vb = &r.varbinds[0];
        if !vb.oid.starts_with(&oid("1.3.6.1.2.1.1")) {
            break;
        }
        assert!(vb.oid > cur, "{} after {}", vb.oid, cur);
        cur = vb.oid.clone();
        seen.push(cur.clone());
    }
    assert!(seen.contains(&oid(SYS_NAME)), "{seen:?}");
    // Past the last object: endOfMibView in v2c.
    let id = a.id();
    let r = a.send(
        Version::V2c,
        "public",
        Pdu::get_next(id, [oid("1.3.6.1.6.3.99")]),
    );
    assert_eq!(r.varbinds[0].value, Value::EndOfMibView);
}

#[test]
fn get_bulk_returns_table_rows() {
    let mut a = agent!();
    let id = a.id();
    let r = a.send(
        Version::V2c,
        "public",
        // Non-repeaters get the *next* object, like GetNext: sysUpTime → sysUpTime.0.
        Pdu::get_bulk(id, 1, 20, [oid("1.3.6.1.2.1.1.3"), oid(IF_TABLE)]),
    );
    assert_eq!(r.status(), ErrorStatus::NoError);
    assert!(matches!(r.varbinds[0].value, Value::TimeTicks(_)));
    assert!(r.varbinds.len() > 2, "{}", r.varbinds.len());
    for w in r.varbinds[1..].windows(2) {
        assert!(w[1].oid > w[0].oid);
    }
    assert!(r.varbinds[1].oid.starts_with(&oid(IF_TABLE)));
}

#[test]
fn set_needs_the_write_community() {
    let mut a = agent!();
    let _turn = SYS_CONTACT_LOCK.blocking_lock();
    let value = format!("ops-{}", std::process::id());
    let id = a.id();
    let r = a.send(
        Version::V2c,
        "private",
        Pdu::set(id, vec![VarBind::new(oid(SYS_CONTACT), value.as_str())]),
    );
    assert_eq!(r.status(), ErrorStatus::NoError);
    let id = a.id();
    let r = a.send(Version::V2c, "public", Pdu::get(id, [oid(SYS_CONTACT)]));
    assert_eq!(r.varbinds[0].value, Value::from(value.as_str()));
    let id = a.id();
    let r = a.send(
        Version::V2c,
        "public",
        Pdu::set(id, vec![VarBind::new(oid(SYS_CONTACT), "nope")]),
    );
    assert_eq!(r.status(), ErrorStatus::NoAccess);
    let id = a.id();
    let r = a.send(
        Version::V2c,
        "private",
        Pdu::set(id, vec![VarBind::new(oid(SYS_CONTACT), 5)]),
    );
    assert_eq!(r.status(), ErrorStatus::WrongType);
}

#[test]
fn walks_the_whole_agent() {
    // GetBulk through everything the agent has: every value decodes.
    let mut a = agent!();
    let mut cur = oid("1.3.6.1");
    let mut count = 0usize;
    'walk: loop {
        let id = a.id();
        let r = a.send(
            Version::V2c,
            "public",
            Pdu::get_bulk(id, 0, 50, [cur.clone()]),
        );
        assert_eq!(r.status(), ErrorStatus::NoError);
        for vb in r.varbinds {
            if vb.value == Value::EndOfMibView {
                break 'walk;
            }
            assert!(vb.oid > cur);
            cur = vb.oid;
            count += 1;
        }
    }
    assert!(count > 1000, "{count}");
}

// ---------------------------------------------------------------------------
// The async client against snmpd
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
mod client {
    use super::*;
    use snmpify::client::{Client, Community, Error, Options};

    async fn client(community: Community) -> Option<Client> {
        let addr = std::env::var("SNMPIFY_AGENT").ok()?;
        Some(Client::connect(&addr, community).await.unwrap())
    }

    macro_rules! client {
        ($c:expr) => {
            match client($c).await {
                Some(c) => c,
                None => {
                    eprintln!("SNMPIFY_AGENT not set; skipped");
                    return;
                }
            }
        };
    }

    #[tokio::test]
    async fn get_set_and_errors() {
        let _turn = SYS_CONTACT_LOCK.lock().await;
        let c = client!(Community::v2c("public"));
        assert_eq!(
            c.get_one(SYS_NAME).await.unwrap(),
            Value::from("snmpify-agent")
        );
        let vbs = c
            .get([SYS_DESCR, SYS_SERVICES, "1.3.6.1.2.1.1.99.0"])
            .await
            .unwrap();
        assert!(vbs[0].value.as_str().unwrap().starts_with("Linux"));
        assert_eq!(vbs[1].value, Value::Integer(72));
        assert_eq!(vbs[2].value, Value::NoSuchObject);

        let w = client!(Community::v2c("private"));
        let contact = format!("client-{}", std::process::id());
        w.set(vec![VarBind::new(oid(SYS_CONTACT), contact.as_str())])
            .await
            .unwrap();
        assert_eq!(
            c.get_one(SYS_CONTACT).await.unwrap(),
            Value::from(contact.as_str())
        );
        match c.set(vec![VarBind::new(oid(SYS_CONTACT), "x")]).await {
            Err(Error::Snmp { status, index, .. }) => {
                assert_eq!(status, ErrorStatus::NoAccess);
                assert_eq!(index, 1);
            }
            r => panic!("{r:?}"),
        }

        let v1 = client!(Community::v1("public"));
        assert!(matches!(
            v1.get_one("1.3.6.1.2.1.1.99.0").await,
            Err(Error::Snmp {
                status: ErrorStatus::NoSuchName,
                ..
            })
        ));
        // A wrong community gets no answer at all.
        let bad = client!(Community::v2c("wrong")).with_options(Options {
            timeout: std::time::Duration::from_millis(200),
            retries: 0,
            ..Options::default()
        });
        assert!(matches!(bad.get_one(SYS_NAME).await, Err(Error::Timeout)));
    }

    #[tokio::test]
    async fn walks_match_between_versions_and_methods() {
        let v2 = client!(Community::v2c("public"));
        let v1 = client!(Community::v1("public"));
        let bulk = v2.walk_all(IF_TABLE).await.unwrap();
        let next = v1.walk_all(IF_TABLE).await.unwrap();
        assert!(!bulk.is_empty());
        // Same objects (values such as counters may move between the walks).
        let names = |v: &[VarBind]| v.iter().map(|vb| vb.oid.clone()).collect::<Vec<_>>();
        assert_eq!(names(&bulk), names(&next));
        // The whole agent, in order, ends cleanly.
        let all = v2.walk_all("1.3.6.1").await.unwrap();
        assert!(all.len() > 1000, "{}", all.len());
        assert!(all.windows(2).all(|w| w[0].oid < w[1].oid));
    }

    // -----------------------------------------------------------------------
    // SNMPv3 (users from tools/snmpd/snmpd.conf: <auth>_<priv>)
    // -----------------------------------------------------------------------

    use snmpify::client::Manager;
    use snmpify::usm::{AuthProtocol, PrivProtocol, UsmUser};
    use snmpify::v3::ReportKind;

    fn short(a: AuthProtocol) -> &'static str {
        match a {
            AuthProtocol::Md5 => "md5",
            AuthProtocol::Sha1 => "sha",
            AuthProtocol::Sha224 => "sha224",
            AuthProtocol::Sha256 => "sha256",
            AuthProtocol::Sha384 => "sha384",
            AuthProtocol::Sha512 => "sha512",
        }
    }

    fn short_priv(p: Option<PrivProtocol>) -> &'static str {
        match p {
            None => "none",
            Some(PrivProtocol::Des) => "des",
            Some(PrivProtocol::Aes128) => "aes",
            Some(PrivProtocol::Aes192) => "aes192",
            Some(PrivProtocol::Aes256) => "aes256",
            Some(p) => unreachable!("snmpd has no {p} users"),
        }
    }

    /// The test agent's user for a combination.
    fn user(a: AuthProtocol, p: Option<PrivProtocol>) -> UsmUser {
        let name = format!("{}_{}", short(a), short_priv(p));
        let u = UsmUser::new(&name)
            .with_auth(a, format!("auth-{name}"))
            .unwrap();
        match p {
            Some(p) => u.with_privacy(p, format!("priv-{name}")).unwrap(),
            None => u,
        }
    }

    fn agent_addr() -> Option<std::net::SocketAddr> {
        let a = std::env::var("SNMPIFY_AGENT").ok()?;
        Some(a.parse().unwrap())
    }

    macro_rules! addr {
        () => {
            match agent_addr() {
                Some(a) => a,
                None => {
                    eprintln!("SNMPIFY_AGENT not set; skipped");
                    return;
                }
            }
        };
    }

    #[tokio::test]
    async fn v3_every_auth_and_privacy_combination() {
        let addr = addr!();
        let m = Manager::bind("127.0.0.1:0").await.unwrap();
        let mut tasks = Vec::new();
        let mut users = vec![("noauth".to_string(), UsmUser::new("noauth"))];
        for a in AuthProtocol::ALL {
            for p in std::iter::once(None).chain(PrivProtocol::ALL.map(Some)) {
                users.push((format!("{a} / {p:?}"), user(a, p)));
            }
        }
        assert_eq!(users.len(), 31);
        for (label, u) in users {
            let c = m.client(addr, u);
            tasks.push(tokio::spawn(async move {
                let r = c.get([SYS_NAME, SYS_SERVICES]).await;
                (label, r, c.engine_id())
            }));
        }
        let mut engine = None;
        for t in tasks {
            let (label, r, e) = t.await.unwrap();
            let vbs = r.unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(vbs[0].value, Value::from("snmpify-agent"), "{label}");
            assert_eq!(vbs[1].value, Value::Integer(72), "{label}");
            // net-snmp engine ids: 0x80 | enterprise 8072, format 3+.
            let e = e.unwrap();
            assert_eq!(&e[..4], &[0x80, 0x00, 0x1f, 0x88], "{label}");
            assert_eq!(*engine.get_or_insert(e.clone()), e);
        }
    }

    #[tokio::test]
    async fn v3_set_walk_and_bulk() {
        let _turn = SYS_CONTACT_LOCK.lock().await;
        let addr = addr!();
        let c = Client::connect(
            &addr.to_string(),
            user(AuthProtocol::Sha256, Some(PrivProtocol::Aes128)),
        )
        .await
        .unwrap();
        let contact = format!("v3-{}", std::process::id());
        c.set(vec![VarBind::new(oid(SYS_CONTACT), contact.as_str())])
            .await
            .unwrap();
        assert_eq!(
            c.get_one(SYS_CONTACT).await.unwrap(),
            Value::from(contact.as_str())
        );
        // A v3 bulk walk sees what a v2c walk sees.
        let v2 = client!(Community::v2c("public"));
        let names = |v: &[VarBind]| v.iter().map(|vb| vb.oid.clone()).collect::<Vec<_>>();
        let a = c.walk_all(IF_TABLE).await.unwrap();
        assert!(!a.is_empty());
        assert_eq!(names(&a), names(&v2.walk_all(IF_TABLE).await.unwrap()));
        let bulk = c
            .get_bulk(1, 5, ["1.3.6.1.2.1.1.3", IF_TABLE])
            .await
            .unwrap();
        assert!(matches!(bulk[0].value, Value::TimeTicks(_)));
        assert_eq!(bulk.len(), 6);
        // The whole agent with DES and SHA-512 (large encrypted answers).
        let d = Client::connect(
            &addr.to_string(),
            user(AuthProtocol::Sha512, Some(PrivProtocol::Des)),
        )
        .await
        .unwrap()
        .with_options(Options {
            max_repetitions: 50,
            ..Options::default()
        });
        let all = d.walk_all("1.3.6.1").await.unwrap();
        assert!(all.len() > 1000, "{}", all.len());
    }

    #[tokio::test]
    async fn v3_errors_are_reports() {
        let addr = addr!();
        let target = addr.to_string();
        let report = |r: Result<Value, Error>| match r {
            Err(Error::Report(k)) => k,
            r => panic!("{r:?}"),
        };
        // Wrong authentication password.
        let u = UsmUser::new("sha_none")
            .with_auth(AuthProtocol::Sha1, "not-the-password")
            .unwrap();
        let c = Client::connect(&target, u).await.unwrap();
        assert_eq!(report(c.get_one(SYS_NAME).await), ReportKind::WrongDigest);
        // Wrong protocol (MD5 for a SHA user) is a wrong digest too.
        let u = UsmUser::new("sha_none")
            .with_auth(AuthProtocol::Md5, "auth-sha_none")
            .unwrap();
        let c = Client::connect(&target, u).await.unwrap();
        assert_eq!(report(c.get_one(SYS_NAME).await), ReportKind::WrongDigest);
        // Unknown user.
        let c = Client::connect(&target, UsmUser::new("nobody"))
            .await
            .unwrap();
        assert_eq!(
            report(c.get_one(SYS_NAME).await),
            ReportKind::UnknownUserName
        );
        // Privacy for a user that has none.
        let u = UsmUser::new("md5_none")
            .with_auth(AuthProtocol::Md5, "auth-md5_none")
            .unwrap()
            .with_privacy(PrivProtocol::Aes128, "priv-md5_none")
            .unwrap();
        let c = Client::connect(&target, u).await.unwrap();
        assert_eq!(
            report(c.get_one(SYS_NAME).await),
            ReportKind::UnsupportedSecurityLevel
        );
        // Wrong privacy password: snmpd drops what it cannot decrypt
        // (net-snmp's own snmpget times out the same way).
        let u = UsmUser::new("sha_aes")
            .with_auth(AuthProtocol::Sha1, "auth-sha_aes")
            .unwrap()
            .with_privacy(PrivProtocol::Aes128, "wrong-priv-password")
            .unwrap();
        let c = Client::connect(&target, u)
            .await
            .unwrap()
            .with_options(Options {
                timeout: std::time::Duration::from_millis(300),
                retries: 0,
                ..Options::default()
            });
        assert!(matches!(c.get_one(SYS_NAME).await, Err(Error::Timeout)));
        // A level below the user's access (noAuthNoPriv for an auth user):
        // VACM refuses.
        let c = Client::connect(&target, UsmUser::new("md5_none"))
            .await
            .unwrap();
        assert!(matches!(
            c.get_one(SYS_NAME).await,
            Err(Error::Snmp {
                status: ErrorStatus::AuthorizationError,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn standard_mibs_name_what_snmpd_serves() {
        let c = client!(Community::v2c("public"));
        let mib = snmpify::mib::Mib::standard();
        let all = c.walk_all("1.3.6.1").await.unwrap();
        let named = all
            .iter()
            .filter(|vb| {
                mib.lookup(&vb.oid)
                    .is_some_and(|(o, _)| !o.module.is_empty() && o.base.is_some())
            })
            .count();
        // Everything snmpd serves is in the built-in modules, bar a few
        // net-snmp extras.
        assert!(named * 100 / all.len() >= 95, "{named} of {}", all.len());
        let text = |oid: &str| {
            let vb = all.iter().find(|vb| vb.oid.to_string() == oid).unwrap();
            mib.format(vb)
        };
        assert_eq!(
            text("1.3.6.1.2.1.1.5.0"),
            "SNMPv2-MIB::sysName.0 = snmpify-agent"
        );
        assert_eq!(
            text("1.3.6.1.2.1.1.2.0"),
            "SNMPv2-MIB::sysObjectID.0 = NET-SNMP-TC::linux"
        );
        assert_eq!(
            text("1.3.6.1.2.1.2.2.1.8.1"),
            "IF-MIB::ifOperStatus.1 = up(1)"
        );
        assert_eq!(
            text("1.3.6.1.2.1.2.2.1.3.1"),
            "IF-MIB::ifType.1 = softwareLoopback(24)"
        );
    }
}
