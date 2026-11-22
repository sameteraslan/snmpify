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
