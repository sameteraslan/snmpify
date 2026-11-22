//! The SNMPv3 client against an in-process USM agent built from the
//! crate's own wire format and `usm` module: discovery, time windows,
//! engine changes, forged and stale answers, reports, contexts.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snmpify::client::{Client, Error, Manager, Options, Usm};
use snmpify::usm::{AuthProtocol, LocalizedUser, PrivProtocol, SecurityLevel, UsmUser};
use snmpify::v3::{flags, ReportKind, ScopedPdu, ScopedPduData, UsmParams, V3Message};
use snmpify::{Pdu, PduType, Value, VarBind};
use tokio::net::UdpSocket;

const ENGINE: &[u8] = &[0x80, 0x00, 0x1f, 0x88, 0x80, 0xaa, 0xbb, 0xcc, 0xdd];

struct State {
    engine_id: Vec<u8>,
    boots: u32,
    time: u32,
    /// Boots and time announced at discovery (some agents send zeros).
    discovery: Option<(u32, u32)>,
    users: Vec<UsmUser>,
    probes: usize,
    salt: u64,
}

impl State {
    fn new(users: Vec<UsmUser>) -> Self {
        State {
            engine_id: ENGINE.to_vec(),
            boots: 5,
            time: 10_000,
            discovery: None,
            users,
            probes: 0,
            salt: 0,
        }
    }

    fn keys(&self, name: &[u8]) -> Option<LocalizedUser> {
        self.users
            .iter()
            .find(|u| u.name() == name)
            .map(|u| u.localize(&self.engine_id))
    }

    fn report_msg(
        &self,
        msg_id: i32,
        request_id: i32,
        kind: ReportKind,
        boots_time: (u32, u32),
    ) -> V3Message {
        V3Message {
            msg_id,
            max_size: 65507,
            flags: 0,
            usm: UsmParams {
                engine_id: self.engine_id.clone(),
                engine_boots: boots_time.0,
                engine_time: boots_time.1,
                ..UsmParams::default()
            },
            data: ScopedPduData::Plaintext(ScopedPdu::new(
                self.engine_id.clone(),
                Vec::new(),
                Pdu {
                    pdu_type: PduType::Report,
                    request_id,
                    error_status: 0,
                    error_index: 0,
                    varbinds: vec![VarBind::new(kind.oid(), Value::Counter32(1))],
                },
            )),
        }
    }

    /// What a USM agent answers (RFC 3414 §3.2), or nothing.
    fn process(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        let msg = V3Message::decode(bytes).ok()?;
        let rid = match &msg.data {
            ScopedPduData::Plaintext(s) => s.pdu.request_id,
            ScopedPduData::Encrypted(_) => 0,
        };
        if msg.usm.engine_id != self.engine_id {
            self.probes += 1;
            let bt = self.discovery.unwrap_or((self.boots, self.time));
            return Some(
                self.report_msg(msg.msg_id, rid, ReportKind::UnknownEngineId, bt)
                    .encode(),
            );
        }
        let now = (self.boots, self.time);
        let Some(keys) = self.keys(&msg.usm.user_name) else {
            return Some(
                self.report_msg(msg.msg_id, rid, ReportKind::UnknownUserName, now)
                    .encode(),
            );
        };
        let opened = match keys.open(bytes) {
            Ok(m) => m,
            Err(snmpify::usm::UsmError::WrongDigest) => {
                return Some(
                    self.report_msg(msg.msg_id, rid, ReportKind::WrongDigest, now)
                        .encode(),
                )
            }
            Err(_) => return None,
        };
        let level = SecurityLevel::from_flags(opened.flags);
        if level < keys.level() {
            return Some(
                self.report_msg(msg.msg_id, rid, ReportKind::UnsupportedSecurityLevel, now)
                    .encode(),
            );
        }
        self.salt += 1;
        if level != SecurityLevel::NoAuthNoPriv
            && (opened.usm.engine_boots != self.boots
                || opened.usm.engine_time.abs_diff(self.time) > 150)
        {
            // Authenticated, with the right time, so the client can resync.
            let r = self.report_msg(msg.msg_id, rid, ReportKind::NotInTimeWindow, now);
            return keys.seal(r, self.salt).ok();
        }
        let ScopedPduData::Plaintext(s) = opened.data else {
            return None;
        };
        let ctx = String::from_utf8_lossy(&s.context_name).into_owned();
        let response = Pdu {
            pdu_type: PduType::Response,
            request_id: s.pdu.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: s
                .pdu
                .varbinds
                .iter()
                .map(|vb| VarBind::new(vb.oid.clone(), Value::from(format!("{}@{ctx}", vb.oid))))
                .collect(),
        };
        let out = V3Message {
            msg_id: msg.msg_id,
            max_size: 65507,
            flags: 0,
            usm: UsmParams {
                engine_boots: self.boots,
                engine_time: self.time,
                ..UsmParams::default()
            },
            data: ScopedPduData::Plaintext(ScopedPdu::new(
                self.engine_id.clone(),
                s.context_name,
                response,
            )),
        };
        keys.seal(out, self.salt).ok()
    }
}

/// Given the request number, the state and the request, what to send back.
type Hook = Arc<dyn Fn(usize, &mut State, &[u8]) -> Vec<Vec<u8>> + Send + Sync>;

struct Agent {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    state: Arc<Mutex<State>>,
}

fn normal() -> Hook {
    Arc::new(|_, st, b| st.process(b).into_iter().collect())
}

async fn agent(state: State, hook: Hook) -> Agent {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(Mutex::new(state));
    let (count, st) = (requests.clone(), state.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await.unwrap();
            let i = count.fetch_add(1, Ordering::SeqCst);
            let out = hook(i, &mut st.lock().unwrap(), &buf[..n]);
            for b in out {
                socket.send_to(&b, from).await.unwrap();
            }
        }
    });
    Agent {
        addr,
        requests,
        state,
    }
}

fn alice() -> UsmUser {
    UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "alice-auth")
        .unwrap()
        .with_privacy(PrivProtocol::Aes128, "alice-priv")
        .unwrap()
}

fn fast() -> Options {
    Options {
        timeout: Duration::from_millis(200),
        retries: 1,
        max_repetitions: 10,
    }
}

async fn client(a: &Agent, user: impl Into<snmpify::client::Credentials>) -> Client {
    Client::connect(&a.addr.to_string(), user)
        .await
        .unwrap()
        .with_options(fast())
}

const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";

#[tokio::test]
async fn discovers_once_for_many_concurrent_requests() {
    let a = agent(State::new(vec![alice()]), normal()).await;
    let c = client(&a, alice()).await;
    assert_eq!(c.engine_id(), None);
    let mut tasks = Vec::new();
    for i in 0..100u32 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            let oid = format!("1.3.6.1.4.1.{i}.0");
            (oid.clone(), c.get_one(oid.as_str()).await)
        }));
    }
    for t in tasks {
        let (oid, v) = t.await.unwrap();
        assert_eq!(v.unwrap(), Value::from(format!("{oid}@")));
    }
    assert_eq!(a.state.lock().unwrap().probes, 1);
    assert_eq!(a.requests.load(Ordering::SeqCst), 101);
    assert_eq!(c.engine_id().unwrap(), ENGINE);
    assert_eq!(c.version(), snmpify::Version::V3);
}

#[tokio::test]
async fn every_level_and_protocol() {
    let mut users = vec![UsmUser::new("plain")];
    for au in AuthProtocol::ALL {
        let u = UsmUser::new(format!("{au}"))
            .with_auth(au, "auth-pass")
            .unwrap();
        users.push(u.clone());
        for p in PrivProtocol::ALL {
            users.push(
                UsmUser::new(format!("{au}-{p}"))
                    .with_auth(au, "auth-pass")
                    .unwrap()
                    .with_privacy(p, "priv-pass")
                    .unwrap(),
            );
        }
    }
    let a = agent(State::new(users.clone()), normal()).await;
    let m = Manager::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_options(fast());
    for u in users {
        let c = m.client(a.addr, u.clone());
        assert_eq!(
            c.get_one(SYS_NAME).await.unwrap(),
            Value::from(format!("{SYS_NAME}@")),
            "{u:?}"
        );
    }
}

#[tokio::test]
async fn resyncs_when_discovery_gives_no_time() {
    let mut st = State::new(vec![alice()]);
    st.discovery = Some((0, 0));
    let a = agent(st, normal()).await;
    let c = client(&a, alice()).await;
    assert!(c.get_one(SYS_NAME).await.is_ok());
    // Probe, request (not in time window), request again.
    assert_eq!(a.requests.load(Ordering::SeqCst), 3);
    // From then on, the time is right.
    assert!(c.get_one(SYS_NAME).await.is_ok());
    assert_eq!(a.requests.load(Ordering::SeqCst), 4);
    // The agent reboots: boots + 1, time from 0.
    {
        let mut s = a.state.lock().unwrap();
        s.boots += 1;
        s.time = 3;
    }
    assert!(c.get_one(SYS_NAME).await.is_ok());
    assert_eq!(a.requests.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn gives_up_when_the_clock_stays_wrong() {
    // Reports always carry a stale time: one resync, then an error.
    let hook: Hook = Arc::new(|_, st, b| {
        let out = st.process(b).into_iter().collect();
        st.time += 1000;
        out
    });
    let mut st = State::new(vec![alice()]);
    st.discovery = Some((5, 0));
    let a = agent(st, hook).await;
    let c = client(&a, alice()).await;
    assert!(matches!(
        c.get_one(SYS_NAME).await,
        Err(Error::Report(ReportKind::NotInTimeWindow))
    ));
}

#[tokio::test]
async fn rediscovers_a_changed_engine() {
    let a = agent(State::new(vec![alice()]), normal()).await;
    let c = client(&a, alice()).await;
    assert!(c.get_one(SYS_NAME).await.is_ok());
    a.state.lock().unwrap().engine_id = vec![0x80, 0, 0, 0, 1, 2, 3];
    assert!(c.get_one(SYS_NAME).await.is_ok());
    assert_eq!(c.engine_id().unwrap(), vec![0x80, 0, 0, 0, 1, 2, 3]);
    // Probe, the request under the old engine id, probe again.
    assert_eq!(a.state.lock().unwrap().probes, 3);
}

#[tokio::test]
async fn gives_up_on_an_engine_that_keeps_changing() {
    let hook: Hook = Arc::new(|i, st, b| {
        st.engine_id = vec![0x80, 0, 0, 0, i as u8 + 1];
        st.process(b).into_iter().collect()
    });
    let a = agent(State::new(vec![alice()]), hook).await;
    let c = client(&a, alice()).await;
    assert!(matches!(
        c.get_one(SYS_NAME).await,
        Err(Error::Report(ReportKind::UnknownEngineId))
    ));
}

#[tokio::test]
async fn ignores_forged_unauthenticated_and_stale_answers() {
    let hook: Hook = Arc::new(|_, st, b| {
        let Some(good) = st.process(b) else {
            return vec![];
        };
        let msg = V3Message::decode(&good).unwrap();
        if msg.flags & flags::AUTH == 0 {
            return vec![good]; // the discovery report
        }
        let request = V3Message::decode(b).unwrap();
        let response = |level_keys: &LocalizedUser, boots: u32, time: u32| {
            let m = V3Message {
                msg_id: request.msg_id,
                max_size: 65507,
                flags: 0,
                usm: UsmParams {
                    engine_boots: boots,
                    engine_time: time,
                    ..UsmParams::default()
                },
                data: ScopedPduData::Plaintext(ScopedPdu::new(
                    ENGINE,
                    Vec::new(),
                    Pdu {
                        pdu_type: PduType::Response,
                        request_id: 0,
                        error_status: 0,
                        error_index: 0,
                        varbinds: vec![VarBind::new([1, 3, 6, 1, 2, 1, 1, 5, 0], "forged")],
                    },
                )),
            };
            level_keys.seal(m, 77).unwrap()
        };
        let (boots, time) = (st.boots, st.time);
        // Wrong password.
        let wrong = UsmUser::new("alice")
            .with_auth(AuthProtocol::Sha256, "not-alice")
            .unwrap()
            .with_privacy(PrivProtocol::Aes128, "alice-priv")
            .unwrap()
            .localize(ENGINE);
        // Right keys but authNoPriv (the request was authPriv).
        let no_priv = UsmUser::new("alice")
            .with_auth(AuthProtocol::Sha256, "alice-auth")
            .unwrap()
            .localize(ENGINE);
        // No security at all.
        let plain = UsmUser::new("alice").localize(ENGINE);
        let right = alice().localize(ENGINE);
        // A trap, not a response.
        let trap = {
            let mut m = right.open(&response(&right, boots, time)).unwrap();
            if let ScopedPduData::Plaintext(sp) = &mut m.data {
                sp.pdu.pdu_type = PduType::TrapV2;
            }
            right.seal(m, 78).unwrap()
        };
        let mut flipped = good.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        vec![
            response(&wrong, boots, time),
            response(&no_priv, boots, time),
            response(&plain, boots, time),
            response(&right, boots - 1, time), // previous boot: a replay
            response(&right, boots, time - 1000), // far in the past
            trap,
            flipped, // altered in transit
            b"not snmp at all".to_vec(),
            good,
        ]
    });
    let a = agent(State::new(vec![alice()]), hook).await;
    let c = client(&a, alice()).await;
    assert_eq!(
        c.get_one(SYS_NAME).await.unwrap(),
        Value::from(format!("{SYS_NAME}@"))
    );
    assert_eq!(
        a.requests.load(Ordering::SeqCst),
        2,
        "answered on the first try"
    );
}

#[tokio::test]
async fn reports_become_errors() {
    let a = agent(State::new(vec![alice()]), normal()).await;
    let report = |r: Result<Value, Error>| match r {
        Err(Error::Report(k)) => k,
        r => panic!("{r:?}"),
    };
    let c = client(&a, UsmUser::new("mallory")).await;
    assert_eq!(
        report(c.get_one(SYS_NAME).await),
        ReportKind::UnknownUserName
    );
    let wrong = UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "not-alice")
        .unwrap();
    let c = client(&a, wrong).await;
    assert_eq!(report(c.get_one(SYS_NAME).await), ReportKind::WrongDigest);
    let lower = UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "alice-auth")
        .unwrap();
    let c = client(&a, lower).await;
    assert_eq!(
        report(c.get_one(SYS_NAME).await),
        ReportKind::UnsupportedSecurityLevel
    );
    let e = c.get_one(SYS_NAME).await.unwrap_err();
    assert!(e.to_string().contains("unsupported security level"), "{e}");
}

#[tokio::test]
async fn contexts_reach_the_agent() {
    let a = agent(State::new(vec![alice()]), normal()).await;
    let c = client(&a, Usm::new(alice()).with_context("vlan-10")).await;
    assert_eq!(
        c.get_one(SYS_NAME).await.unwrap(),
        Value::from(format!("{SYS_NAME}@vlan-10"))
    );
}

#[tokio::test]
async fn walks_over_v3() {
    // GetBulk walk: the agent answers each binding with itself, so make
    // it a table agent by rewriting GetBulk answers.
    let hook: Hook = Arc::new(|_, st, b| {
        let msg = V3Message::decode(b).unwrap();
        if msg.usm.engine_id != st.engine_id {
            return st.process(b).into_iter().collect();
        }
        let keys = st.keys(b"alice").unwrap();
        let m = keys.open(b).unwrap();
        let ScopedPduData::Plaintext(s) = m.data else {
            panic!()
        };
        assert_eq!(s.pdu.pdu_type, PduType::GetBulk);
        let start = s.pdu.varbinds[0].oid.clone();
        let max = s.pdu.max_repetitions() as usize;
        let mut rows: Vec<VarBind> = (1..=25u32)
            .map(|i| VarBind::new([1, 3, 6, 1, 9, 1, i], i as i32))
            .filter(|vb| vb.oid > start)
            .take(max)
            .collect();
        if rows.len() < max {
            rows.push(VarBind::new([1, 3, 6, 1, 10], 0)); // past the table
        }
        let out = V3Message {
            msg_id: m.msg_id,
            max_size: 65507,
            flags: 0,
            usm: UsmParams {
                engine_boots: st.boots,
                engine_time: st.time,
                ..UsmParams::default()
            },
            data: ScopedPduData::Plaintext(ScopedPdu::new(
                ENGINE,
                Vec::new(),
                Pdu {
                    pdu_type: PduType::Response,
                    request_id: s.pdu.request_id,
                    error_status: 0,
                    error_index: 0,
                    varbinds: rows,
                },
            )),
        };
        vec![keys.seal(out, 1).unwrap()]
    });
    let a = agent(State::new(vec![alice()]), hook).await;
    let c = client(&a, alice()).await;
    let all = c.walk_all("1.3.6.1.9").await.unwrap();
    assert_eq!(all.len(), 25);
    // The same through views (SNMPv3 goes through the owned decoder).
    let mut seen = Vec::new();
    let n = c
        .walk_with("1.3.6.1.9", |vb| seen.push(vb.oid.to_oid().unwrap()))
        .await
        .unwrap();
    assert_eq!(n, 25);
    assert_eq!(
        seen,
        all.iter().map(|vb| vb.oid.clone()).collect::<Vec<_>>()
    );
    // Probe + 3 bulks of 10, twice.
    assert_eq!(a.requests.load(Ordering::SeqCst), 7);
}

#[tokio::test]
async fn many_agents_one_user_one_socket() {
    let user = alice();
    let m = Manager::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_options(fast());
    let mut agents = Vec::new();
    for i in 0..40u8 {
        let mut st = State::new(vec![user.clone()]);
        st.engine_id = vec![0x80, 0, 0x1f, 0x88, 0x80, i];
        agents.push(agent(st, normal()).await);
    }
    let mut tasks = Vec::new();
    for a in &agents {
        let c = m.client(a.addr, user.clone());
        tasks.push(tokio::spawn(async move {
            (c.get_one(SYS_NAME).await.is_ok(), c.engine_id().unwrap())
        }));
    }
    for (i, t) in tasks.into_iter().enumerate() {
        let (ok, engine) = t.await.unwrap();
        assert!(ok);
        assert_eq!(engine, vec![0x80, 0, 0x1f, 0x88, 0x80, i as u8]);
    }
}

#[tokio::test]
async fn broken_agents() {
    // Discovery answered without an engine id, or with a Response.
    for response in [false, true] {
        let hook: Hook = Arc::new(move |_, st, b| {
            let msg = V3Message::decode(b).unwrap();
            let mut r = st.report_msg(msg.msg_id, 0, ReportKind::UnknownEngineId, (1, 1));
            r.usm.engine_id.clear();
            if let ScopedPduData::Plaintext(s) = &mut r.data {
                if response {
                    s.pdu.pdu_type = PduType::Response;
                }
            }
            vec![r.encode()]
        });
        let a = agent(State::new(vec![alice()]), hook).await;
        let c = client(&a, UsmUser::new("x")).await;
        let r = c.get_one(SYS_NAME).await;
        assert!(matches!(r, Err(Error::UnexpectedResponse(_))), "{r:?}");
    }

    // A report without bindings.
    let hook: Hook = Arc::new(|_, st, b| {
        let msg = V3Message::decode(b).unwrap();
        if msg.usm.engine_id.is_empty() {
            return st.process(b).into_iter().collect();
        }
        let mut r = st.report_msg(msg.msg_id, 0, ReportKind::UnknownUserName, (5, 10_000));
        if let ScopedPduData::Plaintext(s) = &mut r.data {
            s.pdu.varbinds.clear();
        }
        vec![r.encode()]
    });
    let a = agent(State::new(vec![]), hook).await;
    let c = client(&a, UsmUser::new("x")).await;
    assert!(matches!(
        c.get_one(SYS_NAME).await,
        Err(Error::Report(ReportKind::Other(_)))
    ));

    // A response with another request id.
    let hook: Hook = Arc::new(|_, st, b| {
        let Some(out) = st.process(b) else {
            return vec![];
        };
        let m = V3Message::decode(&out).unwrap();
        if m.flags & flags::AUTH == 0 {
            return vec![out];
        }
        let keys = st.keys(b"alice").unwrap();
        let mut m = keys.open(&out).unwrap();
        if let ScopedPduData::Plaintext(s) = &mut m.data {
            s.pdu.request_id ^= 1;
        }
        vec![keys.seal(m, 3).unwrap()]
    });
    let a = agent(State::new(vec![alice()]), hook).await;
    let c = client(&a, alice()).await;
    assert!(matches!(
        c.get_one(SYS_NAME).await,
        Err(Error::UnexpectedResponse(_))
    ));

    // No answer to the probe at all.
    let a = agent(State::new(vec![alice()]), Arc::new(|_, _, _| vec![])).await;
    let c = client(&a, alice()).await;
    assert!(matches!(c.get_one(SYS_NAME).await, Err(Error::Timeout)));
    assert_eq!(a.requests.load(Ordering::SeqCst), 2);

    // A user name over 32 octets cannot be sent.
    let a = agent(State::new(vec![]), normal()).await;
    let c = client(&a, UsmUser::new([b'n'; 33])).await;
    assert!(matches!(c.get_one(SYS_NAME).await, Err(Error::Usm(_))));
}
