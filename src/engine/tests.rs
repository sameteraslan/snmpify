//! Unit tests of the authoritative engine (RFC 3414 §3.2 checks).

use super::*;
use crate::usm::{AuthProtocol, PrivProtocol};

const ENGINE: &[u8] = &[0x80, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6, 7, 8];

fn alice() -> UsmUser {
    UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "alice-auth")
        .unwrap()
        .with_privacy(PrivProtocol::Aes128, "alice-priv")
        .unwrap()
}

fn engine() -> LocalEngine {
    LocalEngine::new(ENGINE).with_boots(3).with_user(alice())
}

fn msg(engine_id: &[u8], boots: u32, time: u32, pdu: Pdu) -> V3Message {
    V3Message {
        msg_id: 77,
        max_size: 65507,
        flags: flags::REPORTABLE,
        usm: UsmParams {
            engine_id: engine_id.to_vec(),
            engine_boots: boots,
            engine_time: time,
            ..UsmParams::default()
        },
        data: ScopedPduData::Plaintext(ScopedPdu::new(engine_id, b"ctx".to_vec(), pdu)),
    }
}

fn get() -> Pdu {
    Pdu::get(5, [[1u32, 3, 6, 1, 2, 1, 1, 5, 0]])
}

fn report_kind(r: Received, keys: Option<&LocalizedUser>) -> (ReportKind, V3Message) {
    let Received::Report(b) = r else {
        panic!("{r:?}")
    };
    let m = match keys {
        Some(k) => k.open(&b).unwrap(),
        None => V3Message::decode(&b).unwrap(),
    };
    let ScopedPduData::Plaintext(s) = &m.data else {
        panic!()
    };
    assert_eq!(s.pdu.pdu_type, PduType::Report);
    (ReportKind::from_oid(&s.pdu.varbinds[0].oid), m)
}

#[test]
fn discovery_report() {
    let e = engine();
    let probe = msg(&[], 0, 0, Pdu::get(9, Vec::<crate::Oid>::new()));
    let (k, m) = report_kind(e.receive(&probe.encode()), None);
    assert_eq!(k, ReportKind::UnknownEngineId);
    assert_eq!(m.usm.engine_id, ENGINE);
    assert_eq!(m.usm.engine_boots, 3);
    assert_eq!(m.msg_id, 77);
    assert_eq!(m.flags, 0);
    assert_eq!(e.stats().get(&ReportKind::UnknownEngineId), 1);
    // Not reportable: dropped.
    let mut quiet = probe;
    quiet.flags = 0;
    assert!(matches!(e.receive(&quiet.encode()), Received::Drop(_)));
    assert_eq!(e.stats().get(&ReportKind::UnknownEngineId), 2);
}

#[test]
fn authenticated_request_and_response() {
    let e = engine();
    let keys = alice().localize(ENGINE);
    let bytes = keys.seal(msg(ENGINE, 3, e.time(), get()), 1).unwrap();
    let Received::Message(req) = e.receive(&bytes) else {
        panic!()
    };
    assert_eq!(req.level, SecurityLevel::AuthPriv);
    assert_eq!(req.user_name, b"alice");
    assert_eq!(req.context_name, b"ctx");
    assert!(req.reportable);
    assert!(format!("{req:?}").contains("alice"));
    let mut resp = req.pdu.clone();
    resp.pdu_type = PduType::Response;
    let out = e.respond(&req, resp.clone()).unwrap();
    let m = keys.open(&out).unwrap();
    assert_eq!(m.msg_id, 77);
    assert_eq!(SecurityLevel::from_flags(m.flags), SecurityLevel::AuthPriv);
    let ScopedPduData::Plaintext(s) = m.data else {
        panic!()
    };
    assert_eq!(s.pdu, resp);
    assert_eq!(s.context_name, b"ctx");
}

#[test]
fn usm_failures_are_reported() {
    let e = engine();
    // Unknown user.
    let bob = UsmUser::new("bob").localize(ENGINE);
    let (k, _) = report_kind(
        e.receive(&bob.seal(msg(ENGINE, 3, 0, get()), 0).unwrap()),
        None,
    );
    assert_eq!(k, ReportKind::UnknownUserName);
    // Wrong password.
    let wrong = UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "not-alice")
        .unwrap()
        .localize(ENGINE);
    let (k, _) = report_kind(
        e.receive(&wrong.seal(msg(ENGINE, 3, 0, get()), 0).unwrap()),
        None,
    );
    assert_eq!(k, ReportKind::WrongDigest);
    // Right auth, wrong privacy key.
    let wrong_priv = UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "alice-auth")
        .unwrap()
        .with_privacy(PrivProtocol::Aes128, "not-alice")
        .unwrap()
        .localize(ENGINE);
    let (k, _) = report_kind(
        e.receive(&wrong_priv.seal(msg(ENGINE, 3, e.time(), get()), 0).unwrap()),
        None,
    );
    assert_eq!(k, ReportKind::DecryptionError);
    // A level the user does not have.
    let plain_user = LocalEngine::new(ENGINE).with_user(UsmUser::new("alice"));
    let (k, _) = report_kind(
        plain_user.receive(
            &alice()
                .localize(ENGINE)
                .seal(msg(ENGINE, 1, 0, get()), 0)
                .unwrap(),
        ),
        None,
    );
    assert_eq!(k, ReportKind::UnsupportedSecurityLevel);
    // Garbage.
    assert!(matches!(
        e.receive(b"junk"),
        Received::Drop(DropReason::Invalid)
    ));
    // A request for another engine.
    let other = alice().localize(b"other-engine");
    let (k, _) = report_kind(
        e.receive(&other.seal(msg(b"other-engine", 1, 0, get()), 0).unwrap()),
        None,
    );
    assert_eq!(k, ReportKind::UnknownEngineId);
}

#[test]
fn time_window_report_is_authenticated() {
    let e = engine();
    let keys = alice().localize(ENGINE);
    for (boots, time) in [(2, e.time()), (3, e.time() + 1000), (4, 0)] {
        let r = e.receive(&keys.seal(msg(ENGINE, boots, time, get()), 2).unwrap());
        let (k, m) = report_kind(r, Some(&keys));
        assert_eq!(k, ReportKind::NotInTimeWindow);
        assert_eq!(
            SecurityLevel::from_flags(m.flags),
            SecurityLevel::AuthNoPriv
        );
        assert_eq!(
            (m.usm.engine_boots, m.usm.engine_time / 10),
            (3, e.time() / 10)
        );
    }
    assert_eq!(e.stats().get(&ReportKind::NotInTimeWindow), 3);
    // An engine at the last boot accepts nothing authenticated.
    let done = LocalEngine::new(ENGINE)
        .with_boots(u32::MAX)
        .with_user(alice());
    assert_eq!(done.boots(), i32::MAX as u32);
    let r = done.receive(
        &keys
            .seal(msg(ENGINE, i32::MAX as u32, 0, get()), 2)
            .unwrap(),
    );
    assert!(matches!(r, Received::Report(_)));
}

#[test]
fn traps_from_other_engines() {
    let e = engine();
    let sender = b"\x80\x00\x00\x00\x05remote".to_vec();
    let keys = alice().localize(&sender);
    let trap = |boots, time| {
        let mut p = get();
        p.pdu_type = PduType::TrapV2;
        let mut m = msg(&sender, boots, time, p);
        m.flags = 0;
        keys.seal(m, 3).unwrap()
    };
    let Received::Message(r) = e.receive(&trap(5, 1000)) else {
        panic!()
    };
    assert_eq!(r.engine_id, sender);
    assert!(!r.reportable);
    // Later and slightly earlier ones pass; much older ones are replays.
    assert!(matches!(e.receive(&trap(5, 1100)), Received::Message(_)));
    assert!(matches!(e.receive(&trap(5, 1000)), Received::Message(_)));
    assert!(matches!(
        e.receive(&trap(5, 900)),
        Received::Drop(DropReason::NotInTimeWindow)
    ));
    assert!(matches!(
        e.receive(&trap(4, 5000)),
        Received::Drop(DropReason::NotInTimeWindow)
    ));
    assert!(matches!(e.receive(&trap(6, 1)), Received::Message(_)));
    // A Get under another engine id is not taken (reportable: a report;
    // not reportable: dropped).
    let mut m = msg(&sender, 6, 2, get());
    m.flags = 0;
    let get_msg = keys.seal(m, 4).unwrap();
    assert!(matches!(
        e.receive(&get_msg),
        Received::Drop(DropReason::WrongPduForEngine)
    ));
    // Wrong key for the remote engine.
    let wrong = UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "not-alice")
        .unwrap()
        .localize(&sender);
    let mut p = get();
    p.pdu_type = PduType::TrapV2;
    let mut m = msg(&sender, 6, 3, p);
    m.flags = 0;
    assert!(matches!(
        e.receive(&wrong.seal(m, 0).unwrap()),
        Received::Drop(DropReason::Usm(UsmError::WrongDigest))
    ));
}

#[test]
fn originate_and_ids() {
    let e = engine();
    let mut p = get();
    p.pdu_type = PduType::TrapV2;
    let b = e.originate(b"alice", 9, b"", p.clone()).unwrap();
    let m = alice().localize(ENGINE).open(&b).unwrap();
    assert_eq!(m.usm.engine_id, ENGINE);
    assert_eq!(m.usm.engine_boots, 3);
    assert_eq!(
        e.originate(b"nobody", 9, b"", p),
        Err(UsmError::UnknownUserName)
    );
    let id = LocalEngine::generate_id();
    assert_eq!(id.len(), 13);
    assert_eq!(&id[..5], &[0x80, 0, 0, 0, 5]);
    assert_ne!(id, LocalEngine::generate_id());
    assert!(e.uptime() < 100);
    assert!(format!("{e:?}").contains("alice"));
    for r in [
        DropReason::Invalid,
        DropReason::Usm(UsmError::WrongDigest),
        DropReason::NotInTimeWindow,
        DropReason::WrongPduForEngine,
    ] {
        assert!(!r.to_string().is_empty());
    }
}
