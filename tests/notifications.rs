//! Traps and informs, v1/v2c/v3, from the client to the receiver.

use std::net::Ipv4Addr;
use std::time::Duration;

use snmpify::client::{Client, Community, Error, Options, Usm};
use snmpify::engine::LocalEngine;
use snmpify::notification::{trap_v1, NotificationKind, NotificationReceiver, Sender, SNMP_TRAPS};
use snmpify::usm::{AuthProtocol, PrivProtocol, SecurityLevel, UsmUser};
use snmpify::v3::ReportKind;
use snmpify::{Oid, Value, VarBind, Version};

const LINK_DOWN: &str = "1.3.6.1.6.3.1.1.5.3";
const IF_INDEX: [u32; 11] = [1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7];

fn alice() -> UsmUser {
    UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha512, "alice-auth")
        .unwrap()
        .with_privacy(PrivProtocol::Aes256, "alice-priv")
        .unwrap()
}

async fn receiver() -> NotificationReceiver {
    NotificationReceiver::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_community("public")
        .with_engine(LocalEngine::new(LocalEngine::generate_id()).with_user(alice()))
}

async fn to(rx: &NotificationReceiver, c: impl Into<snmpify::client::Credentials>) -> Client {
    Client::connect(&rx.local_addr().unwrap().to_string(), c)
        .await
        .unwrap()
        .with_options(Options {
            timeout: Duration::from_millis(300),
            retries: 1,
            ..Options::default()
        })
}

async fn next(rx: &mut NotificationReceiver) -> snmpify::notification::Notification {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a notification")
        .unwrap()
}

#[tokio::test]
async fn v2c_trap_and_inform() {
    let mut rx = receiver().await;
    let c = to(&rx, Community::v2c("public")).await;
    c.trap(LINK_DOWN, vec![VarBind::new(IF_INDEX, 7)])
        .await
        .unwrap();
    let n = next(&mut rx).await;
    assert_eq!(n.kind, NotificationKind::Trap);
    assert_eq!(n.version, Version::V2c);
    assert_eq!(n.sender, Sender::Community(b"public".to_vec()));
    assert_eq!(n.trap_oid.to_string(), LINK_DOWN);
    assert_eq!(n.varbinds, vec![VarBind::new(IF_INDEX, 7)]);
    assert!(n.uptime.is_some());
    assert_eq!(n.source.ip(), Ipv4Addr::LOCALHOST);

    // An inform is acknowledged: the client gets its bindings back.
    let send =
        tokio::spawn(async move { c.inform(LINK_DOWN, vec![VarBind::new(IF_INDEX, 8)]).await });
    let n = next(&mut rx).await;
    assert_eq!(n.kind, NotificationKind::Inform);
    let echoed = send.await.unwrap().unwrap();
    assert_eq!(echoed.len(), 3);
    assert_eq!(echoed[2], VarBind::new(IF_INDEX, 8));
}

#[tokio::test]
async fn v1_traps_in_v2_form() {
    let mut rx = receiver().await;
    let c = to(&rx, Community::v1("public")).await;
    let ent = Oid::from([1, 3, 6, 1, 4, 1, 99999]);
    // Generic linkDown (2) → snmpTraps.3; enterprise-specific → ent.0.42.
    c.trap_v1(trap_v1(
        ent.clone(),
        Ipv4Addr::new(192, 0, 2, 1),
        2,
        0,
        500,
        vec![VarBind::new(IF_INDEX, 3)],
    ))
    .await
    .unwrap();
    c.trap_v1(trap_v1(
        ent.clone(),
        Ipv4Addr::new(192, 0, 2, 1),
        6,
        42,
        600,
        vec![],
    ))
    .await
    .unwrap();
    let n = next(&mut rx).await;
    assert_eq!(n.version, Version::V1);
    assert_eq!(n.trap_oid, Oid::from(SNMP_TRAPS).child(&[3]));
    assert_eq!(n.uptime, Some(500));
    assert_eq!(
        n.v1.as_ref().unwrap().agent_addr,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    assert_eq!(n.varbinds, vec![VarBind::new(IF_INDEX, 3)]);
    let n = next(&mut rx).await;
    assert_eq!(n.trap_oid, ent.child(&[0, 42]));
    // v1 clients cannot send v2 traps or informs; v2c cannot send v1 traps.
    assert!(matches!(
        c.trap(LINK_DOWN, vec![]).await,
        Err(Error::InvalidArgument(_))
    ));
    assert!(matches!(
        c.inform(LINK_DOWN, vec![]).await,
        Err(Error::InvalidArgument(_))
    ));
    let v2 = to(&rx, Community::v2c("public")).await;
    assert!(matches!(
        v2.trap_v1(trap_v1(ent, Ipv4Addr::LOCALHOST, 0, 0, 0, vec![]))
            .await,
        Err(Error::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn v3_traps_from_any_engine_and_informs_to_ours() {
    let mut rx = receiver().await;
    let c = to(
        &rx,
        Usm::new(alice()).with_engine_id(b"\x80\x00\x00\x00\x05sender01".to_vec()),
    )
    .await;
    c.trap(LINK_DOWN, vec![VarBind::new(IF_INDEX, 1)])
        .await
        .unwrap();
    let n = next(&mut rx).await;
    assert_eq!(n.version, Version::V3);
    assert_eq!(
        n.sender,
        Sender::Usm {
            user: b"alice".to_vec(),
            level: SecurityLevel::AuthPriv,
            engine_id: b"\x80\x00\x00\x00\x05sender01".to_vec(),
            context_name: vec![],
        }
    );
    // A second sender with a random engine id.
    let c2 = to(&rx, alice()).await;
    c2.trap(LINK_DOWN, vec![]).await.unwrap();
    let n = next(&mut rx).await;
    let Sender::Usm { engine_id, .. } = n.sender else {
        panic!()
    };
    assert_ne!(engine_id, b"\x80\x00\x00\x00\x05sender01".to_vec());

    // Inform: the client discovers the receiver's engine first.
    let send =
        tokio::spawn(async move { c2.inform(LINK_DOWN, vec![VarBind::new(IF_INDEX, 2)]).await });
    let n = next(&mut rx).await;
    assert_eq!(n.kind, NotificationKind::Inform);
    assert_eq!(n.varbinds, vec![VarBind::new(IF_INDEX, 2)]);
    assert_eq!(send.await.unwrap().unwrap().len(), 3);
}

#[tokio::test]
async fn refused_notifications() {
    let mut rx = receiver().await;
    // Wrong community, wrong v3 password, unknown user: dropped.
    to(&rx, Community::v2c("private"))
        .await
        .trap(LINK_DOWN, vec![])
        .await
        .unwrap();
    let wrong = UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha512, "not-alice")
        .unwrap();
    to(&rx, wrong.clone())
        .await
        .trap(LINK_DOWN, vec![])
        .await
        .unwrap();
    to(&rx, UsmUser::new("mallory"))
        .await
        .trap(LINK_DOWN, vec![])
        .await
        .unwrap();
    // A Get is not a notification.
    let get = to(&rx, Community::v2c("public"))
        .await
        .with_options(Options {
            timeout: Duration::from_millis(100),
            retries: 0,
            ..Options::default()
        });
    let g = tokio::spawn(async move { get.get_one("1.3.6.1.2.1.1.5.0").await });
    // Informs with a wrong password get a report, not an ack.
    let inform = to(&rx, wrong).await;
    let i = tokio::spawn(async move { inform.inform(LINK_DOWN, vec![]).await });
    // The one good trap arrives; everything else was counted as dropped.
    tokio::time::sleep(Duration::from_millis(50)).await;
    to(&rx, Community::v2c("public"))
        .await
        .trap(LINK_DOWN, vec![VarBind::new(IF_INDEX, 9)])
        .await
        .unwrap();
    // Keep receiving until the line is quiet: informs need several rounds.
    let rx_task = tokio::spawn(async move {
        let mut notes = Vec::new();
        while let Ok(n) = tokio::time::timeout(Duration::from_millis(800), rx.recv()).await {
            notes.push(n.unwrap());
        }
        (notes, rx)
    });
    assert!(matches!(g.await.unwrap(), Err(Error::Timeout)));
    let r = i.await.unwrap();
    assert!(
        matches!(r, Err(Error::Report(ReportKind::WrongDigest))),
        "{r:?}"
    );
    let (notes, rx) = rx_task.await.unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].varbinds, vec![VarBind::new(IF_INDEX, 9)]);
    assert!(rx.dropped() >= 4, "{}", rx.dropped());
    assert!(format!("{rx:?}").contains("dropped"));
}

#[tokio::test]
async fn any_community_and_malformed_traps() {
    let mut rx = NotificationReceiver::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_any_community();
    let addr = rx.local_addr().unwrap();
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Junk, a v2 trap without snmpTrapOID.0, then a v3 message without an
    // engine configured: all dropped.
    sock.send_to(b"junk", addr).await.unwrap();
    let bad = snmpify::CommunityMessage::new(
        Version::V2c,
        "x",
        snmpify::Pdu {
            pdu_type: snmpify::PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                [1, 3, 6, 1, 2, 1, 1, 3, 0],
                Value::TimeTicks(1),
            )],
        },
    );
    sock.send_to(&bad.encode(), addr).await.unwrap();
    let mut bad_inform = bad.clone();
    if let snmpify::AnyPdu::Pdu(p) = &mut bad_inform.pdu {
        p.pdu_type = snmpify::PduType::Inform;
    }
    sock.send_to(&bad_inform.encode(), addr).await.unwrap();
    to(&rx, alice())
        .await
        .trap(LINK_DOWN, vec![])
        .await
        .unwrap();
    to(&rx, Community::v2c("anything"))
        .await
        .trap(LINK_DOWN, vec![])
        .await
        .unwrap();
    let n = next(&mut rx).await;
    assert_eq!(n.sender, Sender::Community(b"anything".to_vec()));
    assert_eq!(rx.dropped(), 4);
    assert_eq!(NotificationKind::Inform.to_string(), "inform");
}
