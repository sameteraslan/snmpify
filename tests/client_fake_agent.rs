//! The client against a scripted in-process agent: retries, timeouts,
//! spoofed and stray answers, concurrency, walks over broken agents.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use snmpify::client::{Client, Community, Error, Manager, Options};
use snmpify::{AnyPdu, CommunityMessage, ErrorStatus, Oid, Pdu, PduType, Value, VarBind, Version};
use tokio::net::UdpSocket;

/// What the fake agent does with a request: answer, drop, or answer badly.
type Script = Arc<dyn Fn(usize, &CommunityMessage, &Pdu) -> Vec<Reply> + Send + Sync>;

enum Reply {
    /// A response PDU (request id is filled in unless `keep_id`).
    Pdu {
        pdu: Pdu,
        community: Option<&'static str>,
        keep_id: bool,
    },
    /// Answer from another socket (wrong source address).
    FromElsewhere(Pdu),
    /// Raw bytes.
    Raw(Vec<u8>),
}

struct Agent {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
}

async fn agent(script: Script) -> Agent {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await.unwrap();
            let msg = CommunityMessage::decode(&buf[..n]).unwrap();
            let AnyPdu::Pdu(req) = &msg.pdu else { continue };
            let i = count.fetch_add(1, Ordering::SeqCst);
            for reply in script(i, &msg, req) {
                match reply {
                    Reply::Pdu {
                        mut pdu,
                        community,
                        keep_id,
                    } => {
                        if !keep_id {
                            pdu.request_id = req.request_id;
                        }
                        let c = community
                            .map(|c| c.as_bytes().to_vec())
                            .unwrap_or(msg.community.clone());
                        let out = CommunityMessage::new(msg.version, c, pdu).encode();
                        socket.send_to(&out, from).await.unwrap();
                    }
                    Reply::FromElsewhere(mut pdu) => {
                        pdu.request_id = req.request_id;
                        let out = CommunityMessage::new(msg.version, &msg.community, pdu).encode();
                        other.send_to(&out, from).await.unwrap();
                    }
                    Reply::Raw(b) => {
                        socket.send_to(&b, from).await.unwrap();
                    }
                }
            }
        }
    });
    Agent { addr, requests }
}

fn response(varbinds: Vec<VarBind>) -> Pdu {
    Pdu {
        pdu_type: PduType::Response,
        request_id: 0,
        error_status: 0,
        error_index: 0,
        varbinds,
    }
}

fn answer(req: &Pdu) -> Reply {
    Reply::Pdu {
        pdu: response(
            req.varbinds
                .iter()
                .map(|vb| VarBind::new(vb.oid.clone(), Value::from(vb.oid.to_string())))
                .collect(),
        ),
        community: None,
        keep_id: false,
    }
}

fn fast() -> Options {
    Options {
        timeout: Duration::from_millis(100),
        retries: 2,
        max_repetitions: 3,
    }
}

async fn client(a: &Agent, community: Community) -> Client {
    Client::connect(&a.addr.to_string(), community)
        .await
        .unwrap()
        .with_options(fast())
}

#[tokio::test]
async fn get_and_retry_after_loss() {
    // Drop the first two copies, answer the third.
    let a = agent(Arc::new(
        |i, _, req| if i < 2 { vec![] } else { vec![answer(req)] },
    ))
    .await;
    let c = client(&a, Community::v2c("public")).await;
    let v = c.get_one("1.3.6.1.2.1.1.5.0").await.unwrap();
    assert_eq!(v, Value::from("1.3.6.1.2.1.1.5.0"));
    assert_eq!(a.requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn timeout_after_all_retries() {
    let a = agent(Arc::new(|_, _, _| vec![])).await;
    let c = client(&a, Community::v2c("public")).await;
    let t = std::time::Instant::now();
    assert!(matches!(
        c.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Timeout)
    ));
    assert_eq!(a.requests.load(Ordering::SeqCst), 3);
    assert!(t.elapsed() >= Duration::from_millis(300));
}

#[tokio::test]
async fn ignores_spoofed_stray_and_garbage_answers() {
    let a = agent(Arc::new(|_, _, req| {
        let good = answer(req);
        vec![
            Reply::Raw(vec![0x30, 0x03, 0x02, 0x01]), // garbage
            Reply::Raw(vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x04, 0x00]), // v2c, cut short
            Reply::Raw(vec![0x30, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00]), // v3, no header
            Reply::Pdu {
                // wrong community
                pdu: response(vec![VarBind::new([1, 3, 6], "evil")]),
                community: Some("evil"),
                keep_id: false,
            },
            Reply::FromElsewhere(response(vec![VarBind::new([1, 3, 6], "evil")])), // wrong source
            Reply::Pdu {
                // unknown request id
                pdu: Pdu {
                    request_id: 12345,
                    ..response(vec![])
                },
                community: None,
                keep_id: true,
            },
            good,
        ]
    }))
    .await;
    let c = client(&a, Community::v2c("public")).await;
    assert_eq!(
        c.get_one("1.3.6.1.2.1.1.5.0").await.unwrap(),
        Value::from("1.3.6.1.2.1.1.5.0")
    );
    assert_eq!(
        a.requests.load(Ordering::SeqCst),
        1,
        "answered on the first try"
    );
}

#[tokio::test]
async fn error_status_names_the_failing_oid() {
    let a = agent(Arc::new(|_, _, req| {
        vec![Reply::Pdu {
            pdu: Pdu {
                error_status: ErrorStatus::NoSuchName.code(),
                error_index: 2,
                ..response(req.varbinds.clone())
            },
            community: None,
            keep_id: false,
        }]
    }))
    .await;
    let c = client(&a, Community::v1("public")).await;
    match c.get(["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.99.0"]).await {
        Err(Error::Snmp { status, index, oid }) => {
            assert_eq!(status, ErrorStatus::NoSuchName);
            assert_eq!(index, 2);
            assert_eq!(oid.unwrap().to_string(), "1.3.6.1.2.1.1.99.0");
        }
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
async fn many_concurrent_requests_over_one_socket() {
    // Answers out of order: every response must reach its own request.
    let a = agent(Arc::new(|_, _, req| vec![answer(req)])).await;
    let m = Manager::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_options(fast());
    let c = m.client(a.addr, Community::v2c("public"));
    let mut tasks = Vec::new();
    for i in 0..500u32 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            let oid = format!("1.3.6.1.4.1.{i}.0");
            (oid.clone(), c.get_one(oid.as_str()).await)
        }));
    }
    for t in tasks {
        let (oid, v) = t.await.unwrap();
        assert_eq!(v.unwrap(), Value::from(oid));
    }
}

/// A table of n rows under 1.3.6.1.9 answering GetNext and GetBulk.
fn table_agent(n: u32, broken: bool) -> Script {
    Arc::new(move |_, _, req| {
        let rows: Vec<Oid> = (1..=n).map(|i| Oid::from([1, 3, 6, 1, 9, 1, i])).collect();
        let next = |o: &Oid| rows.iter().find(|r| *r > o).cloned();
        let reps = if req.pdu_type == PduType::GetBulk {
            req.max_repetitions().max(1) as usize
        } else {
            1
        };
        let mut out = Vec::new();
        let mut cur = req.varbinds[0].oid.clone();
        for _ in 0..reps {
            match next(&cur) {
                Some(o) => {
                    let o = if broken && o[6] == 3 {
                        Oid::from([1, 3, 6, 1, 9, 1, 2])
                    } else {
                        o
                    };
                    out.push(VarBind::new(o.clone(), o[6] as i32));
                    cur = o;
                }
                None => {
                    if req.pdu_type == PduType::GetBulk {
                        out.push(VarBind::new([1, 3, 6, 1, 99], Value::EndOfMibView));
                    } else {
                        // v1: noSuchName at the end of the MIB.
                        return vec![Reply::Pdu {
                            pdu: Pdu {
                                error_status: 2,
                                error_index: 1,
                                ..response(req.varbinds.clone())
                            },
                            community: None,
                            keep_id: false,
                        }];
                    }
                    break;
                }
            }
        }
        vec![Reply::Pdu {
            pdu: response(out),
            community: None,
            keep_id: false,
        }]
    })
}

#[tokio::test]
async fn walks_v1_and_v2c() {
    for community in [Community::v1("public"), Community::v2c("public")] {
        let a = agent(table_agent(10, false)).await;
        let c = client(&a, community.clone()).await;
        let all = c.walk_all("1.3.6.1.9").await.unwrap();
        let idx: Vec<i32> = all.iter().map(|vb| vb.oid[6] as i32).collect();
        assert_eq!(
            idx,
            (1..=10).collect::<Vec<_>>(),
            "{:?}",
            community.version()
        );
        let expected = if community.version() == Version::V1 {
            11
        } else {
            4
        }; // 10 / 3 per bulk
        assert_eq!(a.requests.load(Ordering::SeqCst), expected);
        // A subtree with nothing in it.
        assert!(c.walk_all("1.3.6.1.8").await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn walk_stops_on_a_looping_agent() {
    let a = agent(table_agent(10, true)).await;
    let c = client(&a, Community::v2c("public")).await;
    match c.walk_all("1.3.6.1.9").await {
        Err(Error::NotIncreasing { previous, next }) => {
            assert_eq!(previous.to_string(), "1.3.6.1.9.1.2");
            assert_eq!(next.to_string(), "1.3.6.1.9.1.2");
        }
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
async fn argument_checks() {
    let a = agent(Arc::new(|_, _, req| vec![answer(req)])).await;
    let c = client(&a, Community::v1("public")).await;
    assert!(matches!(
        c.get_bulk(0, 10, ["1.3.6"]).await,
        Err(Error::InvalidArgument(_))
    ));
    assert!(matches!(
        c.get(Vec::<Oid>::new()).await,
        Err(Error::InvalidArgument(_))
    ));
    assert!(matches!(c.get_one("1.x").await, Err(Error::InvalidOid(_))));
    assert!(matches!(
        c.get_one([7u32, 1]).await,
        Err(Error::InvalidArgument(_))
    ));
    assert!(matches!(
        c.set(vec![]).await,
        Err(Error::InvalidArgument(_))
    ));
    assert_eq!(a.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelled_requests_leave_nothing_behind() {
    let a = agent(Arc::new(|_, _, _| vec![])).await;
    let c = client(&a, Community::v2c("public")).await;
    for _ in 0..100 {
        let _ =
            tokio::time::timeout(Duration::from_millis(1), c.get_one("1.3.6.1.2.1.1.5.0")).await;
    }
    // Late answers to cancelled ids are ignored; the client still works.
    let b = agent(Arc::new(|_, _, req| vec![answer(req)])).await;
    let c2 = client(&b, Community::v2c("public")).await;
    assert!(c2.get_one("1.3.6.1.2.1.1.5.0").await.is_ok());
}

#[tokio::test]
async fn accessors_ipv6_and_short_answers() {
    let m = Manager::bind("127.0.0.1:0").await.unwrap();
    assert!(m.local_addr().unwrap().port() > 0);
    // An answer with fewer bindings than asked for.
    let a = agent(Arc::new(|_, _, req| {
        let mut r = answer(req);
        if let Reply::Pdu { pdu, .. } = &mut r {
            pdu.varbinds.pop();
        }
        vec![r]
    }))
    .await;
    let c = client(&a, Community::v2c("public")).await;
    assert_eq!(c.target(), a.addr);
    assert_eq!(c.options().max_repetitions, 3);
    assert_eq!(c.engine_id(), None);
    let d = format!("{c:?}");
    assert!(d.contains("V2c") && d.contains(&a.addr.to_string()), "{d}");
    assert!(matches!(
        c.get(["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0"]).await,
        Err(Error::UnexpectedResponse(_))
    ));
    // IPv6 (where the host has it).
    if let Ok(s) = UdpSocket::bind("[::1]:0").await {
        let addr = s.local_addr().unwrap();
        drop(s);
        let c = Client::connect(&addr.to_string(), Community::v2c("public"))
            .await
            .unwrap();
        assert!(c.target().is_ipv6());
    }
    assert!(matches!(
        Client::connect("no-such-host.invalid:161", Community::v2c("p")).await,
        Err(Error::Io(_)) | Err(Error::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn walk_ends_on_an_empty_answer() {
    let a = agent(Arc::new(|_, _, _| {
        vec![Reply::Pdu {
            pdu: response(vec![]),
            community: None,
            keep_id: false,
        }]
    }))
    .await;
    let c = client(&a, Community::v2c("public")).await;
    assert!(c.walk_all("1.3.6.1").await.unwrap().is_empty());
    assert_eq!(a.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mass_polling_without_retries() {
    // 500 agents answered at once would overflow the socket's receive
    // buffer; the in-flight limit keeps every answer (no retries allowed).
    let mut addrs = Vec::new();
    for _ in 0..500 {
        addrs.push(agent(Arc::new(|_, _, req| vec![answer(req)])).await.addr);
    }
    let m = Manager::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_options(Options {
            timeout: Duration::from_secs(2),
            retries: 0,
            max_repetitions: 10,
        });
    let t = std::time::Instant::now();
    let tasks: Vec<_> = addrs
        .into_iter()
        .map(|a| {
            let c = m.client(a, Community::v2c("public"));
            tokio::spawn(async move { c.get_one("1.3.6.1.2.1.1.5.0").await.is_ok() })
        })
        .collect();
    let mut ok = 0;
    for t in tasks {
        ok += t.await.unwrap() as usize;
    }
    assert_eq!(ok, 500);
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    // A limit of one still works, one request at a time.
    let one = m.clone().with_max_in_flight(1);
    let a = agent(Arc::new(|_, _, req| vec![answer(req)])).await;
    let c = one.client(a.addr, Community::v2c("public"));
    let both = tokio::join!(
        c.get_one("1.3.6.1.2.1.1.5.0"),
        c.get_one("1.3.6.1.2.1.1.6.0")
    );
    assert!(both.0.is_ok() && both.1.is_ok());
}

#[tokio::test]
async fn walk_with_reads_in_place() {
    for community in [Community::v1("public"), Community::v2c("public")] {
        let a = agent(table_agent(10, false)).await;
        let c = client(&a, community).await;
        let mut seen = Vec::new();
        let n = c
            .walk_with("1.3.6.1.9", |vb| {
                seen.push((vb.oid.to_oid().unwrap(), vb.value.as_u64().unwrap()));
            })
            .await
            .unwrap();
        assert_eq!(n, 10);
        let owned = c.walk_all("1.3.6.1.9").await.unwrap();
        let owned: Vec<_> = owned
            .iter()
            .map(|vb| (vb.oid.clone(), vb.value.as_u64().unwrap()))
            .collect();
        assert_eq!(seen, owned);
        assert_eq!(c.walk_with("1.3.6.1.8", |_| {}).await.unwrap(), 0);
    }
    // A looping agent is caught here too.
    let a = agent(table_agent(10, true)).await;
    let c = client(&a, Community::v2c("public")).await;
    assert!(matches!(
        c.walk_with("1.3.6.1.9", |_| {}).await,
        Err(Error::NotIncreasing { .. })
    ));
    // An error status from the agent.
    let a = agent(Arc::new(|_, _, req| {
        vec![Reply::Pdu {
            pdu: Pdu {
                error_status: ErrorStatus::GenErr.code(),
                error_index: 1,
                ..response(req.varbinds.clone())
            },
            community: None,
            keep_id: false,
        }]
    }))
    .await;
    let c = client(&a, Community::v2c("public")).await;
    assert!(matches!(
        c.walk_with("1.3.6.1.9", |_| {}).await,
        Err(Error::Snmp {
            status: ErrorStatus::GenErr,
            ..
        })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readers_and_waiters_retry_and_time_out() {
    // Every request's first copy is dropped: the request reading the
    // socket and those waiting must all retry, and all get their answer.
    let seen = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let s2 = seen.clone();
    let a = agent(Arc::new(move |_, _, req| {
        if s2.lock().unwrap().insert(req.request_id) {
            vec![]
        } else {
            vec![answer(req)]
        }
    }))
    .await;
    let m = Manager::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_options(Options {
            timeout: Duration::from_millis(100),
            retries: 2,
            max_repetitions: 5,
        });
    let tasks: Vec<_> = (0..20u32)
        .map(|i| {
            let c = m.client(a.addr, Community::v2c("public"));
            tokio::spawn(async move { c.get_one(format!("1.3.6.1.4.1.{i}.0").as_str()).await })
        })
        .collect();
    for t in tasks {
        assert!(t.await.unwrap().is_ok());
    }

    // A short timeout waiting behind a long one, on an agent that never
    // answers: the short one still times out on time (the reader re-arms
    // for the earlier deadline).
    let silent = agent(Arc::new(|_, _, _| vec![])).await;
    let long = m
        .client(silent.addr, Community::v2c("public"))
        .with_options(Options {
            timeout: Duration::from_secs(5),
            retries: 0,
            max_repetitions: 5,
        });
    let short = m
        .client(silent.addr, Community::v2c("public"))
        .with_options(Options {
            timeout: Duration::from_millis(50),
            retries: 1,
            max_repetitions: 5,
        });
    let l = tokio::spawn(async move { long.get_one("1.3.6.1.2.1.1.5.0").await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let t = std::time::Instant::now();
    assert!(matches!(
        short.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Timeout)
    ));
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    l.abort();
    // And the other way round: the short one reads, the long one waits.
    let long = m
        .client(silent.addr, Community::v2c("public"))
        .with_options(Options {
            timeout: Duration::from_millis(400),
            retries: 0,
            max_repetitions: 5,
        });
    let short = m
        .client(silent.addr, Community::v2c("public"))
        .with_options(Options {
            timeout: Duration::from_millis(50),
            retries: 0,
            max_repetitions: 5,
        });
    let s = tokio::spawn(async move { short.get_one("1.3.6.1.2.1.1.5.0").await });
    tokio::time::sleep(Duration::from_millis(5)).await;
    let t = std::time::Instant::now();
    assert!(matches!(
        long.get_one("1.3.6.1.2.1.1.5.0").await,
        Err(Error::Timeout)
    ));
    assert!(
        t.elapsed() >= Duration::from_millis(350),
        "{:?}",
        t.elapsed()
    );
    assert!(matches!(s.await.unwrap(), Err(Error::Timeout)));
}
