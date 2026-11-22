//! A blocking API over the async client, notification receiver and agent,
//! for programs without an async runtime (and for the C and Python
//! bindings). Everything runs on one shared background runtime; do not
//! call these from inside an async context.
//!
//! ```no_run
//! use snmpify::blocking::Client;
//! use snmpify::client::Community;
//!
//! let client = Client::connect("192.0.2.1:161", Community::v2c("public"))?;
//! println!("{}", client.get_one("1.3.6.1.2.1.1.5.0")?);
//! for vb in client.walk("1.3.6.1.2.1.2.2")? {
//!     println!("{}", vb?);
//! }
//! # Ok::<(), snmpify::client::Error>(())
//! ```

use std::io;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::client::{self, Credentials, IntoOid, Options, Result};
use crate::notification::{self, Notification};
use crate::{TrapV1Pdu, Value, VarBind, Version};

/// The shared runtime the blocking API runs on (two worker threads,
/// started on first use).
pub fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("snmpify")
            .enable_all()
            .build()
            .expect("the snmpify runtime starts")
    })
}

/// A blocking client for one agent. Cloning is cheap; clones share the
/// socket and may be used from several threads at once.
#[derive(Clone, Debug)]
pub struct Client {
    inner: client::Client,
}

impl Client {
    /// A client with its own socket (`"host:port"`).
    pub fn connect(target: &str, credentials: impl Into<Credentials>) -> Result<Client> {
        let c = credentials.into();
        Ok(Client {
            inner: runtime().block_on(client::Client::connect(target, c))?,
        })
    }

    /// Wraps an async client (its socket must belong to [`runtime`]).
    pub fn from_async(inner: client::Client) -> Client {
        Client { inner }
    }

    /// The async client underneath.
    pub fn as_async(&self) -> &client::Client {
        &self.inner
    }

    /// The same client with other options.
    pub fn with_options(self, options: Options) -> Self {
        Client {
            inner: self.inner.with_options(options),
        }
    }

    /// The SNMP version.
    pub fn version(&self) -> Version {
        self.inner.version()
    }

    /// The agent's address.
    pub fn target(&self) -> SocketAddr {
        self.inner.target()
    }

    /// SNMPv3: the agent's engine id, once discovered.
    pub fn engine_id(&self) -> Option<Vec<u8>> {
        self.inner.engine_id()
    }

    /// See [`client::Client::get`].
    pub fn get<I: IntoOid>(&self, oids: impl IntoIterator<Item = I>) -> Result<Vec<VarBind>> {
        runtime().block_on(self.inner.get(oids))
    }

    /// See [`client::Client::get_one`].
    pub fn get_one(&self, oid: impl IntoOid) -> Result<Value> {
        runtime().block_on(self.inner.get_one(oid))
    }

    /// See [`client::Client::get_next`].
    pub fn get_next<I: IntoOid>(&self, oids: impl IntoIterator<Item = I>) -> Result<Vec<VarBind>> {
        runtime().block_on(self.inner.get_next(oids))
    }

    /// See [`client::Client::get_bulk`].
    pub fn get_bulk<I: IntoOid>(
        &self,
        non_repeaters: u32,
        max_repetitions: u32,
        oids: impl IntoIterator<Item = I>,
    ) -> Result<Vec<VarBind>> {
        runtime().block_on(self.inner.get_bulk(non_repeaters, max_repetitions, oids))
    }

    /// See [`client::Client::set`].
    pub fn set(&self, varbinds: Vec<VarBind>) -> Result<Vec<VarBind>> {
        runtime().block_on(self.inner.set(varbinds))
    }

    /// The subtree under `root`, one binding at a time.
    pub fn walk(&self, root: impl IntoOid) -> Result<Walk> {
        Ok(Walk {
            inner: self.inner.walk(root)?,
        })
    }

    /// The whole subtree under `root`.
    pub fn walk_all(&self, root: impl IntoOid) -> Result<Vec<VarBind>> {
        runtime().block_on(self.inner.walk_all(root))
    }

    /// See [`client::Client::trap`].
    pub fn trap(&self, trap_oid: impl IntoOid, varbinds: Vec<VarBind>) -> Result<()> {
        runtime().block_on(self.inner.trap(trap_oid, varbinds))
    }

    /// See [`client::Client::inform`].
    pub fn inform(&self, trap_oid: impl IntoOid, varbinds: Vec<VarBind>) -> Result<Vec<VarBind>> {
        runtime().block_on(self.inner.inform(trap_oid, varbinds))
    }

    /// See [`client::Client::trap_v1`].
    pub fn trap_v1(&self, trap: TrapV1Pdu) -> Result<()> {
        runtime().block_on(self.inner.trap_v1(trap))
    }
}

/// A blocking subtree walk: an iterator of bindings.
pub struct Walk {
    inner: client::Walk,
}

impl Iterator for Walk {
    type Item = Result<VarBind>;

    fn next(&mut self) -> Option<Self::Item> {
        runtime().block_on(self.inner.next())
    }
}

/// A blocking notification receiver.
pub struct NotificationReceiver {
    inner: notification::NotificationReceiver,
}

impl NotificationReceiver {
    /// Binds a receiver; configure it with the async receiver's builder
    /// methods first, then wrap it ([`from_async`](Self::from_async)), or
    /// use this for community-only receivers.
    pub fn bind(addr: &str, communities: &[&str]) -> io::Result<Self> {
        let mut r = runtime().block_on(notification::NotificationReceiver::bind(addr))?;
        for c in communities {
            r = r.with_community(c);
        }
        Ok(NotificationReceiver { inner: r })
    }

    /// Wraps a configured async receiver. It must have been bound inside
    /// [`runtime`] (e.g. `runtime().block_on(NotificationReceiver::bind(…))`).
    pub fn from_async(inner: notification::NotificationReceiver) -> Self {
        NotificationReceiver { inner }
    }

    /// The local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// The next notification, waiting at most `timeout` (`None`: forever).
    /// `Ok(None)` when the time ran out.
    pub fn recv(&mut self, timeout: Option<Duration>) -> io::Result<Option<Notification>> {
        runtime().block_on(async {
            match timeout {
                None => self.inner.recv().await.map(Some),
                Some(t) => match tokio::time::timeout(t, self.inner.recv()).await {
                    Ok(r) => r.map(Some),
                    Err(_) => Ok(None),
                },
            }
        })
    }
}

/// An agent running in the background; stopped when dropped.
pub struct RunningAgent {
    addr: SocketAddr,
    task: JoinHandle<io::Result<()>>,
}

impl RunningAgent {
    /// Starts serving an agent bound inside [`runtime`] (e.g.
    /// `runtime().block_on(Agent::bind(…))`).
    pub fn start(agent: crate::agent::Agent) -> io::Result<RunningAgent> {
        let addr = agent.local_addr()?;
        let task = runtime().spawn(async move { agent.run().await });
        Ok(RunningAgent { addr, task })
    }

    /// The agent's address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops the agent.
    pub fn stop(self) {}
}

impl Drop for RunningAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl std::fmt::Debug for RunningAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningAgent")
            .field("addr", &self.addr)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Access, Agent, MibTree};
    use crate::client::Community;

    #[test]
    fn client_agent_and_receiver_without_async() {
        let mib = MibTree::new();
        for i in 1..=12u32 {
            mib.insert(
                format!("1.3.6.1.4.1.9.1.{i}").parse().unwrap(),
                Value::Integer(i as i32),
            );
        }
        mib.insert_writable("1.3.6.1.4.1.9.2.0".parse().unwrap(), "a");
        let agent = runtime()
            .block_on(Agent::bind("127.0.0.1:0"))
            .unwrap()
            .with_community("private", Access::ReadWrite)
            .register("1.3.6.1.4.1.9".parse().unwrap(), mib.clone());
        let running = RunningAgent::start(agent).unwrap();
        assert!(format!("{running:?}").contains("addr"));
        let c = Client::connect(&running.local_addr().to_string(), Community::v2c("private"))
            .unwrap()
            .with_options(Options {
                max_repetitions: 5,
                ..Options::default()
            });
        assert_eq!(c.version(), Version::V2c);
        assert_eq!(c.target(), running.local_addr());
        assert_eq!(c.engine_id(), None);
        assert_eq!(c.get_one("1.3.6.1.4.1.9.1.3").unwrap(), Value::Integer(3));
        assert_eq!(
            c.get(["1.3.6.1.4.1.9.1.4"]).unwrap()[0].value,
            Value::Integer(4)
        );
        assert_eq!(
            c.get_next(["1.3.6.1.4.1.9.1.4"]).unwrap()[0].value,
            Value::Integer(5)
        );
        assert_eq!(c.get_bulk(0, 2, ["1.3.6.1.4.1.9.1.4"]).unwrap().len(), 2);
        assert_eq!(c.walk("1.3.6.1.4.1.9.1").unwrap().count(), 12);
        assert_eq!(c.walk_all("1.3.6.1.4.1.9.1").unwrap().len(), 12);
        c.set(vec![VarBind::new([1, 3, 6, 1, 4, 1, 9, 2, 0], "b")])
            .unwrap();
        assert_eq!(
            mib.value(&"1.3.6.1.4.1.9.2.0".parse().unwrap()),
            Some(Value::from("b"))
        );
        // Threads share one client.
        let threads: Vec<_> = (1..=4u32)
            .map(|i| {
                let c = c.clone();
                std::thread::spawn(move || {
                    c.get_one(format!("1.3.6.1.4.1.9.1.{i}").as_str()).unwrap()
                })
            })
            .collect();
        for (i, t) in threads.into_iter().enumerate() {
            assert_eq!(t.join().unwrap(), Value::Integer(i as i32 + 1));
        }

        // Notifications.
        let mut rx = NotificationReceiver::bind("127.0.0.1:0", &["public"]).unwrap();
        let tc = Client::connect(
            &rx.local_addr().unwrap().to_string(),
            Community::v2c("public"),
        )
        .unwrap();
        tc.trap("1.3.6.1.6.3.1.1.5.1", vec![]).unwrap();
        let n = rx.recv(Some(Duration::from_secs(2))).unwrap().unwrap();
        assert_eq!(n.trap_oid.to_string(), "1.3.6.1.6.3.1.1.5.1");
        assert!(rx.recv(Some(Duration::from_millis(50))).unwrap().is_none());
        let inform = std::thread::spawn(move || tc.inform("1.3.6.1.6.3.1.1.5.2", vec![]));
        assert!(rx.recv(None).unwrap().is_some());
        assert!(inform.join().unwrap().is_ok());
        let v1 = Client::connect(
            &rx.local_addr().unwrap().to_string(),
            Community::v1("public"),
        )
        .unwrap();
        v1.trap_v1(crate::notification::trap_v1(
            "1.3.6.1.4.1.9".parse().unwrap(),
            [127, 0, 0, 1].into(),
            0,
            0,
            0,
            vec![],
        ))
        .unwrap();
        assert!(rx.recv(Some(Duration::from_secs(2))).unwrap().is_some());
        assert!(c.as_async().version() == Version::V2c);
        let _ = Client::from_async(c.as_async().clone());
        let _ = NotificationReceiver::from_async(
            runtime()
                .block_on(notification::NotificationReceiver::bind("127.0.0.1:0"))
                .unwrap(),
        );
        running.stop();
    }
}
