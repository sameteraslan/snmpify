# snmpify

[![CI](https://github.com/snmp-rs/snmpify/actions/workflows/ci.yml/badge.svg)](https://github.com/snmp-rs/snmpify/actions/workflows/ci.yml)
[![CodeQL](https://github.com/snmp-rs/snmpify/actions/workflows/codeql.yml/badge.svg)](https://github.com/snmp-rs/snmpify/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/snmp-rs/snmpify/badge)](https://scorecard.dev/viewer/?uri=github.com/snmp-rs/snmpify)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](Cargo.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Fast, safe SNMP for Rust, Python, C and C++.**

> **Status:** early. Done: the SNMP wire format, an async client for
> SNMPv1, v2c and v3 (get, get-next, get-bulk, set, walks, mass polling
> over one socket; USM with every standard authentication and privacy
> protocol), notifications (sending and receiving traps and informs in
> every version), the agent side (a v1/v2c/v3 agent and an AgentX
> subagent), and MIBs (55 standard modules built in, vendor MIB files
> loaded at run time), all tested against net-snmp, with Python bindings
> (`pip install snmpify`, blocking and asyncio) and a C/C++ API (CMake,
> pkg-config; Linux, macOS, Windows), benchmarked against the other SNMP
> libraries ([benchmarks/](benchmarks/README.md)). See the
> [roadmap](ROADMAP.md).

## Why snmpify

- **Safe on hostile input.** No `unsafe`, no panics: every malformed
  packet is an error with its byte offset. Checked by a cargo-fuzz target
  in CI and a robustness test on 130 000 random, mutated and SNMPv3
  messages.
- **Fast by design.** The decoder hands out slices of the packet instead
  of copying; the encoder writes back to front, so a nested value is never
  moved to prepend its length; OIDs up to 15 arcs live inline without
  allocation.
- **Interoperable.** Every change is tested against net-snmp's `snmpd`
  (Get, GetNext, GetBulk, Set, v1 and v2c error handling, a full walk,
  and SNMPv3 with all 31 combinations of authentication and privacy) and
  `snmptrapd` / `snmptrap` / `snmpinform` (traps and informs both ways,
  v1, v2c and v3); the agent is queried with net-snmp's tools and runs
  as an AgentX subagent of snmpd.
- **SNMPv3 done carefully.** MD5, SHA-1, SHA-224/256/384/512; DES,
  AES-128/192/256 (both key extensions in use: the Blumenthal draft's and
  Cisco's). Answers count only if they authenticate at the
  request's level, for the right engine, inside the time window; forged,
  replayed and downgraded answers are dropped. Passwords are hashed into
  keys once per user, not once per agent.
- **Tested.** 99% line coverage of the library (cargo-llvm-cov, measured
  in CI with the interop tests).
- **Few dependencies**: none for the wire format, the RustCrypto hashes
  and ciphers for SNMPv3, tokio for the client.

## Compared with other SNMP libraries

Rust crates, from their documentation (November 2026). ✓ = supported,
— = not supported or not documented, *planned* = on the snmpify
[roadmap](ROADMAP.md).

| | **snmpify** 0.1 | [async-snmp] 0.18 | [snmp2] 0.5 | [csnmp] 0.6 | [snmp] 0.2 |
|---|---|---|---|---|---|
| SNMPv1 / v2c | ✓ | ✓ | ✓ | v2c | v2c |
| SNMPv3 auth: MD5, SHA-1, SHA-224 … SHA-512 | ✓ | ✓ | ✓ | — | — |
| SNMPv3 privacy: DES, AES-128/192/256 | ✓ | ✓ (and 3DES) | ✓ | — | — |
| Async (tokio) | ✓ | ✓ | ✓ | ✓ | — |
| Blocking API | *planned* | example wrapper | ✓ | — | ✓ |
| Many agents over one socket | ✓ | ✓ | — | — | — |
| Timeouts and retries built in | ✓ | ✓ | timeout (blocking API) | ✓ | timeout |
| Walk / bulk walk helper | ✓ | ✓ | — | ✓ | — |
| Traps and informs | send and receive | send and receive | parse received | send | — |
| Agent | ✓ (and AgentX subagent) | ✓ | — | — | — |
| MIB names | ✓ (built in, MIB files) | ✓ (mib-rs) | ✓ (needs libnetsnmp) | — | — |
| TCP transport | — | ✓ | — | — | — |
| Wire format usable without the client | ✓ | — | ✓ | — | ✓ |
| Python bindings | ✓ (sync and asyncio) | — | — | — | — |
| C, C++ API | ✓ (CMake, pkg-config) | — | — | — | — |
| Last release | 2026 | 2026 | 2026 | 2024 | 2017 |

[async-snmp]: https://crates.io/crates/async-snmp
[snmp2]: https://crates.io/crates/snmp2
[csnmp]: https://crates.io/crates/csnmp
[snmp]: https://crates.io/crates/snmp

**Pick async-snmp** today if you need traps, an agent, MIBs or TCP: it
is the most complete Rust SNMP library. **Pick snmp2** for a small
blocking client. **snmpify** focuses on being hard to break and easy to
audit:

- no `unsafe`, and no panics on any input: a cargo-fuzz target and a
  robustness test on 130 000 random, mutated and SNMPv3 messages run in
  CI;
- every change tested against net-snmp's snmpd, including all 31
  SNMPv3 authentication/privacy combinations and the error reports
  (wrong digest, unknown user, unsupported level);
- 99% line coverage, measured in CI;
- SNMPv3 answers accepted only at the request's security level, for
  the right engine, inside the time window;
- MSRV 1.85.

Beyond Rust, [net-snmp] (C) is the reference implementation with every
feature, used here as the test agent; [pysnmp] is pure Python; [ezsnmp]
wraps net-snmp for Python; [gosnmp] is the common Go library. snmpify's
Python and C/C++ bindings ([roadmap](ROADMAP.md) steps 5 and 6) aim at
the first three: one fast, tested core for every language. Speed
comparisons against all of these are in
[benchmarks/](benchmarks/README.md) (below).

[net-snmp]: http://www.net-snmp.org/
[pysnmp]: https://pypi.org/project/pysnmp/
[ezsnmp]: https://pypi.org/project/ezsnmp/
[gosnmp]: https://github.com/gosnmp/gosnmp

## Benchmarks

Against snmp2, async-snmp, csnmp, net-snmp's C library, pysnmp and ezsnmp,
on one machine over loopback, medians of 5 runs
([method, all numbers, how to run them](benchmarks/README.md)):

| | snmpify | snmp2 | async-snmp | csnmp | net-snmp (C) |
|---|---:|---:|---:|---:|---:|
| Walk, 200 000 objects (v2c): time | 165 ms | **139 ms** | 178 ms | 520 ms | 164 ms |
| … CPU | 67 ms | **43 ms** | 79 ms | 396 ms | 60 ms |
| Walk over SNMPv3 (SHA + AES): CPU | 88 ms | **68 ms** | 116 ms | n/a | 100 ms |
| 1000 agents polled at once: time | **9 ms** | 86 ms | 4020 ms | 24 ms | 12 ms |
| … peak memory | **4.8 MB** | 134 MB | 10 MB | 19 MB | 11 MB |

| Python | snmpify | ezsnmp | pysnmp |
|---|---:|---:|---:|
| Walk, 200 000 objects | **304 ms** | 2402 ms | 20 011 ms |
| GetRequest latency (p50) | **11 µs** | 15 µs | 424 µs |
| 1000 agents polled at once | **29 ms** | 171 ms | 4236 ms (663 answered) |

snmp2 walks with the least CPU (it decodes in place); snmpify is at
net-snmp's level there, and leads mass polling and Python.

## Example

```toml
[dependencies]
snmpify = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use snmpify::client::{Client, Community};

#[tokio::main]
async fn main() -> Result<(), snmpify::client::Error> {
    let client = Client::connect("192.0.2.1:161", Community::v2c("public")).await?;

    // One value …
    println!("{}", client.get_one("1.3.6.1.2.1.1.1.0").await?);

    // … or a whole table, with GetBulk (GetNext on SNMPv1).
    let mut walk = client.walk("1.3.6.1.2.1.2.2")?;
    while let Some(vb) = walk.next().await {
        println!("{}", vb?); // 1.3.6.1.2.1.2.2.1.2.1 = lo …
    }
    Ok(())
}
```

SNMPv3: pass a `UsmUser` where a `Community` goes. The agent's engine is
discovered on the first request.

```rust,no_run
use snmpify::client::Client;
use snmpify::usm::{AuthProtocol, PrivProtocol, UsmUser};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user = UsmUser::new("monitor")
        .with_auth(AuthProtocol::Sha256, "auth-password")?
        .with_privacy(PrivProtocol::Aes128, "priv-password")?;
    let client = Client::connect("192.0.2.1:161", user).await?;
    println!("{}", client.get_one("1.3.6.1.2.1.1.5.0").await?);
    Ok(())
}
```

Notifications: `client.trap(oid, varbinds)`, `client.inform(…)` (waits
for the acknowledgement) and `client.trap_v1(…)` send them; a
`NotificationReceiver` takes traps and informs in every version,
acknowledges informs, and hands them over in SNMPv2 form:

```rust,no_run
use snmpify::engine::LocalEngine;
use snmpify::notification::NotificationReceiver;
use snmpify::usm::{AuthProtocol, UsmUser};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user = UsmUser::new("traps").with_auth(AuthProtocol::Sha256, "auth-password")?;
    let mut rx = NotificationReceiver::bind("0.0.0.0:162")
        .await?
        .with_community("public")
        .with_engine(LocalEngine::new(LocalEngine::generate_id()).with_user(user));
    loop {
        let n = rx.recv().await?;
        println!("{} {} from {}", n.kind, n.trap_oid, n.source);
    }
}
```

An agent: values in a `MibTree` (fixed, writable or computed) or any
`MibHandler`, served over v1, v2c and v3 with read-only and read-write
communities and users; the same handlers run as an AgentX subagent of
net-snmp's snmpd (`agentx::Subagent`):

```rust,no_run
use snmpify::agent::{Access, Agent, MibTree};
use snmpify::Value;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mib = MibTree::new().with_system("my device", "1.3.6.1.4.1.99999".parse().unwrap(), "dev-1", || 0);
    mib.insert_fn("1.3.6.1.4.1.99999.1.0".parse().unwrap(), || Value::Gauge32(42));
    Agent::bind("0.0.0.0:161")
        .await?
        .with_community("public", Access::ReadOnly)
        .register("1.3.6.1.2.1.1".parse().unwrap(), mib.clone())
        .register("1.3.6.1.4.1.99999".parse().unwrap(), mib)
        .run()
        .await
}
```

MIBs: `Mib::standard()` knows 55 standard modules (SNMPv2, IF, IP, TCP,
UDP, HOST-RESOURCES, ENTITY, BRIDGE, BGP4, UCD-SNMP, the SNMPv3 MIBs …)
without any file; `load_file` / `load_dir` add vendor MIBs (SMIv1 and
SMIv2). Names resolve both ways and values print with enum labels and
display hints:

```rust
use snmpify::mib::Mib;
use snmpify::{Value, VarBind};

let mib = Mib::standard();
let oid = mib.resolve("IF-MIB::ifPhysAddress.2").unwrap();
let vb = VarBind::new(oid, Value::OctetString(vec![0, 0x1b, 0x21, 0x3a, 0xc6, 8]));
assert_eq!(mib.format(&vb), "IF-MIB::ifPhysAddress.2 = 00:1b:21:3a:c6:08");
```

Polling many agents: `Manager::bind("0.0.0.0:0")` gives clients
(`manager.client(addr, community)`) that share one UDP socket and receive
task; responses are matched by request id, source address and community,
lost packets are retransmitted (`Options`: timeout 1 s, 2 retries).

A blocking API for programs without async: `snmpify::blocking::Client`
(same methods, plus `walk` as an iterator), `NotificationReceiver` and
`RunningAgent`.

From Python ([python/](python/README.md)):

```python
import snmpify

c = snmpify.Client("192.0.2.1", user=snmpify.UsmUser("monitor", auth=("SHA-256", "auth-password")))
for oid, value in c.walk("1.3.6.1.2.1.2.2.1.2"):
    print(oid, value)
```

From C and C++ ([capi/](capi/README.md)): `snmpify.h` and the
header-only `snmpify.hpp`, built with CMake (`find_package(snmpify)`) or
pkg-config, prebuilt for Linux, macOS and Windows.

Only the wire format, without tokio: `default-features = false`, then
`CommunityMessage::new(…).encode()` / `CommunityMessage::decode(bytes)`
(and `v3::V3Message`). Add `features = ["v3"]` for USM security
(`usm::UsmUser`, `seal`, `open`) without the client.

| SNMPv3 cost (50-binding response, `examples/codec_bench.rs`) | seal | open |
|---|---|---|
| no auth, no privacy | 1.4 µs | 2.2 µs |
| SHA-256 | 1.8 µs | 2.6 µs |
| SHA + AES-128 | 3.3 µs | 3.1 µs |
| SHA-256 + AES-256 | 3.3 µs | 3.0 µs |
| SHA + DES | 26 µs | 25 µs |

Making a user's keys from a password takes about 1 ms (a megabyte is
hashed), once per user; localizing them to an agent takes under a
microsecond.

## Testing

```sh
cargo test                                   # unit, robustness and doc tests

# Interoperability with net-snmp's snmpd and snmptrapd
docker build -t snmpify-snmpd tools/snmpd
docker run -d --rm --name snmpify-snmpd -p 127.0.0.1:1161:161/udp \
  -p 127.0.0.1:1705:705/tcp snmpify-snmpd
docker run -d --rm --name snmpify-snmptrapd -p 127.0.0.1:1162:162/udp \
  --entrypoint /usr/sbin/snmptrapd snmpify-snmpd -f -Lo -C -c /etc/snmp/snmptrapd.conf
SNMPIFY_AGENT=127.0.0.1:1161 SNMPIFY_TRAPD=127.0.0.1:1162 SNMPIFY_AGENTX=127.0.0.1:1705 \
  cargo test --test netsnmp --test netsnmp_notifications --test netsnmp_agent

# Coverage (cargo install cargo-llvm-cov), with the snmpd tests
SNMPIFY_AGENT=127.0.0.1:1161 SNMPIFY_TRAPD=127.0.0.1:1162 SNMPIFY_AGENTX=127.0.0.1:1705 \
  cargo llvm-cov --all-targets --summary-only

cargo +nightly fuzz run decode_message       # fuzzing (cargo install cargo-fuzz)
```

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues: [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
