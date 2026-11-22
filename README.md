# snmpify

[![CI](https://github.com/snmp-rs/snmpify/actions/workflows/ci.yml/badge.svg)](https://github.com/snmp-rs/snmpify/actions/workflows/ci.yml)
[![CodeQL](https://github.com/snmp-rs/snmpify/actions/workflows/codeql.yml/badge.svg)](https://github.com/snmp-rs/snmpify/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/snmp-rs/snmpify/badge)](https://scorecard.dev/viewer/?uri=github.com/snmp-rs/snmpify)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](Cargo.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Fast, safe SNMP for Rust, with Python and C/C++ bindings on the way.**

> **Status:** early. Done: the SNMP wire format and an async SNMPv1/v2c
> client (get, get-next, get-bulk, set, walks, mass polling over one
> socket), tested against net-snmp. SNMPv3, traps and the Python and C/C++
> bindings follow; see the [roadmap](ROADMAP.md).

## Why snmpify

- **Safe on hostile input.** No `unsafe`, no panics: every malformed
  packet is an error with its byte offset. Checked by a cargo-fuzz target
  in CI and a robustness test on 70 000 random and mutated messages.
- **Fast by design.** The decoder hands out slices of the packet instead
  of copying; the encoder writes back to front, so a nested value is never
  moved to prepend its length; OIDs up to 15 arcs live inline without
  allocation.
- **Interoperable.** Every change is tested against net-snmp's `snmpd`
  (Get, GetNext, GetBulk, Set, v1 and v2c error handling, a full walk).
- **Few dependencies**: none for the wire format, tokio for the client.

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

Polling many agents: `Manager::bind("0.0.0.0:0")` gives clients
(`manager.client(addr, community)`) that share one UDP socket and receive
task; responses are matched by request id, source address and community,
lost packets are retransmitted (`Options`: timeout 1 s, 2 retries).

Only the wire format, without tokio: `default-features = false`, then
`CommunityMessage::new(…).encode()` / `CommunityMessage::decode(bytes)`.

## Testing

```sh
cargo test                                   # unit, robustness and doc tests

# Interoperability with net-snmp's snmpd
docker build -t snmpify-snmpd tools/snmpd
docker run -d --rm --name snmpify-snmpd -p 127.0.0.1:1161:161/udp snmpify-snmpd
SNMPIFY_AGENT=127.0.0.1:1161 cargo test --test netsnmp

cargo +nightly fuzz run decode_message       # fuzzing (cargo install cargo-fuzz)
```

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues: [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
