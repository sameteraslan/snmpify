# snmpify

[![CI](https://github.com/snmp-rs/snmpify/actions/workflows/ci.yml/badge.svg)](https://github.com/snmp-rs/snmpify/actions/workflows/ci.yml)
[![CodeQL](https://github.com/snmp-rs/snmpify/actions/workflows/codeql.yml/badge.svg)](https://github.com/snmp-rs/snmpify/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/snmp-rs/snmpify/badge)](https://scorecard.dev/viewer/?uri=github.com/snmp-rs/snmpify)
[![MSRV](https://img.shields.io/badge/MSRV-1.80-blue)](Cargo.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Fast, safe SNMP for Rust, with Python and C/C++ bindings on the way.**

> **Status:** early. This first part is the SNMP wire format (BER, OIDs,
> values, every PDU, SNMPv1/v2c messages), tested against net-snmp. The
> async client, SNMPv3, traps and the bindings follow; see the
> [roadmap](ROADMAP.md).

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
- **No dependencies** in the core.

## Example

```rust,no_run
use snmpify::{AnyPdu, CommunityMessage, Oid, Pdu, Version};
use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    let sys_descr: Oid = "1.3.6.1.2.1.1.1.0".parse()?;
    let request = CommunityMessage::new(Version::V2c, "public", Pdu::get(1, [sys_descr]));
    socket.send_to(&request.encode(), "192.0.2.1:161")?;

    let mut buf = [0u8; 65535];
    let n = socket.recv(&mut buf)?;
    if let AnyPdu::Pdu(response) = CommunityMessage::decode(&buf[..n])?.pdu {
        for vb in &response.varbinds {
            println!("{vb}"); // 1.3.6.1.2.1.1.1.0 = Linux router 6.1 …
        }
    }
    Ok(())
}
```

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
