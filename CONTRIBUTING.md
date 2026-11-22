# Contributing to snmpify

Bug reports, interoperability reports and pull requests are welcome.

## Reporting a bug

Open an [issue](https://github.com/snmp-rs/snmpify/issues/new/choose) with
the smallest code that shows the problem and the agent involved (vendor,
model, firmware). For decoding problems, the packet bytes in hex (from
Wireshark or `tcpdump -X`) are the most useful thing you can send.

## Pull requests

`main` is protected: every change goes through a pull request from a fork,
and the CI checks must pass before it is merged.

1. Fork the repository and create a branch.
2. Make the change, with a test for it.
3. Run:

   ```sh
   cargo fmt --all
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```

4. For anything that goes on the wire, also run the tests against net-snmp:

   ```sh
   docker build -t snmpify-snmpd tools/snmpd
   docker run -d --rm --name snmpify-snmpd -p 127.0.0.1:1161:161/udp snmpify-snmpd
   SNMPIFY_AGENT=127.0.0.1:1161 cargo test --test netsnmp
   ```

   and, for decoder changes, fuzz for a while:
   `cargo +nightly fuzz run decode_message`.
5. Add a line to `CHANGELOG.md` for user-visible changes, and open the
   pull request.
