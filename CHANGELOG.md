# Changelog

## Unreleased

First code: the SNMP wire format and an async v1/v2c client.

### Added
- Minimum supported Rust version 1.85 (tokio needs it), checked in CI.
- `client` (feature `client`, on by default; tokio): `Client` with `get`,
  `get_one`, `get_next`, `get_bulk`, `set`, `walk` (GetBulk in v2c, GetNext
  in v1, stops at the end of the subtree, fails instead of looping on an
  agent whose OIDs do not increase), `walk_all` and raw `request`;
  `Manager`: many clients over one UDP socket and receive task, responses
  matched by request id, source address, version and community;
  retransmission (`Options`: timeout, retries, max-repetitions);
  cancellation-safe. Tested against a scripted agent (loss, timeouts,
  spoofed/stray/garbage answers, 500 concurrent requests, broken walks) and
  against net-snmp. `examples/walk.rs`.
- BER codec (`snmpify::ber`): zero-copy `Reader`, back-to-front `Writer`
  (nested values are never copied to prepend their length), definite
  lengths only, strict about malformed input.
- `Oid`: up to 15 arcs inline without allocation, parsing, display,
  MIB-tree ordering, `starts_with`, `child`.
- `Value`: every SMIv2 type and the v2 exceptions; `VarBind`.
- Every PDU (Get, GetNext, GetBulk, Set, Response, Inform, TrapV2, Report,
  v1 Trap), `ErrorStatus`, and `CommunityMessage` (SNMPv1 and v2c).
- Tests: unit tests with known encodings, a robustness test on 70 000
  random and mutated messages, a cargo-fuzz target, and interoperability
  tests against net-snmp's snmpd (Get/GetNext/GetBulk/Set, v1 and v2c,
  a full walk of the agent).
