# Changelog

## Unreleased

First code: the SNMP wire format.

### Added
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
