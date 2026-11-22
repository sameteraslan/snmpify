# Changelog

## Unreleased

### Added
- Agent (`snmpify::agent`): `Agent` answers Get, GetNext, GetBulk and Set
  over SNMPv1, v2c and v3 from `MibHandler`s registered under subtrees
  (deepest registration wins); `MibTree` holds fixed, writable and
  computed values and the MIB-II system group. Two-phase sets, v1 error
  mapping and Counter64 skipping (RFC 3584), tooBig and GetBulk
  truncation by message size, read-only / read-write communities, per
  user access and minimum level (authorizationError below it), unknown
  contexts reported.
- AgentX subagent (`snmpify::agentx`, RFC 2741): the same handlers under
  a master agent (TCP or Unix socket): Open, Register, Get, GetNext,
  GetBulk, TestSet/CommitSet/UndoSet/CleanupSet, Notify, both byte
  orders.
- Tests: the client against the agent in every version; net-snmp's
  snmpget/snmpbulkwalk/snmpset against the agent (v2c and v3 authPriv);
  snmpify as an AgentX subagent of snmpd (get, walk, set, notify).
- Notifications (`snmpify::notification`): `NotificationReceiver` takes
  traps (v1, v2c, v3) and informs (v2c, v3, acknowledged), filtered by
  community and SNMPv3 user, and hands them over in SNMPv2 form
  (`Notification`: trap OID, uptime, bindings; v1 traps translated as in
  RFC 3584). Sending: `Client::trap`, `Client::inform` (waits for the
  acknowledgement, retries) and `Client::trap_v1`; `Usm::with_engine_id`
  sets the engine id of SNMPv3 traps.
- `snmpify::engine::LocalEngine`: the authoritative side of USM (RFC 3414
  §3.2): engine discovery reports, unknown user / wrong digest /
  decryption / security level / time window reports, usmStats
  counters, traps from other engines with replay protection, responses
  at the request's level. `LocalizedUser::seal_with_level`.
- Tests against net-snmp both ways: snmpify → snmptrapd and snmptrap /
  snmpinform → snmpify, v1, v2c and v3; the robustness test also feeds
  the engine.

## 0.1.0 — 2026-11-22

First code: the SNMP wire format and an async v1/v2c/v3 client.

### Added
- SNMPv3 with the User-based Security Model.
  - `snmpify::v3` (always available): `V3Message`, `UsmParams`,
    `ScopedPdu`, `Message` (any version), `ReportKind` (usmStats and
    snmpMPDStats reports).
  - `snmpify::usm` (feature `v3`, on with `client`): `UsmUser` (master
    keys hashed once from the passwords), `LocalizedUser::seal` / `open`.
    Authentication HMAC-MD5-96, HMAC-SHA-96, HMAC-SHA-224/256/384/512
    (RFC 3414, 7860); privacy DES, AES-128, AES-192/256 (RFC 3414, 3826,
    the Blumenthal key extension as in net-snmp). Constant-time MAC check;
    keys never in `Debug`.
  - The client takes a `UsmUser` (or `Usm` with a context) wherever it
    took a `Community`. Engine discovery once per agent for all clones,
    time synchronisation and resync on notInTimeWindow, rediscovery when
    the engine id changes. Answers are accepted only at the request's
    security level, for its engine, within the time window: forged,
    replayed, downgraded and altered answers are ignored. Reports become
    `Error::Report`.
  - Tested: RFC 3414 key vectors, HMAC/AES/DES known answers, every
    protocol combination sealed and opened, tampering, a scripted v3 agent
    (discovery, resync, reboot, engine change, forged answers, contexts,
    40 agents over one socket), the robustness test and the fuzz target
    on v3 input, and all 31 combinations against net-snmp's snmpd.
  - `examples/codec_bench.rs` times seal/open per protocol and key
    derivation.
- CI: tests with `--no-default-features` (wire format only) and
  `--features v3`; a coverage job (cargo-llvm-cov with the snmpd tests,
  summary in the run, lcov as an artifact).
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
