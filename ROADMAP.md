# Roadmap

snmpify aims to be a fast, safe SNMP library for Rust that is just as
usable from Python, C and C++: one tested implementation instead of a
different library per language.

| Step | What | Status |
|---|---|---|
| 1 | **Wire format**: BER codec, OIDs, values, all PDUs, v1/v2c messages; robustness tests, fuzzing, interop tests against net-snmp | done |
| 2 | **Async client** (tokio): get, get-next, get-bulk, set, walk and bulk walk as streams, timeouts and retries, request-id matching; one socket shared by thousands of targets for mass polling; a blocking wrapper | done (the blocking wrapper still to do) |
| 3 | **SNMPv3 / USM**: engine discovery and time sync, authentication MD5, SHA-1, SHA-224/256/384/512 (RFC 3414, 7860), privacy DES, AES-128/192/256 (RFC 3826 and the common 192/256 extension); key localisation cache; tested against snmpd for every combination | done (the Cisco/Reeder AES-192/256 key extension still to do) |
| 4 | **Notifications**: trap (v1, v2c, v3) and inform receiver with acknowledgements; sending traps and informs | |
| 5 | **Python bindings** (PyO3, PyPI `snmpify`): sync and asyncio APIs, walks as iterators, values as Python types | |
| 6 | **C and C++ API**: blocking and callback APIs, CMake package, pkg-config, prebuilt Linux/macOS/Windows archives | |
| 7 | **Benchmarks and comparisons**: walk throughput, request latency, mass polling, CPU and memory against net-snmp (C), pysnmp, ezsnmp/easysnmp, and the Rust crates snmp2, async-snmp, csnmp; reproducible scripts | |
| 8 | **Agent side**: a responder for custom MIB subtrees (sub-agent style), AgentX | |
| 9 | **MIBs**: name ↔ OID for the standard MIBs built in, loading MIB files | |

Design rules: no `unsafe` in the core, no panics on any input, no
allocation per value where it can be avoided, every feature tested against
a real net-snmp agent.
