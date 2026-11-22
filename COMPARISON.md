# snmpify compared with other SNMP libraries

Every SNMP function, library by library, and what each costs. The
features come from each library's source code (the versions in
[benchmarks/results.md](benchmarks/results.md)). The numbers come from
[benchmarks/](benchmarks/README.md): every client against the same local
agent, medians of 5 runs.

✓ = supported, — = not supported.

## Functions

| | **snmpify** | async-snmp | snmp2 | csnmp | net-snmp (C) | pysnmp | ezsnmp |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Language | Rust, Python, C, C++ | Rust | Rust | Rust | C | Python | Python (net-snmp) |
| **Requests** | | | | | | | |
| Get | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GetNext | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GetBulk | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Set | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Walk (GetNext / GetBulk) | ✓ | ✓ | — | ✓ | applications only¹ | ✓ | ✓ |
| Walk decoded in place (zero-copy) | ✓ | — | lazy decoding, no walk | — | — | — | — |
| **Notifications** | | | | | | | |
| Send SNMPv1 traps | ✓ | ✓ | — | — | ✓ | ✓ | `snmptrap` wrapper² |
| Send v2c / v3 traps | ✓ | ✓ | — | v2c | ✓ | ✓ | `snmptrap` wrapper² |
| Send informs (acknowledged) | ✓ | ✓ | — | v2c | ✓ | ✓ | `snmptrap` wrapper² |
| Receive traps and informs | ✓ | ✓ | parse only | — | ✓ (snmptrapd) | ✓ | — |
| **Agent** | | | | | | | |
| Agent (command responder) | ✓ | ✓ | — | — | ✓ (snmpd) | ✓ | — |
| Access control | per community / user, read or read-write | VACM | — | — | VACM | VACM | — |
| AgentX subagent (RFC 2741) | ✓ (TCP, Unix socket) | — | — | — | ✓ | — | — |
| AgentX master | — | — | — | — | ✓ | — | — |
| **Versions and security** | | | | | | | |
| SNMPv1 / v2c | ✓ | ✓ | ✓ | v2c | ✓ | ✓ | ✓ |
| SNMPv3 (USM, engine discovery) | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| Authentication: MD5, SHA-1, SHA-224/256/384/512 | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| Privacy: DES, AES-128 | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| Privacy: AES-192/256 (Blumenthal) | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| Privacy: AES-192/256, Cisco's key extension (Reeder) | ✓ | ✓ | ✓ | — | build option | ✓ | as net-snmp |
| Privacy: 3DES-EDE | ✓ | ✓ | — | — | — | ✓ | — |
| TLS / DTLS (RFC 6353) | — | — | — | — | build option | — | — |
| **Transports** | | | | | | | |
| UDP over IPv4 and IPv6 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| TCP (RFC 3430) | ✓ (client and agent) | ✓ | — | — | ✓ | — in the high-level API | ✓ |
| Many agents over one socket | ✓ | ✓ | — | — | — (a socket per session) | ✓ | — |
| **APIs** | | | | | | | |
| Async | ✓ (tokio; Python asyncio) | ✓ (tokio) | ✓ (tokio) | ✓ (tokio) | callbacks | ✓ (asyncio) | — |
| Blocking | ✓ (Rust, Python, C) | example wrapper | ✓ | — | ✓ | — | ✓ |
| Timeouts and retries | ✓ | ✓ | timeout (blocking API) | ✓ | ✓ | ✓ | ✓ |
| MIB names and files | ✓ (built-in modules, MIB parser) | ✓ (mib-rs) | via libnetsnmp | — | ✓ | ✓ (pysmi) | ✓ |
| Memory-safe | ✓ (no `unsafe`) | ✓ | ✓ | ✓ | — | ✓ | — (C underneath) |

1. net-snmp's library has no walk call; its `snmpwalk` and
   `snmpbulkwalk` applications loop over GetNext or GetBulk.
2. ezsnmp's `Session` has no notification API. `ezsnmp.netsnmp.snmptrap`
   runs net-snmp's `snmptrap` command inside the process, taking
   command-line arguments and opening a new session on every call.

## What each function costs

**CPU time of the work (startup subtracted); lower is better**

| | snmpify | async-snmp | snmp2 | csnmp | net-snmp (C) | snmpify (Python) | pysnmp (Python) | ezsnmp (Python) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Walk, 200 000 objects (v2c) | **42 ms** | 85 ms | 48 ms | 348 ms | 50 ms | **177 ms** | 18284 ms | 2303 ms |
| Walk over SNMPv3 (SHA, AES-128) | 74 ms | 117 ms | **72 ms** | — | 110 ms | **192 ms** | 20825 ms | 2458 ms |
| 5000 Get | 27 ms | 35 ms | 23 ms | 41 ms | **20 ms** | **49 ms** | 1782 ms | 101 ms |
| 2000 GetNext | 13 ms | 19 ms | **10 ms** | 23 ms | ≤ 10 ms | **24 ms** | 729 ms | 41 ms |
| 2000 GetBulk × 50 rows | 17 ms | 25 ms | **13 ms** | 125 ms | ≤ 10 ms | **53 ms** | 8295 ms | 210 ms |
| 2000 Set | 13 ms | 20 ms | **12 ms** | 25 ms | ≤ 10 ms | **25 ms** | 791 ms | 46 ms |
| 2000 traps sent | **7 ms** | **7 ms** | — | 17 ms | ≤ 10 ms | **14 ms** | 534 ms | 222 ms |
| 2000 informs (acknowledged) | **15 ms** | 21 ms | — | 33 ms | ≤ 10 ms | **27 ms** | 1373 ms | 246 ms |
| 1000 agents polled at once | **9 ms** | 32 ms | 85 ms | 26 ms | ≤ 10 ms | **61 ms** | 1454 ms | 167 ms |

**Wall-clock time; lower is better**

| | snmpify | async-snmp | snmp2 | csnmp | net-snmp (C) | snmpify (Python) | pysnmp (Python) | ezsnmp (Python) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Walk, 200 000 objects (v2c) | **140 ms** | 185 ms | 141 ms | 457 ms | 158 ms | **275 ms** | 19794 ms | 2444 ms |
| Walk over SNMPv3 (SHA, AES-128) | 193 ms | 237 ms | **190 ms** | — | 238 ms | **324 ms** | 22474 ms | 2653 ms |
| 5000 Get | 46 ms | 55 ms | **44 ms** | 61 ms | 47 ms | **60 ms** | 2252 ms | 125 ms |
| 2000 GetNext | 22 ms | 30 ms | 21 ms | 31 ms | **19 ms** | **29 ms** | 908 ms | 51 ms |
| 2000 GetBulk × 50 rows | 58 ms | 65 ms | **52 ms** | 169 ms | 59 ms | **84 ms** | 8728 ms | 257 ms |
| 2000 Set | 23 ms | 31 ms | 22 ms | 33 ms | **20 ms** | **27 ms** | 987 ms | 57 ms |
| 2000 traps sent | 7 ms | 8 ms | — | 16 ms | **6 ms** | **8 ms** | 535 ms | 224 ms |
| 2000 informs (acknowledged) | 24 ms | 30 ms | — | 41 ms | **21 ms** | **30 ms** | 1591 ms | 268 ms |
| 1000 agents polled at once | **9 ms** | 4023 ms | 85 ms | 24 ms | 12 ms | **29 ms** | 4275 ms | 176 ms |

**Latency per request, median (p50)**

| | snmpify | async-snmp | snmp2 | csnmp | net-snmp (C) | snmpify (Python) | pysnmp (Python) | ezsnmp (Python) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 5000 Get | 8 µs | 10 µs | 8 µs | 10 µs | 9 µs | 10 µs | 431 µs | 24 µs |
| 2000 GetNext | 8 µs | 11 µs | 8 µs | 11 µs | 9 µs | 11 µs | 433 µs | 24 µs |
| 2000 GetBulk × 50 rows | 24 µs | 28 µs | 23 µs | 75 µs | 28 µs | 39 µs | 4304 µs | 117 µs |
| 2000 Set | 8 µs | 11 µs | 9 µs | 12 µs | 10 µs | 11 µs | 464 µs | 26 µs |
| 2000 traps sent | 2 µs | 3 µs | — | 6 µs | 3 µs | 3 µs | 256 µs | 106 µs |
| 2000 informs (acknowledged) | 8 µs | 11 µs | — | 16 µs | 10 µs | 12 µs | 741 µs | 118 µs |

Bold: the lowest among the Rust and C libraries, and among the Python
ones. net-snmp runs in a container whose `time` measures CPU only to
10 ms: its small CPU figures read "≤ 10 ms" and are not ranked. snmpify's walk
reads the answers in place (`Client::walk_with`); with owned values
(`walk_all`) it uses 54 ms (v2c) and 72 ms (v3). snmp2 has no
notification API, and ezsnmp sends notifications only through its
`snmptrap` command wrapper. Full tables, with p99 latencies and memory:
[benchmarks/results.md](benchmarks/results.md).

## Summary

- **Functions**: net-snmp is the reference, with everything (including
  an AgentX master and TLS) but none of the memory safety. Among the
  memory-safe libraries, snmpify and async-snmp cover the most: every
  request, sending and receiving notifications, an agent, all SNMPv3
  protocols and TCP. On top of that, snmpify has an AgentX subagent,
  Python and C/C++ bindings, a zero-copy walk and mass polling over one
  socket. async-snmp has full VACM. pysnmp is the most complete in
  Python. snmp2 is a client without walks or notifications. csnmp is a
  v2c-only client. ezsnmp is a client over net-snmp.
- **Speed**: snmpify, snmp2 and net-snmp are close for single requests
  (8–10 µs, mostly the kernel's UDP work). snmpify and snmp2 walk with
  the least CPU, ahead of net-snmp. snmpify polls 1000 agents in 9 ms
  (snmp2 85 ms, async-snmp 4 s). async-snmp uses about 40% more CPU
  than snmpify per request and twice as much per walk (the same for
  traps). csnmp is the slowest Rust client for bulk data.
- **Python**: snmpify's package is the fastest in every operation. It is
  2–9 times faster than ezsnmp for requests and walks (28 times for
  traps, which ezsnmp sends through a command wrapper), and 40–100 times
  faster than pysnmp.
