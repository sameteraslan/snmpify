# Benchmarks

snmpify against other SNMP libraries: Rust ([snmp2], [async-snmp],
[csnmp]), C ([net-snmp]'s libnetsnmp, the reference implementation) and
Python ([pysnmp], [ezsnmp]; and snmpify's own Python package).

[snmp2]: https://crates.io/crates/snmp2
[async-snmp]: https://crates.io/crates/async-snmp
[csnmp]: https://crates.io/crates/csnmp
[net-snmp]: http://www.net-snmp.org/
[pysnmp]: https://pypi.org/project/pysnmp/
[ezsnmp]: https://pypi.org/project/ezsnmp/

## Method

- **The agent** (`agent/`) is snmpify's own, in a separate process: a
  10 000-object table (5000 rows of an OCTET STRING and a Counter64), the
  system group, an SNMPv3 user (SHA, AES-128), and 1000 small agents on
  the following ports for mass polling. It is fast, so the clients are
  what is measured; every client talks to the same agent.
- **One program per library and scenario** (`clients/`, `python/`, `c/`),
  each printing one JSON line; all use their library's documented API for
  the job (GetBulk walks with max-repetitions 25; the library's async API
  and shared socket for mass polling where it has one).
- `run.py` runs every client in turn, interleaved, five times, and reports
  medians. CPU time comes from `wait4` (microseconds; for net-snmp, which
  runs in a container, from `/usr/bin/time` inside it: 10 ms steps), peak
  memory from `/usr/bin/time`. "CPU, work" subtracts each client's startup
  (the `idle` scenario: start, load the library, exit).
- Loopback, one machine; the numbers compare libraries, they are not
  network performance.

## Results

Medians of 5 runs, 2026-11-22, Intel(R) Core(TM) Ultra 7 255HX, Linux 7.0.0-43-generic.
Versions: snmp2 0.5.3, async-snmp 0.18.1, csnmp 0.6.0, pysnmp 7.1.33, ezsnmp 2.5.0, net-snmp 5.9.4.pre2.

### walk: 20 walks of a 10 000-object table, SNMPv2c GetBulk (max-repetitions 25)

| | Time | Objects/s | CPU | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 134 ms | 1,487,675 | 46 ms | 43 ms | 3.3 MB |
| snmpify (owned values) | 138 ms | 1,449,601 | 52 ms | 47 ms | 4.6 MB |
| snmp2 | 135 ms | 1,481,646 | 48 ms | 43 ms | 4.2 MB |
| async-snmp | 173 ms | 1,153,429 | 82 ms | 78 ms | 3.9 MB |
| csnmp | 475 ms | 421,318 | 373 ms | 370 ms | 22.6 MB |
| net-snmp (C) | 163 ms | 1,223,743 | 60 ms | 60 ms | 8.2 MB |
| snmpify (Python) | 248 ms | 806,757 | 199 ms | 154 ms | 23.0 MB |
| ezsnmp (Python) | 2421 ms | 82,619 | 2294 ms | 2271 ms | 29.0 MB |
| pysnmp (Python) | 19548 ms | 10,231 | 18229 ms | 18124 ms | 37.6 MB |

### walk3: the same over SNMPv3 authPriv (SHA, AES-128)

| | Time | Objects/s | CPU | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 190 ms | 1,055,370 | 76 ms | 72 ms | 3.3 MB |
| snmpify (owned values) | 183 ms | 1,093,057 | 69 ms | 64 ms | 5.3 MB |
| snmp2 | 192 ms | 1,040,226 | 77 ms | 72 ms | 4.2 MB |
| async-snmp | 232 ms | 863,647 | 121 ms | 116 ms | 4.0 MB |
| csnmp | n/a | n/a | n/a | n/a | n/a |
| net-snmp (C) | 227 ms | 880,852 | 100 ms | 100 ms | 8.4 MB |
| snmpify (Python) | 312 ms | 641,964 | 236 ms | 191 ms | 23.0 MB |
| ezsnmp (Python) | 2530 ms | 79,051 | 2388 ms | 2365 ms | 28.6 MB |
| pysnmp (Python) | 21896 ms | 9,134 | 20435 ms | 20330 ms | 38.9 MB |

### get: 5000 sequential GetRequests for one object

| | Time | Latency p50 | Latency p99 | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 47 ms | 8 µs | 21 µs | 26 ms | 3.3 MB |
| snmpify (owned values) | 48 ms | 8 µs | 24 µs | 27 ms | 3.2 MB |
| snmp2 | 46 ms | 8 µs | 23 µs | 25 ms | 4.2 MB |
| async-snmp | 62 ms | 11 µs | 34 µs | 40 ms | 3.9 MB |
| csnmp | 66 ms | 12 µs | 38 µs | 48 ms | 2.9 MB |
| net-snmp (C) | 47 ms | 9 µs | 11 µs | 20 ms | 8.2 MB |
| snmpify (Python) | 61 ms | 11 µs | 18 µs | 49 ms | 23.3 MB |
| ezsnmp (Python) | 100 ms | 16 µs | 40 µs | 79 ms | 20.7 MB |
| pysnmp (Python) | 2190 ms | 422 µs | 715 µs | 1752 ms | 37.0 MB |

### poll: 1000 agents, one GetRequest each, all at once

| | Time | Answered | CPU | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 8 ms | 1000 / 1000 | 11 ms | 7 ms | 5.5 MB |
| snmpify (owned values) | 9 ms | 1000 / 1000 | 13 ms | 8 ms | 5.4 MB |
| snmp2 | 86 ms | 1000 / 1000 | 90 ms | 85 ms | 133.5 MB |
| async-snmp | 4020 ms | 1000 / 1000 | 35 ms | 31 ms | 10.2 MB |
| csnmp | 27 ms | 1000 / 1000 | 31 ms | 27 ms | 18.4 MB |
| net-snmp (C) | 12 ms | 1000 / 1000 | 10 ms | 10 ms | 10.8 MB |
| snmpify (Python) | 31 ms | 1000 / 1000 | 107 ms | 62 ms | 33.7 MB |
| ezsnmp (Python) | 163 ms | 1000 / 1000 | 171 ms | 148 ms | 20.1 MB |
| pysnmp (Python) | 4255 ms | 663 / 1000 | 1552 ms | 1448 ms | 66.7 MB |

### idle: start, load the library, exit

| | CPU | Peak RSS |
|---|---:|---:|
| snmpify | 4 ms | 3.1 MB |
| snmpify (owned values) | 5 ms | 3.1 MB |
| snmp2 | 5 ms | 4.0 MB |
| async-snmp | 4 ms | 3.3 MB |
| csnmp | 4 ms | 2.9 MB |
| net-snmp (C) | 0 ms | 8.2 MB |
| snmpify (Python) | 45 ms | 21.7 MB |
| ezsnmp (Python) | 23 ms | 17.5 MB |
| pysnmp (Python) | 104 ms | 36.8 MB |

## Findings

- **Mass polling** (1000 agents at once) is where snmpify stands out: 9 ms
  and 5 MB, using one socket for every agent. It caps the requests in
  flight per socket (64 by default): a burst of 1000 answers overflows a
  socket's receive buffer (about 200 datagrams with Linux defaults) and the
  dropped answers wait a whole timeout for their retry. Without that cap
  snmpify took 2 s here (that is why it has one now); async-snmp, whose
  shared transport has no such cap, takes 4 s, and pysnmp loses a third
  of the answers. snmp2 and csnmp open a socket per agent (snmp2: 134 MB).
- **Walks** and single GetRequests: snmpify and snmp2 are level (the
  same CPU per walk and per request, within the noise between runs), and
  ahead of net-snmp's C library, async-snmp and csnmp. What is left is the
  kernel's UDP work (`sendto`, `recvfrom`, `epoll_wait`: the same calls,
  as many, in every library). snmpify's walk reads the answers in place
  (`Client::walk_with`), as snmp2's does; `walk_all` with owned values costs
  about 10% more CPU. Getting there (see the git history): requests read
  the socket themselves instead of a receive task, no per-request timer
  (one shared deadline sleep), no table entry or channel when nobody else
  is waiting, answers matched on their headers and decoded where they lie,
  connected sockets for single-agent clients, vectors sized once.
- **SNMPv3** (SHA + AES-128): snmpify's owned walk takes the least CPU
  of all (64 ms against snmp2's 72 ms and net-snmp's 100 ms).
- **Python**: snmpify's package walks about 10 times faster than ezsnmp
  (net-snmp underneath) and about 80 times faster than pysnmp, with the
  least CPU; a GetRequest takes 11 µs (ezsnmp 16 µs, pysnmp 422 µs).
- **Failures seen**: csnmp's `walk_bulk` fails when a walk reaches the end
  of the agent's MIB (the standard endOfMibView answer echoes the request's
  OID, which it takes for a loop); the agent has one object after the
  table so walks end by leaving the subtree, as they usually do. csnmp has
  no SNMPv3.

## Run them

```sh
cd benchmarks
cargo build --release                               # agent + Rust clients
docker build -t snmpify-bench-netsnmp c             # net-snmp's C client
python3 -m venv python/.venv
python/.venv/bin/pip install --require-hashes -r python/requirements.txt
(cd ../python && ../benchmarks/python/.venv/bin/maturin build --release -o /tmp/wheels) \
  && python/.venv/bin/pip install /tmp/wheels/snmpify-*.whl
python3 run.py --runs 5                             # writes results.json, results.md
```
