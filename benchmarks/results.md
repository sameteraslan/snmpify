Medians of 5 runs, 2026-11-22, Intel(R) Core(TM) Ultra 7 255HX, Linux 7.0.0-43-generic.
Versions: snmp2 0.5.3, async-snmp 0.18.1, csnmp 0.6.0, pysnmp 7.1.33, ezsnmp 2.5.0, net-snmp 5.9.4.pre2.

### walk: 20 walks of a 10 000-object table, SNMPv2c GetBulk (max-repetitions 25)

| | Time | Objects/s | CPU | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 165 ms | 1,212,717 | 70 ms | 67 ms | 4.4 MB |
| snmp2 | 139 ms | 1,442,107 | 48 ms | 43 ms | 4.2 MB |
| async-snmp | 178 ms | 1,125,606 | 83 ms | 79 ms | 4.0 MB |
| csnmp | 520 ms | 384,344 | 400 ms | 396 ms | 22.6 MB |
| net-snmp (C) | 164 ms | 1,219,706 | 60 ms | 60 ms | 8.2 MB |
| snmpify (Python) | 304 ms | 658,716 | 237 ms | 193 ms | 22.8 MB |
| ezsnmp (Python) | 2402 ms | 83,251 | 2286 ms | 2263 ms | 29.3 MB |
| pysnmp (Python) | 20011 ms | 9,994 | 18608 ms | 18502 ms | 38.2 MB |

### walk3: the same over SNMPv3 authPriv (SHA, AES-128)

| | Time | Objects/s | CPU | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 210 ms | 953,871 | 90 ms | 88 ms | 5.5 MB |
| snmp2 | 185 ms | 1,078,435 | 74 ms | 68 ms | 4.1 MB |
| async-snmp | 238 ms | 839,342 | 121 ms | 116 ms | 4.0 MB |
| csnmp | n/a | n/a | n/a | n/a | n/a |
| net-snmp (C) | 233 ms | 858,878 | 100 ms | 100 ms | 8.3 MB |
| snmpify (Python) | 348 ms | 574,104 | 267 ms | 223 ms | 22.9 MB |
| ezsnmp (Python) | 2629 ms | 76,087 | 2452 ms | 2429 ms | 28.7 MB |
| pysnmp (Python) | 22961 ms | 8,710 | 21266 ms | 21160 ms | 39.6 MB |

### get: 5000 sequential GetRequests for one object

| | Time | Latency p50 | Latency p99 | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 54 ms | 9 µs | 23 µs | 33 ms | 3.1 MB |
| snmp2 | 46 ms | 8 µs | 22 µs | 26 ms | 4.2 MB |
| async-snmp | 61 ms | 10 µs | 32 µs | 40 ms | 3.8 MB |
| csnmp | 61 ms | 12 µs | 32 µs | 44 ms | 3.1 MB |
| net-snmp (C) | 47 ms | 9 µs | 12 µs | 20 ms | 8.2 MB |
| snmpify (Python) | 64 ms | 11 µs | 24 µs | 56 ms | 23.0 MB |
| ezsnmp (Python) | 89 ms | 15 µs | 42 µs | 63 ms | 20.7 MB |
| pysnmp (Python) | 2221 ms | 424 µs | 733 µs | 1768 ms | 37.8 MB |

### poll: 1000 agents, one GetRequest each, all at once

| | Time | Answered | CPU | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 9 ms | 1000 / 1000 | 12 ms | 9 ms | 4.8 MB |
| snmp2 | 86 ms | 1000 / 1000 | 90 ms | 85 ms | 133.6 MB |
| async-snmp | 4020 ms | 1000 / 1000 | 31 ms | 27 ms | 10.1 MB |
| csnmp | 24 ms | 1000 / 1000 | 28 ms | 24 ms | 18.5 MB |
| net-snmp (C) | 12 ms | 1000 / 1000 | 10 ms | 10 ms | 10.9 MB |
| snmpify (Python) | 29 ms | 1000 / 1000 | 107 ms | 63 ms | 32.3 MB |
| ezsnmp (Python) | 171 ms | 1000 / 1000 | 183 ms | 159 ms | 20.1 MB |
| pysnmp (Python) | 4236 ms | 663 / 1000 | 1531 ms | 1425 ms | 67.9 MB |

### idle: start, load the library, exit

| | CPU | Peak RSS |
|---|---:|---:|
| snmpify | 2 ms | 2.9 MB |
| snmp2 | 5 ms | 3.9 MB |
| async-snmp | 4 ms | 3.3 MB |
| csnmp | 3 ms | 2.9 MB |
| net-snmp (C) | 0 ms | 8.2 MB |
| snmpify (Python) | 44 ms | 21.8 MB |
| ezsnmp (Python) | 23 ms | 17.7 MB |
| pysnmp (Python) | 106 ms | 37.7 MB |
