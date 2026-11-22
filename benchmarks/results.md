Medians of 5 runs, 2026-11-22, Intel(R) Core(TM) Ultra 7 255HX, Linux 7.0.0-43-generic.
Versions: snmp2 0.5.3, async-snmp 0.18.1, csnmp 0.6.0, pysnmp 7.1.33, ezsnmp 2.5.0, net-snmp 5.9.4.pre2.

### walk: 20 walks of a 10 000-object table, SNMPv2c GetBulk (max-repetitions 25)

| | Time | Objects/s | CPU | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 140 ms | 1,432,470 | 45 ms | 42 ms | 3.3 MB |
| snmpify (owned values) | 147 ms | 1,365,104 | 56 ms | 54 ms | 4.7 MB |
| snmp2 | 141 ms | 1,418,601 | 53 ms | 48 ms | 5.4 MB |
| async-snmp | 185 ms | 1,083,917 | 89 ms | 85 ms | 4.0 MB |
| csnmp | 457 ms | 437,303 | 350 ms | 348 ms | 22.7 MB |
| net-snmp (C) | 158 ms | 1,263,376 | 50 ms | 50 ms | 8.4 MB |
| snmpify (Python) | 275 ms | 728,054 | 221 ms | 177 ms | 22.9 MB |
| ezsnmp (Python) | 2444 ms | 81,831 | 2326 ms | 2303 ms | 29.2 MB |
| pysnmp (Python) | 19794 ms | 10,104 | 18392 ms | 18284 ms | 37.2 MB |

### walk3: the same over SNMPv3 authPriv (SHA, AES-128)

| | Time | Objects/s | CPU | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 193 ms | 1,033,741 | 77 ms | 74 ms | 3.2 MB |
| snmpify (owned values) | 183 ms | 1,094,355 | 74 ms | 72 ms | 5.2 MB |
| snmp2 | 190 ms | 1,052,122 | 78 ms | 72 ms | 5.4 MB |
| async-snmp | 237 ms | 845,641 | 121 ms | 117 ms | 4.1 MB |
| csnmp | n/a | n/a | n/a | n/a | n/a |
| net-snmp (C) | 238 ms | 838,796 | 110 ms | 110 ms | 8.3 MB |
| snmpify (Python) | 324 ms | 617,862 | 235 ms | 192 ms | 23.0 MB |
| ezsnmp (Python) | 2653 ms | 75,385 | 2482 ms | 2458 ms | 28.1 MB |
| pysnmp (Python) | 22474 ms | 8,899 | 20932 ms | 20825 ms | 38.6 MB |

### get: 5000 sequential GetRequests for one object

| | Time | Latency p50 | Latency p99 | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 46 ms | 8 µs | 20 µs | 27 ms | 3.4 MB |
| snmp2 | 44 ms | 8 µs | 15 µs | 23 ms | 5.5 MB |
| async-snmp | 55 ms | 10 µs | 21 µs | 35 ms | 4.0 MB |
| csnmp | 61 ms | 10 µs | 33 µs | 41 ms | 3.0 MB |
| net-snmp (C) | 47 ms | 9 µs | 17 µs | 20 ms | 8.2 MB |
| snmpify (Python) | 60 ms | 10 µs | 18 µs | 49 ms | 23.3 MB |
| ezsnmp (Python) | 125 ms | 24 µs | 67 µs | 101 ms | 20.8 MB |
| pysnmp (Python) | 2252 ms | 431 µs | 736 µs | 1782 ms | 36.9 MB |

### getnext: 2000 sequential GetNextRequests

| | Time | Latency p50 | Latency p99 | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 22 ms | 8 µs | 23 µs | 13 ms | 3.3 MB |
| snmp2 | 21 ms | 8 µs | 24 µs | 10 ms | 5.5 MB |
| async-snmp | 30 ms | 11 µs | 44 µs | 19 ms | 3.9 MB |
| csnmp | 31 ms | 11 µs | 39 µs | 23 ms | 2.9 MB |
| net-snmp (C) | 19 ms | 9 µs | 17 µs | 0 ms | 8.2 MB |
| snmpify (Python) | 29 ms | 11 µs | 26 µs | 24 ms | 23.3 MB |
| ezsnmp (Python) | 51 ms | 24 µs | 72 µs | 41 ms | 20.3 MB |
| pysnmp (Python) | 908 ms | 433 µs | 752 µs | 729 ms | 37.2 MB |

### bulk: 2000 sequential GetBulkRequests, 50 rows each (100 000 objects)

| | Time | Latency p50 | Latency p99 | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 58 ms | 24 µs | 81 µs | 17 ms | 3.2 MB |
| snmp2 | 52 ms | 23 µs | 102 µs | 13 ms | 5.4 MB |
| async-snmp | 65 ms | 28 µs | 157 µs | 25 ms | 4.0 MB |
| csnmp | 169 ms | 75 µs | 306 µs | 125 ms | 3.4 MB |
| net-snmp (C) | 59 ms | 28 µs | 63 µs | 10 ms | 8.3 MB |
| snmpify (Python) | 84 ms | 39 µs | 214 µs | 53 ms | 23.2 MB |
| ezsnmp (Python) | 257 ms | 117 µs | 328 µs | 210 ms | 20.3 MB |
| pysnmp (Python) | 8728 ms | 4304 µs | 7733 µs | 8295 ms | 37.2 MB |

### set: 2000 sequential SetRequests (an OCTET STRING)

| | Time | Latency p50 | Latency p99 | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 23 ms | 8 µs | 30 µs | 13 ms | 3.2 MB |
| snmp2 | 22 ms | 9 µs | 23 µs | 12 ms | 5.5 MB |
| async-snmp | 31 ms | 11 µs | 42 µs | 20 ms | 4.0 MB |
| csnmp | 33 ms | 12 µs | 41 µs | 25 ms | 3.1 MB |
| net-snmp (C) | 20 ms | 10 µs | 12 µs | 0 ms | 8.1 MB |
| snmpify (Python) | 27 ms | 11 µs | 20 µs | 25 ms | 23.0 MB |
| ezsnmp (Python) | 57 ms | 26 µs | 137 µs | 46 ms | 20.3 MB |
| pysnmp (Python) | 987 ms | 464 µs | 781 µs | 791 ms | 36.8 MB |

### trap: 2000 SNMPv2c traps sent (no answer; the time to hand each to the socket)

| | Time | Latency p50 | Latency p99 | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 7 ms | 2 µs | 7 µs | 7 ms | 3.3 MB |
| snmp2 | n/a | n/a | n/a | n/a | n/a |
| async-snmp | 8 ms | 3 µs | 8 µs | 7 ms | 4.0 MB |
| csnmp | 16 ms | 6 µs | 17 µs | 17 ms | 3.1 MB |
| net-snmp (C) | 6 ms | 3 µs | 3 µs | 0 ms | 8.4 MB |
| snmpify (Python) | 8 ms | 3 µs | 5 µs | 14 ms | 23.0 MB |
| ezsnmp (Python) | 224 ms | 106 µs | 238 µs | 222 ms | 20.2 MB |
| pysnmp (Python) | 535 ms | 256 µs | 278 µs | 534 ms | 37.2 MB |

### inform: 2000 SNMPv2c informs, each waiting for its acknowledgement

| | Time | Latency p50 | Latency p99 | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 24 ms | 8 µs | 26 µs | 15 ms | 3.3 MB |
| snmp2 | n/a | n/a | n/a | n/a | n/a |
| async-snmp | 30 ms | 11 µs | 37 µs | 21 ms | 4.0 MB |
| csnmp | 41 ms | 16 µs | 147 µs | 33 ms | 3.2 MB |
| net-snmp (C) | 21 ms | 10 µs | 14 µs | 10 ms | 8.2 MB |
| snmpify (Python) | 30 ms | 12 µs | 22 µs | 27 ms | 23.3 MB |
| ezsnmp (Python) | 268 ms | 118 µs | 297 µs | 246 ms | 20.2 MB |
| pysnmp (Python) | 1591 ms | 741 µs | 1092 µs | 1373 ms | 37.7 MB |

### poll: 1000 agents, one GetRequest each, all at once

| | Time | Answered | CPU | CPU, work | Peak RSS |
|---|---:|---:|---:|---:|---:|
| snmpify | 9 ms | 1000 / 1000 | 12 ms | 9 ms | 5.5 MB |
| snmp2 | 85 ms | 1000 / 1000 | 90 ms | 85 ms | 134.8 MB |
| async-snmp | 4023 ms | 1000 / 1000 | 36 ms | 32 ms | 10.2 MB |
| csnmp | 24 ms | 1000 / 1000 | 28 ms | 26 ms | 18.4 MB |
| net-snmp (C) | 12 ms | 1000 / 1000 | 10 ms | 10 ms | 11.0 MB |
| snmpify (Python) | 29 ms | 1000 / 1000 | 104 ms | 61 ms | 34.1 MB |
| ezsnmp (Python) | 176 ms | 1000 / 1000 | 191 ms | 167 ms | 20.0 MB |
| pysnmp (Python) | 4275 ms | 663 / 1000 | 1562 ms | 1454 ms | 66.9 MB |

### idle: start, load the library, exit

| | CPU | Peak RSS |
|---|---:|---:|
| snmpify | 3 ms | 3.1 MB |
| snmp2 | 5 ms | 5.2 MB |
| async-snmp | 4 ms | 3.5 MB |
| csnmp | 3 ms | 2.9 MB |
| net-snmp (C) | 0 ms | 8.1 MB |
| snmpify (Python) | 44 ms | 21.9 MB |
| ezsnmp (Python) | 24 ms | 17.6 MB |
| pysnmp (Python) | 108 ms | 36.9 MB |
