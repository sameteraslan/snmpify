"""ezsnmp (net-snmp's C library underneath, blocking; no asyncio, so
polling is sequential)."""
import time

from ezsnmp import Session

from common import MAX_REP, SYS_NAME, TABLE, args, report, unsupported

scenario, host, port, n = args()
t0 = time.perf_counter()
if scenario in ("walk", "walk3"):
    if scenario == "walk":
        s = Session(hostname=host, port_number=port, version="2c", community="public",
                    set_max_repeaters_to_num=MAX_REP)
    else:
        s = Session(hostname=host, port_number=port, version="3", security_level="authPriv",
                    security_username="bench", auth_protocol="SHA", auth_passphrase="bench-auth-pass",
                    privacy_protocol="AES", privacy_passphrase="bench-priv-pass",
                    set_max_repeaters_to_num=MAX_REP)
    items = sum(len(s.bulk_walk(TABLE)) for _ in range(n))
    report(items, t0)
elif scenario == "get":
    s = Session(hostname=host, port_number=port, version="2c", community="public")
    lat = []
    for _ in range(n):
        st = time.perf_counter()
        s.get(SYS_NAME)
        lat.append((time.perf_counter() - st) * 1e6)
    report(n, t0, lat)
elif scenario == "poll":
    ok = 0
    for k in range(1, n + 1):
        s = Session(hostname=host, port_number=port + k, version="2c", community="public",
                    timeout=1, retries=2)
        ok += len(s.get(SYS_NAME)) == 1
    report(ok, t0)
elif scenario == "idle":
    report(0, t0)
else:
    unsupported()
