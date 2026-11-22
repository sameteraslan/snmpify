"""ezsnmp (net-snmp's C library underneath, blocking; no asyncio, so
polling is sequential)."""
import time

from ezsnmp import Session

from common import BULK_REP, IF_INDEX, LINK_DOWN, MAX_REP, SYS_NAME, TABLE, WRITABLE, args, report, timed, unsupported

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
elif scenario in ("getnext", "bulk", "set"):
    s = Session(hostname=host, port_number=port, version="2c",
                community="private" if scenario == "set" else "public", set_max_repeaters_to_num=BULK_REP)
    op = {
        "getnext": lambda i: len(s.get_next(SYS_NAME)),
        "bulk": lambda i: len(s.bulk_get([TABLE])),
        "set": lambda i: len(s.set([WRITABLE, "s", f"value {i}"])),
    }[scenario]
    items, lat = timed(n, op)
    report(items, t0, lat)
elif scenario in ("trap", "inform"):
    # ezsnmp has no notification API on Session; its snmptrap() runs
    # net-snmp's snmptrap command in-process (a new session per call).
    from ezsnmp.netsnmp import snmptrap
    flags = ["-v", "2c", "-c", "public"] + (["-Ci"] if scenario == "inform" else [])
    argv = flags + [f"udp:{host}:{port - 1}", "", LINK_DOWN, IF_INDEX, "i", "7"]
    items, lat = timed(n, lambda i: (snmptrap(argv), 1)[1])
    report(items, t0, lat)
elif scenario == "idle":
    report(0, t0)
else:
    unsupported()
