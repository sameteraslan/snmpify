"""snmpify (Python): blocking client for walks and gets, asyncio for polling."""
import asyncio
import time

import snmpify
from common import (BULK_REP, IF_INDEX, LINK_DOWN, MAX_REP, SYS_NAME, TABLE, WRITABLE, args, report,
                    timed, unsupported)

scenario, host, port, n = args()
t0 = time.perf_counter()
if scenario in ("walk", "walk3"):
    user = None
    if scenario == "walk3":
        user = snmpify.UsmUser("bench", auth=("SHA", "bench-auth-pass"), privacy=("AES", "bench-priv-pass"))
    c = snmpify.Client(f"{host}:{port}", user=user, max_repetitions=MAX_REP)
    items = sum(sum(1 for _ in c.walk(TABLE)) for _ in range(n))
    report(items, t0)
elif scenario == "get":
    c = snmpify.Client(f"{host}:{port}")
    lat = []
    for _ in range(n):
        s = time.perf_counter()
        c.get(SYS_NAME)
        lat.append((time.perf_counter() - s) * 1e6)
    report(n, t0, lat)
elif scenario == "poll":
    async def poll():
        m = snmpify.Manager()  # one socket for every agent
        clients = [m.client(f"{host}:{port + k}") for k in range(1, n + 1)]
        res = await asyncio.gather(*(c.get(SYS_NAME) for c in clients), return_exceptions=True)
        return sum(1 for r in res if not isinstance(r, Exception))
    report(asyncio.run(poll()), t0)
elif scenario in ("getnext", "bulk", "set"):
    c = snmpify.Client(f"{host}:{port}", community="private" if scenario == "set" else "public")
    op = {
        "getnext": lambda i: len(c.get_next(SYS_NAME)),
        "bulk": lambda i: len(c.get_bulk(TABLE, 0, BULK_REP)),
        "set": lambda i: len(c.set([(WRITABLE, f"value {i}")])),
    }[scenario]
    items, lat = timed(n, op)
    report(items, t0, lat)
elif scenario in ("trap", "inform"):
    c = snmpify.Client(f"{host}:{port - 1}")
    send = c.trap if scenario == "trap" else c.inform
    items, lat = timed(n, lambda i: (send(LINK_DOWN, [(IF_INDEX, 7)]), 1)[1])
    report(items, t0, lat)
elif scenario == "idle":
    report(0, t0)
else:
    unsupported()
