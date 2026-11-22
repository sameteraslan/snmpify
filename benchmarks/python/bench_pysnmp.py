"""pysnmp 7 (asyncio, pure Python)."""
import asyncio
import time

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget,
    UsmUserData, bulk_walk_cmd, get_cmd, usmAesCfb128Protocol, usmHMACSHAAuthProtocol,
)

from common import MAX_REP, SYS_NAME, TABLE, args, report, unsupported

scenario, host, port, n = args()


async def main():
    engine = SnmpEngine()
    t0 = time.perf_counter()
    if scenario in ("walk", "walk3"):
        auth = CommunityData("public")
        if scenario == "walk3":
            auth = UsmUserData("bench", "bench-auth-pass", "bench-priv-pass",
                               authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol)
        target = await UdpTransportTarget.create((host, port), timeout=1, retries=2)
        items = 0
        for _ in range(n):
            async for err, status, _idx, vbs in bulk_walk_cmd(
                engine, auth, target, ContextData(), 0, MAX_REP,
                ObjectType(ObjectIdentity(TABLE)), lexicographicMode=False):
                assert not err and not status, (err, status)
                items += len(vbs)
        report(items, t0)
    elif scenario == "get":
        target = await UdpTransportTarget.create((host, port), timeout=1, retries=2)
        lat = []
        for _ in range(n):
            s = time.perf_counter()
            err, status, _idx, _vbs = await get_cmd(engine, CommunityData("public"), target, ContextData(),
                                                   ObjectType(ObjectIdentity(SYS_NAME)))
            assert not err and not status, (err, status)
            lat.append((time.perf_counter() - s) * 1e6)
        report(n, t0, lat)
    elif scenario == "poll":
        async def one(k):
            target = await UdpTransportTarget.create((host, port + k), timeout=1, retries=2)
            err, status, _idx, _vbs = await get_cmd(engine, CommunityData("public"), target, ContextData(),
                                                   ObjectType(ObjectIdentity(SYS_NAME)))
            return not err and not status
        res = await asyncio.gather(*(one(k) for k in range(1, n + 1)))
        report(sum(res), t0)
    elif scenario == "idle":
        report(0, t0)
    else:
        unsupported()
    engine.close_dispatcher()


asyncio.run(main())
