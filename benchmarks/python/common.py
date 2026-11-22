"""Shared by the Python clients: arguments and the JSON line printed."""
import json
import sys
import time

SYS_NAME = "1.3.6.1.2.1.1.5.0"
TABLE = "1.3.6.1.4.1.99999.1"
MAX_REP = 25


def args():
    if len(sys.argv) < 5:
        sys.exit(f"usage: {sys.argv[0]} walk|walk3|get|poll HOST PORT N")
    return sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])


def report(items, t0, lat=()):
    ms = (time.perf_counter() - t0) * 1e3
    lat = sorted(lat)
    pct = lambda p: lat[round((len(lat) - 1) * p)] if lat else 0.0
    print(json.dumps({"items": items, "ms": round(ms, 3), "p50_us": round(pct(0.5), 1),
                      "p99_us": round(pct(0.99), 1)}))


def unsupported():
    print(json.dumps({"unsupported": True}))
