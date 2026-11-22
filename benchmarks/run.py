#!/usr/bin/env python3
"""Runs every client against bench-agent; writes results.json and results.md.

    cargo build --release                         # agent + Rust clients
    docker build -t snmpify-bench-netsnmp c       # net-snmp's C client
    python3 -m venv python/.venv && python/.venv/bin/pip install --require-hashes -r python/requirements.txt
    (cd ../python && ../benchmarks/python/.venv/bin/maturin develop --release)
    python3 run.py --runs 5

Clients run one at a time, interleaved (A, B, C, A, B, C …), so drift
affects all alike; the tables show medians. Every client runs under
/usr/bin/time (inside its container for net-snmp) for CPU time and peak
memory; an "idle" run (start, load the library, exit) measures each
client's startup, which "CPU, work" subtracts.
"""
import argparse
import json
import os
import pathlib
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
REL = HERE / "target" / "release"
PY = HERE / "python" / ".venv" / "bin" / "python"
HOST, PORT, N_POLL = "127.0.0.1", 16100, 1000
TIME_FMT = "TIME %e %U %S %M"

SCENARIOS = {
    # name: (argument, description)
    "walk": (20, "20 walks of a 10 000-object table, SNMPv2c GetBulk (max-repetitions 25)"),
    "walk3": (20, "the same over SNMPv3 authPriv (SHA, AES-128)"),
    "get": (5000, "5000 sequential GetRequests for one object"),
    "poll": (N_POLL, f"{N_POLL} agents, one GetRequest each, all at once"),
    "idle": (0, "start, load the library, exit"),
}


def clients():
    py = lambda script: [str(PY), str(HERE / "python" / script)]
    return {
        "snmpify": [str(REL / "bench-snmpify")],
        "snmpify (owned values)": ["env", "SNMPIFY_BENCH_OWNED=1", str(REL / "bench-snmpify")],
        "snmp2": [str(REL / "bench-snmp2")],
        "async-snmp": [str(REL / "bench-async-snmp")],
        "csnmp": [str(REL / "bench-csnmp")],
        "net-snmp (C)": ["@docker"],
        "snmpify (Python)": py("bench_snmpify.py"),
        "ezsnmp (Python)": py("bench_ezsnmp.py"),
        "pysnmp (Python)": py("bench_pysnmp.py"),
    }


def run_one(cmd, scenario, n):
    args = [scenario, HOST, str(PORT), str(n)]
    if cmd == ["@docker"]:
        full = ["docker", "run", "--rm", "--network", "host", "snmpify-bench-netsnmp",
                "/usr/bin/time", "-f", TIME_FMT, "bench_netsnmp", *args]
    else:
        full = ["/usr/bin/time", "-f", TIME_FMT, *cmd, *args]
    # wait4 on /usr/bin/time gives its (and so the client's) CPU time in
    # microseconds; time's own output (10 ms resolution) is used only for
    # the container, where wait4 would measure the docker CLI.
    with tempfile.TemporaryFile("w+") as out, tempfile.TemporaryFile("w+") as err:
        p = subprocess.Popen(full, stdout=out, stderr=err, text=True)
        _, status, ru = os.wait4(p.pid, 0)
        p.returncode = os.waitstatus_to_exitcode(status)
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(), err.read()
    rec = None
    for line in stdout.splitlines():
        if line.startswith("{"):
            rec = json.loads(line)
    t = [l.split() for l in stderr.splitlines() if l.startswith("TIME ")]
    if p.returncode != 0 or rec is None or not t:
        return {"failed": (stderr or stdout)[-800:]}
    if rec.get("unsupported"):
        return rec
    _, wall, user, sys_, rss = t[-1]
    if cmd == ["@docker"]:
        rec["cpu_ms"] = (float(user) + float(sys_)) * 1e3
    else:
        rec["cpu_ms"] = (ru.ru_utime + ru.ru_stime) * 1e3
    rec["rss_mb"] = int(rss) / 1024
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--only", nargs="*", help="clients to run")
    ap.add_argument("--scenarios", nargs="*", default=list(SCENARIOS))
    a = ap.parse_args()
    agent = subprocess.Popen([str(REL / "bench-agent"), HOST, str(PORT), str(N_POLL)],
                             stdout=subprocess.PIPE, text=True)
    assert agent.stdout.readline().strip() == "READY"
    results = {}
    try:
        for run in range(a.runs):
            for scenario in a.scenarios:
                n = SCENARIOS[scenario][0]
                for name, cmd in clients().items():
                    if a.only and name not in a.only:
                        continue
                    rec = run_one(cmd, scenario, n)
                    results.setdefault(scenario, {}).setdefault(name, []).append(rec)
                    if "failed" in rec:
                        print(f"run {run} {scenario} {name}: FAILED {rec['failed']}", file=sys.stderr)
                    elif not rec.get("unsupported"):
                        print(f"run {run} {scenario:5} {name:18} {rec['ms']:9.1f} ms  items {rec['items']:6}  "
                              f"cpu {rec['cpu_ms']:7.0f} ms  rss {rec['rss_mb']:6.1f} MB", flush=True)
                    time.sleep(0.2)
    finally:
        agent.terminate()
    meta = {
        "runs": a.runs,
        "date": time.strftime("%Y-%m-%d"),
        "kernel": platform.release(),
        "cpu": next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), ""),
        "versions": versions(),
        "scenarios": {k: v[1] for k, v in SCENARIOS.items()},
    }
    (HERE / "results.json").write_text(json.dumps({"meta": meta, "results": results}, indent=1))
    summarize()


def versions():
    v = {}
    lock = (HERE / "Cargo.lock").read_text()
    for crate in ["snmp2", "async-snmp", "csnmp"]:
        m = re.search(r'name = "%s"\nversion = "([^"]+)"' % re.escape(crate), lock)
        v[crate] = m.group(1) if m else "?"
    reqs = (HERE / "python" / "requirements.txt").read_text()
    for pkg in ["pysnmp", "ezsnmp"]:
        m = re.search(r"^%s==([^\s]+)" % pkg, reqs, re.M)
        v[pkg] = m.group(1) if m else "?"
    out = subprocess.run(["docker", "run", "--rm", "snmpify-bench-netsnmp", "net-snmp-config", "--version"],
                         capture_output=True, text=True).stdout.strip()
    v["net-snmp"] = out or "?"
    return v


def summarize():
    data = json.loads((HERE / "results.json").read_text())
    meta, results = data["meta"], data["results"]
    med = {}
    for scenario, by_client in results.items():
        for name, recs in by_client.items():
            ok = [r for r in recs if "failed" not in r and not r.get("unsupported")]
            if not ok:
                med.setdefault(scenario, {})[name] = None if any(r.get("unsupported") for r in recs) else "failed"
                continue
            med.setdefault(scenario, {})[name] = {
                k: statistics.median(r[k] for r in ok) for k in ok[0] if isinstance(ok[0][k], (int, float))
            }
    idle = med.get("idle", {})
    lines = [f"Medians of {meta['runs']} runs, {meta['date']}, {meta['cpu']}, Linux {meta['kernel']}.",
             "Versions: " + ", ".join(f"{k} {v}" for k, v in meta["versions"].items()) + ".", ""]
    heads = {
        "walk": ["Time", "Objects/s", "CPU", "CPU, work", "Peak RSS"],
        "walk3": ["Time", "Objects/s", "CPU", "CPU, work", "Peak RSS"],
        "get": ["Time", "Latency p50", "Latency p99", "CPU, work", "Peak RSS"],
        "poll": ["Time", "Answered", "CPU", "CPU, work", "Peak RSS"],
        "idle": ["CPU", "Peak RSS"],
    }
    for scenario in ["walk", "walk3", "get", "poll", "idle"]:
        if scenario not in med:
            continue
        lines += [f"### {scenario}: {meta['scenarios'][scenario]}", "",
                  "| | " + " | ".join(heads[scenario]) + " |", "|---|" + "---:|" * len(heads[scenario])]
        for name, m in med[scenario].items():
            if m is None:
                lines.append(f"| {name} | " + " | ".join(["n/a"] * len(heads[scenario])) + " |")
                continue
            if m == "failed":
                lines.append(f"| {name} | " + " | ".join(["failed"] * len(heads[scenario])) + " |")
                continue
            base = idle.get(name) if isinstance(idle.get(name), dict) else None
            work = f"{max(m['cpu_ms'] - base['cpu_ms'], 0):.0f} ms" if base else "?"
            if scenario in ("walk", "walk3"):
                row = [f"{m['ms']:.0f} ms", f"{m['items'] / m['ms'] * 1e3:,.0f}", f"{m['cpu_ms']:.0f} ms", work,
                       f"{m['rss_mb']:.1f} MB"]
            elif scenario == "get":
                row = [f"{m['ms']:.0f} ms", f"{m['p50_us']:.0f} µs", f"{m['p99_us']:.0f} µs", work,
                       f"{m['rss_mb']:.1f} MB"]
            elif scenario == "poll":
                row = [f"{m['ms']:.0f} ms", f"{m['items']:.0f} / {N_POLL}", f"{m['cpu_ms']:.0f} ms", work,
                       f"{m['rss_mb']:.1f} MB"]
            else:
                row = [f"{m['cpu_ms']:.0f} ms", f"{m['rss_mb']:.1f} MB"]
            lines.append(f"| {name} | " + " | ".join(row) + " |")
        lines.append("")
    (HERE / "results.md").write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    if "--summarize" in sys.argv:
        summarize()
    else:
        main()
