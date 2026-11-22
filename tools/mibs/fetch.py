#!/usr/bin/env python3
"""Fetches the standard MIB modules from their RFCs and IANA registries
into a directory, for examples/gen_builtin_mibs.rs. The module text is
not committed: only the generated table of names, OIDs and types is.

    python3 tools/mibs/fetch.py /tmp/mibs [--netsnmp-container snmpify-snmpd]
"""
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

RFCS = {
    1155: ["RFC1155-SMI"], 1213: ["RFC1213-MIB"],
    2578: ["SNMPv2-SMI"], 2579: ["SNMPv2-TC"], 2580: ["SNMPv2-CONF"],
    3418: ["SNMPv2-MIB"], 2863: ["IF-MIB"], 4293: ["IP-MIB"], 4022: ["TCP-MIB"],
    4113: ["UDP-MIB"], 2790: ["HOST-RESOURCES-MIB", "HOST-RESOURCES-TYPES"],
    6933: ["ENTITY-MIB", "UUID-TC-MIB"], 3433: ["ENTITY-SENSOR-MIB"],
    3411: ["SNMP-FRAMEWORK-MIB"], 3412: ["SNMP-MPD-MIB"],
    3413: ["SNMP-TARGET-MIB", "SNMP-NOTIFICATION-MIB", "SNMP-PROXY-MIB"],
    3414: ["SNMP-USER-BASED-SM-MIB"], 3415: ["SNMP-VIEW-BASED-ACM-MIB"],
    3584: ["SNMP-COMMUNITY-MIB"], 4001: ["INET-ADDRESS-MIB"], 2856: ["HCNUM-TC"],
    4188: ["BRIDGE-MIB"], 3635: ["EtherLike-MIB"], 2819: ["RMON-MIB"],
    4292: ["IP-FORWARD-MIB"], 4273: ["BGP4-MIB"], 2742: ["AGENTX-MIB"],
    3826: ["SNMP-USM-AES-MIB"], 7860: ["SNMP-USM-HMAC-SHA2-MIB"],
    3014: ["NOTIFICATION-LOG-MIB"], 2981: ["DISMAN-EVENT-MIB"], 2788: ["NETWORK-SERVICES-MIB"],
    2789: ["MTA-MIB"], 2465: ["IPV6-TC", "IPV6-MIB"],
}
IANA = {
    "IANAifType-MIB": "https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib",
    "IANA-ADDRESS-FAMILY-NUMBERS-MIB": "https://www.iana.org/assignments/ianaaddressfamilynumbers-mib/ianaaddressfamilynumbers-mib",
    "IANA-RTPROTO-MIB": "https://www.iana.org/assignments/ianaiprouteprotocol-mib/ianaiprouteprotocol-mib",
}
NETSNMP = ["NET-SNMP-MIB", "NET-SNMP-TC", "NET-SNMP-AGENT-MIB", "NET-SNMP-EXTEND-MIB",
           "NET-SNMP-VACM-MIB", "NET-SNMP-PASS-MIB", "NET-SNMP-EXAMPLES-MIB", "UCD-SNMP-MIB",
           "UCD-DISKIO-MIB", "UCD-DLMOD-MIB", "UCD-DEMO-MIB", "UCD-IPFWACC-MIB", "LM-SENSORS-MIB"]

UA = {"User-Agent": "snmpify-mib-fetch"}


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def strip_pages(text):
    out = []
    for line in text.replace("\r", "").split("\n"):
        line = line.replace("\f", "")
        if re.search(r"\[Page \d+\]\s*$", line) or re.match(r"^RFC \d+\s.*\s\d{4}\s*$", line):
            continue
        out.append(line)
    return "\n".join(out)


def modules(text, wanted):
    found = {}
    lines = strip_pages(text).split("\n")
    i = 0
    while i < len(lines):
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s+DEFINITIONS\s*::=\s*BEGIN", lines[i])
        if m and m.group(1) in wanted:
            # MACRO definitions nest BEGIN … END inside the module.
            j, depth = i, 0
            while j < len(lines):
                code = lines[j].split("--")[0]
                depth += len(re.findall(r"\bBEGIN\b", code))
                if re.match(r"^\s*END\s*$", code):
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            found[m.group(1)] = "\n".join(lines[i:j + 1]) + "\n"
            i = j
        i += 1
    return found


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    for rfc, names in RFCS.items():
        text = get(f"https://www.rfc-editor.org/rfc/rfc{rfc}.txt")
        got = modules(text, names)
        for n in names:
            if n not in got:
                sys.exit(f"RFC {rfc}: {n} not found")
            (out / n).write_text(got[n])
        print(f"RFC {rfc}: {', '.join(names)}")
    for n, url in IANA.items():
        got = modules(get(url), [n])
        (out / n).write_text(got[n])
        print(f"IANA: {n}")
    if "--netsnmp-container" in sys.argv:
        c = sys.argv[sys.argv.index("--netsnmp-container") + 1]
        for n in NETSNMP:
            text = subprocess.run(["docker", "exec", c, "cat", f"/usr/share/snmp/mibs/{n}.txt"],
                                  check=True, capture_output=True, text=True).stdout
            (out / n).write_text(text)
            print(f"net-snmp: {n}")


if __name__ == "__main__":
    main()
