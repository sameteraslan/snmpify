# Security policy

## Supported versions

Security fixes go into the latest release of `snmpify` (and, once
published, its Python and C packages).

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub security advisories](https://github.com/snmp-rs/snmpify/security/advisories/new).
Include the version and, for parsing problems, the message bytes that
trigger it.

snmpify decodes packets from the network, so crashes, hangs or excessive
memory use on malformed input are security issues. You should get a reply
within a week. Once a fix is released, the advisory is published with
credit to the reporter, unless you prefer otherwise.
