# snmpify for Python

Fast, safe SNMP for Python with a Rust core: SNMPv1, v2c and v3
(every standard authentication and privacy protocol), blocking and
asyncio APIs, traps and informs, an agent, and MIBs with the standard
modules built in. No C library to install; wheels for Python 3.9+.

```sh
pip install snmpify
```

## Client

```python
import snmpify

c = snmpify.Client("192.0.2.1", community="public")          # v2c, port 161
print(c.get("1.3.6.1.2.1.1.5.0"))                            # b'router-1'
for oid, value in c.walk("1.3.6.1.2.1.2.2.1.2"):             # GetBulk walk
    print(oid, value)
c.set({"1.3.6.1.2.1.1.4.0": "ops@example.net"})

# SNMPv3
user = snmpify.UsmUser("monitor", auth=("SHA-256", "auth-password"),
                       privacy=("AES", "priv-password"))
v3 = snmpify.Client("192.0.2.1", user=user)
```

asyncio: the same methods on `snmpify.AsyncClient`, and
`async for oid, value in client.walk(...)`. Many agents over one socket:
`m = snmpify.Manager()`, then `m.client("192.0.2.7")` for each agent
(`asyncio.gather` them; 1000 agents take about 30 ms).

Values keep their SNMP type: `int` (INTEGER), `bytes` (OCTET STRING),
`snmpify.Counter32` / `Gauge32` / `TimeTicks` / `Counter64` (`int`
subclasses), `snmpify.IpAddress` / `ObjectId` (`str` subclasses),
`snmpify.NO_SUCH_OBJECT` … Pass them to `set` to choose the type.

Protocols: `MD5`, `SHA`, `SHA-224` … `SHA-512`; `DES`, `AES`, `AES-192`,
`AES-256`, and Cisco's AES variants `AES-192-C`, `AES-256-C`.

Errors: `snmpify.SnmpTimeout`, `AgentError` (`.status`, `.index`,
`.oid`), `ReportError` (SNMPv3: `.kind`, e.g. `wrongDigest`), all
`snmpify.SnmpError`.

## Traps and informs

```python
rx = snmpify.NotificationReceiver("0.0.0.0:162", communities=["public"], users=[user])
n = rx.recv(timeout=5)            # or: async for n in rx
print(n.kind, n.trap_oid, n.varbinds)

c.trap("1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.2.2.1.1.7", 7)])
c.inform("1.3.6.1.6.3.1.1.5.3")   # waits for the acknowledgement
```

## Agent

```python
agent = snmpify.Agent("0.0.0.0:161", communities={"public": "ro", "private": "rw"})
agent.set("1.3.6.1.2.1.1.5.0", "my-device")
agent.set("1.3.6.1.4.1.99999.1.0", 5, writable=True)
agent.set_callback("1.3.6.1.4.1.99999.2.0", lambda: snmpify.Gauge32(read_sensor()))
agent.start()
```

## MIBs

```python
mib = snmpify.Mib()                       # the standard modules, built in
mib.load_file("VENDOR-MIB.txt")
mib.resolve("IF-MIB::ifDescr.3")          # '1.3.6.1.2.1.2.2.1.2.3'
mib.format("1.3.6.1.2.1.2.2.1.8.3", 1)    # 'IF-MIB::ifOperStatus.3 = up(1)'
```

See the [main README](https://github.com/snmp-rs/snmpify) for the Rust
library, the comparison with other SNMP libraries and the benchmarks.
