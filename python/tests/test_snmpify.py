"""The Python bindings against an in-process snmpify agent (and net-snmp's
snmpd when SNMPIFY_AGENT is set)."""

import asyncio
import os
import threading
import time

import pytest

import snmpify
from snmpify import (
    END_OF_MIB_VIEW,
    NO_SUCH_INSTANCE,
    NO_SUCH_OBJECT,
    Counter32,
    Counter64,
    Gauge32,
    IpAddress,
    ObjectId,
    Opaque,
    TimeTicks,
)

ENT = "1.3.6.1.4.1.99999"
ALICE = snmpify.UsmUser("alice", auth=("SHA-256", "alice-auth"), privacy=("AES", "alice-priv"))
BOB = snmpify.UsmUser("bob", auth=("MD5", "bob-auth-pass"))


@pytest.fixture(scope="module")
def agent():
    a = snmpify.Agent(
        "127.0.0.1:0",
        communities={"public": "ro", "private": "rw"},
        users=[(ALICE, "rw"), (BOB, "ro")],
    )
    a.set("1.3.6.1.2.1.1.5.0", "py-agent")
    a.set(f"{ENT}.1.0", 7)
    a.set(f"{ENT}.2.0", Counter32(4_000_000_000))
    a.set(f"{ENT}.3.0", Gauge32(5))
    a.set(f"{ENT}.4.0", TimeTicks(12345))
    a.set(f"{ENT}.5.0", Counter64(1 << 40))
    a.set(f"{ENT}.6.0", IpAddress("192.0.2.1"))
    a.set(f"{ENT}.7.0", ObjectId("1.3.6.1.4.1.8072"))
    a.set(f"{ENT}.8.0", Opaque(b"\x01\x02"))
    a.set(f"{ENT}.9.0", b"\x00\xff")
    a.set(f"{ENT}.10.0", "writable", writable=True)
    for i in range(1, 31):
        a.set(f"{ENT}.20.1.{i}", f"row {i}")
    calls = []
    a.set_callback(f"{ENT}.11.0", lambda: Gauge32(len(calls.append(1) or calls)))
    a.start()
    yield a
    a.stop()


def client(agent, **kw):
    kw.setdefault("timeout", 0.5)
    kw.setdefault("retries", 1)
    return snmpify.Client(agent.address, **kw)


VERSIONS = [
    {"community": "public", "version": "1"},
    {"community": "public"},
    {"user": ALICE},
    {"user": BOB},
]


@pytest.mark.parametrize("kw", VERSIONS, ids=["v1", "v2c", "v3-authPriv", "v3-authNoPriv"])
def test_get_types_walk(agent, kw):
    c = client(agent, **kw)
    assert c.get("1.3.6.1.2.1.1.5.0") == b"py-agent"
    assert c.get(f"{ENT}.1.0") == 7
    v = c.get(f"{ENT}.2.0")
    assert isinstance(v, Counter32) and v == 4_000_000_000
    assert repr(c.get(f"{ENT}.3.0")) == "Gauge32(5)"
    assert c.get(f"{ENT}.4.0").seconds == 123.45
    assert c.get(f"{ENT}.6.0") == IpAddress("192.0.2.1")
    assert isinstance(c.get(f"{ENT}.7.0"), ObjectId)
    assert c.get(f"{ENT}.8.0") == Opaque(b"\x01\x02")
    assert c.get(f"{ENT}.9.0") == b"\x00\xff"
    rows = list(c.walk(f"{ENT}.20"))
    assert len(rows) == 30
    assert rows[0] == (f"{ENT}.20.1.1", b"row 1")
    if c.version == "1":
        # No Counter64 in SNMPv1: noSuchName.
        with pytest.raises(snmpify.AgentError) as e:
            c.get(f"{ENT}.5.0")
        assert e.value.status == "noSuchName" and e.value.index == 1
    else:
        assert c.get(f"{ENT}.5.0") == Counter64(1 << 40)
        assert c.get(f"{ENT}.99.0") is NO_SUCH_OBJECT
        assert c.get(f"{ENT}.1.1") is NO_SUCH_INSTANCE
        assert c.get_next(["1.3.6.1.9"])[0][1] is END_OF_MIB_VIEW
        assert not NO_SUCH_OBJECT
        bulk = c.get_bulk([f"{ENT}.20.1.28"], max_repetitions=2)
        assert [o for o, _ in bulk] == [f"{ENT}.20.1.29", f"{ENT}.20.1.30"]
    many = c.get_many(["1.3.6.1.2.1.1.5.0", f"{ENT}.1.0"])
    assert many == [("1.3.6.1.2.1.1.5.0", b"py-agent"), (f"{ENT}.1.0", 7)]
    assert c.get_next(f"{ENT}.1.0")[0][0] == f"{ENT}.2.0"


def test_set_and_errors(agent):
    rw = client(agent, community="private")
    rw.set({f"{ENT}.10.0": "changed"})
    assert agent.get(f"{ENT}.10.0") == b"changed"
    rw.set([(f"{ENT}.10.0", b"bytes too")])
    assert client(agent).get(f"{ENT}.10.0") == b"bytes too"
    with pytest.raises(snmpify.AgentError) as e:
        rw.set({f"{ENT}.10.0": 5})
    assert e.value.status == "wrongType" and e.value.oid == f"{ENT}.10.0"
    with pytest.raises(snmpify.AgentError) as e:
        client(agent).set({f"{ENT}.10.0": "x"})
    assert e.value.status == "noAccess"
    # v3: alice may write, bob not.
    client(agent, user=ALICE).set({f"{ENT}.10.0": "alice"})
    with pytest.raises(snmpify.AgentError):
        client(agent, user=BOB).set({f"{ENT}.10.0": "bob"})
    # Reports, timeouts, bad arguments.
    wrong = snmpify.UsmUser("alice", auth=("SHA-256", "not-alice"))
    with pytest.raises(snmpify.ReportError) as e:
        client(agent, user=wrong).get("1.3.6.1.2.1.1.5.0")
    assert e.value.kind == "wrongDigest"
    with pytest.raises(snmpify.ReportError) as e:
        client(agent, user=snmpify.UsmUser("mallory")).get("1.3.6.1.2.1.1.5.0")
    assert e.value.kind == "unknownUserName"
    t = time.monotonic()
    with pytest.raises(snmpify.SnmpTimeout):
        client(agent, community="nope", timeout=0.1, retries=1).get("1.3.6.1.2.1.1.5.0")
    assert time.monotonic() - t >= 0.2
    assert issubclass(snmpify.SnmpTimeout, TimeoutError)
    c = client(agent)
    for bad in ["1.x", "", "7.1"]:
        with pytest.raises(snmpify.InvalidArgument):
            c.get(bad)
    with pytest.raises(snmpify.InvalidArgument):
        rw.set({f"{ENT}.10.0": True})
    with pytest.raises(snmpify.InvalidArgument):
        rw.set({f"{ENT}.10.0": 1.5})
    with pytest.raises(snmpify.InvalidArgument):
        rw.set({f"{ENT}.10.0": 2**40})
    with pytest.raises(snmpify.InvalidArgument):
        client(agent, community="public", version="3")
    with pytest.raises(snmpify.InvalidArgument):
        snmpify.UsmUser("x", auth=("SHA-999", "password"))
    with pytest.raises(snmpify.InvalidArgument):
        snmpify.UsmUser("x", auth=("SHA", "short"))
    with pytest.raises(snmpify.InvalidArgument):
        client(agent, timeout=0)
    with pytest.raises(snmpify.InvalidArgument):
        client(agent, version="1").get_bulk([ENT])
    assert isinstance(snmpify.SnmpTimeout("x"), snmpify.SnmpError)


def test_callbacks_and_threads(agent):
    c = client(agent)
    a, b = c.get(f"{ENT}.11.0"), c.get(f"{ENT}.11.0")
    assert isinstance(a, Gauge32) and b == a + 1
    results = []

    def worker(i):
        results.append(c.get(f"{ENT}.20.1.{i}"))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 21)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == sorted(f"row {i}".encode() for i in range(1, 21))


async def test_asyncio(agent):
    c = snmpify.AsyncClient(agent.address, user=ALICE, timeout=0.5)
    assert await c.get("1.3.6.1.2.1.1.5.0") == b"py-agent"
    assert c.engine_id is not None
    values = await asyncio.gather(*(c.get(f"{ENT}.20.1.{i}") for i in range(1, 31)))
    assert values == [f"row {i}".encode() for i in range(1, 31)]
    rows = [r async for r in c.walk(f"{ENT}.20")]
    assert len(rows) == 30
    assert (await c.get_many([f"{ENT}.1.0"]))[0][1] == 7
    assert (await c.get_next([f"{ENT}.1.0"]))[0][0] == f"{ENT}.2.0"
    assert len(await c.get_bulk([f"{ENT}.20"], max_repetitions=5)) == 5
    await c.set({f"{ENT}.10.0": "async"})
    assert agent.get(f"{ENT}.10.0") == b"async"
    with pytest.raises(snmpify.SnmpTimeout):
        await snmpify.AsyncClient(agent.address, community="nope", timeout=0.1, retries=0).get(ENT + ".1.0")
    assert "AsyncClient" in repr(c) and c.version == "3"


async def test_manager_polls_many_agents(agent):
    m = snmpify.Manager("127.0.0.1:0", timeout=0.5, max_in_flight=8)
    assert m.address.startswith("127.0.0.1:")
    clients = [m.client(agent.address) for _ in range(30)]
    res = await asyncio.gather(*(c.get(f"{ENT}.20.1.{i + 1}") for i, c in enumerate(clients)))
    assert res == [f"row {i + 1}".encode() for i in range(30)]
    b = m.blocking_client(agent.address, user=ALICE)
    assert b.get("1.3.6.1.2.1.1.5.0") == b"py-agent"
    with pytest.raises(snmpify.InvalidArgument):
        m.client("no-such-host.invalid")


def test_notifications_sync():
    rx = snmpify.NotificationReceiver("127.0.0.1:0", communities=["public"], users=[ALICE])
    v2 = snmpify.Client(rx.address, community="public")
    v2.trap("1.3.6.1.6.3.1.1.5.3", [("1.3.6.1.2.1.2.2.1.1.7", 7)])
    n = rx.recv(timeout=2)
    assert (n.kind, n.version, n.trap_oid) == ("trap", "2c", "1.3.6.1.6.3.1.1.5.3")
    assert n.community == b"public" and n.user is None
    assert n.varbinds == [("1.3.6.1.2.1.2.2.1.1.7", 7)]
    assert n.uptime is not None and "trap" in repr(n)
    assert rx.recv(timeout=0.05) is None
    # A v3 inform from another thread: discovery, then the ack.
    v3 = snmpify.Client(rx.address, user=ALICE)
    t = threading.Thread(target=lambda: v3.inform("1.3.6.1.6.3.1.1.5.1"))
    t.start()
    n = rx.recv(timeout=5)
    t.join()
    assert (n.kind, n.version, n.user, n.level) == ("inform", "3", "alice", "authPriv")
    assert "NotificationReceiver" in repr(rx)


async def test_notifications_async():
    rx = snmpify.NotificationReceiver("127.0.0.1:0", communities=None)
    c = snmpify.AsyncClient(rx.address, community="anything")
    await c.trap("1.3.6.1.6.3.1.1.5.4")
    async for n in rx:
        assert n.trap_oid == "1.3.6.1.6.3.1.1.5.4"
        break
    inform = asyncio.ensure_future(c.inform("1.3.6.1.6.3.1.1.5.2", {"1.3.6.1.2.1.1.5.0": "x"}))
    n = await rx.recv_async()
    assert n.kind == "inform"
    assert len(await inform) == 3


def test_mib():
    mib = snmpify.Mib()
    assert len(mib.modules) >= 50
    assert mib.resolve("IF-MIB::ifDescr.3") == "1.3.6.1.2.1.2.2.1.2.3"
    assert mib.name("1.3.6.1.2.1.1.3.0") == "SNMPv2-MIB::sysUpTime.0"
    assert mib.format("1.3.6.1.2.1.2.2.1.8.3", 1) == "IF-MIB::ifOperStatus.3 = up(1)"
    assert mib.format_value("1.3.6.1.2.1.2.2.1.6.1", b"\x00\x1b\x21\x3a\xc6\x08") == "00:1b:21:3a:c6:08"
    o = mib.object("ifOperStatus")
    assert o["kind"] == "column" and o["access"] == "ReadOnly" and (2, "down") in o["enums"]
    assert mib.object("nothing") is None
    with pytest.raises(snmpify.InvalidArgument):
        mib.resolve("noSuchName.0")
    mods = mib.load_str(
        "ACME-MIB DEFINITIONS ::= BEGIN IMPORTS enterprises FROM SNMPv2-SMI; "
        "acme OBJECT IDENTIFIER ::= { enterprises 99999 } END"
    )
    assert mods == ["ACME-MIB"]
    assert mib.name(ENT + ".5") == "ACME-MIB::acme.5"
    assert snmpify.Mib(standard=False).modules == []
    with pytest.raises(snmpify.InvalidArgument):
        mib.load_file("/no/such/file")
    assert "Mib(" in repr(mib)


def test_agent_lifecycle():
    with snmpify.Agent("127.0.0.1:0") as a:
        a.set("1.3.6.1.2.1.1.5.0", "ctx")
        assert snmpify.Client(a.address).get("1.3.6.1.2.1.1.5.0") == b"ctx"
        assert a.remove("1.3.6.1.2.1.1.5.0") and a.get("1.3.6.1.2.1.1.5.0") is None
        with pytest.raises(snmpify.InvalidArgument):
            a.start()
        assert "Agent(" in repr(a)
    with pytest.raises(snmpify.InvalidArgument):
        snmpify.Agent("127.0.0.1:0", communities={"x": "admin"})


@pytest.mark.skipif("SNMPIFY_AGENT" not in os.environ, reason="SNMPIFY_AGENT not set")
def test_netsnmp():
    target = os.environ["SNMPIFY_AGENT"]
    c = snmpify.Client(target)
    assert c.get("1.3.6.1.2.1.1.5.0") == b"snmpify-agent"
    assert len(list(c.walk("1.3.6.1.2.1.2.2"))) > 10
    user = snmpify.UsmUser("sha512_aes256", auth=("SHA-512", "auth-sha512_aes256"),
                           privacy=("AES-256", "priv-sha512_aes256"))
    assert snmpify.Client(target, user=user).get("1.3.6.1.2.1.1.5.0") == b"snmpify-agent"
    mib = snmpify.Mib()
    lines = [mib.format(o, v) for o, v in c.walk("1.3.6.1.2.1.2.2.1.8")]
    assert lines[0].startswith("IF-MIB::ifOperStatus.1 = up(1)")
