"""SNMP value types that keep their SNMP type through Python.

Numbers are ``int`` subclasses and addresses ``str`` subclasses, so they
work wherever a plain value does; ``set`` sends them with the right type.
Plain ``int`` is sent as INTEGER, ``str`` and ``bytes`` as OCTET STRING.
"""

__all__ = [
    "Counter32", "Gauge32", "Unsigned32", "TimeTicks", "Counter64",
    "IpAddress", "ObjectId", "Opaque",
    "NoSuchObject", "NoSuchInstance", "EndOfMibView",
    "NO_SUCH_OBJECT", "NO_SUCH_INSTANCE", "END_OF_MIB_VIEW",
]


class _Int(int):
    __slots__ = ()

    def __repr__(self) -> str:
        return f"{type(self).__name__}({int(self)})"


class Counter32(_Int):
    """Counter32: a wrapping 32-bit counter."""


class Gauge32(_Int):
    """Gauge32 (also Unsigned32)."""


Unsigned32 = Gauge32


class TimeTicks(_Int):
    """TimeTicks: hundredths of a second."""

    @property
    def seconds(self) -> float:
        return int(self) / 100


class Counter64(_Int):
    """Counter64: a wrapping 64-bit counter."""


class IpAddress(str):
    """IpAddress: a dotted IPv4 address."""

    __slots__ = ()

    def __repr__(self) -> str:
        return f"IpAddress({str(self)!r})"


class ObjectId(str):
    """OBJECT IDENTIFIER as a dotted string."""

    __slots__ = ()

    def __repr__(self) -> str:
        return f"ObjectId({str(self)!r})"


class Opaque(bytes):
    """Opaque: arbitrary BER, as bytes."""

    def __repr__(self) -> str:
        return f"Opaque({bytes(self)!r})"


class _Exception:
    """An SNMPv2 exception value: the object or instance is missing, or a
    walk reached the end of the MIB view. Falsy."""

    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        self._name = name

    def __repr__(self) -> str:
        return self._name

    def __bool__(self) -> bool:
        return False


NoSuchObject = _Exception
NO_SUCH_OBJECT = _Exception("NoSuchObject")
NO_SUCH_INSTANCE = _Exception("NoSuchInstance")
END_OF_MIB_VIEW = _Exception("EndOfMibView")
NoSuchInstance = _Exception
EndOfMibView = _Exception
