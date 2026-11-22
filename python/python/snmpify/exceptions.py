"""Exceptions raised by snmpify."""

__all__ = ["SnmpError", "SnmpTimeout", "AgentError", "ReportError", "InvalidArgument"]


class SnmpError(Exception):
    """Base class of snmpify errors."""


class SnmpTimeout(SnmpError, TimeoutError):
    """No answer from the agent after all retries."""


class AgentError(SnmpError):
    """The agent answered with an error status (noSuchName, noAccess …).

    ``status`` is the RFC 3416 name, ``index`` the 1-based failing binding
    (0: the whole request) and ``oid`` that binding's OID, if any."""

    def __init__(self, message: str, status: str, index: int, oid: "str | None") -> None:
        super().__init__(message)
        self.status = status
        self.index = index
        self.oid = oid


class ReportError(SnmpError):
    """SNMPv3: the agent answered with a Report (unknown user, wrong
    digest: a wrong password or protocol …). ``kind`` names it."""

    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.kind = kind


class InvalidArgument(SnmpError, ValueError):
    """An argument snmpify cannot use (a bad OID, an unknown protocol …)."""
