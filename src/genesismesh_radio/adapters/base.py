"""Transport contracts. Receipts describe transport submission, never execution."""

from __future__ import annotations

from dataclasses import dataclass
from queue import Empty, Full, Queue
from typing import Protocol


class AdapterError(ValueError):
    """Invalid transport input or a failed/ambiguous transport operation."""


@dataclass(frozen=True)
class Inbound:
    route: str
    payload: bytes


class Transport(Protocol):
    def send(self, route: str, payload: bytes, command_id: str) -> str: ...

    def receive(self, timeout: float) -> Inbound | None: ...

    def close(self) -> None: ...


def validate_budget(value: int, maximum: int = 255) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise AdapterError("invalid_payload_budget")
    return value


def validate_payload(payload: bytes, maximum: int) -> bytes:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= maximum:
        raise AdapterError("invalid_payload_size")
    return payload


def validate_command_id(command_id: str) -> None:
    if (
        not isinstance(command_id, str)
        or not 1 <= len(command_id) <= 128
        or not command_id.isascii()
        or any(ord(char) < 33 or ord(char) > 126 for char in command_id)
    ):
        raise AdapterError("invalid_command_id")


class QueuedTransport:
    """Bounded callback ingress; callers must monitor rejection/overflow counts."""

    def __init__(self, queue_size: int) -> None:
        if type(queue_size) is not int or not 1 <= queue_size <= 65536:
            raise AdapterError("invalid_queue_size")
        self._incoming: Queue[Inbound] = Queue(maxsize=queue_size)
        self.rejected_count = 0
        self.overflow_count = 0
        self.closed = False

    def _offer(self, packet: Inbound) -> None:
        if self.closed:
            return
        try:
            self._incoming.put_nowait(packet)
        except Full:
            self.overflow_count += 1

    def receive(self, timeout: float) -> Inbound | None:
        if timeout < 0:
            raise AdapterError("invalid_timeout")
        try:
            return self._incoming.get(timeout=timeout)
        except Empty:
            return None
