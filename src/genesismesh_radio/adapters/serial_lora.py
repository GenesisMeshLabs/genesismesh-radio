"""Bounded line framing for an external LoRa modem, not a Semtech driver."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Collection
from typing import Any

from .base import AdapterError, Inbound, validate_budget, validate_command_id, validate_payload

_ROUTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_HEX = re.compile(rb"[0-9a-fA-F]+\Z")


def validate_route(route: str) -> str:
    if not isinstance(route, str) or not _ROUTE.fullmatch(route):
        raise AdapterError("invalid_serial_route")
    return route


def encode_serial_line(route: str, payload: bytes, max_payload: int = 51) -> bytes:
    validate_route(route)
    validate_payload(payload, max_payload)
    return b"GM1 " + route.encode("ascii") + b" " + payload.hex().encode("ascii") + b"\n"


def parse_serial_line(line: bytes, *, routes: Collection[str], max_payload: int = 51) -> Inbound:
    if not isinstance(line, bytes) or len(line) > 70 + max_payload * 2:
        raise AdapterError("serial_line_too_long")
    if not line.endswith(b"\n") or line.count(b"\n") != 1:
        raise AdapterError("invalid_serial_framing")
    fields = line[:-1].split(b" ")
    if len(fields) != 3 or fields[0] != b"GM1":
        raise AdapterError("invalid_serial_framing")
    try:
        route = validate_route(fields[1].decode("ascii"))
    except (UnicodeDecodeError, AdapterError) as exc:
        raise AdapterError("invalid_serial_route") from exc
    if route not in routes:
        raise AdapterError("unconfigured_serial_source")
    if not _HEX.fullmatch(fields[2]) or len(fields[2]) % 2:
        raise AdapterError("invalid_serial_hex")
    payload = bytes.fromhex(fields[2].decode("ascii"))
    return Inbound(route, validate_payload(payload, max_payload))


class SerialLoRaTransport:
    def __init__(
        self,
        port: str,
        *,
        routes: Collection[str],
        baudrate: int = 115200,
        max_payload: int = 51,
        serial_port: Any = None,
    ) -> None:
        self.routes = frozenset(validate_route(route) for route in routes)
        if not self.routes:
            raise AdapterError("serial_routes_required")
        if not isinstance(port, str) or not port:
            raise AdapterError("serial_port_required")
        if type(baudrate) is not int or not 1200 <= baudrate <= 4000000:
            raise AdapterError("invalid_baudrate")
        self.max_payload = validate_budget(max_payload)
        self.max_line = 70 + 2 * self.max_payload
        self._buffer = bytearray()
        self._discarding = False
        self._write_lock = threading.Lock()
        self.rejected_count = 0
        self.closed = False
        if serial_port is None:
            import serial

            serial_port = serial.Serial(port=port, baudrate=baudrate, timeout=0.05, write_timeout=5)
        self.serial_port = serial_port

    def send(self, route: str, payload: bytes, command_id: str) -> str:
        if self.closed:
            raise AdapterError("transport_closed")
        if route not in self.routes:
            raise AdapterError("unconfigured_serial_destination")
        validate_command_id(command_id)
        line = encode_serial_line(route, payload, self.max_payload)
        try:
            with self._write_lock:
                if self.serial_port.write(line) != len(line):
                    raise AdapterError("serial_short_write_ambiguous")
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError("serial_send_ambiguous") from exc
        return f"uart:{command_id}"

    def receive(self, timeout: float) -> Inbound | None:
        if self.closed:
            raise AdapterError("transport_closed")
        if timeout < 0:
            raise AdapterError("invalid_timeout")
        deadline = time.monotonic() + timeout
        first = True
        while first or time.monotonic() < deadline:
            first = False
            self.serial_port.timeout = max(0, min(0.05, deadline - time.monotonic()))
            try:
                byte = self.serial_port.read(1)
            except Exception as exc:
                raise AdapterError("serial_receive_failed") from exc
            if not byte:
                continue
            if self._discarding:
                if byte == b"\n":
                    self._discarding = False
                continue
            self._buffer.extend(byte)
            if len(self._buffer) > self.max_line:
                self._buffer.clear()
                self._discarding = byte != b"\n"
                self.rejected_count += 1
                continue
            if byte == b"\n":
                line = bytes(self._buffer)
                self._buffer.clear()
                try:
                    return parse_serial_line(line, routes=self.routes, max_payload=self.max_payload)
                except AdapterError:
                    self.rejected_count += 1
        return None

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.serial_port.close()
