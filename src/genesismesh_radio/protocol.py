"""Version-one, audience-bound radio datagrams.

This profile authenticates messages with per-device shared keys. It does not
encrypt their contents and is not a device-signature or key-exchange protocol.
Replay protection and trusted-clock persistence belong to the caller.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from enum import IntEnum

VERSION = 1
MAX_PAYLOAD_BYTES = 16
TAG_BYTES = 16
HEADER_BYTES = 19
MAX_FRAME_BYTES = HEADER_BYTES + MAX_PAYLOAD_BYTES + TAG_BYTES
DOMAIN = b"GenesisMeshRadio\x00v1\x00"
_HEADER = struct.Struct(">BBIQIB")
_TELEMETRY = struct.Struct(">Bi")
_COMMAND = struct.Struct(">BH")
_OUTCOME = struct.Struct(">QBH")


class ProtocolError(ValueError):
    """A datagram or protocol parameter is invalid."""


class Kind(IntEnum):
    TELEMETRY = 1
    COMMAND = 2
    OUTCOME = 3


class OutcomeStatus(IntEnum):
    SUCCESS = 0
    REJECTED = 1
    UNCERTAIN = 2


@dataclass(frozen=True)
class Frame:
    kind: Kind
    device_id: int
    counter: int
    expires_at: int
    payload: bytes


def _integer(value: object, name: str, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ProtocolError(f"{name} is outside its integer range")
    return value


def _bytes(value: object, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise ProtocolError(f"{name} must be bytes")
    return value


def _audience(value: object) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError("audience must be a string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError("audience must be printable ASCII") from exc
    if not 1 <= len(encoded) <= 128 or any(c < 33 or c > 126 for c in encoded):
        raise ProtocolError("audience must contain 1..128 non-space ASCII characters")
    return encoded


def _key(value: object) -> bytes:
    value = _bytes(value, "key")
    if len(value) < 32:
        raise ProtocolError("key must contain at least 32 bytes")
    return value


def _tag(body: bytes, key: bytes, audience: bytes, kind: Kind) -> bytes:
    direction = b"\x02" if kind is Kind.COMMAND else b"\x01"
    prefix = DOMAIN + len(audience).to_bytes(2, "big") + audience + direction
    return hmac.new(key, prefix + body, hashlib.sha256).digest()[:TAG_BYTES]


def _validate_payload(kind: Kind, payload: bytes) -> None:
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("payload exceeds the version-one limit")
    if kind is Kind.TELEMETRY:
        decode_telemetry(payload)
    elif kind is Kind.COMMAND:
        decode_command(payload)
    else:
        decode_outcome(payload)


def encode(frame: Frame, key: bytes, audience: str) -> bytes:
    """Encode and authenticate a frame; reserve its counter before calling."""
    if not isinstance(frame, Frame) or not isinstance(frame.kind, Kind):
        raise ProtocolError("frame must have a supported Kind")
    key = _key(key)
    bound_audience = _audience(audience)
    device_id = _integer(frame.device_id, "device_id", 1, 0xFFFFFFFF)
    counter = _integer(frame.counter, "counter", 1, 0xFFFFFFFFFFFFFFFF)
    expiry = _integer(frame.expires_at, "expires_at", 1, 0xFFFFFFFF)
    payload = _bytes(frame.payload, "payload")
    _validate_payload(frame.kind, payload)
    body = _HEADER.pack(VERSION, frame.kind, device_id, counter, expiry, len(payload)) + payload
    return body + _tag(body, key, bound_audience, frame.kind)


def _parse_header(data: bytes) -> tuple[int, Kind, int, int, bytes]:
    data = _bytes(data, "data")
    if not HEADER_BYTES + TAG_BYTES <= len(data) <= MAX_FRAME_BYTES:
        raise ProtocolError("invalid frame size")
    version, raw_kind, device_id, counter, expiry, payload_size = _HEADER.unpack_from(data)
    if version != VERSION:
        raise ProtocolError("unsupported protocol version")
    try:
        kind = Kind(raw_kind)
    except ValueError as exc:
        raise ProtocolError("unsupported message kind") from exc
    if payload_size > MAX_PAYLOAD_BYTES or len(data) != HEADER_BYTES + payload_size + TAG_BYTES:
        raise ProtocolError("payload length mismatch")
    return device_id, kind, counter, expiry, data[HEADER_BYTES:-TAG_BYTES]


def peek_device_id(data: bytes) -> int:
    """Return an UNAUTHENTICATED routing hint. Never use it to authorize work."""
    device_id, _, _, _, _ = _parse_header(data)
    return _integer(device_id, "device_id", 1, 0xFFFFFFFF)


def decode(
    data: bytes,
    key: bytes,
    audience: str,
    now: int,
    max_future_seconds: int = 300,
    max_payload: int = MAX_FRAME_BYTES,
) -> Frame:
    """Authenticate a frame and enforce freshness and transport byte limits.

    ``max_payload`` is the entire application frame budget, including its tag.
    This function does not advance replay counters or establish clock trust.
    """
    data = _bytes(data, "data")
    key = _key(key)
    bound_audience = _audience(audience)
    now = _integer(now, "now", 0, 0xFFFFFFFF)
    future = _integer(max_future_seconds, "max_future_seconds", 1, 0xFFFFFFFF)
    limit = _integer(max_payload, "max_payload", 1, 0xFFFFFFFF)
    if len(data) > limit:
        raise ProtocolError("frame exceeds transport payload budget")
    device_id, kind, counter, expiry, payload = _parse_header(data)
    expected = _tag(data[:-TAG_BYTES], key, bound_audience, kind)
    if not hmac.compare_digest(data[-TAG_BYTES:], expected):
        raise ProtocolError("authentication failed")
    _integer(device_id, "device_id", 1, 0xFFFFFFFF)
    _integer(counter, "counter", 1, 0xFFFFFFFFFFFFFFFF)
    if expiry <= now:
        raise ProtocolError("frame expired")
    if expiry > now + future:
        raise ProtocolError("frame expiry exceeds freshness window")
    _validate_payload(kind, payload)
    return Frame(kind, device_id, counter, expiry, payload)


def encode_telemetry(metric: int, value: int) -> bytes:
    return _TELEMETRY.pack(
        _integer(metric, "metric", 0, 0xFF),
        _integer(value, "value", -0x80000000, 0x7FFFFFFF),
    )


def decode_telemetry(payload: bytes) -> tuple[int, int]:
    payload = _bytes(payload, "payload")
    if len(payload) != _TELEMETRY.size:
        raise ProtocolError("telemetry payload must contain five bytes")
    return _TELEMETRY.unpack(payload)


def encode_command(interval_seconds: int) -> bytes:
    return _COMMAND.pack(1, _integer(interval_seconds, "interval_seconds", 1, 0xFFFF))


def decode_command(payload: bytes) -> int:
    payload = _bytes(payload, "payload")
    if len(payload) != _COMMAND.size:
        raise ProtocolError("command payload must contain three bytes")
    opcode, interval = _COMMAND.unpack(payload)
    if opcode != 1:
        raise ProtocolError("unsupported command opcode")
    return _integer(interval, "interval_seconds", 1, 0xFFFF)


def encode_outcome(command_counter: int, status: OutcomeStatus, applied_interval: int) -> bytes:
    command_counter = _integer(command_counter, "command_counter", 1, 0xFFFFFFFFFFFFFFFF)
    if not isinstance(status, OutcomeStatus):
        raise ProtocolError("status must be an OutcomeStatus")
    applied_interval = _integer(applied_interval, "applied_interval", 0, 0xFFFF)
    if status is OutcomeStatus.SUCCESS and applied_interval == 0:
        raise ProtocolError("successful outcome requires a positive applied interval")
    return _OUTCOME.pack(command_counter, status, applied_interval)


def decode_outcome(payload: bytes) -> tuple[int, OutcomeStatus, int]:
    payload = _bytes(payload, "payload")
    if len(payload) != _OUTCOME.size:
        raise ProtocolError("outcome payload must contain eleven bytes")
    counter, raw_status, interval = _OUTCOME.unpack(payload)
    try:
        status = OutcomeStatus(raw_status)
    except ValueError as exc:
        raise ProtocolError("unsupported outcome status") from exc
    encode_outcome(counter, status, interval)
    return counter, status, interval
