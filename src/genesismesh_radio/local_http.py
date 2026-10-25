"""Small, bounded loopback HTTP transport; it never accesses bridge state directly."""

from __future__ import annotations

import hmac
import ipaddress
import json
import math
import re
import socket
import socketserver
import time
import uuid
from http import HTTPStatus

MAX_BODY = 4096
MAX_HEADERS = 8192
MAX_RESPONSE = 262144
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_TOKEN = re.compile(r"[0-9a-f]{64}\Z")


class RequestError(ValueError):
    def __init__(self, code: str, status: int = 400):
        self.code, self.status = code, status
        super().__init__(code)


def validate_endpoint(host: str, port: int, token: str) -> None:
    if not isinstance(host, str):
        raise ValueError("service_requires_literal_loopback")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("service_requires_literal_loopback") from exc
    if address.version != 4 or not address.is_loopback or "%" in host:
        raise ValueError("service_requires_literal_loopback")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("invalid_service_port")
    if not isinstance(token, str) or not _TOKEN.fullmatch(token):
        raise ValueError("service_token_requires_32_random_bytes_lowercase_hex")


def canonical_uuid(value) -> str:
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise RequestError("invalid_command_id") from exc
    return value


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RequestError("invalid_json")
        result[key] = value
    return result


def _constant(_):
    raise RequestError("invalid_json")


def command_body(raw: bytes) -> dict:
    try:
        parsed = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RequestError("invalid_json") from exc
    # Explicit depth/shape limits apply even on interpreters accepting deeply nested JSON.
    pending = [(parsed, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 8 or (isinstance(item, float) and not math.isfinite(item)):
            raise RequestError("invalid_json")
        children = (
            item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        )
        pending.extend((child, depth + 1) for child in children)
    required = {"command_id", "device_id", "interval_seconds"}
    if not isinstance(parsed, dict) or not required <= parsed.keys():
        raise RequestError("invalid_command")
    if parsed.keys() - (required | {"ttl"}):
        raise RequestError("invalid_command")
    canonical_uuid(parsed["command_id"])
    parsed.setdefault("ttl", 60)
    for name, low, high in (
        ("device_id", 1, 2**32 - 1),
        ("interval_seconds", 1, 65535),
        ("ttl", 3, 300),
    ):
        if type(parsed[name]) is not int or not low <= parsed[name] <= high:
            raise RequestError("invalid_command")
    return parsed


class _Reader:
    def __init__(self, sock, timeout):
        self.sock = sock
        self.deadline = time.monotonic() + timeout
        self.buffer = bytearray()

    def _receive(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise RequestError("request_timeout", 408)
        self.sock.settimeout(remaining)
        try:
            chunk = self.sock.recv(1024)
        except TimeoutError as exc:
            raise RequestError("request_timeout", 408) from exc
        if not chunk:
            raise RequestError("incomplete_request")
        self.buffer.extend(chunk)

    def line(self, maximum):
        while True:
            end = self.buffer.find(b"\n")
            if end >= 0:
                if end + 1 > maximum or end == 0 or self.buffer[end - 1] != 13:
                    raise RequestError("invalid_headers")
                result = bytes(self.buffer[: end - 1])
                del self.buffer[: end + 1]
                return result
            if len(self.buffer) >= maximum:
                raise RequestError("headers_too_large", 431)
            self._receive()

    def body(self, length):
        while len(self.buffer) < length:
            self._receive()
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        # No pipelining or additional request bytes on this close-only connection.
        if self.buffer:
            raise RequestError("unexpected_request_bytes")
        return result


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            try:
                status, payload = self._handle_request()
            except RequestError as exc:
                status, payload = exc.status, {"code": exc.code}
            except Exception:
                status, payload = 503, {"code": "service_unavailable"}
            raw = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
            if len(raw) > MAX_RESPONSE:
                status, raw = 503, b'{"code":"response_too_large"}'
            header = (
                f"HTTP/1.1 {status} {HTTPStatus(status).phrase}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(raw)}\r\n"
                "Connection: close\r\nCache-Control: no-store\r\n"
                "X-Content-Type-Options: nosniff\r\n\r\n"
            ).encode("ascii")
            self.request.settimeout(self.server.request_timeout)
            self.request.sendall(header + raw)
        except (OSError, ValueError, TypeError):
            # A vanished client never cancels an already admitted owner operation.
            return

    def _handle_request(self):
        server = self.server
        reader = _Reader(self.request, server.request_timeout)
        first = reader.line(512)
        parts = first.split(b" ")
        if len(parts) != 3 or parts[2] not in {b"HTTP/1.0", b"HTTP/1.1"}:
            raise RequestError("invalid_request_line")
        try:
            method, path = parts[0].decode("ascii"), parts[1].decode("ascii")
        except UnicodeError as exc:
            raise RequestError("invalid_request_line") from exc
        headers, total = {}, len(first) + 2
        for _ in range(33):
            line = reader.line(MAX_HEADERS - total)
            total += len(line) + 2
            if not line:
                break
            if len(headers) == 32 or b":" not in line:
                raise RequestError("invalid_headers")
            name, value = line.split(b":", 1)
            if not _HEADER_NAME.fullmatch(name):
                raise RequestError("invalid_headers")
            name = name.lower()
            value = value.strip(b" \t")
            if name in headers or any(byte < 32 or byte > 126 for byte in value):
                raise RequestError("invalid_headers")
            headers[name] = value
        else:
            raise RequestError("invalid_headers")
        if b"transfer-encoding" in headers or b"expect" in headers:
            raise RequestError("unsupported_framing")
        if b"origin" in headers:
            raise RequestError("origin_not_allowed", 403)
        if headers.get(b"host") != server.expected_host.encode("ascii"):
            raise RequestError("invalid_host")
        if not hmac.compare_digest(
            headers.get(b"authorization", b""), b"Bearer " + server.token.encode("ascii")
        ):
            raise RequestError("unauthorized", 401)
        length = headers.get(b"content-length")
        if length is not None and not re.fullmatch(rb"0|[1-9][0-9]{0,5}", length):
            raise RequestError("invalid_content_length")
        length = int(length) if length is not None else None
        if length is not None and length > MAX_BODY:
            raise RequestError("body_too_large", 413)
        if method == "POST" and path == "/v1/commands":
            if length is None:
                raise RequestError("content_length_required")
            if headers.get(b"content-type", b"").lower() not in {
                b"application/json",
                b"application/json; charset=utf-8",
            }:
                raise RequestError("content_type_must_be_json", 415)
            return server.dispatch("command", command_body(reader.body(length)))
        if length not in {None, 0}:
            raise RequestError("unexpected_request_body")
        reader.body(0)
        if method == "GET":
            if path == "/healthz":
                return server.dispatch("health", None)
            if path == "/v1/status":
                return server.dispatch("status", None)
            if path.startswith("/v1/commands/"):
                return server.dispatch("lookup", canonical_uuid(path.removeprefix("/v1/commands/")))
        raise RequestError("not_found", 404)


class LocalHTTPServer(socketserver.TCPServer):
    """One HTTP handler at a time, bounded listen backlog and absolute read deadline."""

    allow_reuse_address = False
    request_queue_size = 16

    def __init__(self, host, port, token, dispatch, *, request_timeout=2.0):
        validate_endpoint(host, port, token)
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.token, self.dispatch, self.request_timeout = token, dispatch, request_timeout
        super().__init__((host, port), _Handler)
        actual_port = self.server_address[1]
        self.expected_host = f"[{host}]:{actual_port}" if ":" in host else f"{host}:{actual_port}"

    def handle_error(self, request, client_address):
        # Avoid socketserver's traceback, which can include operator-supplied input.
        pass
