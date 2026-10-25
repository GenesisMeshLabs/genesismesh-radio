"""Bounded local control client. Never retries a possibly admitted command."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import uuid
from urllib.parse import urlsplit

import httpx


class ControlError(RuntimeError):
    def __init__(self, code: str, *, status_code: int | None = None, command_id=None):
        super().__init__(code)
        self.code, self.status_code, self.command_id = code, status_code, command_id


def command_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("canonical_command_uuid_required")
    return value


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _response(raw):
    value = json.loads(raw, object_pairs_hook=_object)
    if not isinstance(value, dict):
        raise ValueError("object_required")
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 64 or count > 20_000:
            raise ValueError("response_structure_limit")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("nonfinite_json")
    return value


class ControlClient:
    def __init__(self, url, token, *, timeout=15.0, transport=None):
        parsed = urlsplit(url)
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
            port = parsed.port
        except ValueError as exc:
            raise ValueError("literal_loopback_origin_required") from exc
        if (
            parsed.scheme != "http"
            or address.version != 4
            or not address.is_loopback
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("literal_loopback_origin_required")
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise ValueError("control_token_requires_32_random_bytes_hex")
        if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("invalid_control_timeout")
        self._client = httpx.Client(
            base_url=url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Host": f"{parsed.hostname}:{port or 80}",
            },
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _request(self, method, path, body=None):
        command_id = body.get("command_id") if body else None
        try:
            with self._client.stream(method, path, json=body) as response:
                if response.status_code not in {200, 202}:
                    raise ControlError(
                        "command_result_unknown"
                        if command_id and response.status_code >= 500
                        else "control_http_error",
                        status_code=response.status_code,
                        command_id=command_id,
                    )
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 262144:
                        raise ValueError("response_too_large")
                return _response(raw)
        except httpx.HTTPError as exc:
            raise ControlError(
                "command_result_unknown" if command_id else "control_unavailable",
                command_id=command_id,
            ) from exc
        except (ValueError, RecursionError) as exc:
            raise ControlError(
                "command_result_unknown" if command_id else "control_invalid_response",
                command_id=command_id,
            ) from exc

    def health(self):
        return self._request("GET", "/healthz")

    def status(self):
        return self._request("GET", "/v1/status")

    def result(self, command_id):
        return self._request("GET", f"/v1/commands/{command_uuid(command_id)}")

    def command(self, command_id, device_id, interval_seconds, ttl=60):
        command_uuid(command_id)
        for value, low, high in (
            (device_id, 1, 2**32 - 1),
            (interval_seconds, 1, 65535),
            (ttl, 3, 300),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("invalid_command_parameter")
        return self._request(
            "POST",
            "/v1/commands",
            {
                "command_id": command_id,
                "device_id": device_id,
                "interval_seconds": interval_seconds,
                "ttl": ttl,
            },
        )
