"""Client of the existing GenesisMesh edge agent's authenticated local API.

This module does not hold operator credentials or implement policy evaluation.
Network failures have ambiguous outcomes and are never automatically retried.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_AUTHORITIES = {"decision", "grant", "break_glass"}
_OUTCOMES = {"success", "failure", "partial"}
_RECORD_KINDS = {"execution", "grant_execution", "break_glass"}
_DENIAL_CODES = {
    "na_denied",
    "na_refused",
    "decision_unverifiable",
    "outside_grant",
    "justification_required",
    "no_attestation",
}


class EdgeError(RuntimeError):
    """A sanitized transport or contract error; it may follow a completed request."""

    def __init__(self, code: str, *, status_code: int | None = None) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(code)


@dataclass(frozen=True)
class Authorization:
    """A dispatch authorization; report_by is only an outcome-report deadline."""

    allowed: bool
    authorization_id: str | None
    authority: str | None
    report_by: int
    code: str | None = None


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise EdgeError("edge_invalid_identifier")
    return value


def _deadline(value: Any) -> int:
    if not isinstance(value, str):
        raise EdgeError("edge_invalid_deadline")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        seconds = parsed.timestamp()
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("invalid deadline")
        return int(seconds)
    except (ValueError, OverflowError, OSError) as exc:
        raise EdgeError("edge_invalid_deadline") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


class EdgeClient:
    """Connect through a Unix socket or a bearer-authenticated literal loopback IP.

    HTTP redirects, proxy environment variables, and automatic retries are disabled.
    A custom transport exists for contract tests, not to relax connection validation.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:7000",
        *,
        token: str | None = None,
        unix_socket: str | None = None,
        timeout: float = 10,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not isinstance(base_url, str):
            raise ValueError("edge URL must be a string")
        parsed = urlsplit(base_url)
        try:
            loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
            _ = parsed.port  # Validate an explicitly supplied port.
        except ValueError as exc:
            raise ValueError("edge URL must use a literal loopback IP address") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not loopback
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("edge URL must be a loopback origin without credentials or a path")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise ValueError("edge timeout must be a positive finite number")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("edge timeout must be a positive finite number")
        if unix_socket is not None and (
            not isinstance(unix_socket, str) or not os.path.isabs(unix_socket)
        ):
            raise ValueError("edge Unix socket must be an absolute path")
        if token is not None and (
            not isinstance(token, str) or not token or any(not 33 <= ord(c) <= 126 for c in token)
        ):
            raise ValueError("invalid edge bearer token")
        if unix_socket is None and token is None:
            raise ValueError("loopback edge API requires a bearer token")
        if transport is None:
            transport = httpx.HTTPTransport(uds=unix_socket, retries=0)
        headers = {"Accept": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers=headers,
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        try:
            with self._client.stream(method, path, json=body) as response:
                if response.status_code != 200:
                    raise EdgeError("edge_http_error", status_code=response.status_code)
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 65536:
                        raise EdgeError("edge_response_too_large")
                parsed = json.loads(
                    raw,
                    object_pairs_hook=_unique_object,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
                )
        except httpx.HTTPError as exc:
            raise EdgeError("edge_transport_error") from exc
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise EdgeError("edge_invalid_json") from exc
        if not isinstance(parsed, dict):
            raise EdgeError("edge_invalid_response")
        return parsed

    def authorize(self, resource_id: str, interval_seconds: int, command_id: str) -> Authorization:
        if not isinstance(resource_id, str) or not 1 <= len(resource_id) <= 1024:
            raise ValueError("invalid resource ID")
        if type(interval_seconds) is not int or not 1 <= interval_seconds <= 4294967295:
            raise ValueError("invalid sampling interval")
        _identifier(command_id)
        value = self._request(
            "POST",
            "/v1/authorize",
            {
                "capability": "radio.command.dispatch",
                "request_parameters": {
                    "interval_seconds": interval_seconds,
                },
                "attributes": {"command_id": command_id},
                "resource_id": resource_id,
                "resource_action": "update",
            },
        )
        if type(value.get("allowed")) is not bool:
            raise EdgeError("edge_invalid_authorization")
        allowed = value["allowed"]
        authority = value.get("authority")
        code = value.get("code")
        authorization_id = value.get("authorization_id")
        if code is not None and (not isinstance(code, str) or not code):
            raise EdgeError("edge_invalid_authorization")
        if authorization_id is not None:
            authorization_id = _identifier(authorization_id)
        if allowed:
            if (
                authorization_id is None
                or not isinstance(authority, str)
                or authority not in _AUTHORITIES
            ):
                raise EdgeError("edge_invalid_authorization")
            report_by = _deadline(value.get("report_by"))
        else:
            if authority is not None or value.get("report_by") is not None:
                raise EdgeError("edge_invalid_authorization")
            if code not in _DENIAL_CODES:
                code = "edge_denied"
            report_by = 0
        return Authorization(allowed, authorization_id, authority, report_by, code)

    def report(self, authorization_id: str, outcome: str, metadata: dict, detail: str) -> dict:
        authorization_id = _identifier(authorization_id)
        if not isinstance(outcome, str) or outcome not in _OUTCOMES:
            raise ValueError("invalid outcome")
        if not isinstance(metadata, dict):
            raise ValueError("execution metadata must be an object")
        if not isinstance(detail, str) or not 1 <= len(detail) <= 1024:
            raise ValueError("outcome detail must contain 1 to 1024 characters")
        value = self._request(
            "POST",
            f"/v1/authorizations/{authorization_id}/outcome",
            {"outcome": outcome, "execution_parameters": metadata, "outcome_detail": detail},
        )
        if (
            type(value.get("queued")) is not bool
            or not isinstance(value.get("record_kind"), str)
            or value.get("record_kind") not in _RECORD_KINDS
            or not isinstance(value.get("record_id"), str)
            or not value["record_id"]
        ):
            raise EdgeError("edge_invalid_outcome_response")
        return value

    def status(self) -> dict:
        return self._request("GET", "/v1/status")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> EdgeClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
