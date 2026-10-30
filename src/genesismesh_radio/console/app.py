"""Browser admission boundary over the existing governed loopback control client."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import re
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie
from importlib.resources import files
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from ..control_client import ControlError, command_uuid
from ..local_http import RequestError, command_body
from .store import AdmissionError


@dataclass(frozen=True)
class ConsoleSettings:
    origin: str
    development_loopback: bool = False
    mode: str = "configured_bridge"

    def __post_init__(self):
        p = urlsplit(self.origin)
        try:
            address = ipaddress.IPv4Address(p.hostname or "")
            port = p.port
        except ValueError as exc:
            raise ValueError("console_requires_literal_ipv4_origin") from exc
        if (
            p.username is not None
            or p.password is not None
            or p.query
            or p.fragment
            or p.path
            or port is None
            or not 1 <= port <= 65535
            or self.origin != f"{p.scheme}://{address}:{port}"
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            or not (address.is_private or address.is_loopback)
        ):
            raise ValueError("invalid_console_origin")
        if p.scheme != "https" and not (
            p.scheme == "http" and address.is_loopback and self.development_loopback
        ):
            raise ValueError("https_required_for_phone_console")
        if self.mode not in {
            "configured_bridge",
            "simulated_authority_and_radio",
            "real_authority_simulated_radio",
        }:
            raise ValueError("invalid_console_mode")

    @property
    def cookie(self):
        return "gm_console_dev" if self.origin.startswith("http:") else "__Host-gm_console"


def _token(request, settings):
    raw = request.headers.get("cookie", "")
    if len(raw) > 4096:
        raise AdmissionError("authentication_required")
    parts = [piece.strip().partition("=")[0] for piece in raw.split(";") if piece.strip()]
    if len(parts) != len(set(parts)):
        raise AdmissionError("authentication_required")
    try:
        cookies = SimpleCookie(raw)
        return cookies[settings.cookie].value if settings.cookie in cookies else ""
    except CookieError:
        raise AdmissionError("authentication_required") from None


async def _body(request):
    raw = bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw) > 4096:
                    raise RequestError("body_too_large", 413)
    except TimeoutError:
        raise RequestError("request_timeout", 408) from None
    return bytes(raw)


def _login_body(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        if (
            not isinstance(value, dict)
            or set(value) != {"username", "password"}
            or not isinstance(value["username"], str)
            or len(value["username"]) > 32
            or not isinstance(value["password"], str)
            or len(value["password"]) > 128
        ):
            raise ValueError
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise RequestError("invalid_login") from None


class BrowserBoundary:
    """Exact browser origin, finite concurrency and response hardening; no proxy trust."""

    def __init__(self, app, settings):
        self.app, self.settings = app, settings
        self.active = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def hardened(message):
            if message["type"] == "http.response.start":
                message["headers"].extend(
                    [
                        (b"cache-control", b"no-store"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"content-security-policy",
                            b"default-src 'none'; script-src 'self'; "
                            b"style-src 'self'; connect-src 'self'; img-src 'self'; "
                            b"frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                        ),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    ]
                )
            await send(message)

        async def refuse(code, status):
            await JSONResponse({"code": code}, status_code=status)(scope, receive, hardened)

        headers = {}
        for key, value in scope["headers"]:
            headers.setdefault(key.lower(), []).append(value)
        for name in (
            b"host",
            b"origin",
            b"cookie",
            b"content-type",
            b"content-length",
            b"x-csrf-token",
            b"x-console-request",
        ):
            if len(headers.get(name, [])) > 1:
                return await refuse("duplicate_security_header", 400)
        p = urlsplit(self.settings.origin)
        if (
            headers.get(b"host") != [p.netloc.encode()]
            or scope.get("scheme") != p.scheme
            or scope.get("query_string")
        ):
            return await refuse("console_origin_refused", 400)
        if sum(len(k) + len(v) for k, vs in headers.items() for v in vs) > 8192:
            return await refuse("headers_too_large", 431)
        origin = headers.get(b"origin", [])
        if origin and origin != [self.settings.origin.encode()]:
            return await refuse("origin_refused", 403)
        if scope["method"] == "POST":
            if origin != [self.settings.origin.encode()]:
                return await refuse("origin_required", 403)
            if headers.get(b"content-type") != [b"application/json"]:
                return await refuse("json_required", 415)
            if headers.get(b"x-console-request") != [b"1"]:
                return await refuse("console_request_required", 403)
        if scope["method"] not in {"GET", "POST", "HEAD"}:
            return await refuse("method_refused", 405)
        if self.active >= 16:
            return await refuse("console_busy", 503)
        self.active += 1
        try:
            await self.app(scope, receive, hardened)
        finally:
            self.active -= 1


def create_app(settings, store, backend):
    """Use one console worker. The backend is a fixed ControlClient, never a caller URL."""

    def authenticate(request, *, write=False):
        token = _token(request, settings)
        session, role = store.authenticate(token)
        if write:
            csrf = request.headers.get("x-csrf-token", "")
            if not re.fullmatch(r"[0-9a-f]{64}", csrf) or not hmac.compare_digest(
                csrf, session.csrf
            ):
                raise RequestError("csrf_refused", 403)
        return token, session, role

    async def admission_error(request, exc):
        code = str(exc)
        status = (
            401
            if code in {"authentication_required", "login_refused"}
            else (
                429
                if code in {"login_rate_limited", "login_busy"}
                else 409
                if code == "command_id_conflict"
                else 403
            )
        )
        return JSONResponse({"code": code}, status_code=status)

    async def request_error(request, exc):
        return JSONResponse({"code": exc.code}, status_code=exc.status)

    async def backend_call(operation, *args):
        try:
            return await run_in_threadpool(getattr(backend, operation), *args)
        except ControlError as exc:
            status = exc.status_code if exc.status_code in {400, 404, 409, 422} else 503
            data = {"code": exc.code, "execution_confirmed": False}
            if exc.command_id:
                data["command_id"] = exc.command_id
            return JSONResponse(data, status_code=status)

    async def page(request):
        return HTMLResponse(files(__package__).joinpath("assets/index.html").read_text("utf-8"))

    async def asset(request):
        name = request.path_params["name"]
        if name not in {"app.js", "style.css"}:
            return Response(status_code=404)
        return Response(
            files(__package__).joinpath(f"assets/{name}").read_bytes(),
            media_type="text/javascript" if name.endswith(".js") else "text/css",
        )

    async def login(request):
        value = _login_body(await _body(request))
        token, session = await run_in_threadpool(
            store.login,
            value["username"],
            value["password"],
            request.client.host if request.client else "unknown",
            _token(request, settings),
        )
        _, role = store.authenticate(token)
        response = JSONResponse(
            {
                "username": session.username,
                "role": role,
                "csrf": session.csrf,
                "mode": settings.mode,
            }
        )
        response.set_cookie(
            settings.cookie,
            token,
            httponly=True,
            secure=p.scheme == "https",
            samesite="strict",
            path="/",
        )
        return response

    async def session_info(request):
        _, session, role = authenticate(request)
        return JSONResponse(
            {
                "username": session.username,
                "role": role,
                "csrf": session.csrf,
                "mode": settings.mode,
                "identity_scope": "local_console_admission",
                "core_actor": "enrolled_bridge_identity",
            }
        )

    async def logout(request):
        token, _, _ = authenticate(request, write=True)
        if await _body(request) != b"{}":
            raise RequestError("empty_object_required")
        store.logout(token)
        response = JSONResponse({"signed_out": True})
        response.delete_cookie(
            settings.cookie, path="/", secure=p.scheme == "https", httponly=True, samesite="strict"
        )
        return response

    async def status(request):
        authenticate(request)
        data = await backend_call("status")
        if isinstance(data, Response):
            return data
        health = await backend_call("health")
        return JSONResponse(
            {
                "bridge": data,
                "process_health": health if isinstance(health, dict) else {"ready": False},
                "mode": settings.mode,
                "authority_availability": "not_probed",
                "adapter_connectivity": "not_independently_probed",
            }
        )

    async def command(request):
        _, session, role = authenticate(request, write=True)
        if role != "operator":
            raise RequestError("operator_permission_required", 403)
        body = command_body(await _body(request))
        first = store.reserve(session, body)
        if first:
            result = await backend_call(
                "command",
                body["command_id"],
                body["device_id"],
                body["interval_seconds"],
                body["ttl"],
            )
        else:
            result = await backend_call("result", body["command_id"])
            if isinstance(result, Response) and result.status_code == 404:
                return JSONResponse(
                    {
                        "code": "submission_uncertain_no_redispatch",
                        "command_id": body["command_id"],
                        "execution_confirmed": False,
                    },
                    status_code=409,
                )
        return (
            result
            if isinstance(result, Response)
            else JSONResponse(
                {
                    "command": result,
                    "local_operator": session.username,
                    "core_actor": "enrolled_bridge_identity",
                },
                status_code=202 if first else 200,
            )
        )

    async def lookup(request):
        authenticate(request)
        try:
            identifier = command_uuid(request.path_params["command_id"])
        except ValueError:
            raise RequestError("invalid_command_id") from None
        result = await backend_call("result", identifier)
        return result if isinstance(result, Response) else JSONResponse({"command": result})

    p = urlsplit(settings.origin)
    app = Starlette(
        routes=[
            Route("/", page),
            Route("/assets/{name}", asset),
            Route("/api/login", login, methods=["POST"]),
            Route("/api/session", session_info),
            Route("/api/logout", logout, methods=["POST"]),
            Route("/api/status", status),
            Route("/api/commands", command, methods=["POST"]),
            Route("/api/commands/{command_id}", lookup),
        ],
        exception_handlers={AdmissionError: admission_error, RequestError: request_error},
    )
    return BrowserBoundary(app, settings)
