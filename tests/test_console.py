import json
import secrets
import time
import uuid
from types import SimpleNamespace

import pytest

pytest.importorskip("starlette")
from starlette.testclient import TestClient

from genesismesh_radio.console.app import ConsoleSettings, create_app
from genesismesh_radio.console.store import AdmissionError, OperatorStore, private_database
from genesismesh_radio.console_cli import demo_bridge
from genesismesh_radio.control_client import ControlError

ORIGIN = "https://127.0.0.1:17902"
PASSWORD = "disposable-console-password"


class Backend:
    def __init__(self):
        self.commands, self.calls = {}, []
        self.fail = False

    def health(self):
        self.calls.append("health")
        return {"ready": True, "scope": "local_bridge_process_only"}

    def status(self):
        self.calls.append("status")
        return {
            "commands": list(self.commands.values()),
            "event_count": 0,
            "latest_telemetry": [],
            "devices": [],
        }

    def command(self, command_id, device_id, interval, ttl):
        self.calls.append("command")
        if self.fail:
            raise ControlError("command_result_unknown", command_id=command_id)
        value = {"command_id": command_id, "state": "dispatched", "report_status": "none"}
        self.commands[command_id] = value
        return value

    def result(self, identifier):
        self.calls.append("result")
        if identifier not in self.commands:
            raise ControlError("control_http_error", status_code=404)
        return self.commands[identifier]


@pytest.fixture
def lab():
    clock = [1000.0]
    store = OperatorStore(clock=lambda: clock[0], lifetime=60)
    store.set_user("owner", PASSWORD, "operator")
    store.set_user("viewer", PASSWORD, "observer")
    backend = Backend()
    with TestClient(create_app(ConsoleSettings(ORIGIN), store, backend), base_url=ORIGIN) as client:
        yield SimpleNamespace(store=store, clock=clock, backend=backend, client=client)
    store.close()


def post(client, path, data, csrf=None, **kwargs):
    headers = {"Origin": ORIGIN, "Content-Type": "application/json", "X-Console-Request": "1"}
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    headers.update(kwargs.pop("headers", {}))
    return client.post(
        path,
        content=json.dumps(data) if not isinstance(data, bytes) else data,
        headers=headers,
        **kwargs,
    )


def login(lab, username="owner"):
    response = post(lab.client, "/api/login", {"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["csrf"]


def body():
    return {"command_id": str(uuid.uuid4()), "device_id": 1, "interval_seconds": 60, "ttl": 30}


def test_anonymous_cannot_read_or_dispatch(lab):
    for path in ["/api/status", "/api/session", "/api/commands/" + str(uuid.uuid4())]:
        assert lab.client.get(path).status_code == 401
    assert post(lab.client, "/api/commands", body()).status_code == 401
    assert not lab.backend.calls


def test_observer_can_read_but_not_dispatch(lab):
    csrf = login(lab, "viewer")
    assert lab.client.get("/api/status").status_code == 200
    assert post(lab.client, "/api/commands", body(), csrf).status_code == 403
    assert "command" not in lab.backend.calls


def test_operator_request_is_bound_and_retry_only_looks_up(lab):
    csrf, request = login(lab), body()
    response = post(lab.client, "/api/commands", request, csrf)
    assert response.status_code == 202
    assert response.json()["command"]["state"] == "dispatched"
    assert response.json()["core_actor"] == "enrolled_bridge_identity"
    assert post(lab.client, "/api/commands", request, csrf).status_code == 200
    assert lab.backend.calls.count("command") == 1
    assert post(lab.client, "/api/commands", {**request, "ttl": 31}, csrf).status_code == 409
    assert lab.backend.calls.count("command") == 1


def test_unknown_submission_is_not_redispatched(lab):
    csrf, request = login(lab), body()
    lab.backend.fail = True
    response = post(lab.client, "/api/commands", request, csrf)
    assert response.status_code == 503
    assert response.json()["command_id"] == request["command_id"]
    assert response.json()["execution_confirmed"] is False
    lab.backend.fail = False
    response = post(lab.client, "/api/commands", request, csrf)
    assert response.status_code == 409
    assert response.json()["code"] == "submission_uncertain_no_redispatch"
    assert lab.backend.calls.count("command") == 1


@pytest.mark.parametrize(
    "headers,status",
    [
        ({"Origin": "https://attacker.invalid"}, 403),
        ({"Origin": "null"}, 403),
        ({"Content-Type": "application/x-www-form-urlencoded"}, 415),
        ({"X-Console-Request": "0"}, 403),
        ({"Host": "attacker.invalid"}, 400),
        ({"Host": "127.0.0.1:17903"}, 400),
    ],
)
def test_browser_boundary_blocks_before_backend(lab, headers, status):
    csrf = login(lab)
    assert post(lab.client, "/api/commands", body(), csrf, headers=headers).status_code == status
    assert not lab.backend.calls


def test_missing_origin_and_forged_proxy_scheme_refused(lab):
    assert (
        lab.client.post(
            "/api/login",
            json={"username": "owner", "password": PASSWORD},
            headers={"X-Console-Request": "1"},
        ).status_code
        == 403
    )
    with TestClient(
        create_app(ConsoleSettings(ORIGIN), lab.store, lab.backend),
        base_url="http://127.0.0.1:17902",
    ) as client:
        assert client.get("/api/status", headers={"X-Forwarded-Proto": "https"}).status_code == 400
    assert not lab.backend.calls


@pytest.mark.parametrize(
    "name,value",
    [("Host", "127.0.0.1:17902"), ("Origin", ORIGIN), ("Cookie", "x=1"), ("X-CSRF-Token", "x")],
)
def test_duplicate_security_headers_refused(lab, name, value):
    response = lab.client.get("/api/status", headers=[(name, value), (name, value)])
    assert response.status_code == 400


def test_csrf_is_bound_to_session(lab):
    csrf = login(lab)
    assert post(lab.client, "/api/commands", body()).status_code == 403
    assert post(lab.client, "/api/commands", body(), secrets.token_hex(32)).status_code == 403
    login(lab)
    assert post(lab.client, "/api/commands", body(), csrf).status_code == 403
    assert not lab.backend.calls


def test_nonascii_csrf_and_surrogate_password_are_clean_refusals(lab):
    login(lab)
    response = lab.client.post(
        "/api/commands",
        content=json.dumps(body()),
        headers=[
            (b"origin", ORIGIN.encode()),
            (b"content-type", b"application/json"),
            (b"x-console-request", b"1"),
            (b"x-csrf-token", b"\xff"),
        ],
    )
    assert response.status_code == 403
    response = post(
        lab.client, "/api/login", {"username": "owner", "password": "x" * 20 + "\ud800"}
    )
    assert response.status_code == 401 and response.json()["code"] == "login_refused"
    assert not lab.backend.calls


def test_logout_revocation_password_reset_and_expiry(lab):
    csrf = login(lab)
    cookie = lab.client.cookies.get("__Host-gm_console")
    assert post(lab.client, "/api/logout", {}, csrf).status_code == 200
    lab.client.cookies.clear()
    lab.client.cookies.set("__Host-gm_console", cookie)
    assert lab.client.get("/api/session").status_code == 401
    lab.client.cookies.clear()
    login(lab)
    lab.store.set_user("owner", "a-completely-new-password", "operator")
    assert lab.client.get("/api/session").status_code == 401
    login(lab, "viewer")
    lab.clock[0] += 60
    assert lab.client.get("/api/session").status_code == 401
    login(lab, "viewer")
    lab.store.revoke("viewer")
    assert lab.client.get("/api/session").status_code == 401


def test_clock_rollback_invalidates_sessions(lab):
    login(lab)
    lab.clock[0] -= 1
    assert lab.client.get("/api/session").status_code == 403


def test_login_generic_failure_rate_limit_and_security_cookie(lab):
    for name in ("unknown", "owner"):
        response = post(
            lab.client, "/api/login", {"username": name, "password": PASSWORD + "wrong"}
        )
        assert response.status_code == 401 and response.json()["code"] == "login_refused"
    response = post(lab.client, "/api/login", {"username": "owner", "password": PASSWORD})
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert "Domain=" not in cookie
    for _ in range(2):
        post(lab.client, "/api/login", {"username": "owner", "password": "wrong"})
    assert (
        post(lab.client, "/api/login", {"username": "owner", "password": PASSWORD}).status_code
        == 429
    )


@pytest.mark.parametrize(
    "patch",
    [
        {"device_id": True},
        {"device_id": 0},
        {"ttl": 301},
        {"ttl": 2},
        {"interval_seconds": 0},
        {"interval_seconds": 1.2},
        {"command_id": "new-id"},
        {"role": "operator"},
        {"url": "http://evil.invalid"},
    ],
)
def test_invalid_command_never_reaches_backend(lab, patch):
    assert post(lab.client, "/api/commands", {**body(), **patch}, login(lab)).status_code == 400
    assert not lab.backend.calls


def test_oversize_duplicate_keys_and_no_unsafe_get(lab):
    csrf = login(lab)
    assert post(lab.client, "/api/commands", b" " * 4097, csrf).status_code == 413
    assert (
        post(lab.client, "/api/commands", b'{"device_id":1,"device_id":2}', csrf).status_code == 400
    )
    assert lab.client.get("/api/commands").status_code == 405
    assert lab.client.get("/api/status?token=never").status_code == 400
    assert not lab.backend.calls


def test_static_assets_and_csp_contain_no_secrets(lab):
    page = lab.client.get("/")
    assert page.status_code == 200
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-store"
    script = lab.client.get("/assets/app.js").text
    assert "textContent" in script and "innerHTML" not in script
    assert "GM_RADIO_CONTROL_TOKEN" not in page.text + script
    assert lab.client.get("/assets/../store.py").status_code == 404
    assert lab.client.options("/api/login").status_code == 405


@pytest.mark.parametrize(
    "origin",
    [
        "http://192.168.1.3:17902",
        "https://0.0.0.0:17902",
        "https://example.org:443",
        "https://127.0.0.1:17902/",
        "https://127.0.0.1:17902?x=y",
        "ftp://127.0.0.1:17902",
    ],
)
def test_unsafe_console_origins_refused(origin):
    with pytest.raises(ValueError):
        ConsoleSettings(origin, development_loopback=True)


def test_loopback_http_requires_explicit_development_mode():
    with pytest.raises(ValueError):
        ConsoleSettings("http://127.0.0.1:17902")
    ConsoleSettings("http://127.0.0.1:17902", True)


def test_real_control_service_demo_and_confirmation():
    store = OperatorStore()
    store.set_user("owner", PASSWORD, "operator")
    try:
        with demo_bridge() as backend:
            app = create_app(
                ConsoleSettings(ORIGIN, mode="simulated_authority_and_radio"), store, backend
            )
            with TestClient(app, base_url=ORIGIN) as client:
                csrf = post(
                    client, "/api/login", {"username": "owner", "password": PASSWORD}
                ).json()["csrf"]
                request = body()
                assert post(client, "/api/commands", request, csrf).status_code == 202
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    response = client.get("/api/commands/" + request["command_id"])
                    if response.json()["command"]["state"] == "confirmed":
                        break
                    time.sleep(0.01)
                assert response.json()["command"]["state"] == "confirmed"
                status = client.get("/api/status").json()
                assert status["bridge"]["latest_telemetry"][0]["details"]["value"] == 2250
                assert status["bridge"]["devices"][0]["device_id"] == 1
    finally:
        store.close()


@pytest.mark.skipif(__import__("os").name != "posix", reason="private console state requires POSIX")
def test_private_state_permissions_restart_and_submission_survive(tmp_path):
    import os

    os.chmod(tmp_path, 0o700)
    path = tmp_path / "operators.db"
    store = OperatorStore(path, create=True)
    store.set_user("owner", PASSWORD, "operator")
    token, session = store.login("owner", PASSWORD, "local")
    request = body()
    assert store.reserve(session, request)
    store.close()
    store = OperatorStore(path)
    with pytest.raises(AdmissionError):
        store.authenticate(token)
    _, session = store.login("owner", PASSWORD, "local")
    assert not store.reserve(session, request)
    store.close()
    os.chmod(path, 0o644)
    with pytest.raises(AdmissionError):
        private_database(path)


def test_store_capacity_and_hash_work_are_bounded(lab):
    assert lab.store._hash_slots.acquire(False)
    assert lab.store._hash_slots.acquire(False)
    try:
        with pytest.raises(AdmissionError, match="login_busy"):
            lab.store.login("owner", PASSWORD, "another-client")
    finally:
        lab.store._hash_slots.release()
        lab.store._hash_slots.release()
