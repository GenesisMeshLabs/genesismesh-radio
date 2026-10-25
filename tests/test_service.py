import http.client
import json
import secrets
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from genesismesh_radio.adapters.base import Inbound
from genesismesh_radio.bridge import Bridge
from genesismesh_radio.config import Config, DeviceConfig, binding
from genesismesh_radio.control_client import ControlClient
from genesismesh_radio.journal import Journal
from genesismesh_radio.protocol import Frame, Kind, encode, encode_telemetry
from genesismesh_radio.service import ControlService, ServiceError
from genesismesh_radio.simulator import DeviceSimulator, LoopbackTransport, SimulationEdge


def eventually(function, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = function()
        if result:
            return result
        time.sleep(0.01)
    pytest.fail("condition was not reached")


@pytest.fixture
def lab(tmp_path):
    now = 1_800_000_000
    key, token = secrets.token_bytes(32), secrets.token_hex(32)
    config = Config(
        "service.lab",
        (DeviceConfig(7, "sensor-7", "radio", "edge:lab/sensor-7", "KEY"),),
        tmp_path / "bridge.db",
    )
    keys = {7: key}
    Journal.initialize(config.state_path, binding(config, keys))
    state = SimpleNamespace(
        config=config,
        keys=keys,
        token=token,
        now=now,
        drop_outcomes=False,
        authorize_entered=threading.Event(),
        authorize_release=threading.Event(),
        hold_authorize=False,
        fail_tick=threading.Event(),
        owner_ids=[],
        closed_ids=[],
        services=[],
        executions=[],
    )

    @contextmanager
    def factory(config, keys):
        state.owner_ids.append(threading.get_ident())
        journal = Journal(config.state_path, binding(config, keys))
        peer = DeviceSimulator(
            7, key, config.audience, clock=lambda: now, state_path=tmp_path / "device.db"
        )
        transport = LoopbackTransport({"sensor-7": peer})
        transport.drop_outcomes = state.drop_outcomes
        edge = SimulationEdge(lambda: now)
        original_authorize = edge.authorize

        def authorize(*args):
            state.authorize_entered.set()
            if state.hold_authorize:
                assert state.authorize_release.wait(5)
            return original_authorize(*args)

        edge.authorize = authorize
        bridge = Bridge(config, journal, edge, {"radio": transport}, clock=lambda: now, keys=keys)
        original_run_once = bridge.run_once

        def run_once(timeout):
            if state.fail_tick.is_set():
                raise RuntimeError("sensitive operator detail must not be returned")
            original_run_once(timeout)

        bridge.run_once = run_once
        state.transport, state.edge = transport, edge
        try:
            yield bridge
        finally:
            state.executions.append(peer.executions)
            peer.close()
            journal.close()
            state.closed_ids.append(threading.get_ident())

    def start(**kwargs):
        service = ControlService(config, keys, token, port=0, resource_factory=factory, **kwargs)
        state.services.append(service)
        return service.start()

    state.start, state.factory = start, factory
    yield state
    state.authorize_release.set()
    for service in state.services:
        service.close()


def request(service, token, method="GET", path="/v1/status", body=None, headers=None):
    connection = http.client.HTTPConnection(*service.address, timeout=3)
    supplied = {"Authorization": "Bearer " + token}
    if body is not None:
        body = json.dumps(body)
        supplied["Content-Type"] = "application/json"
    supplied.update(headers or {})
    try:
        connection.request(method, path, body, supplied)
        response = connection.getresponse()
        result = response.read()
        assert response.getheader("Connection") == "close"
        return response.status, json.loads(result)
    finally:
        connection.close()


def command(**kwargs):
    return {"command_id": str(uuid.uuid4()), "device_id": 7, "interval_seconds": 60, **kwargs}


def wire(service, token, extra=b"", body=b"", *, method=b"POST", path=b"/v1/commands"):
    host, port = service.address
    return (
        method
        + b" "
        + path
        + b" HTTP/1.1\r\n"
        + f"Host: {host}:{port}\r\nAuthorization: Bearer {token}\r\n".encode()
        + extra
        + b"\r\n"
        + body
    )


def raw_request(service, raw):
    with socket.create_connection(service.address, timeout=3) as sock:
        sock.sendall(raw)
        result = bytearray()
        while chunk := sock.recv(4096):
            result.extend(chunk)
    first, body = bytes(result).split(b"\r\n\r\n", 1)
    return int(first.split(b" ")[1]), json.loads(body)


def test_continuous_command_telemetry_and_owner_thread(lab):
    service = lab.start()
    assert request(service, lab.token, path="/healthz")[1]["scope"] == "local_bridge_process_only"
    item = command()
    status, result = request(service, lab.token, "POST", "/v1/commands", item)
    assert status == 202 and result["state"] == "dispatched"
    path = "/v1/commands/" + item["command_id"]
    eventually(lambda: request(service, lab.token, path=path)[1]["state"] == "confirmed")
    raw = encode(
        Frame(Kind.TELEMETRY, 7, 2, lab.now + 60, encode_telemetry(1, 2150)),
        lab.keys[7],
        lab.config.audience,
    )
    lab.transport.incoming.put(Inbound("sensor-7", raw))
    eventually(lambda: request(service, lab.token)[1]["event_count"] == 2)
    assert [entry["outcome"] for entry in lab.edge.reports] == ["success"]
    service.close()
    assert lab.executions == [1]
    assert lab.closed_ids == lab.owner_ids
    assert lab.owner_ids[0] != threading.get_ident()


def test_auth_host_origin_and_unknown_resource(lab):
    service = lab.start()
    assert request(service, "0" * 64, path="/healthz")[0] == 401
    assert request(service, lab.token, headers={"Host": "attacker.invalid"})[0] == 400
    assert request(service, lab.token, headers={"Origin": "http://localhost"})[0] == 403
    assert request(service, lab.token, path="/v1/commands/" + str(uuid.uuid4()))[0] == 404
    assert request(service, lab.token, path="/v1/commands/not-a-uuid")[0] == 400
    assert request(service, lab.token, path="/elsewhere")[0] == 404
    assert request(service, lab.token)[0] == 200


def test_pending_command_and_reused_id_conflicts(lab):
    lab.drop_outcomes = True
    service = lab.start()
    item = command()
    first = request(service, lab.token, "POST", "/v1/commands", item)
    again = request(service, lab.token, "POST", "/v1/commands", item)
    assert first == again
    assert request(service, lab.token, "POST", "/v1/commands", command())[0] == 409
    changed = {**item, "interval_seconds": 61}
    assert request(service, lab.token, "POST", "/v1/commands", changed)[0] == 409
    assert len(lab.transport.sent) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"device_id": True},
        {"device_id": 8},
        {"interval_seconds": False},
        {"interval_seconds": 1},
        {"ttl": True},
        {"ttl": 301},
        {"extra": "value"},
        {"command_id": "00112233-4455-6677-8899-AABBCCDDEEFF"},
    ],
)
def test_invalid_commands_do_not_create_intent(lab, change):
    service = lab.start()
    assert request(service, lab.token, "POST", "/v1/commands", command(**change))[0] == 400
    assert request(service, lab.token)[1]["command_count"] == 0


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b"[]",
        b'{"device_id":7,"device_id":8}',
        b'{"number":NaN}',
        b'{"number":Infinity}',
        b'{"number":1e999}',
        b"[" * 1000 + b"]" * 1000,
        b'{"a":' * 20 + b"0" + b"}" * 20,
        b"\xff",
        b"null",
    ],
)
def test_strict_json(lab, body):
    service = lab.start()
    extra = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()
    assert raw_request(service, wire(service, lab.token, extra, body))[0] == 400
    assert request(service, lab.token)[1]["command_count"] == 0


@pytest.mark.parametrize(
    "extra,expected",
    [
        (b"Content-Length: 2\r\nContent-Length: 2\r\n", 400),
        (b"Content-Length: +2\r\n", 400),
        (b"Content-Length: 02\r\n", 400),
        (b"Content-Length: 4097\r\n", 413),
        (b"Transfer-Encoding: chunked\r\n", 400),
        (b"Expect: 100-continue\r\n", 400),
        (b"Content-Length: 2\r\nContent-Type: text/plain\r\n", 415),
        (b"Content-Type: application/json\r\n", 400),
        (b"Authorization: Bearer duplicate\r\n", 400),
        (b" folded-header: invalid\r\n", 400),
        (b"Huge: " + b"a" * 9000 + b"\r\n", 431),
    ],
)
def test_bad_framing_is_closed_and_service_remains_available(lab, extra, expected):
    service = lab.start()
    assert raw_request(service, wire(service, lab.token, extra, b"{}"))[0] == expected
    assert request(service, lab.token)[0] == 200


def test_extra_pipelined_bytes_rejected(lab):
    service = lab.start()
    body = json.dumps(command()).encode()
    extra = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()
    raw = wire(service, lab.token, extra, body + b"GET /healthz HTTP/1.1\r\n")
    assert raw_request(service, raw)[0] == 400
    assert request(service, lab.token)[1]["command_count"] == 0


def test_request_deadline_bounds_slow_client_and_body_read(lab):
    service = lab.start(request_timeout=0.1)
    with socket.create_connection(service.address, timeout=1) as sock:
        sock.sendall(b"G")
        started = time.monotonic()
        time.sleep(0.07)
        sock.sendall(b"E")
        assert b"408 Request Timeout" in sock.recv(4096)
        assert time.monotonic() - started < 0.3
    header = b"Content-Type: application/json\r\nContent-Length: 20\r\n"
    assert raw_request(service, wire(service, lab.token, header, b"{"))[0] == 408
    assert request(service, lab.token)[0] == 200


def test_timeout_preserves_admitted_operation_and_retry_identity(lab):
    lab.hold_authorize = True
    service = lab.start(operation_timeout=0.05, stale_after=0.02, tick_interval=0.005)
    item = command()
    status, response = request(service, lab.token, "POST", "/v1/commands", item)
    assert status == 504
    assert response == {"code": "operation_unconfirmed", "command_id": item["command_id"]}
    assert service.health()["owner_stale"] and not service.health()["ready"]
    lab.authorize_release.set()
    eventually(lambda: service.health()["ready"])
    assert request(service, lab.token, "POST", "/v1/commands", item)[0] == 202
    eventually(lambda: len(lab.edge.reports) == 1)
    assert len(lab.transport.sent) == 1


def test_disconnected_client_does_not_cancel_or_resend(lab):
    lab.hold_authorize = True
    service = lab.start()
    item = command()
    body = json.dumps(item).encode()
    extra = f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n".encode()
    with socket.create_connection(service.address, timeout=1) as sock:
        sock.sendall(wire(service, lab.token, extra, body))
        assert lab.authorize_entered.wait(1)
    lab.authorize_release.set()
    assert request(service, lab.token, "POST", "/v1/commands", item)[0] == 202
    assert len(lab.transport.sent) == 1


def test_restart_keeps_unknown_execution_and_does_not_redispatch(lab):
    lab.drop_outcomes = True
    first = lab.start()
    item = command()
    assert request(first, lab.token, "POST", "/v1/commands", item)[1]["state"] == "dispatched"
    first.close()
    second = lab.start()
    result = request(second, lab.token, "POST", "/v1/commands", item)[1]
    assert result["state"] == "uncertain"
    assert result["result"]["reason"] == "process_interrupted_confirmation_unknown"
    assert not lab.transport.sent
    eventually(lambda: len(lab.edge.reports) == 1)
    assert lab.edge.reports[0]["outcome"] == "partial"
    second.close()
    assert lab.executions == [1, 1]


def test_bounded_mailbox_does_not_cancel_queued_timeouts(lab):
    lab.hold_authorize = True
    service = lab.start(mailbox_size=1, operation_timeout=0.1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(service._dispatch, "command", command())
        assert lab.authorize_entered.wait(1)
        second = pool.submit(service._dispatch, "status", None)
        eventually(lambda: service.health()["queue_depth"] == 1)
        assert service._dispatch("status", None) == (503, {"code": "mailbox_full"})
        assert first.result()[0] == second.result()[0] == 504
    lab.authorize_release.set()
    eventually(lambda: service.health()["queue_depth"] == 0)
    assert request(service, lab.token)[1]["command_count"] == 1


def test_fatal_owner_error_marks_unready_and_sanitizes_response(lab):
    service = lab.start()
    lab.fail_tick.set()
    eventually(lambda: not service.health()["alive"])
    assert request(service, lab.token, path="/healthz")[0] == 503
    assert request(service, lab.token) == (503, {"code": "service_unavailable"})
    assert "sensitive" not in json.dumps(service.health())


def test_real_control_client_uses_service_contract(lab):
    service = lab.start()
    host, port = service.address
    with ControlClient(f"http://{host}:{port}", lab.token) as client:
        assert client.health()["ready"]
        item = client.command(str(uuid.uuid4()), 7, 60)
        assert item["state"] == "dispatched"
        eventually(lambda: client.result(item["command_id"])["state"] == "confirmed")
        assert client.status()["command_count"] == 1


def test_shutdown_rejects_queued_work_without_discarding_active_intent(lab):
    lab.hold_authorize = True
    service = lab.start(operation_timeout=1)
    with ThreadPoolExecutor(max_workers=3) as pool:
        first = pool.submit(service._dispatch, "command", command())
        assert lab.authorize_entered.wait(1)
        second = pool.submit(service._dispatch, "status", None)
        eventually(lambda: service.health()["queue_depth"] == 1)
        closing = pool.submit(service.close)
        eventually(lambda: service.health()["state"] == "stopping")
        assert service._dispatch("status", None)[0] == 503
        lab.authorize_release.set()
        assert first.result()[0] == 202
        assert second.result() == (503, {"code": "service_unavailable"})
        closing.result()
    assert lab.executions == [1]
    assert not service.health()["alive"]
    restarted = lab.start()
    assert request(restarted, lab.token)[1]["command_count"] == 1


def test_command_admission_never_schedules_second_action_after_busy_timeout(lab):
    lab.hold_authorize = True
    service = lab.start(operation_timeout=0.05, tick_interval=0.005)
    item = command()
    assert request(service, lab.token, "POST", "/v1/commands", item)[0] == 504
    assert lab.authorize_entered.wait(1)
    same = request(service, lab.token, "POST", "/v1/commands", item)
    assert same == (504, {"code": "operation_unconfirmed", "command_id": item["command_id"]})
    assert service.health()["queue_depth"] == 0
    different = command()
    assert request(service, lab.token, "POST", "/v1/commands", different)[0] == 409
    for change in ({"interval_seconds": 61}, {"ttl": 59}):
        changed = request(service, lab.token, "POST", "/v1/commands", {**item, **change})
        assert changed == (409, {"code": "command_id_conflict"})
    lab.authorize_release.set()
    eventually(lambda: len(lab.edge.reports) == 1)
    status, result = request(service, lab.token)
    assert status == 200 and result["command_count"] == 1
    assert len(lab.transport.sent) == 1
    assert request(service, lab.token, path="/v1/commands/" + different["command_id"])[0] == 404


def test_shutdown_between_dequeue_and_owner_admission_rejects_command(lab, monkeypatch):
    service = lab.start(operation_timeout=1)
    dequeued, release = threading.Event(), threading.Event()
    original = service._mailbox.get_nowait

    def paused_dequeue():
        work = original()
        dequeued.set()
        assert release.wait(2)
        return work

    monkeypatch.setattr(service._mailbox, "get_nowait", paused_dequeue)
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(service._dispatch, "command", command())
        assert dequeued.wait(1)
        closing = pool.submit(service.close)
        eventually(lambda: service.health()["state"] == "stopping")
        release.set()
        assert pending.result() == (503, {"code": "service_unavailable"})
        closing.result()
    assert lab.executions == [0]
    restarted = lab.start()
    assert request(restarted, lab.token)[1]["command_count"] == 0


def test_fatal_error_during_command_returns_uncertain_id(lab):
    @contextmanager
    def factory(config, keys):
        with lab.factory(config, keys) as bridge:

            def broken(**kwargs):
                bridge.journal.reserve_command(kwargs["command_id"], 7, 60, lab.now, lab.now + 60)
                raise RuntimeError("sensitive detail")

            bridge.start_command = broken
            yield bridge

    service = ControlService(lab.config, lab.keys, lab.token, port=0, resource_factory=factory)
    lab.services.append(service)
    service.start()
    item = command()
    result = request(service, lab.token, "POST", "/v1/commands", item)
    assert result == (504, {"code": "operation_unconfirmed", "command_id": item["command_id"]})
    assert not service.health()["ready"]
    service.close()
    restarted = lab.start()
    recovered = request(restarted, lab.token, path="/v1/commands/" + item["command_id"])[1]
    assert recovered["state"] == "uncertain"
    assert not lab.transport.sent


def test_startup_failure_and_double_start_are_safe(lab):
    @contextmanager
    def broken(*args):
        raise RuntimeError("sensitive private path")
        yield

    service = ControlService(lab.config, lab.keys, lab.token, port=0, resource_factory=broken)
    with pytest.raises(ServiceError, match="^service_start_failed$"):
        service.start()
    assert not service.health()["alive"]
    running = lab.start()
    with pytest.raises(ServiceError, match="service_already_started"):
        running.start()


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.2", "localhost", "::", "::1", "::1%lo", 0])
def test_loopback_literal_required(lab, host):
    with pytest.raises(ValueError, match="loopback"):
        ControlService(lab.config, lab.keys, lab.token, host=host)


@pytest.mark.parametrize("token", ["", "secret", "f" * 63, "F" * 64, "g" * 64])
def test_service_token_validation(lab, token):
    with pytest.raises(ValueError, match="token"):
        ControlService(lab.config, lab.keys, token)


def test_token_must_not_be_device_key(lab):
    with pytest.raises(ValueError, match="differ"):
        ControlService(lab.config, lab.keys, lab.keys[7].hex())
