"""Bounded home rehearsal: real authority/control API with explicitly simulated RF."""

from __future__ import annotations

import json
import os
import secrets
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import httpx
from live_support import running_stack, wait_for
from offline_verifier import verify_export
from radio_peers import DevicePeer, RadioHarness

from genesismesh_radio.bridge import Bridge
from genesismesh_radio.config import Config, DeviceConfig, binding
from genesismesh_radio.control_client import ControlClient, ControlError
from genesismesh_radio.edge import EdgeClient
from genesismesh_radio.journal import Journal
from genesismesh_radio.service import ControlService

SESSION_SCHEMA = "genesismesh-radio-home-session/v1"
MAX_HOLD_SECONDS = 300


def private_session(root, service, config, token, hold_seconds):
    """Create a fresh private local-console handoff; never include this in reports."""
    if type(hold_seconds) is not int or not 1 <= hold_seconds <= MAX_HOLD_SECONDS:
        raise ValueError("invalid_hold_seconds")
    result = root.stat()
    if (
        root.is_symlink()
        or result.st_uid != os.getuid()
        or not stat.S_ISDIR(result.st_mode)
        or stat.S_IMODE(result.st_mode) != 0o700
    ):
        raise ValueError("private_session_directory_required")
    expires = datetime.now(UTC) + timedelta(seconds=hold_seconds)
    session = {
        "schema": SESSION_SCHEMA,
        "control_url": f"http://{service.address[0]}:{service.address[1]}",
        "control_token": token,
        "audience": config.audience,
        "devices": [
            {
                "device_id": item.device_id,
                "resource_id": item.resource_id,
                "route": item.route,
                "transport": item.transport,
                "min_interval": item.min_interval,
                "max_interval": item.max_interval,
            }
            for item in config.devices
        ],
        "authority": "real_disposable_genesismesh",
        "radio": "simulated_injected_meshtastic",
        "hardware_rf_tested": False,
        "expires_at": expires.isoformat(),
    }
    path = root / "session.json"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            descriptor = None
            json.dump(session, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return path


def home_pilot_scenarios(
    root,
    binary,
    verify_binary,
    report,
    check,
    *,
    hold_seconds=0,
    on_session=None,
    console_checks=False,
):
    if type(hold_seconds) is not int or not 0 <= hold_seconds <= MAX_HOLD_SECONDS:
        raise ValueError("invalid_hold_seconds")
    with running_stack(root, binary) as (authority, process, _):
        device_ids = (1, 2, 3) if console_checks else (1, 2)
        keys = {device_id: secrets.token_bytes(32) for device_id in device_ids}
        devices = tuple(
            DeviceConfig(
                device_id,
                f"!aabbccd{device_id}",
                f"mesh-{device_id}",
                (
                    f"edge:radio-lab/home-node-{device_id}"
                    if device_id != 3
                    else "edge:outside-home/node-3"
                ),
                f"HOME_TEST_KEY_{device_id}",
                max_interval=1000,
            )
            for device_id in device_ids
        )
        config = Config("home-pilot-lab", devices, root / "bridge.db")
        Journal.initialize(config.state_path, binding(config, keys))
        peers = {
            item.device_id: DevicePeer(item.device_id, keys[item.device_id], config.audience)
            for item in devices
        }
        token = secrets.token_hex(32)
        resources = {}
        peer_lock = threading.RLock()
        automatic = threading.Event()

        @contextmanager
        def factory(config, keys):
            with (
                Journal(config.state_path, binding(config, keys)) as journal,
                EdgeClient(unix_socket=str(process.socket)) as edge,
            ):
                radios = {
                    item.device_id: RadioHarness("meshtastic", item.route, peers[item.device_id])
                    for item in devices
                }
                resources["radios"] = radios
                for radio in radios.values():
                    original = radio.peer.sendData

                    def send(payload, *, _original=original, _radio=radio, **kwargs):
                        # The optional hold phase must queue an outcome before any
                        # newer telemetry counter. Only the bridge owner executes it.
                        with peer_lock:
                            receipt = _original(payload, **kwargs)
                            if automatic.is_set():
                                _radio.release_outcome()
                            return receipt

                    radio.peer.sendData = send
                try:
                    yield Bridge(
                        config,
                        journal,
                        edge,
                        {item.transport: radios[item.device_id].transport for item in devices},
                        keys=keys,
                    )
                finally:
                    for radio in radios.values():
                        radio.close()

        def open_service():
            service = ControlService(config, keys, token, port=0, resource_factory=factory).start()
            return service, ControlClient(
                f"http://{service.address[0]}:{service.address[1]}", token, timeout=10
            )

        def confirmed(client, command_id):
            record = client.result(command_id)
            return (
                record
                if (record["state"], record["report_status"])
                == (
                    "confirmed",
                    "accepted",
                )
                else None
            )

        def finish(client, command_id, device_id):
            resources["radios"][device_id].release_outcome()
            return wait_for(
                lambda: confirmed(client, command_id), description="home device outcome"
            )

        with EdgeClient(unix_socket=str(process.socket)) as observer:
            wait_for(lambda: observer.status().get("grants"), description="home signed grant")
            service, client = open_service()
            try:
                check(report, "home_control_ready", client.health()["ready"])
                with httpx.Client(timeout=5, trust_env=False) as anonymous:
                    response = anonymous.get(
                        f"http://{service.address[0]}:{service.address[1]}/healthz"
                    )
                check(report, "home_missing_control_token_refused", response.status_code == 401)
                for item in devices:
                    resources["radios"][item.device_id].inbound(peers[item.device_id].telemetry())
                wait_for(
                    lambda: client.status()["event_count"] == len(devices),
                    description="home telemetry",
                )
                check(
                    report,
                    "home_simulated_devices_visible",
                    client.status()["event_count"] == len(devices),
                )

                for item in devices[:2]:
                    command_id = str(uuid.uuid4())
                    record = client.command(command_id, item.device_id, 60)
                    check(
                        report,
                        f"home_node_{item.device_id}_online_dispatch_only",
                        record["state"] == "dispatched" and record["authority"] == "decision",
                    )
                    before = peers[item.device_id].rx
                    duplicate = client.command(command_id, item.device_id, 60)
                    check(
                        report,
                        f"home_node_{item.device_id}_pending_duplicate_never_redispatches",
                        duplicate["state"] == "dispatched" and peers[item.device_id].rx == before,
                    )
                    finish(client, command_id, item.device_id)
                    check(
                        report,
                        f"home_node_{item.device_id}_authenticated_outcome",
                        peers[item.device_id].applied == 60,
                    )
                try:
                    peers[1].execute(peers[1].last_command)
                except AssertionError:
                    check(report, "home_device_replay_refused", True)
                else:
                    raise AssertionError("home_device_replay_refused")

                before = peers[1].rx
                denied = client.command(str(uuid.uuid4()), 1, 700)
                check(
                    report,
                    "home_online_policy_denial_never_dispatches",
                    denied["state"] == "denied" and peers[1].rx == before,
                )
                authority.stop()
                offline_id = str(uuid.uuid4())
                offline = client.command(offline_id, 1, 120)
                check(
                    report,
                    "home_authority_outage_uses_real_offline_grant",
                    offline["state"] == "dispatched" and offline["authority"] == "grant",
                )
                finish(client, offline_id, 1)
                check(
                    report,
                    "home_offline_evidence_queued",
                    observer.status()["pending_uploads"] >= 1,
                )
                before = peers[1].rx
                denied = client.command(str(uuid.uuid4()), 1, 500)
                check(
                    report,
                    "home_offline_grant_bound_never_dispatches",
                    denied["state"] == "denied" and peers[1].rx == before,
                )
                interrupted_id = str(uuid.uuid4())
                uncertain = client.command(interrupted_id, 2, 90)
                check(
                    report, "home_unconfirmed_command_durable", uncertain["state"] == "dispatched"
                )
            finally:
                client.close()
                service.close()

            before = peers[2].rx
            service, client = open_service()
            session_path = None
            try:
                recovered = client.result(interrupted_id)
                check(
                    report, "home_restart_preserves_uncertainty", recovered["state"] == "uncertain"
                )
                duplicate = client.command(interrupted_id, 2, 90)
                check(
                    report,
                    "home_uncertain_duplicate_never_redispatches",
                    duplicate["state"] == "uncertain" and peers[2].rx == before,
                )
                try:
                    client.command(interrupted_id, 2, 91)
                except ControlError as error:
                    check(report, "home_conflicting_id_refused", error.status_code == 409)
                else:
                    raise AssertionError("home_conflicting_id_refused")
                authority.start()
                wait_for(
                    lambda: (
                        observer.status().get("connected")
                        and observer.status().get("pending_uploads") == 0
                    ),
                    timeout=45,
                    description="home evidence resynchronization",
                )
                check(report, "home_offline_evidence_resynchronized", True)
                if console_checks:
                    automatic.set()
                    console_scenarios(service, token, peers, process.socket, report, check)
                if hold_seconds:
                    automatic.set()
                    until = time.monotonic() + hold_seconds
                    session_path = private_session(root, service, config, token, hold_seconds)
                    if on_session is not None:
                        on_session(session_path)
                    while time.monotonic() < until:
                        with peer_lock:
                            for item in devices:
                                radio = resources["radios"][item.device_id]
                                radio.inbound(peers[item.device_id].telemetry())
                        time.sleep(min(2, max(0, until - time.monotonic())))
                    # Expiry closes the endpoint, not merely its discovery file.
                    client.close()
                    service.close()
                    session_path.unlink(missing_ok=True)
                    session_path = None
                    wait_for(
                        lambda: observer.status().get("pending_uploads") == 0,
                        description="home optional session evidence sync",
                    )
                    check(report, "home_optional_session_expired", True)
                verification = authority.admin("GET", "/admin/evidence/verify")
                good, tampered = verify_export(authority, root, verify_binary)
                check(
                    report,
                    "home_authority_evidence_verified",
                    verification.get("verified") is True and verification.get("failures") == [],
                )
                check(
                    report,
                    "home_independent_verifier_accepts_and_rejects_tamper",
                    good["verified"] is True and tampered["verified"] is False,
                )
                report["evidence"] = {
                    "authority_verified": True,
                    "independent_verified": True,
                    "tampered_export_rejected": True,
                    "entries_checked": good["checked_entries"],
                }
            finally:
                if session_path is not None:
                    session_path.unlink(missing_ok=True)
                client.close()
                service.close()


def console_scenarios(service, token, peers, edge_socket, report, check):
    """Exercise local admission against the real core; ASGI is not a TLS/LAN test."""
    from starlette.testclient import TestClient

    from genesismesh_radio.console.app import ConsoleSettings, create_app
    from genesismesh_radio.console.store import OperatorStore

    origin = "https://127.0.0.1:17902"
    settings = ConsoleSettings(origin, mode="real_authority_simulated_radio")
    password = secrets.token_urlsafe(32)
    store = OperatorStore()
    store.set_user("home-owner", password, "operator")
    store.set_user("home-viewer", password, "observer")
    report["console_execution"] = "ASGI TestClient; no TLS or LAN listener tested"

    def post(web, path, body, csrf=None):
        headers = {"Origin": origin, "Content-Type": "application/json", "X-Console-Request": "1"}
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf
        return web.post(path, content=json.dumps(body), headers=headers)

    def login(web, username):
        response = post(web, "/api/login", {"username": username, "password": password})
        if response.status_code != 200:
            raise AssertionError("console_login_failed")
        return response.json()["csrf"]

    def body(device_id=1, interval=45):
        return {
            "command_id": str(uuid.uuid4()),
            "device_id": device_id,
            "interval_seconds": interval,
            "ttl": 60,
        }

    def result(web, command_id):
        response = web.get(f"/api/commands/{command_id}")
        if response.status_code != 200:
            raise AssertionError("console_command_lookup_failed")
        value = response.json()["command"]
        return (
            value
            if (value["state"], value["report_status"])
            == (
                "confirmed",
                "accepted",
            )
            else None
        )

    try:
        with (
            ControlClient(f"http://{service.address[0]}:{service.address[1]}", token) as backend,
            TestClient(create_app(settings, store, backend), base_url=origin) as web,
        ):
            check(
                report,
                "console_anonymous_status_refused",
                web.get("/api/status").status_code == 401,
            )
            csrf = login(web, "home-viewer")
            before = peers[1].rx
            response = post(web, "/api/commands", body(), csrf)
            check(
                report,
                "console_observer_cannot_dispatch",
                response.status_code == 403 and peers[1].rx == before,
            )
            check(
                report,
                "console_observer_can_read_status",
                web.get("/api/status").status_code == 200,
            )
            csrf = login(web, "home-owner")
            request = body()
            submitted = post(web, "/api/commands", request, csrf)
            check(
                report,
                "console_operator_dispatch_is_not_execution",
                submitted.status_code == 202
                and submitted.json()["command"]["state"] == "dispatched",
            )
            check(
                report,
                "console_local_operator_is_admission_only",
                submitted.json()["local_operator"] == "home-owner"
                and submitted.json()["core_actor"] == "enrolled_bridge_identity",
            )
            outcome = wait_for(
                lambda: result(web, request["command_id"]),
                description="console authenticated outcome",
            )
            check(
                report,
                "console_real_core_allowed_authenticated_outcome",
                peers[1].applied == 45 and outcome["counter"] == peers[1].rx,
            )
            before = peers[1].rx
            retried = post(web, "/api/commands", request, csrf)
            check(
                report,
                "console_original_id_retry_never_redispatches",
                retried.status_code == 200
                and peers[1].rx == before
                and retried.json()["command"]["counter"] == outcome["counter"],
            )
            denied = post(web, "/api/commands", body(interval=700), csrf)
            check(
                report,
                "console_real_core_policy_denial_never_dispatches",
                denied.status_code == 202
                and denied.json()["command"]["state"] == "denied"
                and peers[1].rx == before,
            )
            before_outside = peers[3].rx
            outside = post(web, "/api/commands", body(device_id=3), csrf)
            # The existing bridge deliberately treats non-200 authorization
            # responses as unconfirmed. Verify the actual core scope rejection
            # separately instead of relabeling its uncertain journal as denied.
            with httpx.Client(
                base_url="http://127.0.0.1:7000",
                trust_env=False,
                timeout=5,
                transport=httpx.HTTPTransport(uds=str(edge_socket)),
            ) as core:
                refused = core.post(
                    "/v1/authorize",
                    json={
                        "capability": "radio.command.dispatch",
                        "request_parameters": {"interval_seconds": 45},
                        "attributes": {"command_id": str(uuid.uuid4())},
                        "resource_id": "edge:outside-home/node-3",
                        "resource_action": "update",
                    },
                )
            check(
                report,
                "console_outside_scope_refused_with_uncertain_authorization",
                outside.status_code == 202
                and outside.json()["command"]["state"] == "uncertain"
                and refused.status_code == 400
                and refused.json()["error"]["code"] == "resource_out_of_scope"
                and peers[3].rx == before_outside,
            )
            report["console_scope_refusal"] = {
                "core_http_status": 400,
                "core_code": "resource_out_of_scope",
                "bridge_state": "uncertain",
                "simulated_device_dispatched": False,
            }
            old_cookie = web.cookies.get(settings.cookie)
            check(
                report,
                "console_logout_succeeds",
                post(web, "/api/logout", {}, csrf).status_code == 200,
            )
            web.cookies.clear()
            web.cookies.set(settings.cookie, old_cookie)
            check(
                report,
                "console_logged_out_cookie_cannot_dispatch",
                post(web, "/api/commands", body(), csrf).status_code == 401
                and peers[1].rx == before,
            )
            web.cookies.clear()
            csrf = login(web, "home-owner")
            store.revoke("home-owner")
            check(
                report,
                "console_revoked_session_cannot_dispatch",
                post(web, "/api/commands", body(), csrf).status_code == 401
                and peers[1].rx == before,
            )
    finally:
        store.close()
