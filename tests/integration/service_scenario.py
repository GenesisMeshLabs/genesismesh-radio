"""Real local control HTTP, real authority/edge, and an injected radio peer."""

from __future__ import annotations

import secrets
import uuid
from contextlib import contextmanager

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


def service_scenarios(root, binary, verify_binary, report, check):
    root.mkdir(mode=0o700)
    with running_stack(root, binary) as (authority, process, _):
        keys = {1: secrets.token_bytes(32)}
        device = DeviceConfig(1, "!aabbccdd", "meshtastic", "edge:radio-lab/meshtastic", "LAB_KEY")
        config = Config("service-live-lab", (device,), root / "bridge.db")
        Journal.initialize(config.state_path, binding(config, keys))
        peer = DevicePeer(1, keys[1], config.audience)
        token = secrets.token_hex(32)
        resources = {}

        @contextmanager
        def factory(config, keys):
            with (
                Journal(config.state_path, binding(config, keys)) as journal,
                EdgeClient(unix_socket=str(process.socket)) as edge,
            ):
                radio = RadioHarness("meshtastic", device.route, peer)
                resources["radio"] = radio
                try:
                    yield Bridge(config, journal, edge, {"meshtastic": radio.transport}, keys=keys)
                finally:
                    radio.close()

        def open_service():
            service = ControlService(config, keys, token, port=0, resource_factory=factory).start()
            return service, ControlClient(
                f"http://{service.address[0]}:{service.address[1]}", token
            )

        def confirmed(client, command_id):
            record = client.result(command_id)
            return (
                record
                if record["state"] == "confirmed" and record["report_status"] == "accepted"
                else None
            )

        with EdgeClient(unix_socket=str(process.socket)) as observer:
            wait_for(lambda: observer.status().get("grants"), description="service lab grant")
            service, client = open_service()
            interrupted_id = str(uuid.uuid4())
            try:
                check(report, "service_authenticated_health", client.health()["ready"])
                response = httpx.get(f"http://{service.address[0]}:{service.address[1]}/healthz")
                check(report, "service_rejects_missing_control_token", response.status_code == 401)
                radio = resources["radio"]
                radio.inbound(peer.telemetry())
                wait_for(
                    lambda: client.status()["event_count"] == 1, description="service telemetry"
                )
                check(report, "service_ingests_telemetry_without_cli_journal_owner", True)

                # Queue an older telemetry frame before the command creates its newer outcome.
                # Deliver it during the outcome wait while preserving per-device counter order.
                buffered_telemetry = peer.telemetry()
                online_id = str(uuid.uuid4())
                record = client.command(online_id, 1, 60)
                check(
                    report,
                    "service_online_command_is_dispatched_not_confirmed",
                    record["state"] == "dispatched" and record["authority"] == "decision",
                )
                radio.inbound(buffered_telemetry)
                wait_for(
                    lambda: client.status()["event_count"] == 2,
                    description="telemetry during command",
                )
                check(
                    report,
                    "service_continues_ingestion_while_waiting_for_outcome",
                    client.result(online_id)["state"] == "dispatched",
                )
                radio.release_outcome()
                wait_for(lambda: confirmed(client, online_id), description="online device outcome")
                check(report, "service_online_device_outcome_reported", peer.applied == 60)
                before = peer.rx
                duplicate = client.command(online_id, 1, 60)
                check(
                    report,
                    "service_idempotent_http_retry_does_not_redispatch",
                    peer.rx == before and duplicate["state"] == "confirmed",
                )

                authority.stop()
                offline_id = str(uuid.uuid4())
                record = client.command(offline_id, 1, 120)
                check(
                    report,
                    "service_offline_command_uses_real_signed_grant",
                    record["authority"] == "grant" and record["state"] == "dispatched",
                )
                radio.release_outcome()
                wait_for(
                    lambda: confirmed(client, offline_id), description="offline device outcome"
                )
                check(
                    report,
                    "service_offline_evidence_queued",
                    observer.status()["pending_uploads"] >= 1,
                )

                pending = client.command(interrupted_id, 1, 90)
                check(
                    report,
                    "service_unconfirmed_dispatch_durable_before_shutdown",
                    pending["state"] == "dispatched",
                )
            finally:
                client.close()
                service.close()

            before = peer.rx
            service, client = open_service()
            try:
                recovered = client.result(interrupted_id)
                check(
                    report,
                    "service_restart_preserves_uncertainty",
                    recovered["state"] == "uncertain",
                )
                retried = client.command(interrupted_id, 1, 90)
                check(
                    report,
                    "service_restart_retry_does_not_execute_again",
                    peer.rx == before and retried["state"] == "uncertain",
                )
                try:
                    client.command(interrupted_id, 1, 91)
                except ControlError as error:
                    check(report, "service_uuid_conflict_is_refused", error.status_code == 409)
                else:
                    raise AssertionError("conflicting UUID accepted")

                authority.start()
                wait_for(
                    lambda: (
                        observer.status().get("connected")
                        and observer.status().get("pending_uploads") == 0
                    ),
                    timeout=45,
                    description="service evidence sync",
                )
                verification = authority.admin("GET", "/admin/evidence/verify")
                check(
                    report,
                    "service_real_evidence_store_verifies",
                    verification.get("verified") is True and verification.get("failures") == [],
                )
                original, tampered = verify_export(authority, root, verify_binary)
                report["service_evidence_verification"] = verification
                report["service_independent_verification"] = original
                check(
                    report,
                    "service_rust_verifier_accepts_original_and_refuses_tamper",
                    original["verified"] and not tampered["verified"],
                )
            finally:
                client.close()
                service.close()
