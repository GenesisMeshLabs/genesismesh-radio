#!/usr/bin/env python3
"""Run the bridge against a disposable real NA and Linux edge agent."""

from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "integration"))

from live_support import running_stack, wait_for  # noqa: E402
from offline_verifier import verify_export  # noqa: E402
from radio_peers import DevicePeer, RadioHarness  # noqa: E402
from rust_device_scenario import rust_device_scenarios  # noqa: E402
from service_scenario import service_scenarios  # noqa: E402

from genesismesh_radio.bridge import Bridge  # noqa: E402
from genesismesh_radio.config import Config, DeviceConfig, binding  # noqa: E402
from genesismesh_radio.edge import EdgeClient  # noqa: E402
from genesismesh_radio.journal import Journal  # noqa: E402


def check(report, name, condition):
    if not condition:
        raise AssertionError(name)
    report["checks"].append(name)
    print(f"PASS {name}", flush=True)


def core_runtime_info():
    """Describe imported source separately from potentially stale installed metadata."""
    import genesis_mesh

    info = {"core_version": genesis_mesh.__version__, "core_version_source": "module"}
    source_root = Path(genesis_mesh.__file__).resolve().parent.parent
    manifest = source_root / "pyproject.toml"
    if manifest.is_file():
        project = tomllib.loads(manifest.read_text())["project"]
        if project.get("name") == "genesis-mesh":
            info.update(
                core_version=project["version"],
                core_version_source="source_pyproject",
                core_reported_version=genesis_mesh.__version__,
            )
            revision = subprocess.run(
                ["git", "-C", str(source_root), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if revision.returncode == 0:
                info["core_source_commit"] = revision.stdout.strip()
    return info


def scenarios(root, binary, verify_binary, report):
    with running_stack(root, binary) as (authority, process, grant_id):
        edge = EdgeClient(unix_socket=str(process.socket))
        radios = []
        journal = None
        try:
            wait_for(lambda: edge.status().get("grants"), description="signed offline grant")
            check(report, "real_edge_enrolled_and_grant_synced", edge.status()["state"] == "active")
            keys = {device_id: secrets.token_bytes(32) for device_id in range(1, 4)}
            devices = tuple(
                DeviceConfig(
                    device_id,
                    route,
                    name,
                    f"edge:radio-lab/{name}",
                    f"TEST_DEVICE_{device_id}",
                    max_interval=1000,
                )
                for device_id, route, name in [
                    (1, "!aabbccdd", "meshtastic"),
                    (2, "sensor-2", "serial"),
                    (3, "sensor-3", "tts"),
                ]
            )
            config = Config("radio-live-lab", devices, root / "bridge.sqlite")
            Journal.initialize(config.state_path, binding(config, keys))
            journal = Journal(config.state_path, binding(config, keys))
            radios = [
                RadioHarness(
                    d.transport,
                    d.route,
                    DevicePeer(d.device_id, keys[d.device_id], config.audience),
                )
                for d in devices
            ]
            bridge = Bridge(config, journal, edge, {r.name: r.transport for r in radios}, keys=keys)

            def command_round(radio, interval, expected_authority):
                command = bridge.start_command(radio.device.device_id, interval)
                check(
                    report,
                    f"{radio.name}_{expected_authority}_dispatch",
                    command["state"] == "dispatched" and command["authority"] == expected_authority,
                )
                check(
                    report,
                    f"{radio.name}_{expected_authority}_ack_is_not_success",
                    command["report_status"] == "none",
                )
                radio.release_outcome()
                for _ in range(4):
                    bridge.run_once(0.1)
                final = journal.command(command["command_id"])
                check(
                    report,
                    f"{radio.name}_{expected_authority}_device_confirmed",
                    final["state"] == "confirmed"
                    and final["report_status"] == "accepted"
                    and radio.device.applied == interval,
                )

            for radio in radios:
                telemetry = radio.device.telemetry()
                radio.inbound(telemetry)
                bridge.run_once(0.1)
                prior = journal.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                radio.inbound(telemetry)
                bridge.run_once(0.1)
                check(
                    report,
                    f"{radio.name}_duplicate_uplink_idempotent",
                    journal.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == prior,
                )
                mutated = telemetry[:-1] + bytes([telemetry[-1] ^ 1])
                radio.inbound(mutated)
                rejected = bridge.rejected_frames
                bridge.run_once(0.1)
                check(
                    report,
                    f"{radio.name}_tampered_uplink_rejected",
                    bridge.rejected_frames == rejected + 1,
                )
                command_round(radio, 60, "decision")
                try:
                    radio.device.execute(radio.device.last_command)
                except AssertionError:
                    check(report, f"{radio.name}_device_replay_rejected", True)
                else:
                    raise AssertionError("replayed command executed")

            refused = bridge.start_command(1, 700)
            check(report, "online_policy_denial_prevents_dispatch", refused["state"] == "denied")
            authority.stop()
            for radio in radios:
                command_round(radio, 120, "grant")
            check(report, "offline_evidence_durably_queued", edge.status()["pending_uploads"] >= 3)
            refused = bridge.start_command(1, 500)
            check(report, "outside_offline_grant_prevents_dispatch", refused["state"] == "denied")

            authority.start()
            wait_for(
                lambda: (
                    edge.status().get("connected") and edge.status().get("pending_uploads") == 0
                ),
                timeout=45,
                description="evidence resynchronization",
            )
            status = edge.status()
            check(
                report, "evidence_resynchronized_without_dead_letters", status["dead_letters"] == 0
            )
            verification = authority.admin("GET", "/admin/evidence/verify")
            report["evidence_verification"] = verification
            check(
                report,
                "real_authority_store_signatures_and_chains_verify",
                verification.get("verified") is True
                and verification.get("failures") == []
                and verification.get("executions") == 3
                and verification.get("grant_executions") == 3,
            )
            independent, corrupted = verify_export(authority, root, verify_binary)
            report["independent_verification"] = independent
            report["tampered_export_verification"] = corrupted
            check(report, "standalone_rust_verifier_accepts_export_and_held_anchors", True)
            check(report, "standalone_rust_verifier_rejects_tampered_export", True)

            authority.stop()
            process.expire_snapshot()
            check(
                report,
                "expired_cached_snapshot_refuses_offline_grant",
                not edge.authorize("edge:radio-lab/meshtastic", 60, "stale-check").allowed,
            )
            authority.start()
            wait_for(
                lambda: edge.status().get("snapshot_fresh") and edge.status().get("connected"),
                timeout=45,
                description="fresh snapshot",
            )
            authority.admin("POST", f"/admin/grants/{grant_id}/revoke", {"reason": "lab complete"})
            wait_for(
                lambda: not any(g["usable"] for g in edge.status().get("grants", [])),
                timeout=30,
                description="grant revocation learned",
            )
            authority.stop()
            check(
                report,
                "learned_revocation_refuses_offline_grant",
                not edge.authorize("edge:radio-lab/meshtastic", 60, "revoked-check").allowed,
            )
            authority.start()

            journal.close()
            journal = Journal(config.state_path, binding(config, keys))
            recovered = Bridge(
                config, journal, edge, {r.name: r.transport for r in radios}, keys=keys
            )
            check(
                report,
                "bridge_state_survives_reopen",
                len(journal.commands()) == 8 and recovered.rejected_frames == 0,
            )
        finally:
            if journal is not None:
                journal.close()
            for radio in radios:
                radio.close()
            edge.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edge-binary", default=os.environ.get("GM_EDGE_BINARY"))
    parser.add_argument("--verify-binary", default=os.environ.get("GM_VERIFY_BINARY"))
    parser.add_argument("--rust-device-binary", default=os.environ.get("GM_RUST_DEVICE_BINARY"))
    parser.add_argument("--report", type=Path, default=ROOT / "artifacts" / "live-lab.json")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("the live edge lab requires Linux (WSL is supported)")
    if not args.edge_binary or not Path(args.edge_binary).is_file():
        parser.error("--edge-binary must name a built genesis-mesh-edge executable")
    if not args.verify_binary:
        args.verify_binary = str(Path(args.edge_binary).with_name("genesis-mesh-verify"))
    if not Path(args.verify_binary).is_file():
        parser.error("--verify-binary must name a built genesis-mesh-verify executable")
    if not args.rust_device_binary or not Path(args.rust_device_binary).is_file():
        parser.error("--rust-device-binary must name the built Rust device_peer host example")
    version = subprocess.run(
        [args.edge_binary, "--version"], capture_output=True, text=True, check=True, timeout=10
    ).stdout.strip()
    verifier_version = subprocess.run(
        [args.verify_binary, "--version"], capture_output=True, text=True, check=True, timeout=10
    ).stdout.strip()
    report = {
        "status": "running",
        **core_runtime_info(),
        "edge_version": version,
        "verifier_version": verifier_version,
        "python": platform.python_version(),
        "transport_execution": "real adapters with injected SDK/MQTT/UART peers",
        "hardware_rf_tested": False,
        "rust_device_storage": "simulated in-process memory; engine reopen is not a board reset",
        "checks": [],
    }
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="gm-radio-live-") as directory:
            Path(directory).chmod(0o700)
            scenarios(Path(directory), args.edge_binary, args.verify_binary, report)
            service_scenarios(
                Path(directory) / "service", args.edge_binary, args.verify_binary, report, check
            )
            rust_device_scenarios(
                Path(directory) / "rust-device",
                args.edge_binary,
                args.verify_binary,
                args.rust_device_binary,
                report,
                check,
            )
        report["status"] = "passed"
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = str(exc)
        raise
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": report["status"],
                "checks": len(report["checks"]),
                "report": str(args.report),
            }
        )
    )


if __name__ == "__main__":
    main()
