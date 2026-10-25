"""Real Rust engine under simulated hardware, connected to real GenesisMesh services."""

from __future__ import annotations

import json
import secrets
import select
import subprocess
import threading
from queue import Queue

from live_support import running_stack, wait_for
from offline_verifier import verify_export

from genesismesh_radio.adapters.base import Inbound, QueuedTransport
from genesismesh_radio.bridge import Bridge
from genesismesh_radio.config import Config, DeviceConfig, binding
from genesismesh_radio.edge import EdgeClient
from genesismesh_radio.journal import Journal


class RustPeer:
    def __init__(self, binary, key, audience):
        self._lock = threading.Lock()
        self.process = subprocess.Popen(
            [binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        try:
            response = self.request(
                op="init",
                device_id=1,
                key_hex=key.hex(),
                audience=audience,
                min_interval=5,
                max_interval=120,
                max_frame=51,
                initial_interval=60,
            )
            if response.get("hardware_tested") is not False:
                raise AssertionError("Rust peer must explicitly identify simulated hardware")
        except BaseException:
            self.close()
            raise

    def request(self, *, allow_error=False, **body):
        with self._lock:
            if self.process.poll() is not None:
                raise AssertionError("Rust test peer stopped")
            self.process.stdin.write(json.dumps(body) + "\n")
            self.process.stdin.flush()
            ready, _, _ = select.select([self.process.stdout], [], [], 10)
            if not ready:
                raise AssertionError("Rust test peer response timeout")
            raw = self.process.stdout.readline(8193)
            if not raw.endswith("\n") or len(raw) > 8192:
                raise AssertionError("Rust test peer response framing")
            response = json.loads(raw)
            if not allow_error and response.get("ok") is not True:
                raise AssertionError("Rust test peer refused operation")
            return response

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()


class RustTransport(QueuedTransport):
    def __init__(self, peer):
        super().__init__(queue_size=16)
        self.max_payload = 51
        self.peer, self.pending, self.last_command = peer, Queue(maxsize=16), None

    def send(self, route, payload, command_id):
        assert route == "rust-1"
        result = self.peer.request(op="command", wire_hex=payload.hex())
        self.last_command = payload
        self.pending.put_nowait(bytes.fromhex(result["wire_hex"]))
        return "rust-host-submitted:" + command_id

    def release(self):
        self.inbound(self.pending.get(timeout=2))

    def inbound(self, payload):
        self._offer(Inbound("rust-1", payload))

    def close(self):
        self.closed = True
        self.peer.close()


def rust_device_scenarios(root, binary, verify_binary, peer_binary, report, check):
    root.mkdir(mode=0o700)
    with running_stack(root, binary) as (authority, process, _):
        key, audience = secrets.token_bytes(32), "rust-device-live-lab"
        device = DeviceConfig(1, "rust-1", "rust", "edge:radio-lab/rust", "LAB_RUST_KEY")
        config = Config(audience, (device,), root / "bridge.db")
        keys = {1: key}
        Journal.initialize(config.state_path, binding(config, keys))
        peer = RustPeer(peer_binary, key, audience)
        transport = RustTransport(peer)
        try:
            with (
                Journal(config.state_path, binding(config, keys)) as journal,
                EdgeClient(unix_socket=str(process.socket)) as edge,
            ):
                wait_for(lambda: edge.status().get("grants"), description="Rust lab signed grant")
                bridge = Bridge(config, journal, edge, {"rust": transport}, keys=keys)
                telemetry = peer.request(op="telemetry", metric=1, value=-1234)
                transport.inbound(bytes.fromhex(telemetry["wire_hex"]))
                bridge.run_once()
                check(
                    report,
                    "rust_device_authenticated_telemetry_ingested",
                    journal.event_count() == 1,
                )

                def operation(interval, authority_kind, state):
                    record = bridge.start_command(1, interval)
                    check(
                        report,
                        f"rust_device_{authority_kind}_{interval}_dispatch_only",
                        record["state"] == "dispatched" and record["authority"] == authority_kind,
                    )
                    transport.release()
                    bridge.run_once()
                    final = journal.command(record["command_id"])
                    check(
                        report,
                        f"rust_device_{authority_kind}_{interval}_authenticated_outcome",
                        final["state"] == state and final["report_status"] == "accepted",
                    )
                    return final

                operation(60, "decision", "confirmed")
                before = peer.request(op="status")
                reopened = peer.request(op="restart")
                check(
                    report,
                    "rust_device_engine_reopen_preserves_authenticated_snapshot",
                    (reopened["rx"], reopened["tx"], reopened["interval"])
                    == (before["rx"], before["tx"], before["interval"]),
                )
                replay = peer.request(
                    op="command", wire_hex=transport.last_command.hex(), allow_error=True
                )
                check(
                    report,
                    "rust_device_replay_refused_after_engine_reopen",
                    replay.get("ok") is False and peer.request(op="status")["rx"] == before["rx"],
                )

                operation(180, "decision", "rejected")
                check(
                    report,
                    "rust_device_enforces_its_own_parameter_bound",
                    peer.request(op="status")["interval"] == 60,
                )
                authority.stop()
                operation(120, "grant", "confirmed")
                check(
                    report,
                    "rust_device_offline_evidence_queued",
                    edge.status()["pending_uploads"] >= 1,
                )
                authority.start()
                wait_for(
                    lambda: (
                        edge.status().get("connected") and edge.status().get("pending_uploads") == 0
                    ),
                    timeout=45,
                    description="Rust device evidence sync",
                )
                verification = authority.admin("GET", "/admin/evidence/verify")
                check(
                    report,
                    "rust_device_real_evidence_store_verifies",
                    verification.get("verified") is True and verification.get("failures") == [],
                )
                original, tampered = verify_export(authority, root, verify_binary)
                report["rust_device_evidence_verification"] = verification
                report["rust_device_independent_verification"] = original
                check(
                    report,
                    "rust_device_rust_verifier_accepts_original_refuses_tamper",
                    original["verified"] and not tampered["verified"],
                )
        finally:
            transport.close()
