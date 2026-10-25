"""A persistent device model for software tests, never an RF or hardware claim."""

from __future__ import annotations

import hashlib
import json
import queue
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

from .adapters.base import Inbound
from .protocol import (
    Frame,
    Kind,
    OutcomeStatus,
    ProtocolError,
    decode,
    decode_command,
    encode,
    encode_outcome,
    encode_telemetry,
)


class DeviceSimulator:
    def __init__(
        self,
        device_id: int,
        key: bytes,
        audience: str,
        *,
        clock=time.time,
        min_interval=5,
        max_interval=3600,
        state_path: Path | None = None,
    ):
        self.device_id, self.key, self.audience = device_id, key, audience
        self.clock, self.min_interval, self.max_interval = clock, min_interval, max_interval
        self.db = sqlite3.connect(str(state_path) if state_path else ":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS device
            (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT, rx TEXT, tx TEXT,
             last_time INTEGER, interval INTEGER, digest TEXT, outcome BLOB, executions INTEGER)""")
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "device_id": device_id,
                    "audience": audience,
                    "key_digest": hashlib.sha256(key).hexdigest(),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        self.db.execute(
            "INSERT OR IGNORE INTO device VALUES(1,?,'0','0',0,30,'',NULL,0)", (fingerprint,)
        )
        self.db.commit()
        if self._state()["binding"] != fingerprint:
            self.close()
            raise ProtocolError("simulator_identity_changed")

    def _state(self):
        return self.db.execute("SELECT * FROM device WHERE id=1").fetchone()

    @property
    def interval(self):
        return self._state()["interval"]

    @property
    def executions(self):
        return self._state()["executions"]

    def _now(self):
        now = int(self.clock())
        if now < self._state()["last_time"]:
            raise ProtocolError("simulator_clock_rollback")
        return now

    def handle_command(self, raw: bytes) -> bytes:
        now = self._now()
        frame = decode(raw, self.key, self.audience, now=now)
        if frame.kind != Kind.COMMAND or frame.device_id != self.device_id:
            raise ProtocolError("simulator_wrong_destination_or_kind")
        digest = hashlib.sha256(raw).hexdigest()
        state = self._state()
        if frame.counter == int(state["rx"]) and digest == state["digest"]:
            return state["outcome"]
        if frame.counter <= int(state["rx"]):
            raise ProtocolError("simulator_replayed_command")
        interval = decode_command(frame.payload)
        accepted = self.min_interval <= interval <= self.max_interval
        applied = interval if accepted else state["interval"]
        counter = int(state["tx"]) + 1
        result = encode(
            Frame(
                Kind.OUTCOME,
                self.device_id,
                counter,
                now + 60,
                encode_outcome(
                    frame.counter,
                    OutcomeStatus.SUCCESS if accepted else OutcomeStatus.REJECTED,
                    applied,
                ),
            ),
            self.key,
            self.audience,
        )
        # This simulated setting is transactional. Real hardware must journal intent
        # before effects and reconcile after crashes; this is not exactly-once hardware.
        self.db.execute(
            """UPDATE device SET rx=?,tx=?,last_time=?,interval=?,digest=?,outcome=?,
            executions=executions+? WHERE id=1""",
            (str(frame.counter), str(counter), now, applied, digest, result, int(accepted)),
        )
        self.db.commit()
        return result

    def telemetry(self, metric=1, value=2150):
        now = self._now()
        counter = int(self._state()["tx"]) + 1
        raw = encode(
            Frame(
                Kind.TELEMETRY, self.device_id, counter, now + 60, encode_telemetry(metric, value)
            ),
            self.key,
            self.audience,
        )
        self.db.execute("UPDATE device SET tx=?,last_time=? WHERE id=1", (str(counter), now))
        self.db.commit()
        return raw

    def close(self):
        self.db.close()


class LoopbackTransport:
    """In-memory delivery with controllable loss; no actual radio is exercised."""

    max_payload = 51

    def __init__(self, peers: dict[str, DeviceSimulator]):
        self.peers = peers
        self.incoming = queue.Queue()
        self.sent = []
        self.drop_outcomes = False
        self.raise_after_send = False

    def send(self, route, payload, command_id):
        self.sent.append((route, payload, command_id))
        result = self.peers[route].handle_command(payload)
        if self.raise_after_send:
            raise OSError("simulated_lost_send_response")
        if not self.drop_outcomes:
            self.incoming.put(Inbound(route, result))
        return "simulated-dispatch:" + command_id

    def receive(self, timeout):
        try:
            return self.incoming.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        pass


class SimulationEdge:
    """Explicit fake authority for the CLI demo; live_lab uses real GenesisMesh."""

    def __init__(self, clock=time.time):
        self.clock, self.reports = clock, []

    def authorize(self, resource_id, interval_seconds, command_id):
        return SimpleNamespace(
            allowed=True,
            authorization_id=command_id,
            authority="decision",
            report_by=int(self.clock()) + 120,
            code=None,
        )

    def report(self, authorization_id, outcome, metadata, detail):
        self.reports.append(
            {
                "authorization_id": authorization_id,
                "outcome": outcome,
                "metadata": json.loads(json.dumps(metadata)),
                "detail": detail,
            }
        )
        return {"queued": False, "simulation": True}

    def close(self):
        pass
