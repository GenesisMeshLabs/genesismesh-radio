"""Govern a bounded device command; distinguish dispatch from execution."""

from __future__ import annotations

import hashlib
import time
import uuid

from .config import Config, binding
from .edge import EdgeError
from .journal import Journal, JournalError
from .protocol import (
    Frame,
    Kind,
    OutcomeStatus,
    ProtocolError,
    decode,
    decode_outcome,
    decode_telemetry,
    encode,
    encode_command,
    peek_device_id,
)

IN_FLIGHT = {"authorizing", "authorized", "sending", "dispatched"}


class BridgeError(RuntimeError):
    pass


class Bridge:
    def __init__(
        self,
        config: Config,
        journal: Journal,
        edge,
        transports: dict,
        *,
        clock=time.time,
        keys: dict[int, bytes],
        recover: bool = True,
    ):
        if binding(config, keys) != journal.config_binding:
            raise BridgeError("journal_identity_binding_mismatch")
        if set(transports) != {device.transport for device in config.devices}:
            raise BridgeError("missing_transport")
        self.config, self.journal, self.edge = config, journal, edge
        self.transports, self.clock, self.keys = transports, clock, keys
        self.rejected_frames = 0
        self.last_rejection = None
        self._now()
        if recover:
            for command in journal.pending_commands():
                if command["state"] in IN_FLIGHT:
                    journal.update_command(
                        command["command_id"],
                        state="uncertain",
                        result={"reason": "process_interrupted_confirmation_unknown"},
                        report_status="pending" if command["authorization_id"] else "unavailable",
                    )

    def _now(self):
        now = int(self.clock())
        self.journal.observe_time(now)
        return now

    def start_command(
        self, device_id: int, interval_seconds: int, ttl: int = 60, *, command_id: str | None = None
    ) -> dict:
        now = self._now()
        device = self.config.device(device_id)
        if type(interval_seconds) is not int or not (
            device.min_interval <= interval_seconds <= device.max_interval
        ):
            raise BridgeError("interval_outside_device_limits")
        if type(ttl) is not int or not 3 <= ttl <= 300:
            raise BridgeError("command_ttl_must_be_3_to_300_seconds")
        command_id = str(uuid.uuid4()) if command_id is None else command_id
        try:
            if str(uuid.UUID(command_id)) != command_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise BridgeError("invalid_command_id") from exc
        previous = self.journal.command(command_id)
        if previous:
            if (previous["device_id"], previous["interval_seconds"]) != (
                device_id,
                interval_seconds,
            ):
                raise BridgeError("command_id_conflict")
            return previous
        if any(
            c["state"] in IN_FLIGHT or c["report_status"] == "pending"
            for c in self.journal.pending_commands()
        ):
            raise BridgeError("another_command_or_report_is_pending")
        payload = encode_command(interval_seconds)
        transport = self.transports[device.transport]
        budget = min(device.max_payload, getattr(transport, "max_payload", device.max_payload))
        if max(len(payload) + 35, 46) > budget:
            raise BridgeError("transport_payload_budget_too_small")
        command = self.journal.reserve_command(
            command_id, device_id, interval_seconds, now, now + ttl
        )
        try:
            authorization = self.edge.authorize(device.resource_id, interval_seconds, command_id)
        except EdgeError as exc:
            return self.journal.update_command(
                command_id,
                state="uncertain",
                result={"reason": "authorization_unconfirmed", "code": exc.code},
                report_status="unavailable",
            )
        now = self._now()
        if not authorization.allowed:
            return self.journal.update_command(
                command_id, state="denied", result={"reason": authorization.code or "denied"}
            )
        self.journal.update_command(
            command_id,
            authorization_id=authorization.authorization_id,
            authority=authorization.authority,
            state="authorized",
        )
        if authorization.authority not in {"decision", "grant"}:
            self.journal.update_command(
                command_id,
                state="rejected",
                result={"reason": "unsupported_authority"},
                report_status="pending",
            )
            self.tick()
            return self.journal.command(command_id)
        expires_at = min(command["expires_at"], authorization.report_by - 2)
        if expires_at <= now:
            self.journal.update_command(
                command_id,
                state="expired",
                result={"reason": "authorization_window_too_short"},
                report_status="pending",
            )
            self.tick()
            return self.journal.command(command_id)
        frame = Frame(Kind.COMMAND, device_id, command["counter"], expires_at, payload)
        raw = encode(frame, self.keys[device_id], self.config.audience)
        digest = hashlib.sha256(raw).hexdigest()
        # Committed before any I/O: recovery never redispatches an ambiguous command.
        self.journal.update_command(
            command_id, state="sending", expires_at=expires_at, frame_digest=digest
        )
        try:
            receipt = transport.send(device.route, raw, command_id)
        except Exception:
            self.journal.update_command(
                command_id,
                state="uncertain",
                result={"reason": "dispatch_unconfirmed"},
                report_status="pending",
            )
            self.tick()
            return self.journal.command(command_id)
        return self.journal.update_command(
            command_id,
            state="dispatched",
            result={"transport_receipt": str(receipt), "execution_confirmed": False},
        )

    def ingest(self, transport: str, incoming) -> dict:
        now = self._now()
        device_id = peek_device_id(incoming.payload)
        device = self.config.device(device_id)
        if (transport, incoming.route) != (device.transport, device.route):
            raise BridgeError("device_transport_route_mismatch")
        frame = decode(
            incoming.payload,
            self.keys[device_id],
            self.config.audience,
            now=now,
            max_payload=device.max_payload,
        )
        if frame.kind not in {Kind.TELEMETRY, Kind.OUTCOME}:
            raise BridgeError("uplink_kind_not_allowed")
        digest = hashlib.sha256(incoming.payload).hexdigest()
        details = {
            "source_device_id": device_id,
            "transport": transport,
            "route": incoming.route,
            "bridge_audience": self.config.audience,
            "authentication": "shared_key_mac",
            "device_signature": False,
        }
        command_update = None
        if frame.kind == Kind.TELEMETRY:
            metric, value = decode_telemetry(frame.payload)
            details.update(metric=metric, value=value)
        else:
            counter, status, interval = decode_outcome(frame.payload)
            command = self.journal.command_by_counter(device_id, counter)
            if command is None:
                raise BridgeError("outcome_has_no_matching_command")
            if status == OutcomeStatus.SUCCESS and interval != command["interval_seconds"]:
                raise BridgeError("outcome_applied_value_mismatch")
            details.update(
                command_id=command["command_id"],
                command_counter=counter,
                status=status.name.lower(),
                applied_interval=interval,
            )
            if command["state"] in {"sending", "dispatched"} and now < command["expires_at"]:
                state = {
                    OutcomeStatus.SUCCESS: "confirmed",
                    OutcomeStatus.REJECTED: "rejected",
                    OutcomeStatus.UNCERTAIN: "uncertain",
                }[status]
                command_update = (
                    command["command_id"],
                    state,
                    {
                        "reason": "device_" + status.name.lower(),
                        "outcome_digest": digest,
                        "applied_interval": interval,
                    },
                )
                details["accepted_for_execution_evidence"] = True
            else:
                details["accepted_for_execution_evidence"] = False
                details["reason"] = "late_or_already_finalized_outcome"
        result = self.journal.accept_event(
            device_id=device_id,
            counter=frame.counter,
            digest=digest,
            kind=frame.kind.name.lower(),
            now=now,
            raw=incoming.payload,
            details=details,
            command_update=command_update,
        )
        self.tick()
        return result

    def tick(self):
        now = self._now()
        for command in self.journal.pending_commands():
            if command["state"] in {"sending", "dispatched"} and now >= command["expires_at"]:
                self.journal.update_command(
                    command["command_id"],
                    state="uncertain",
                    result={"reason": "confirmation_missing"},
                    report_status="pending",
                )
        for command in self.journal.pending_commands():
            if command["report_status"] != "pending" or command["next_report_at"] > now:
                continue
            outcome = (
                "success"
                if command["state"] == "confirmed"
                else "partial"
                if command["state"] == "uncertain"
                else "failure"
            )
            metadata = {
                "authorized_operation": "command_dispatch",
                "command_id": command["command_id"],
                "device_id": str(command["device_id"]),
                "interval_seconds": command["interval_seconds"],
                "command_counter": str(command["counter"]),
                "confirmation": command["state"],
            }
            if command["frame_digest"]:
                metadata["frame_digest"] = command["frame_digest"]
            result = command["result"] or {}
            if result.get("outcome_digest"):
                metadata["outcome_digest"] = result["outcome_digest"]
            try:
                self.edge.report(
                    command["authorization_id"],
                    outcome,
                    metadata,
                    result.get("reason", command["state"]),
                )
            except EdgeError as exc:
                if exc.status_code in {403, 404, 409, 410}:
                    # A lost response followed by 409 is ambiguous, not proof of acceptance.
                    status = "expired" if exc.status_code == 410 else "uncertain"
                    self.journal.update_command(command["command_id"], report_status=status)
                else:
                    attempts = command["report_attempts"] + 1
                    self.journal.update_command(
                        command["command_id"],
                        report_attempts=attempts,
                        next_report_at=now + min(30, 2 ** min(attempts, 5)),
                    )
            else:
                self.journal.update_command(command["command_id"], report_status="accepted")

    def run_once(self, timeout: float = 0.1):
        self.tick()
        for name, transport in self.transports.items():
            incoming = transport.receive(timeout / len(self.transports))
            if incoming is None:
                continue
            try:
                self.ingest(name, incoming)
            except JournalError as exc:
                if str(exc) != "replayed_or_reordered_frame":
                    raise
                self.rejected_frames += 1
                self.last_rejection = "replayed_or_reordered_frame"
            except (BridgeError, ProtocolError, ValueError):
                self.rejected_frames += 1
                self.last_rejection = "invalid_or_unbound_frame"

    def status(self):
        return {
            "audience": self.config.audience,
            "commands": self.journal.commands(),
            "devices": [
                {
                    "device_id": d.device_id,
                    "resource_id": d.resource_id,
                    "transport": d.transport,
                    "min_interval": d.min_interval,
                    "max_interval": d.max_interval,
                }
                for d in self.config.devices
            ],
            "latest_telemetry": self.journal.latest_telemetry(),
            "event_count": self.journal.event_count(),
            "command_count": self.journal.command_count(),
            "rejected_frames": self.rejected_frames,
            "last_rejection": self.last_rejection,
            "transports": {
                name: {
                    "rejected": getattr(adapter, "rejected_count", 0),
                    "overflow": getattr(adapter, "overflow_count", 0),
                }
                for name, adapter in self.transports.items()
            },
        }
