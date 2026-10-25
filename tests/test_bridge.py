from dataclasses import replace
from types import SimpleNamespace

import pytest

from genesismesh_radio.adapters.base import Inbound
from genesismesh_radio.bridge import Bridge, BridgeError
from genesismesh_radio.config import Config, DeviceConfig, binding
from genesismesh_radio.edge import EdgeError
from genesismesh_radio.journal import Journal, JournalError
from genesismesh_radio.protocol import (
    Frame,
    Kind,
    OutcomeStatus,
    ProtocolError,
    encode,
    encode_outcome,
    encode_telemetry,
)
from genesismesh_radio.simulator import DeviceSimulator, LoopbackTransport, SimulationEdge


@pytest.fixture
def lab(tmp_path):
    now = [1_800_000_000]

    def clock():
        return now[0]

    key = bytes(range(32))
    device = DeviceConfig(7, "sensor-7", "radio", "edge:lab/sensor-7", "DEVICE_KEY")
    config = Config("site.lab", (device,), tmp_path / "bridge.db")
    identity = binding(config, {7: key})
    Journal.initialize(config.state_path, identity)
    journal = Journal(config.state_path, identity)
    peer = DeviceSimulator(7, key, config.audience, clock=clock, state_path=tmp_path / "device.db")
    transport = LoopbackTransport({device.route: peer})
    edge = SimulationEdge(clock)
    bridge = Bridge(config, journal, edge, {"radio": transport}, clock=clock, keys={7: key})
    result = SimpleNamespace(
        now=now,
        clock=clock,
        key=key,
        device=device,
        config=config,
        identity=identity,
        journal=journal,
        peer=peer,
        transport=transport,
        edge=edge,
        bridge=bridge,
    )
    yield result
    result.journal.close()
    result.peer.close()


def test_only_authenticated_application_result_becomes_success(lab):
    command = lab.bridge.start_command(7, 60)
    assert command["state"] == "dispatched"
    assert not lab.edge.reports
    lab.bridge.run_once(0)
    assert lab.journal.command(command["command_id"])["state"] == "confirmed"
    assert lab.edge.reports[0]["outcome"] == "success"
    assert lab.journal.events()[0]["details"]["device_signature"] is False


def test_lost_outcome_does_not_become_success_or_redispatch(lab):
    lab.transport.drop_outcomes = True
    command = lab.bridge.start_command(7, 60, ttl=3)
    lab.now[0] += 3
    lab.bridge.tick()
    result = lab.bridge.start_command(7, 60, command_id=command["command_id"])
    assert result["state"] == "uncertain"
    assert lab.edge.reports[0]["outcome"] == "partial"
    assert len(lab.transport.sent) == lab.peer.executions == 1


def test_same_request_id_with_different_action_is_rejected(lab):
    command = lab.bridge.start_command(7, 60)
    with pytest.raises(BridgeError, match="command_id_conflict"):
        lab.bridge.start_command(7, 61, command_id=command["command_id"])


def test_late_success_is_preserved_without_rewriting_uncertain_evidence(lab):
    command = lab.bridge.start_command(7, 60, ttl=3)
    incoming = lab.transport.receive(0)
    lab.now[0] += 3
    lab.bridge.tick()
    event = lab.bridge.ingest("radio", incoming)
    assert event["details"]["accepted_for_execution_evidence"] is False
    assert lab.journal.command(command["command_id"])["state"] == "uncertain"
    assert [report["outcome"] for report in lab.edge.reports] == ["partial"]


def test_timeout_during_send_keeps_ambiguity_and_never_retries_actuator(lab):
    lab.transport.raise_after_send = True
    command = lab.bridge.start_command(7, 70)
    assert lab.peer.interval == 70
    assert command["state"] == "uncertain"
    assert lab.edge.reports[0]["outcome"] == "partial"
    lab.bridge.tick()
    assert lab.peer.executions == 1


@pytest.mark.parametrize("authority", ["decision", "grant"])
def test_supported_authority_modes(lab, authority):
    lab.edge.authorize = lambda *args: SimpleNamespace(
        allowed=True,
        authorization_id="a",
        authority=authority,
        report_by=lab.now[0] + 30,
        code=None,
    )
    command = lab.bridge.start_command(7, 50)
    assert command["authority"] == authority
    assert command["expires_at"] == lab.now[0] + 28
    lab.bridge.run_once(0)
    assert lab.edge.reports[0]["outcome"] == "success"


def test_deny_never_sends(lab):
    lab.edge.authorize = lambda *args: SimpleNamespace(allowed=False, code="outside_grant")
    command = lab.bridge.start_command(7, 50)
    assert command["state"] == "denied"
    assert not lab.transport.sent
    assert not lab.edge.reports


def test_break_glass_never_sends(lab):
    lab.edge.authorize = lambda *args: SimpleNamespace(
        allowed=True,
        authorization_id="a",
        authority="break_glass",
        report_by=lab.now[0] + 30,
        code=None,
    )
    command = lab.bridge.start_command(7, 50)
    assert command["state"] == "rejected"
    assert not lab.transport.sent
    assert lab.edge.reports[0]["outcome"] == "failure"


def test_authorization_timeout_never_sends(lab):
    def broken(*args):
        raise EdgeError("timeout")

    lab.edge.authorize = broken
    command = lab.bridge.start_command(7, 50)
    assert command["state"] == "uncertain"
    assert command["report_status"] == "unavailable"
    assert not lab.transport.sent


def test_authorization_deadline_must_leave_time_to_report(lab):
    lab.edge.authorize = lambda *args: SimpleNamespace(
        allowed=True,
        authorization_id="a",
        authority="decision",
        report_by=lab.now[0] + 2,
        code=None,
    )
    command = lab.bridge.start_command(7, 50)
    assert command["state"] == "expired"
    assert not lab.transport.sent


def test_one_outstanding_operation(lab):
    lab.bridge.start_command(7, 60)
    with pytest.raises(BridgeError, match="another_command"):
        lab.bridge.start_command(7, 70)


@pytest.mark.parametrize("interval", [True, 0, 4, 3601, "60", 60.0])
def test_device_parameter_limits_before_authorization(lab, interval):
    with pytest.raises(BridgeError):
        lab.bridge.start_command(7, interval)
    assert not lab.journal.commands()


@pytest.mark.parametrize("ttl", [True, 0, 2, 301, "60", 60.0])
def test_ttl_limits(lab, ttl):
    with pytest.raises(BridgeError):
        lab.bridge.start_command(7, 60, ttl)


def test_small_payload_budget_refuses_before_authorization(lab):
    lab.transport.max_payload = 37
    with pytest.raises(BridgeError, match="payload_budget"):
        lab.bridge.start_command(7, 60)
    assert not lab.journal.commands()


def test_route_binding_prevents_cross_device_submission(lab):
    raw = lab.peer.telemetry()
    with pytest.raises(BridgeError, match="route_mismatch"):
        lab.bridge.ingest("radio", Inbound("different-device", raw))
    assert not lab.journal.events()


def test_tamper_cannot_advance_replay_counter(lab):
    raw = lab.peer.telemetry()
    tampered = raw[:-1] + bytes([raw[-1] ^ 1])
    with pytest.raises(ProtocolError):
        lab.bridge.ingest("radio", Inbound(lab.device.route, tampered))
    accepted = lab.bridge.ingest("radio", Inbound(lab.device.route, raw))
    assert not accepted["duplicate"]


def test_replay_and_counter_conflict_survive_restart(lab):
    raw = lab.peer.telemetry()
    lab.bridge.ingest("radio", Inbound(lab.device.route, raw))
    lab.journal.close()
    lab.journal = Journal(lab.config.state_path, lab.identity)
    lab.bridge = Bridge(
        lab.config,
        lab.journal,
        lab.edge,
        {"radio": lab.transport},
        clock=lab.clock,
        keys={7: lab.key},
    )
    assert lab.bridge.ingest("radio", Inbound(lab.device.route, raw))["duplicate"]
    conflict = encode(
        Frame(Kind.TELEMETRY, 7, 1, lab.now[0] + 60, encode_telemetry(1, 999)),
        lab.key,
        lab.config.audience,
    )
    with pytest.raises(JournalError, match="replayed"):
        lab.bridge.ingest("radio", Inbound(lab.device.route, conflict))
    assert len(lab.journal.events()) == 1


def test_restart_preserves_uncertain_operation_without_resend(lab):
    command = lab.bridge.start_command(7, 60)
    lab.journal.close()
    lab.journal = Journal(lab.config.state_path, lab.identity)
    lab.bridge = Bridge(
        lab.config,
        lab.journal,
        lab.edge,
        {"radio": lab.transport},
        clock=lab.clock,
        keys={7: lab.key},
    )
    lab.bridge.tick()
    assert lab.journal.command(command["command_id"])["state"] == "uncertain"
    assert lab.edge.reports[0]["outcome"] == "partial"
    assert len(lab.transport.sent) == 1


def test_wrong_command_counter_or_value_is_rejected(lab):
    lab.bridge.start_command(7, 60)
    for counter, interval in [(2, 60), (1, 61)]:
        raw = encode(
            Frame(
                Kind.OUTCOME,
                7,
                1,
                lab.now[0] + 60,
                encode_outcome(counter, OutcomeStatus.SUCCESS, interval),
            ),
            lab.key,
            lab.config.audience,
        )
        with pytest.raises(BridgeError):
            lab.bridge.ingest("radio", Inbound(lab.device.route, raw))
    assert not lab.edge.reports
    assert not lab.journal.events()


def test_clock_rollback_stops_processing(lab):
    lab.now[0] -= 1
    with pytest.raises(JournalError, match="clock_rollback"):
        lab.bridge.start_command(7, 60)


def test_report_retry_only_retries_evidence(lab):
    real_report = lab.edge.report
    calls = []

    def failing_report(*args):
        calls.append(args)
        if len(calls) == 1:
            raise EdgeError("network_error")
        return real_report(*args)

    lab.edge.report = failing_report
    command = lab.bridge.start_command(7, 60)
    lab.bridge.run_once(0)
    assert lab.journal.command(command["command_id"])["report_status"] == "pending"
    lab.now[0] += 2
    lab.bridge.tick()
    assert len(calls) == 2
    assert lab.journal.command(command["command_id"])["report_status"] == "accepted"
    assert lab.peer.executions == 1


@pytest.mark.parametrize(
    "status,expected",
    [(409, "uncertain"), (410, "expired"), (403, "uncertain"), (404, "uncertain")],
)
def test_ambiguous_or_expired_report_never_claims_acceptance(lab, status, expected):
    def report(*args):
        raise EdgeError("refused", status_code=status)

    lab.edge.report = report
    command = lab.bridge.start_command(7, 60)
    lab.bridge.run_once(0)
    assert lab.journal.command(command["command_id"])["report_status"] == expected


def test_receive_rejects_injected_command(lab):
    lab.bridge.start_command(7, 60)
    raw = lab.transport.sent[0][1]
    with pytest.raises(BridgeError, match="uplink_kind"):
        lab.bridge.ingest("radio", Inbound(lab.device.route, raw))


def test_run_keeps_processing_after_hostile_frame(lab):
    lab.transport.incoming.put(Inbound(lab.device.route, b"invalid"))
    lab.transport.incoming.put(Inbound(lab.device.route, lab.peer.telemetry()))
    lab.bridge.run_once(0)
    lab.bridge.run_once(0)
    assert lab.bridge.rejected_frames == 1
    assert len(lab.journal.events()) == 1


def test_device_reboot_preserves_command_deduplication(lab, tmp_path):
    lab.bridge.start_command(7, 60)
    raw = lab.transport.sent[0][1]
    original = lab.peer.handle_command(raw)
    lab.peer.close()
    lab.peer = DeviceSimulator(
        7, lab.key, lab.config.audience, clock=lab.clock, state_path=tmp_path / "device.db"
    )
    assert lab.peer.handle_command(raw) == original
    assert lab.peer.executions == 1


def test_journal_rejects_rebound_identity(lab):
    lab.journal.close()
    bad = replace(lab.config, audience="another.site")
    with pytest.raises(JournalError, match="binding_mismatch"):
        Journal(lab.config.state_path, binding(bad, {7: lab.key}))
    lab.journal = Journal(lab.config.state_path, lab.identity)


def test_private_key_does_not_enter_records(lab):
    import json

    command = lab.bridge.start_command(7, 60)
    lab.bridge.run_once(0)
    content = json.dumps(
        [lab.journal.command(command["command_id"]), lab.journal.events(), lab.edge.reports]
    )
    assert lab.key.hex() not in content
