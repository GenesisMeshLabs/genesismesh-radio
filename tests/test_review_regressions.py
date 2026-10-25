"""Independent security/lifecycle regressions from implementation review."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from genesismesh_radio.adapters.base import Inbound
from genesismesh_radio.bridge import Bridge, BridgeError
from genesismesh_radio.config import Config, ConfigError, DeviceConfig, binding
from genesismesh_radio.journal import Journal, JournalError
from genesismesh_radio.protocol import (
    Frame,
    Kind,
    OutcomeStatus,
    ProtocolError,
    encode,
    encode_outcome,
)
from genesismesh_radio.simulator import DeviceSimulator, LoopbackTransport, SimulationEdge


@pytest.fixture
def review_lab(tmp_path):
    now = [1_800_000_000]

    def clock():
        return now[0]

    key = bytes(range(32))
    device = DeviceConfig(1, "sensor-1", "radio", "edge:review/sensor-1", "DEVICE_KEY")
    config = Config("review.site", (device,), tmp_path / "state.db")
    keys = {1: key}
    identity = binding(config, keys)
    Journal.initialize(config.state_path, identity)
    with Journal(config.state_path, identity) as journal:
        peer = DeviceSimulator(1, key, config.audience, clock=clock)
        transport = LoopbackTransport({device.route: peer})
        edge = SimulationEdge(clock)
        calls = []
        original_authorize = edge.authorize

        def authorize(*args):
            calls.append(args)
            return original_authorize(*args)

        edge.authorize = authorize
        bridge = Bridge(config, journal, edge, {"radio": transport}, clock=clock, keys=keys)
        try:
            yield SimpleNamespace(
                now=now,
                clock=clock,
                key=key,
                keys=keys,
                device=device,
                config=config,
                identity=identity,
                journal=journal,
                peer=peer,
                transport=transport,
                edge=edge,
                bridge=bridge,
                authorization_calls=calls,
            )
        finally:
            peer.close()


@pytest.mark.parametrize("change", ["audience", "key", "resource"])
def test_public_bridge_constructor_rejects_rebound_journal(review_lab, change):
    lab = review_lab
    config, keys = lab.config, lab.keys
    if change == "audience":
        config = replace(config, audience="another.site")
    elif change == "key":
        keys = {1: b"x" * 32}
    else:
        config = replace(config, devices=(replace(lab.device, resource_id="edge:other/device"),))
    with pytest.raises((BridgeError, JournalError, ConfigError)):
        Bridge(config, lab.journal, lab.edge, {"radio": lab.transport}, clock=lab.clock, keys=keys)
    assert not lab.authorization_calls
    assert not lab.journal.commands()


@pytest.mark.parametrize("device_id", [True, False, 1.0, "1", None, -1, 0, 2**32])
def test_device_identifier_is_validated_before_authorization(review_lab, device_id):
    lab = review_lab
    with pytest.raises((BridgeError, ConfigError, ProtocolError)):
        lab.bridge.start_command(device_id, 60)
    assert not lab.authorization_calls
    assert not lab.journal.commands()
    assert not lab.transport.sent


def test_authenticated_unsolicited_outcome_cannot_advance_replay_state(review_lab):
    lab = review_lab
    raw = encode(
        Frame(Kind.OUTCOME, 1, 1, lab.now[0] + 60, encode_outcome(999, OutcomeStatus.SUCCESS, 60)),
        lab.key,
        lab.config.audience,
    )
    with pytest.raises(BridgeError, match="no_matching_command"):
        lab.bridge.ingest("radio", Inbound(lab.device.route, raw))
    assert not lab.edge.reports
    assert not lab.journal.events()
    # The legitimate first frame must still be accepted.
    assert not lab.bridge.ingest(
        "radio",
        Inbound(lab.device.route, lab.peer.telemetry()),
    )["duplicate"]


def test_conflicting_final_outcome_cannot_rewrite_execution_evidence(review_lab):
    lab = review_lab
    command = lab.bridge.start_command(1, 60)
    lab.bridge.run_once(0)
    original_reports = list(lab.edge.reports)
    raw = encode(
        Frame(
            Kind.OUTCOME,
            1,
            2,
            lab.now[0] + 60,
            encode_outcome(command["counter"], OutcomeStatus.REJECTED, 30),
        ),
        lab.key,
        lab.config.audience,
    )
    event = lab.bridge.ingest("radio", Inbound(lab.device.route, raw))
    assert event["details"]["accepted_for_execution_evidence"] is False
    assert lab.journal.command(command["command_id"])["state"] == "confirmed"
    assert lab.edge.reports == original_reports


def test_pending_evidence_retry_never_redispatches_after_recovery(review_lab):
    from genesismesh_radio.edge import EdgeError

    lab = review_lab

    def unavailable(*_args):
        raise EdgeError("edge_transport_error")

    real_report = lab.edge.report
    lab.edge.report = unavailable
    command = lab.bridge.start_command(1, 60)
    lab.bridge.run_once(0)
    assert lab.journal.command(command["command_id"])["report_status"] == "pending"
    replacement = Bridge(
        lab.config, lab.journal, lab.edge, {"radio": lab.transport}, clock=lab.clock, keys=lab.keys
    )
    lab.edge.report = real_report
    lab.now[0] += 2
    replacement.tick()
    assert lab.journal.command(command["command_id"])["report_status"] == "accepted"
    assert len(lab.transport.sent) == lab.peer.executions == 1


def test_event_capacity_does_not_consume_authenticated_counter(review_lab):
    lab = review_lab
    lab.journal.max_events = 1
    first = lab.peer.telemetry(value=10)
    second = lab.peer.telemetry(value=11)
    lab.bridge.ingest("radio", Inbound(lab.device.route, first))
    with pytest.raises(JournalError, match="capacity"):
        lab.bridge.ingest("radio", Inbound(lab.device.route, second))
    assert lab.journal.event_count() == 1
    # After deliberate capacity adjustment, the rejected frame is still usable.
    lab.journal.max_events = 2
    accepted = lab.bridge.ingest("radio", Inbound(lab.device.route, second))
    assert accepted["counter"] == 2
    assert lab.journal.event_count() == 2


def test_command_capacity_stops_before_authority_or_dispatch(review_lab):
    lab = review_lab
    lab.journal.max_commands = 1
    lab.bridge.start_command(1, 60)
    lab.bridge.run_once(0)
    with pytest.raises(JournalError, match="capacity"):
        lab.bridge.start_command(1, 70)
    assert len(lab.authorization_calls) == 1
    assert len(lab.transport.sent) == lab.peer.executions == 1


def test_polling_and_dispatch_do_not_scan_finalized_history(review_lab, monkeypatch):
    lab = review_lab
    lab.bridge.start_command(1, 60)
    lab.bridge.run_once(0)

    def history_scan_forbidden(*_args, **_kwargs):
        raise AssertionError("polling must query pending commands, not all command history")

    monkeypatch.setattr(lab.journal, "commands", history_scan_forbidden)
    lab.bridge.tick()
    assert lab.bridge.start_command(1, 70)["state"] == "dispatched"


def test_simulator_binding_uses_unambiguous_field_encoding(tmp_path):
    key = bytes(range(32))
    path = tmp_path / "device.db"
    first = DeviceSimulator(1, key, "23", state_path=path)
    first.close()
    with pytest.raises(ProtocolError, match="identity_changed"):
        DeviceSimulator(12, key, "3", state_path=path)
