"""Operator entry points validate before I/O and preserve command uncertainty."""

from __future__ import annotations

import json
import uuid
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

import pytest

from genesismesh_radio import cli, runtime
from genesismesh_radio.adapters.base import Inbound
from genesismesh_radio.config import Config, ConfigError, DeviceConfig, load_config
from genesismesh_radio.edge import EdgeError
from genesismesh_radio.simulator import DeviceSimulator, LoopbackTransport, SimulationEdge

KEY = "12" * 32


def configured(tmp_path, kind="lora_serial"):
    route = "!12345678" if kind == "meshtastic" else "sensor-01"
    settings = {
        "lora_serial": {"kind": "lora_serial", "port": "/dev/ttyUSB0", "baudrate": 115200},
        "meshtastic": {"kind": "meshtastic", "port": "/dev/ttyUSB0", "channel": 1},
        "tts": {
            "kind": "tts",
            "host": "example.com",
            "application": "field-site@ttn",
            "username": "field-site@ttn",
            "device_euis": {"sensor-01": "0102030405060708"},
            "password_env": "TEST_MQTT_PASSWORD",
        },
    }[kind]
    return Config(
        "test.site",
        (DeviceConfig(1, route, "radio", "edge:test/sensor-01", "TEST_DEVICE_KEY"),),
        tmp_path / "state.db",
        {"base_url": "http://127.0.0.1:17900", "token_env": "TEST_EDGE_TOKEN"},
        {"radio": settings},
    )


@pytest.fixture
def configured_file(tmp_path, monkeypatch):
    path = tmp_path / "bridge.toml"
    path.write_text(
        """[bridge]
audience = "test.site"
state_path = "bridge.db"
[edge]
base_url = "http://127.0.0.1:17900"
token_env = "TEST_EDGE_TOKEN"
[transports.radio]
kind = "lora_serial"
port = "/dev/no-hardware-opened"
[[devices]]
device_id = 1
route = "sensor-01"
transport = "radio"
resource_id = "edge:test/sensor-01"
key_env = "TEST_DEVICE_KEY"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("TEST_DEVICE_KEY", KEY)
    monkeypatch.setenv("TEST_EDGE_TOKEN", "disposable-private-edge-token")
    return path


class CaptureAdapter:
    def __init__(self, **settings):
        self.settings = settings
        self.device_euis = settings.get("device_euis", {})
        self.closed = 0

    def close(self):
        self.closed += 1


@pytest.mark.parametrize(
    "kind,factory",
    [
        ("lora_serial", "SerialLoRaTransport"),
        ("meshtastic", "MeshtasticTransport"),
        ("tts", "TtsMqttTransport"),
    ],
)
def test_constructor_wiring_and_exitstack_cleanup(tmp_path, monkeypatch, kind, factory):
    config = configured(tmp_path, kind)
    made = []

    def create(**kwargs):
        adapter = CaptureAdapter(**kwargs)
        made.append(adapter)
        return adapter

    monkeypatch.setattr(runtime, factory, create)
    monkeypatch.setenv("TEST_MQTT_PASSWORD", "disposable-private-mqtt-password")
    with ExitStack() as stack:
        transports = runtime.create_transports(config, stack)
        assert transports == {"radio": made[0]}
        settings = made[0].settings
        assert settings["max_payload"] == 51
        assert "kind" not in settings
        if kind == "meshtastic":
            assert settings["nodes"] == ["!12345678"]
        elif kind == "lora_serial":
            assert settings["routes"] == ["sensor-01"]
        else:
            assert settings["device_euis"] == {"sensor-01": "0102030405060708"}
            assert settings["password"] == "disposable-private-mqtt-password"
            assert "password_env" not in settings
        assert made[0].closed == 0
    assert made[0].closed == 1


def test_create_edge_resolves_only_configured_token(tmp_path, monkeypatch):
    config = configured(tmp_path)
    captured = {}

    def edge(**kwargs):
        captured.update(kwargs)
        return "edge"

    monkeypatch.setenv("TEST_EDGE_TOKEN", "disposable-edge-token")
    monkeypatch.setenv("GM_EDGE_TOKEN", "must-not-be-used")
    monkeypatch.setattr(runtime, "EdgeClient", edge)
    assert runtime.create_edge(config) == "edge"
    assert captured == {
        "base_url": "http://127.0.0.1:17900",
        "token": "disposable-edge-token",
        "unix_socket": None,
        "timeout": 10,
    }


@pytest.mark.parametrize(
    "settings",
    [
        {"kind": "unknown", "port": "fake"},
        {"kind": "lora_serial", "port": "fake", "password": "must-not-be-accepted"},
        {"kind": "lora_serial", "port": "fake", "baudrate": True},
        {"kind": "lora_serial", "port": "fake", "baudrate": 0},
        {"kind": "lora_serial", "port": ""},
        {"kind": "lora_serial", "port": "fake\n"},
        {"kind": "meshtastic", "port": "fake", "channel": 8},
    ],
)
def test_runtime_rejects_invalid_settings_without_opening(tmp_path, monkeypatch, settings):
    config = replace(configured(tmp_path), transports={"radio": settings})

    def forbidden(**kwargs):
        pytest.fail("transport opened before configuration rejection")

    monkeypatch.setattr(runtime, "SerialLoRaTransport", forbidden)
    monkeypatch.setattr(runtime, "MeshtasticTransport", forbidden)
    with ExitStack() as stack, pytest.raises(ConfigError):
        runtime.create_transports(config, stack)


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "https://example.com"),
        ("host", "user@example.com"),
        ("tls", False),
        ("tls", 1),
        ("port", 0),
        ("f_port", 234),
        ("username", "different@ttn"),
        ("device_euis", {"other-device": "0102030405060708"}),
        ("device_euis", {"sensor-01": "not-an-eui"}),
        ("password_env", "inline secret"),
        ("connect_timeout", float("nan")),
        ("publish_timeout", float("inf")),
        ("queue_size", 0),
    ],
)
def test_tts_preflight_is_pure_and_strict(tmp_path, monkeypatch, field, value):
    config = configured(tmp_path, "tts")
    config.transports["radio"][field] = value

    def forbidden(**kwargs):
        pytest.fail("MQTT connected before configuration rejection")

    monkeypatch.setattr(runtime, "TtsMqttTransport", forbidden)
    with ExitStack() as stack, pytest.raises(ConfigError):
        runtime.create_transports(config, stack)


def two_transports(tmp_path):
    serial_config = configured(tmp_path)
    tts = configured(tmp_path, "tts")
    second = replace(
        tts.devices[0],
        device_id=2,
        transport="wan",
        resource_id="edge:test/s2",
        key_env="SECOND_DEVICE_KEY",
    )
    return replace(
        serial_config,
        devices=(*serial_config.devices, second),
        transports={**serial_config.transports, "wan": tts.transports["radio"]},
    )


@pytest.mark.parametrize("failure", ["binding", "credential"])
def test_all_transports_preflight_before_first_open(tmp_path, monkeypatch, failure):
    config = two_transports(tmp_path)
    monkeypatch.delenv("TEST_MQTT_PASSWORD", raising=False)
    if failure == "binding":
        config.transports["wan"]["device_euis"] = {"other-device": "0102030405060708"}

    def forbidden(**kwargs):
        pytest.fail("first transport opened before later configuration rejection")

    monkeypatch.setattr(runtime, "SerialLoRaTransport", forbidden)
    monkeypatch.setattr(runtime, "TtsMqttTransport", forbidden)
    with ExitStack() as stack, pytest.raises(ConfigError):
        runtime.create_transports(config, stack)


@pytest.mark.parametrize(
    "settings",
    [
        {"base_url": "https://remote.example"},
        {"base_url": "http://token:secret@127.0.0.1"},
        {"base_url": "http://127.0.0.1/path"},
        {"base_url": "http://127.0.0.1/?token=secret"},
        {"base_url": "http://127.0.0.1:invalid"},
        {"token_env": "inline secret"},
        {"timeout": False},
        {"timeout": -1},
        {"timeout": float("nan")},
        {"unix_socket": "relative/path"},
        {"operator_key": "not-supported"},
    ],
)
def test_edge_config_rejects_before_client_construction(tmp_path, monkeypatch, settings):
    config = replace(configured(tmp_path), edge=settings)

    def forbidden(**kwargs):
        pytest.fail("edge client constructed before configuration rejection")

    monkeypatch.setattr(runtime, "EdgeClient", forbidden)
    with pytest.raises(ConfigError):
        runtime.create_edge(config)


def forbid_services(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("CLI opened services for a read-only or invalid request")

    monkeypatch.setattr(cli, "create_edge", forbidden)
    monkeypatch.setattr(cli, "create_transports", forbidden)


def test_config_init_status_do_not_open_services(configured_file, capsys, monkeypatch):
    forbid_services(monkeypatch)
    assert cli.main(["check-config", "--config", str(configured_file)]) == 0
    checked = json.loads(capsys.readouterr().out)
    assert checked["valid"] is True
    assert checked["state_exists"] is False
    assert cli.main(["init-state", "--config", str(configured_file)]) == 0
    initialized = json.loads(capsys.readouterr().out)
    assert Path(initialized["state_path"]).is_file()
    assert cli.main(["status", "--config", str(configured_file)]) == 0
    raw = capsys.readouterr().out
    assert json.loads(raw) == {"commands": [], "event_count": 0}
    assert KEY not in raw
    assert "disposable-private-edge-token" not in raw


@pytest.mark.parametrize("seconds", ["-1", "nan", "inf"])
def test_run_duration_rejected_before_io(configured_file, monkeypatch, capsys, seconds):
    forbid_services(monkeypatch)
    assert cli.main(["run", "--config", str(configured_file), "--seconds", seconds]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "ValueError"


@pytest.mark.parametrize(
    "extra",
    [
        ["--interval", "0"],
        ["--interval", "4000"],
        ["--ttl", "0"],
        ["--ttl", "301"],
        ["--device-id", "2"],
        ["--request-id", "not-a-uuid"],
    ],
)
def test_bad_command_rejected_before_io(configured_file, monkeypatch, capsys, extra):
    forbid_services(monkeypatch)
    command = ["command", "--config", str(configured_file), "--device-id", "1", "--interval", "60"]
    assert cli.main(command + extra) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "operation_failed"


def test_command_requires_room_for_outcome_before_io(configured_file, monkeypatch, capsys):
    config = load_config(configured_file)
    config = replace(config, devices=(replace(config.devices[0], max_payload=40),))
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    forbid_services(monkeypatch)
    assert (
        cli.main(
            ["command", "--config", str(configured_file), "--device-id", "1", "--interval", "60"]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "ValueError"


def test_cli_command_runs_and_reused_id_never_redispatches(configured_file, monkeypatch, capsys):
    config = load_config(configured_file)
    peer = DeviceSimulator(1, bytes.fromhex(KEY), config.audience)
    edges, transports, closed = [], [], []

    def create_edge(_):
        edge = SimulationEdge()
        edge.close = lambda: closed.append("edge")
        edges.append(edge)
        return edge

    def create_transports(_, stack):
        transport = LoopbackTransport({"sensor-01": peer})
        transport.close = lambda: closed.append("radio")
        transports.append(transport)
        stack.callback(transport.close)
        return {"radio": transport}

    monkeypatch.setattr(cli, "create_edge", create_edge)
    monkeypatch.setattr(cli, "create_transports", create_transports)
    request_id = str(uuid.uuid4())
    try:
        assert cli.main(["init-state", "--config", str(configured_file)]) == 0
        capsys.readouterr()
        args = [
            "command",
            "--config",
            str(configured_file),
            "--device-id",
            "1",
            "--interval",
            "60",
            "--request-id",
            request_id,
        ]
        assert cli.main(args) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["state"] == "confirmed"
        assert result["report_status"] == "accepted"
        assert peer.interval == 60
        assert edges[0].reports[0]["outcome"] == "success"
        assert cli.main(args) == 0
        repeated = json.loads(capsys.readouterr().out)
        assert repeated["command_id"] == request_id
        assert peer.executions == 1
        assert len(transports[0].sent) == 1
        assert not transports[1].sent
        assert closed == ["radio", "edge", "radio", "edge"]
        assert cli.main(["status", "--config", str(configured_file)]) == 0
        raw = capsys.readouterr().out
        assert json.loads(raw)["event_count"] == 1
        assert KEY not in raw
        assert "disposable-private-edge-token" not in raw
    finally:
        peer.close()


def test_cli_run_ingests_and_closes_services(configured_file, monkeypatch, capsys):
    config = load_config(configured_file)
    peer = DeviceSimulator(1, bytes.fromhex(KEY), config.audience)
    transport = LoopbackTransport({"sensor-01": peer})
    transport.incoming.put(Inbound("sensor-01", peer.telemetry()))
    closed = []
    edge = SimulationEdge()
    edge.close = lambda: closed.append("edge")

    def create_transports(_, stack):
        stack.callback(lambda: closed.append("radio"))
        return {"radio": transport}

    monkeypatch.setattr(cli, "create_edge", lambda _: edge)
    monkeypatch.setattr(cli, "create_transports", create_transports)
    try:
        assert cli.main(["init-state", "--config", str(configured_file)]) == 0
        capsys.readouterr()
        assert cli.main(["run", "--config", str(configured_file), "--seconds", "0.01"]) == 0
        status = json.loads(capsys.readouterr().out)
        assert status["event_count"] == 1
        assert status["commands"] == []
        assert closed == ["radio", "edge"]
    finally:
        peer.close()


@pytest.mark.parametrize(
    "secret_code", ["token=very-private", "a" * 1000, {"token": "very-private"}]
)
def test_arbitrary_dependency_error_codes_are_not_printed(monkeypatch, capsys, secret_code):
    class DependencyError(RuntimeError):
        code = secret_code

    def fail(_):
        raise DependencyError("very-private")

    monkeypatch.setattr(cli, "load_config", fail)
    assert cli.main(["check-config", "--config", "unused.toml"]) == 2
    raw = capsys.readouterr().out
    assert "very-private" not in raw
    assert json.loads(raw)["code"] == "operation_failed"


def test_known_edge_error_code_is_reported_without_context(monkeypatch, capsys):
    def fail(_):
        raise EdgeError("edge_transport_error") from RuntimeError("very-private")

    monkeypatch.setattr(cli, "load_config", fail)
    assert cli.main(["check-config", "--config", "unused.toml"]) == 2
    raw = capsys.readouterr().out
    assert "very-private" not in raw
    assert json.loads(raw)["code"] == "edge_transport_error"


@pytest.mark.parametrize("filename", ["lora-serial.toml", "lorawan-tts.toml", "meshtastic.toml"])
def test_shipped_examples_pass_offline_preflight(filename, monkeypatch, capsys):
    path = Path(__file__).resolve().parents[1] / "examples" / filename
    monkeypatch.setenv("GM_RADIO_DEVICE_1_KEY", KEY)
    monkeypatch.delenv("GM_RADIO_TTS_API_KEY", raising=False)
    monkeypatch.delenv("GM_RADIO_EDGE_TOKEN", raising=False)
    forbid_services(monkeypatch)
    config = load_config(path)
    runtime.validate_runtime(config)
    assert cli.main(["check-config", "--config", str(path)]) == 0
    raw = capsys.readouterr().out
    assert json.loads(raw)["valid"] is True
    assert KEY not in raw
