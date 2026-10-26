"""Documented WisGateOS2 envelopes and disposable local-broker tests; no RF."""

from __future__ import annotations

import base64
import json
import os
import queue
import ssl
import threading
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish
import pytest
from test_adapters_io import mqtt_broker as mqtt_broker

from genesismesh_radio import runtime
from genesismesh_radio.adapters.base import AdapterError, Inbound
from genesismesh_radio.adapters.wisgate import (
    WisGateMqttTransport,
    build_wisgate_downlink,
    parse_wisgate_uplink,
)
from genesismesh_radio.bridge import Bridge
from genesismesh_radio.config import Config, ConfigError, DeviceConfig, binding, load_config
from genesismesh_radio.journal import Journal
from genesismesh_radio.protocol import ProtocolError
from genesismesh_radio.provision import (
    CONTROL_TOKEN_ENV,
    ProvisionError,
    _references,
    provision_bundle,
)
from genesismesh_radio.simulator import DeviceSimulator, SimulationEdge

APPLICATION = "home-pilot"
APPLICATION_ID = "1"
ROUTE = "sensor-1"
EUI = "0011223344556677"
TOPIC = f"application/{APPLICATION}/device/{EUI}/rx"
FIXTURE = Path(__file__).parent / "fixtures" / "wisgate-uplink.json"


def event(payload=b"reading"):
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["data"] = base64.b64encode(payload).decode("ascii")
    return data


def parse(data=None, topic=TOPIC, **kwargs):
    if data is None:
        data = event()
    if isinstance(data, dict):
        data = json.dumps(data).encode()
    return parse_wisgate_uplink(
        topic,
        data,
        application=APPLICATION,
        application_id=APPLICATION_ID,
        device_euis={ROUTE: EUI},
        **kwargs,
    )


def test_documented_fixture_raw_payload_and_downlink_contract():
    # This fixture follows the vendor schema; it is not captured hardware data.
    assert parse(FIXTURE.read_bytes()) == Inbound(ROUTE, b"disposable-telemetry")
    topic, body = build_wisgate_downlink(APPLICATION, EUI.upper(), b"\x00\xff", "command-id")
    assert topic == f"application/{APPLICATION}/device/{EUI}/tx"
    assert json.loads(body) == {"confirmed": True, "data": "AP8=", "fPort": 10}
    assert "command-id" not in body.decode()  # No invented vendor correlation field.


@pytest.mark.parametrize("payload", [b"\x00", bytes(range(51)), b"\x00\xff\x80\x7f"])
def test_raw_bytes_are_preserved(payload):
    assert parse(event(payload)).payload == payload


@pytest.mark.parametrize(
    "field,value",
    [
        ("applicationID", "2"),
        ("applicationID", 1),
        ("applicationName", "other"),
        ("devEUI", "8899aabbccddeeff"),
        ("devEUI", 11223344556677),
        ("devEUI", "00:11:22:33:44:55:66:77"),
        ("fPort", 11),
        ("fPort", True),
        ("fPort", "10"),
        ("data_encode", "hex"),
        ("data_encode", None),
        ("data", "not base64!"),
        ("data", ""),
        ("data", "💥"),
        ("data", 17),
    ],
)
def test_identity_f_port_and_encoding_confusion_is_refused(field, value):
    data = event()
    data[field] = value
    with pytest.raises(AdapterError):
        parse(data)


@pytest.mark.parametrize(
    "topic",
    [
        "application/other/device/0011223344556677/rx",
        "application/home-pilot/device/8899aabbccddeeff/rx",
        "application/home-pilot/device/0011223344556677/ack",
        "application/home-pilot/device/0011223344556677/tx",
        "application/home-pilot/device/0011223344556677/join",
        "application/home-pilot/device/0011223344556677/status",
        "application/home-pilot/device/+/rx",
        "application/home-pilot/device/0011223344556677/rx/extra",
        "v3/home-pilot/devices/sensor-1/up",
        None,
    ],
)
def test_only_exact_raw_uplink_topics_are_accepted(topic):
    with pytest.raises(AdapterError):
        parse(topic=topic)


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"null",
        b"{",
        b"\xff",
        b"x" * 65537,
        b'{"applicationID":"1","applicationID":"2"}',
        b'{"other":NaN}',
        b'{"other":Infinity}',
        b'{"other":1e400}',
        b"[" * 1000 + b"0" + b"]" * 1000,
    ],
    ids=[
        "missing-fields",
        "array",
        "null",
        "malformed",
        "invalid-utf8",
        "oversized",
        "duplicate-keys",
        "nan",
        "infinity",
        "float-overflow",
        "excessive-depth",
    ],
)
def test_bounded_strict_json_and_duplicate_keys(raw):
    with pytest.raises(AdapterError):
        parse(raw)


def test_structure_limit_and_nonfinite_unknown_metadata_are_refused():
    data = event()
    nested = 0
    for _ in range(34):
        nested = {"a": nested}
    data["metadata"] = nested
    with pytest.raises(AdapterError, match="json"):
        parse(data)
    data["metadata"] = [0] * 4100
    with pytest.raises(AdapterError, match="json"):
        parse(data)
    data["metadata"] = {"other": float("nan")}
    with pytest.raises(AdapterError, match="json"):
        parse(data)


def test_retained_stale_data_payload_bounds_and_missing_raw_encoding_are_refused():
    with pytest.raises(AdapterError, match="retained"):
        parse(retained=True)
    with pytest.raises(AdapterError):
        parse(event(b"a" * 52))
    with pytest.raises(AdapterError):
        parse(event(b"123"), max_payload=2)
    data = event()
    del data["data_encode"]
    with pytest.raises(AdapterError, match="base64"):
        parse(data)


class FakePublish:
    rc = 0
    mid = 10
    done = True

    def wait_for_publish(self, timeout):
        self.timeout = timeout

    def is_published(self):
        return self.done


class FakeMqtt:
    def __init__(self, *, connack=0, suback=0, subscribe_result=0):
        self.connack = connack
        self.suback = suback
        self.subscribe_result = subscribe_result
        self.closed = False
        self.published = []
        self.subscriptions = []
        self.tls = None
        self.info = FakePublish()

    def username_pw_set(self, username, password):
        self.credentials = (username, password)

    def tls_set(self, **kwargs):
        self.tls = kwargs

    def reconnect_delay_set(self, **kwargs):
        pass

    def max_queued_messages_set(self, maximum):
        pass

    def connect(self, host, **kwargs):
        self.host = host
        return 0

    def loop_start(self):
        self.on_connect(self, None, {}, self.connack, None)
        if not self.connack and not self.subscribe_result:
            self.on_subscribe(self, None, 7, [self.suback], None)

    def subscribe(self, topics):
        self.subscriptions.append(topics)
        return self.subscribe_result, 7

    def publish(self, topic, body, **kwargs):
        self.published.append((topic, body, kwargs))
        return self.info

    def disconnect(self):
        self.closed = True

    def loop_stop(self):
        pass


def transport(client=None, **kwargs):
    settings = {
        "host": "127.0.0.1",
        "application": APPLICATION,
        "application_id": APPLICATION_ID,
        "device_euis": {ROUTE: EUI},
        "username": "test-bridge",
        "password": "disposable-loopback-password",
        "tls": False,
        "client": client or FakeMqtt(),
    }
    settings.update(kwargs)
    return WisGateMqttTransport(**settings)


def test_callbacks_subscribe_only_uplinks_and_keep_transport_receipts_local():
    client = FakeMqtt()
    link = transport(client, queue_size=1)
    try:
        assert client.subscriptions == [[(TOPIC, 0)]]
        assert link.send(ROUTE, b"command", "id") == "mqtt-local:10"
        assert client.published[0][0] == f"application/{APPLICATION}/device/{EUI}/tx"
        assert client.published[0][2] == {"qos": 0, "retain": False}
        message = SimpleNamespace(topic=TOPIC, payload=json.dumps(event()).encode(), retain=False)
        client.on_message(client, None, message)
        client.on_message(client, None, message)
        assert link.overflow_count == 1
        assert link.receive(0) == Inbound(ROUTE, b"reading")
        message.retain = True
        client.on_message(client, None, message)
        message.retain = False
        message.topic = TOPIC.removesuffix("rx") + "ack"
        message.payload = b'{"acknowledged":true}'
        client.on_message(client, None, message)
        assert link.rejected_count == 2
        assert link.receive(0) is None
        client.on_disconnect(client, None, {}, 0, None)
        with pytest.raises(AdapterError, match="disconnected"):
            link.send(ROUTE, b"command", "id")
        client.loop_start()
        assert client.subscriptions == [[(TOPIC, 0)], [(TOPIC, 0)]]
        with pytest.raises(AdapterError, match="destination"):
            link.send("other", b"command", "id")
        client.info.done = False
        with pytest.raises(AdapterError, match="ambiguous"):
            link.send(ROUTE, b"command", "id")
    finally:
        link.close()
    link.close()
    assert client.closed
    with pytest.raises(AdapterError, match="closed"):
        link.send(ROUTE, b"command", "id")


@pytest.mark.parametrize(
    "settings",
    [
        {"connack": 5},
        {"suback": 128},
        {"subscribe_result": 4},
    ],
)
def test_failed_broker_connection_or_subscription_closes_client(settings):
    client = FakeMqtt(**settings)
    with pytest.raises(AdapterError):
        transport(client)
    assert client.closed


def test_tls_is_enabled_with_ca_and_never_disabled_for_a_remote_host():
    client = FakeMqtt()
    link = transport(client, host="broker.home", tls=True, ca_file="test-ca.crt")
    assert client.tls == {"ca_certs": "test-ca.crt"}
    link.close()
    with pytest.raises(AdapterError, match="tls"):
        transport(host="192.168.1.20", tls=False)


def test_actual_paho_tls_context_requires_certificate_and_hostname_verification(monkeypatch):
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv311)

    def start():
        client.on_connect(client, None, {}, 0, None)
        client.on_subscribe(client, None, 7, [0], None)

    monkeypatch.setattr(client, "connect", lambda *args, **kwargs: 0)
    monkeypatch.setattr(client, "loop_start", start)
    monkeypatch.setattr(client, "subscribe", lambda *args, **kwargs: (0, 7))
    monkeypatch.setattr(client, "disconnect", lambda: 0)
    monkeypatch.setattr(client, "loop_stop", lambda: 0)
    link = transport(client, host="broker.home", tls=True)
    try:
        assert client._ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert client._ssl_context.check_hostname is True
        assert client._tls_insecure is False
    finally:
        link.close()


def config(tmp_path):
    return Config(
        "test.home",
        (DeviceConfig(1, ROUTE, "lorawan", "edge:test/sensor-1", "TEST_DEVICE_KEY"),),
        tmp_path / "state.db",
        {"base_url": "http://127.0.0.1:17900", "token_env": "TEST_EDGE_TOKEN"},
        {
            "lorawan": {
                "kind": "wisgate",
                "host": "broker.home",
                "application": APPLICATION,
                "application_id": APPLICATION_ID,
                "device_euis": {ROUTE: EUI},
                "username": "test-bridge",
                "password_env": "TEST_MQTT_PASSWORD",
            }
        },
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("application", "UpperCase"),
        ("application", "topic/+"),
        ("application_id", 1),
        ("application_id", ""),
        ("device_euis", {"other": EUI}),
        ("device_euis", {ROUTE: "not-eui"}),
        ("device_euis", {ROUTE: EUI, "duplicate": EUI.upper()}),
        ("host", "https://broker.home"),
        ("host", "user@broker.home"),
        ("host", "broker.home\n"),
        ("host", "broker.home\x7f"),
        ("host", "broker.home:8883"),
        ("host", "-invalid.home"),
        ("tls", False),
        ("tls", 1),
        ("port", 0),
        ("f_port", True),
        ("f_port", 224),
        ("password_env", "inline-secret"),
        ("queue_size", 0),
        ("connect_timeout", float("nan")),
        ("publish_timeout", float("inf")),
        ("password", "must-never-be-inline"),
    ],
)
def test_all_settings_validate_without_environment_reads_or_opening(
    tmp_path, monkeypatch, field, value
):
    supplied = config(tmp_path)
    supplied.transports["lorawan"][field] = value

    def forbidden(*args, **kwargs):
        pytest.fail("credential read or MQTT I/O happened before preflight")

    monkeypatch.setattr(runtime, "WisGateMqttTransport", forbidden)
    monkeypatch.setattr(runtime.os.environ, "get", forbidden)
    with pytest.raises(ConfigError):
        runtime.validate_runtime(supplied)


def test_runtime_wiring_secret_resolution_and_exitstack_cleanup(tmp_path, monkeypatch):
    supplied = config(tmp_path)
    made = []

    class Adapter:
        def __init__(self, **settings):
            self.settings = settings
            self.closed = False
            made.append(self)

        def close(self):
            self.closed = True

    monkeypatch.setattr(runtime, "WisGateMqttTransport", Adapter)
    monkeypatch.setenv("TEST_MQTT_PASSWORD", "disposable-private-test-password")
    with ExitStack() as stack:
        created = runtime.create_transports(supplied, stack)
        assert created == {"lorawan": made[0]}
        assert made[0].settings["password"] == "disposable-private-test-password"
        assert made[0].settings["application_id"] == APPLICATION_ID
        assert made[0].settings["device_euis"] == {ROUTE: EUI}
        assert made[0].settings["max_payload"] == 51
        assert "password_env" not in made[0].settings
        assert "kind" not in made[0].settings
    assert made[0].closed


def test_missing_wisgate_credentials_refuse_before_any_transport_opens(tmp_path, monkeypatch):
    supplied = config(tmp_path)
    extra = replace(supplied.devices[0], device_id=2, transport="serial", key_env="SECOND_KEY")
    extra = replace(extra, route="sensor-2", resource_id="edge:test/sensor-2")
    supplied = replace(
        supplied,
        devices=(*supplied.devices, extra),
        transports={
            "serial": {"kind": "lora_serial", "port": "/dev/no-open"},
            **supplied.transports,
        },
    )

    def forbidden(**kwargs):
        pytest.fail("transport opened before all credentials resolved")

    monkeypatch.setattr(runtime, "SerialLoRaTransport", forbidden)
    monkeypatch.delenv("TEST_MQTT_PASSWORD", raising=False)
    with ExitStack() as stack, pytest.raises(ConfigError, match="missing_mqtt_password"):
        runtime.create_transports(supplied, stack)


def test_committed_example_passes_pure_preflight():
    runtime.validate_runtime(
        load_config(Path(__file__).parents[1] / "examples/lorawan-wisgate.toml")
    )


def test_gateway_ack_and_bad_mac_cannot_confirm_real_bridge_command(tmp_path):
    supplied = config(tmp_path)
    key = bytes(range(32))  # Public disposable application fixture.

    def clock():
        return 1_800_000_000

    identity = binding(supplied, {1: key})
    Journal.initialize(supplied.state_path, identity)
    client = FakeMqtt()
    link = transport(client)
    peer = DeviceSimulator(1, key, supplied.audience, clock=clock)
    edge = SimulationEdge(clock)
    with Journal(supplied.state_path, identity) as journal:
        bridge = Bridge(supplied, journal, edge, {"lorawan": link}, clock=clock, keys={1: key})
        try:
            command = bridge.start_command(1, 60)
            assert command["state"] == "dispatched"
            assert edge.reports == []
            ack = SimpleNamespace(
                topic=TOPIC.removesuffix("rx") + "ack",
                payload=b'{"acknowledged":true}',
                retain=False,
            )
            client.on_message(client, None, ack)
            bridge.run_once(0)
            assert journal.command(command["command_id"])["state"] == "dispatched"
            assert edge.reports == []
            downlink = json.loads(client.published[0][1])
            outcome = peer.handle_command(base64.b64decode(downlink["data"]))
            tampered = outcome[:-1] + bytes([outcome[-1] ^ 1])
            with pytest.raises(ProtocolError, match="authentication"):
                bridge.ingest("lorawan", parse(event(tampered)))
            assert edge.reports == []
            result = bridge.ingest("lorawan", parse(event(outcome)))
            assert result["details"]["authentication"] == "shared_key_mac"
            assert result["details"]["device_signature"] is False
            assert journal.command(command["command_id"])["state"] == "confirmed"
            assert edge.reports[0]["outcome"] == "success"
        finally:
            link.close()
            peer.close()


@pytest.mark.parametrize("reference", ["TEST_DEVICE_KEY", CONTROL_TOKEN_ENV])
def test_wisgate_external_credential_cannot_collide_with_generated_material(tmp_path, reference):
    supplied = config(tmp_path)
    supplied.transports["lorawan"]["password_env"] = reference
    with pytest.raises(ProvisionError, match="credential_reference_collision"):
        _references(supplied)


def test_wisgate_default_broker_credential_is_reserved(tmp_path):
    supplied = config(tmp_path)
    del supplied.transports["lorawan"]["password_env"]
    assert _references(supplied) == {"TEST_EDGE_TOKEN", "GM_WISGATE_MQTT_PASSWORD"}


@pytest.mark.skipif(os.name != "posix", reason="private bundles require POSIX filesystem")
def test_wisgate_provision_bundle_records_real_lorawan_metadata_without_broker_secret(
    tmp_path, monkeypatch
):
    example = Path(__file__).parents[1] / "examples/lorawan-wisgate.toml"
    template = tmp_path / "source.toml"
    template.write_text(
        example.read_text().replace("../.local/lorawan-wisgate.db", "unused-state.db"),
        encoding="utf-8",
    )
    monkeypatch.setenv("GM_WISGATE_MQTT_PASSWORD", "ambient-broker-secret-must-not-be-copied")
    destination = tmp_path / "bundle"
    result = provision_bundle(template, destination)
    assert result["external_credential_refs"] == ["GM_EDGE_TOKEN", "GM_WISGATE_MQTT_PASSWORD"]
    profile = json.loads((destination / "devices/1.json").read_text())
    assert profile["transport_metadata"] == {
        "kind": "wisgate",
        "application": APPLICATION,
        "application_id": APPLICATION_ID,
        "dev_eui": EUI,
        "f_port": 10,
    }
    assert "baudrate" not in profile["transport_metadata"]
    for file in destination.rglob("*"):
        if file.is_file():
            assert "ambient-broker-secret-must-not-be-copied" not in file.read_text()


@pytest.mark.integration
def test_real_local_broker_uplink_and_downlink_round_trip(mqtt_broker):
    received = queue.Queue()
    subscribed = threading.Event()
    observer = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv311)

    def on_connect(client, userdata, flags, reason_code, properties):
        assert reason_code == 0
        client.subscribe(f"application/{APPLICATION}/device/{EUI}/tx", qos=0)

    def on_subscribe(client, userdata, mid, reason_codes, properties):
        subscribed.set()

    def on_message(client, userdata, message):
        received.put((message.topic, message.payload, message.retain))

    observer.on_connect = on_connect
    observer.on_subscribe = on_subscribe
    observer.on_message = on_message
    observer.connect("127.0.0.1", port=mqtt_broker)
    observer.loop_start()
    link = None
    try:
        assert subscribed.wait(5)
        link = WisGateMqttTransport(
            "127.0.0.1",
            port=mqtt_broker,
            application=APPLICATION,
            application_id=APPLICATION_ID,
            device_euis={ROUTE: EUI},
            username="disposable-bridge",
            password="disposable-loopback-test",
            tls=False,
        )
        publish.single(
            TOPIC, json.dumps(event(b"telemetry")).encode(), hostname="127.0.0.1", port=mqtt_broker
        )
        assert link.receive(5) == Inbound(ROUTE, b"telemetry")
        receipt = link.send(ROUTE, b"command", "local-command")
        assert receipt.startswith("mqtt-local:")
        topic, body, retained = received.get(timeout=5)
        assert topic == f"application/{APPLICATION}/device/{EUI}/tx"
        assert json.loads(body) == {"confirmed": True, "fPort": 10, "data": "Y29tbWFuZA=="}
        assert not retained
    finally:
        if link is not None:
            link.close()
        observer.disconnect()
        observer.loop_stop()


@pytest.mark.integration
def test_real_broker_retained_uplink_never_becomes_fresh_reading(mqtt_broker):
    publish.single(
        TOPIC,
        json.dumps(event(b"old-reading")).encode(),
        retain=True,
        hostname="127.0.0.1",
        port=mqtt_broker,
    )
    link = WisGateMqttTransport(
        "127.0.0.1",
        port=mqtt_broker,
        application=APPLICATION,
        application_id=APPLICATION_ID,
        device_euis={ROUTE: EUI},
        username="disposable-bridge",
        password="disposable-loopback-test",
        tls=False,
    )
    try:
        assert link.receive(0.2) is None
        assert link.rejected_count == 1
    finally:
        link.close()
