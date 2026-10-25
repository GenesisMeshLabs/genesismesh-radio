"""Official transport envelopes and fail-closed framing/binding behavior."""

from __future__ import annotations

import base64
import copy
import json
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from genesismesh_radio.adapters.base import AdapterError, Inbound, QueuedTransport
from genesismesh_radio.adapters.meshtastic import MeshtasticTransport, parse_meshtastic_packet
from genesismesh_radio.adapters.serial_lora import (
    SerialLoRaTransport,
    encode_serial_line,
    parse_serial_line,
)
from genesismesh_radio.adapters.tts import (
    TtsMqttTransport,
    build_tts_downlink,
    parse_tts_uplink,
)

APPLICATION = "field-site@ttn"
DEVICE = "sensor-01"
EUI = "0102030405060708"
TOPIC = f"v3/{APPLICATION}/devices/{DEVICE}/up"
NODE = "!12345678"


def tts_event(payload: bytes = b"reading") -> dict:
    return {
        "end_device_ids": {
            "device_id": DEVICE,
            "application_ids": {"application_id": "field-site"},
            "dev_eui": EUI,
        },
        "uplink_message": {
            "f_port": 10,
            "frm_payload": base64.b64encode(payload).decode("ascii"),
        },
    }


def parse_event(data: dict | bytes, topic: str = TOPIC, **kwargs) -> Inbound:
    if isinstance(data, dict):
        data = json.dumps(data).encode()
    return parse_tts_uplink(
        topic, data, application=APPLICATION, device_euis={DEVICE: EUI}, **kwargs
    )


def mesh_packet(payload: bytes = b"reading") -> dict:
    return {
        "from": 0x12345678,
        "fromId": NODE,
        "decoded": {"portnum": "PRIVATE_APP", "payload": payload},
    }


@given(st.binary(min_size=1, max_size=51))
def test_serial_payload_round_trip(payload):
    line = encode_serial_line("sensor:01", payload)
    assert parse_serial_line(line, routes={"sensor:01"}) == Inbound("sensor:01", payload)


@pytest.mark.parametrize(
    "line",
    [
        b"GM1 node aa",
        b"GM2 node aa\n",
        b"GM1 node aa\r\n",
        b"GM1 node a\n",
        b"GM1 node gg\n",
        b"GM1 node \n",
        b"GM1 node aa\nGM1 node bb\n",
        b"GM1 node  aa\n",
        b"GM1 node aa extra\n",
        b"GM1 ../../node aa\n",
        b"GM1 \xff aa\n",
        b"GM1 unknown aa\n",
        b"GM1 node " + b"aa" * 52 + b"\n",
    ],
)
def test_serial_rejects_malformed_or_unbound(line):
    with pytest.raises(AdapterError):
        parse_serial_line(line, routes={"node"})


def test_payload_budget_is_explicit():
    with pytest.raises(AdapterError, match="size"):
        encode_serial_line("node", b"a" * 12, max_payload=11)
    assert parse_serial_line(b"GM1 node 6161\n", routes={"node"}, max_payload=11).payload == b"aa"


def test_tts_round_trip_shape():
    assert parse_event(tts_event()) == Inbound(DEVICE, b"reading")
    topic, body = build_tts_downlink(APPLICATION, DEVICE, b"command", "command-1")
    assert topic == f"v3/{APPLICATION}/devices/{DEVICE}/down/push"
    downlink = json.loads(body)["downlinks"][0]
    assert downlink == {
        "f_port": 10,
        "frm_payload": base64.b64encode(b"command").decode(),
        "priority": "NORMAL",
        "confirmed": True,
        "correlation_ids": ["gm-radio:command-1"],
    }


@pytest.mark.parametrize(
    "topic",
    [
        TOPIC.replace(APPLICATION, "other@ttn"),
        TOPIC.replace("@ttn", "@other-tenant"),
        TOPIC.replace(DEVICE, "sensor-02"),
        TOPIC.replace("/up", "/down/ack"),
        TOPIC.replace("/up", "/join"),
        TOPIC + "/extra",
        TOPIC.replace("v3/", "v2/"),
    ],
)
def test_tts_topic_binding(topic):
    with pytest.raises(AdapterError):
        parse_event(tts_event(), topic)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("end_device_ids", "device_id"), "different"),
        (("end_device_ids", "dev_eui"), "1111111111111111"),
        (("end_device_ids", "dev_eui"), 0x0102030405060708),
        (("end_device_ids", "application_ids", "application_id"), "different"),
        (("uplink_message", "f_port"), 11),
        (("uplink_message", "f_port"), True),
        (("uplink_message", "frm_payload"), "!!!"),
        (("uplink_message", "frm_payload"), "YQ==\n"),
        (("uplink_message", "frm_payload"), ""),
        (("uplink_message", "frm_payload"), "a" * 1000),
        (("uplink_message",), []),
        (("end_device_ids",), []),
    ],
)
def test_tts_payload_binding(path, value):
    data = copy.deepcopy(tts_event())
    parent = data
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(AdapterError):
        parse_event(data)


@pytest.mark.parametrize(
    "event",
    [b"[]", b"null", b"\xff", b"{", b"{}" * 40000],
    ids=["array", "null", "invalid-utf8", "truncated", "oversize"],
)
def test_tts_rejects_bad_json(event):
    with pytest.raises(AdapterError):
        parse_event(event)


def test_tts_rejects_duplicate_json_key():
    event = json.dumps(tts_event()).replace('"f_port": 10', '"f_port": 11, "f_port": 10')
    with pytest.raises(AdapterError):
        parse_event(event.encode())


def test_tts_rejects_retained_and_oversize():
    with pytest.raises(AdapterError, match="retained"):
        parse_event(tts_event(), retained=True)
    with pytest.raises(AdapterError):
        parse_event(tts_event(b"a" * 52))
    assert parse_event(tts_event(b"a" * 51)).payload == b"a" * 51


@pytest.mark.parametrize("port", [0, 234, 255, True, "10"])
def test_tts_downlink_port_range(port):
    with pytest.raises(AdapterError, match="f_port"):
        build_tts_downlink(APPLICATION, DEVICE, b"x", "id", f_port=port)


def test_mesh_private_port_decoded_bytes_and_default_channel():
    assert parse_meshtastic_packet(mesh_packet(), nodes={NODE}) == Inbound(NODE, b"reading")
    packet = mesh_packet()
    packet["decoded"]["portnum"] = 300
    assert parse_meshtastic_packet(packet, nodes={NODE}, app_port=300).payload == b"reading"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("from", True),
        ("from", 0),
        ("from", 0xFFFFFFFF),
        ("from", 0x87654321),
        ("fromId", "!87654321"),
        ("channel", 1),
        ("decoded", None),
    ],
)
def test_mesh_rejects_invalid_source_or_channel(key, value):
    packet = mesh_packet()
    packet[key] = value
    with pytest.raises(AdapterError):
        parse_meshtastic_packet(packet, nodes={NODE})


@pytest.mark.parametrize("port", [1, "TEXT_MESSAGE_APP", 257, True, None])
def test_mesh_rejects_wrong_port(port):
    packet = mesh_packet()
    packet["decoded"]["portnum"] = port
    with pytest.raises(AdapterError):
        parse_meshtastic_packet(packet, nodes={NODE})


class FakePub:
    def __init__(self):
        self.subscriptions = []

    def subscribe(self, callback, topic):
        self.subscriptions.append((callback, topic))

    def unsubscribe(self, callback, topic):
        self.subscriptions.remove((callback, topic))


class FakeMesh:
    def __init__(self):
        self.sent = []
        self.closed = False

    def sendData(self, payload, **kwargs):
        self.sent.append((payload, kwargs))
        return SimpleNamespace(id=123)

    def close(self):
        self.closed = True


def test_mesh_lifecycle_private_unicast_and_queue_overflow():
    radio = FakeMesh()
    pub = FakePub()
    transport = MeshtasticTransport("fake", nodes={NODE}, interface=radio, pubsub=pub, queue_size=1)
    assert transport.send(NODE, b"cmd", "id") == "meshtastic:123"
    assert radio.sent == [
        (
            b"cmd",
            {
                "destinationId": NODE,
                "portNum": 256,
                "channelIndex": 0,
                "wantAck": True,
                "wantResponse": False,
            },
        )
    ]
    callback = pub.subscriptions[0][0]
    callback(mesh_packet(), FakeMesh())
    assert transport.receive(0) is None
    callback(mesh_packet(), radio)
    callback(mesh_packet(), radio)
    assert transport.overflow_count == 1
    assert transport.receive(0) == Inbound(NODE, b"reading")
    callback({"decoded": {}}, radio)
    assert transport.rejected_count == 1
    transport.close()
    transport.close()
    assert pub.subscriptions == []
    assert radio.closed
    with pytest.raises(AdapterError, match="closed"):
        transport.send(NODE, b"cmd", "id")


def test_mesh_only_configured_destination():
    transport = MeshtasticTransport("fake", nodes={NODE}, interface=FakeMesh(), pubsub=FakePub())
    with pytest.raises(AdapterError):
        transport.send("!87654321", b"cmd", "id")
    transport.close()


class FakeSerial:
    def __init__(self, incoming=b"", short_write=False):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.short_write = short_write
        self.closed = False

    def read(self, count):
        chunk = bytes(self.incoming[:count])
        del self.incoming[:count]
        return chunk

    def write(self, payload):
        self.sent.extend(payload)
        return len(payload) - int(self.short_write)

    def close(self):
        self.closed = True


def test_serial_stream_discards_oversize_then_recovers():
    serial = FakeSerial(b"GM1 node " + b"aa" * 200 + b"\nGM1 node aa\n")
    transport = SerialLoRaTransport("fake", routes={"node"}, serial_port=serial)
    assert transport.receive(1) == Inbound("node", b"\xaa")
    assert transport.rejected_count == 1
    assert transport.send("node", b"cmd", "command-id") == "uart:command-id"
    assert bytes(serial.sent) == b"GM1 node 636d64\n"
    transport.close()
    assert serial.closed


def test_serial_partial_lines_survive_receive_timeout():
    serial = FakeSerial(b"GM1 node a")
    transport = SerialLoRaTransport("fake", routes={"node"}, serial_port=serial)
    assert transport.receive(0.01) is None
    serial.incoming.extend(b"a\n")
    assert transport.receive(0.01) == Inbound("node", b"\xaa")
    transport.close()


def test_serial_short_write_is_ambiguous():
    transport = SerialLoRaTransport(
        "fake", routes={"node"}, serial_port=FakeSerial(short_write=True)
    )
    with pytest.raises(AdapterError, match="ambiguous"):
        transport.send("node", b"cmd", "id")
    transport.close()


class FakePublish:
    rc = 0
    mid = 10

    def wait_for_publish(self, timeout):
        self.timeout = timeout

    def is_published(self):
        return True


class FakeMqtt:
    def __init__(self, connack=0, suback=0):
        self.connack = connack
        self.suback = suback
        self.subscriptions = []
        self.published = []
        self.tls = None
        self.closed = False
        self.info = FakePublish()

    def username_pw_set(self, username, password):
        self.credentials = (username, password)

    def tls_set(self, **kwargs):
        self.tls = kwargs

    def reconnect_delay_set(self, **kwargs):
        self.reconnect = kwargs

    def max_queued_messages_set(self, maximum):
        self.max_queue = maximum

    def connect(self, host, **kwargs):
        self.host = host
        return 0

    def loop_start(self):
        self.on_connect(self, None, {}, self.connack, None)
        if self.connack == 0:
            self.on_subscribe(self, None, 7, [self.suback], None)

    def subscribe(self, topics):
        self.subscriptions.append(topics)
        return 0, 7

    def publish(self, topic, body, **kwargs):
        self.published.append((topic, body, kwargs))
        return self.info

    def disconnect(self):
        self.closed = True

    def loop_stop(self):
        pass


def make_mqtt(client=None, **kwargs):
    return TtsMqttTransport(
        "127.0.0.1",
        application=APPLICATION,
        device_euis={DEVICE: EUI},
        username=APPLICATION,
        password="disposable-test-password",
        tls=False,
        client=client or FakeMqtt(),
        **kwargs,
    )


def test_mqtt_callbacks_and_local_submission_receipt():
    client = FakeMqtt()
    transport = make_mqtt(client, queue_size=1)
    assert client.subscriptions == [[(TOPIC, 0)]]
    assert transport.send(DEVICE, b"command", "id") == "mqtt-local:10"
    assert client.published[0][0].endswith("/down/push")
    assert client.published[0][2] == {"qos": 0, "retain": False}
    event = SimpleNamespace(topic=TOPIC, payload=json.dumps(tts_event()).encode(), retain=False)
    client.on_message(client, None, event)
    client.on_message(client, None, event)
    assert transport.overflow_count == 1
    assert transport.receive(0) == Inbound(DEVICE, b"reading")
    event.retain = True
    client.on_message(client, None, event)
    assert transport.rejected_count == 1
    assert transport.receive(0) is None
    client.on_disconnect(client, None, {}, 0, None)
    with pytest.raises(AdapterError, match="disconnected"):
        transport.send(DEVICE, b"command", "id")
    client.loop_start()
    assert len(client.subscriptions) == 2
    assert transport.send(DEVICE, b"command", "id") == "mqtt-local:10"
    transport.close()
    assert client.closed


@pytest.mark.parametrize("connack,suback", [(5, 0), (0, 128)])
def test_mqtt_refuses_failed_connection_or_subscription(connack, suback):
    client = FakeMqtt(connack=connack, suback=suback)
    with pytest.raises(AdapterError, match="refused"):
        make_mqtt(client)
    assert client.closed


def test_mqtt_refuses_remote_plaintext():
    with pytest.raises(AdapterError, match="requires_tls"):
        TtsMqttTransport(
            "example.com",
            application=APPLICATION,
            device_euis={DEVICE: EUI},
            username=APPLICATION,
            password="test",
            tls=False,
            client=FakeMqtt(),
        )


def test_mqtt_remote_tls_and_auth():
    client = FakeMqtt()
    transport = TtsMqttTransport(
        "example.com",
        application=APPLICATION,
        device_euis={DEVICE: EUI},
        username=APPLICATION,
        password="test",
        client=client,
    )
    assert client.tls == {"ca_certs": None}
    assert client.credentials == (APPLICATION, "test")
    transport.close()


def test_mqtt_publish_failures_are_not_execution_success():
    client = FakeMqtt()
    transport = make_mqtt(client)
    client.info.rc = 4
    with pytest.raises(AdapterError, match="publish_failed"):
        transport.send(DEVICE, b"command", "id")
    client.info.rc = 0
    client.info.is_published = lambda: False
    with pytest.raises(AdapterError, match="ambiguous"):
        transport.send(DEVICE, b"command", "id")
    transport.close()


def test_queue_size_and_timeout_validation():
    with pytest.raises(AdapterError):
        QueuedTransport(0)
    transport = QueuedTransport(1)
    with pytest.raises(AdapterError):
        transport.receive(-1)
