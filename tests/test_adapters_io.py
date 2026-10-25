"""Real local serial/MQTT I/O, without a radio or an external network service."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import queue
import socket
import threading

import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish
import pytest
import serial

from genesismesh_radio.adapters.base import Inbound
from genesismesh_radio.adapters.meshtastic import MeshtasticTransport
from genesismesh_radio.adapters.serial_lora import SerialLoRaTransport
from genesismesh_radio.adapters.tts import TtsMqttTransport

APP = "disposable@ttn"
DEVICE = "sensor-01"
EUI = "0102030405060708"
UP_TOPIC = f"v3/{APP}/devices/{DEVICE}/up"


def event_bytes(payload: bytes) -> bytes:
    return json.dumps(
        {
            "end_device_ids": {
                "device_id": DEVICE,
                "application_ids": {"application_id": "disposable"},
                "dev_eui": EUI,
            },
            "uplink_message": {
                "f_port": 10,
                "frm_payload": base64.b64encode(payload).decode(),
            },
        }
    ).encode()


def test_real_pyserial_loopback():
    port = serial.serial_for_url("loop://", timeout=0.05, write_timeout=1)
    transport = SerialLoRaTransport("loop://", routes={"sensor-01"}, serial_port=port)
    try:
        assert transport.send("sensor-01", b"\x00\xff\x01", "command-1") == "uart:command-1"
        assert transport.receive(1) == Inbound("sensor-01", b"\x00\xff\x01")
        port.write(b"invalid line\nGM1 sensor-01 ff\n")
        assert transport.receive(1) == Inbound("sensor-01", b"\xff")
        assert transport.rejected_count == 1
    finally:
        transport.close()


@pytest.mark.parametrize("port_number", [256, 300])
def test_actual_meshtastic_python_packet_contract(monkeypatch, port_number):
    mesh_interface = pytest.importorskip("meshtastic.mesh_interface")
    from meshtastic.protobuf import mesh_pb2
    from pubsub import pub

    interface = mesh_interface.MeshInterface(noProto=True)
    sent = []

    def send_packet(packet, destination_id, **kwargs):
        sent.append((packet, destination_id, kwargs))
        return packet

    monkeypatch.setattr(interface, "_sendPacket", send_packet)
    monkeypatch.setattr(interface, "_sendDisconnect", lambda: None)
    transport = MeshtasticTransport(
        "no-radio", nodes={"!12345678"}, app_port=port_number, interface=interface, pubsub=pub
    )
    try:
        packet = mesh_pb2.MeshPacket()
        setattr(packet, "from", 0x12345678)
        packet.decoded.portnum = port_number
        packet.decoded.payload = b"library-payload"
        interface._handlePacketFromRadio(packet)
        assert transport.receive(2) == Inbound("!12345678", b"library-payload")
        receipt = transport.send("!12345678", b"command", "command-1")
        assert receipt.startswith("meshtastic:")
        assert sent[0][0].decoded.portnum == port_number
        assert sent[0][0].decoded.payload == b"command"
        assert sent[0][1] == "!12345678"
        assert sent[0][2]["wantAck"] is True
    finally:
        transport.close()


@pytest.mark.skipif(os.name != "posix", reason="PTY integration requires POSIX")
def test_real_pyserial_pty():
    import select

    master, slave = os.openpty()
    transport = SerialLoRaTransport(os.ttyname(slave), routes={"sensor-01"})
    try:
        os.write(master, b"GM1 sensor-01 1234\n")
        assert transport.receive(1) == Inbound("sensor-01", b"\x12\x34")
        transport.send("sensor-01", b"\x01\x02", "command-1")
        readable, _, _ = select.select([master], [], [], 1)
        assert readable
        assert os.read(master, 1024) == b"GM1 sensor-01 0102\n"
    finally:
        transport.close()
        os.close(master)
        os.close(slave)


@pytest.fixture
def mqtt_broker():
    broker_module = pytest.importorskip("amqtt.broker", reason="install test extra: amqtt==0.11.3")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    ready = threading.Event()
    state = {}
    errors = []

    async def serve():
        state["loop"] = asyncio.get_running_loop()
        state["stop"] = asyncio.Event()
        broker = broker_module.Broker(
            {
                "listeners": {"default": {"type": "tcp", "bind": f"127.0.0.1:{port}"}},
                "plugins": {
                    "amqtt.plugins.authentication.AnonymousAuthPlugin": {"allow_anonymous": True}
                },
            }
        )
        await broker.start()
        ready.set()
        try:
            await state["stop"].wait()
        finally:
            await broker.shutdown()

    def run():
        try:
            asyncio.run(serve())
        except BaseException as exc:
            errors.append(exc)
            ready.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert ready.wait(10), "local MQTT broker did not start"
    if errors:
        raise errors[0]
    try:
        yield port
    finally:
        state["loop"].call_soon_threadsafe(state["stop"].set)
        thread.join(10)
        assert not thread.is_alive(), "local MQTT broker did not stop"
        assert not errors


def mqtt_transport(port):
    return TtsMqttTransport(
        "127.0.0.1",
        port=port,
        application=APP,
        device_euis={DEVICE: EUI},
        username=APP,
        password="disposable-loopback-test",
        tls=False,
    )


@pytest.mark.integration
def test_real_mqtt_uplink_downlink_roundtrip(mqtt_broker):
    received = queue.Queue()
    subscribed = threading.Event()
    observer = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv311)

    def on_connect(client, userdata, flags, reason_code, properties):
        assert reason_code == 0
        client.subscribe(f"v3/{APP}/devices/{DEVICE}/down/push", qos=0)

    def on_subscribe(client, userdata, mid, reason_codes, properties):
        subscribed.set()

    def on_message(client, userdata, message):
        received.put((message.topic, message.payload, message.retain))

    observer.on_connect = on_connect
    observer.on_subscribe = on_subscribe
    observer.on_message = on_message
    observer.connect("127.0.0.1", port=mqtt_broker)
    observer.loop_start()
    transport = mqtt_transport(mqtt_broker)
    try:
        assert subscribed.wait(5)
        publish.single(UP_TOPIC, event_bytes(b"telemetry"), hostname="127.0.0.1", port=mqtt_broker)
        assert transport.receive(5) == Inbound(DEVICE, b"telemetry")
        receipt = transport.send(DEVICE, b"command", "real-socket-test")
        assert receipt.startswith("mqtt-local:")
        topic, payload, retained = received.get(timeout=5)
        assert topic.endswith("/down/push")
        assert not retained
        downlink = json.loads(payload)["downlinks"][0]
        assert base64.b64decode(downlink["frm_payload"]) == b"command"
        assert downlink["correlation_ids"] == ["gm-radio:real-socket-test"]
    finally:
        transport.close()
        observer.disconnect()
        observer.loop_stop()


@pytest.mark.integration
def test_real_mqtt_retained_uplink_is_refused(mqtt_broker):
    publish.single(
        UP_TOPIC,
        event_bytes(b"old-reading"),
        retain=True,
        hostname="127.0.0.1",
        port=mqtt_broker,
    )
    transport = mqtt_transport(mqtt_broker)
    try:
        assert transport.receive(0.2) is None
        assert transport.rejected_count == 1
        publish.single(
            UP_TOPIC, event_bytes(b"fresh-reading"), hostname="127.0.0.1", port=mqtt_broker
        )
        assert transport.receive(5) == Inbound(DEVICE, b"fresh-reading")
    finally:
        transport.close()
