"""Injected radio peers for real-NA tests; these do not claim RF validation."""

from __future__ import annotations

import base64
import json
import time
from collections import deque
from types import SimpleNamespace

from genesismesh_radio.adapters.meshtastic import MeshtasticTransport
from genesismesh_radio.adapters.serial_lora import SerialLoRaTransport, parse_serial_line
from genesismesh_radio.adapters.tts import TtsMqttTransport
from genesismesh_radio.protocol import (
    Frame,
    Kind,
    OutcomeStatus,
    decode,
    decode_command,
    encode,
    encode_outcome,
    encode_telemetry,
)


class DevicePeer:
    def __init__(self, device_id, key, audience):
        self.device_id, self.key, self.audience = device_id, key, audience
        self.tx = 0
        self.rx = 0
        self.applied = 60
        self.last_command = None

    def uplink(self, kind, payload):
        self.tx += 1
        return encode(
            Frame(kind, self.device_id, self.tx, int(time.time()) + 60, payload),
            self.key,
            self.audience,
        )

    def telemetry(self):
        return self.uplink(Kind.TELEMETRY, encode_telemetry(1, 2150))

    def execute(self, raw):
        command = decode(raw, self.key, self.audience, now=int(time.time()))
        assert command.kind is Kind.COMMAND
        assert command.device_id == self.device_id
        assert command.counter > self.rx, "device refuses replayed commands"
        self.rx = command.counter
        self.applied = decode_command(command.payload)
        self.last_command = raw
        return self.uplink(
            Kind.OUTCOME, encode_outcome(command.counter, OutcomeStatus.SUCCESS, self.applied)
        )


class PubSubPeer:
    def subscribe(self, callback, topic):
        self.callback = callback

    def unsubscribe(self, callback, topic):
        self.callback = None


class MeshRadioPeer:
    def __init__(self, device):
        self.device = device
        self.pending = deque()

    def sendData(self, payload, **kwargs):
        self.pending.append(self.device.execute(payload))
        return SimpleNamespace(id=len(self.pending))

    def close(self):
        pass


class SerialPeer:
    def __init__(self, device, route):
        self.device, self.route = device, route
        self.pending = bytearray()
        self.timeout = 0

    def write(self, raw):
        inbound = parse_serial_line(raw, routes={self.route})
        outcome = self.device.execute(inbound.payload)
        self.inject(outcome)
        return len(raw)

    def inject(self, payload):
        self.pending.extend(b"GM1 " + self.route.encode() + b" " + payload.hex().encode() + b"\n")

    def read(self, size):
        data = bytes(self.pending[:size])
        del self.pending[:size]
        return data

    def close(self):
        pass


class MqttPeer:
    def __init__(self, device):
        self.device = device
        self.pending = deque()

    def username_pw_set(self, *args):
        pass

    def reconnect_delay_set(self, **kwargs):
        pass

    def max_queued_messages_set(self, size):
        pass

    def connect(self, *args, **kwargs):
        return 0

    def loop_start(self):
        self.on_connect(self, None, None, 0, None)
        self.on_subscribe(self, None, 1, [0], None)

    def subscribe(self, topics):
        return 0, 1

    def publish(self, topic, body, **kwargs):
        message = json.loads(body)
        payload = base64.b64decode(message["downlinks"][0]["frm_payload"], validate=True)
        self.pending.append(self.device.execute(payload))
        return SimpleNamespace(
            rc=0,
            mid=len(self.pending),
            wait_for_publish=lambda **_: None,
            is_published=lambda: True,
        )

    def disconnect(self):
        pass

    def loop_stop(self):
        pass


class RadioHarness:
    def __init__(self, name, route, device):
        self.name, self.route, self.device = name, route, device
        if name == "meshtastic":
            self.peer = MeshRadioPeer(device)
            self.pub = PubSubPeer()
            self.transport = MeshtasticTransport(
                "injected-radio", nodes={route}, interface=self.peer, pubsub=self.pub
            )
        elif name == "serial":
            self.peer = SerialPeer(device, route)
            self.transport = SerialLoRaTransport(
                "injected-uart", routes={route}, serial_port=self.peer
            )
        else:
            self.peer = MqttPeer(device)
            self.transport = TtsMqttTransport(
                "127.0.0.1",
                application="radio-lab",
                device_euis={route: "0102030405060708"},
                username="radio-lab",
                password="test-only",
                tls=False,
                client=self.peer,
            )

    def inbound(self, raw):
        if self.name == "meshtastic":
            packet = {
                "from": int(self.route[1:], 16),
                "fromId": self.route,
                "channel": 0,
                "decoded": {"portnum": "PRIVATE_APP", "payload": raw},
            }
            self.pub.callback(packet, self.peer)
        elif self.name == "serial":
            self.peer.inject(raw)
        else:
            event = {
                "end_device_ids": {
                    "device_id": self.route,
                    "application_ids": {"application_id": "radio-lab"},
                    "dev_eui": "0102030405060708",
                },
                "uplink_message": {"f_port": 10, "frm_payload": base64.b64encode(raw).decode()},
            }
            self.peer.on_message(
                self.peer,
                None,
                SimpleNamespace(
                    topic=f"v3/radio-lab/devices/{self.route}/up",
                    payload=json.dumps(event).encode(),
                    retain=False,
                ),
            )

    def release_outcome(self):
        if self.name != "serial":
            self.inbound(self.peer.pending.popleft())

    def close(self):
        self.transport.close()
