"""WisGateOS 2 built-in LNS Generic MQTT, not the gateway packet-forwarder API.

The official RAK MQTT guide defines raw base64 uplinks and downlinks. Topics use
the application name and lowercase DevEUI; applicationID is checked separately.
See docs/local-lorawan.md for sources and the explicit supported profile.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import re
import threading
from collections.abc import Mapping
from typing import Any

from .base import (
    AdapterError,
    Inbound,
    QueuedTransport,
    validate_budget,
    validate_command_id,
    validate_payload,
)

MAX_EVENT_BYTES = 65536
_APPLICATION = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_APPLICATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_ROUTE = re.compile(r"[A-Za-z0-9_!.-]{1,64}\Z")
_EUI = re.compile(r"[0-9a-fA-F]{16}\Z")


def validate_application(application: str) -> str:
    if not isinstance(application, str) or not _APPLICATION.fullmatch(application):
        raise AdapterError("invalid_wisgate_application")
    return application


def validate_application_id(application_id: str) -> str:
    if not isinstance(application_id, str) or not _APPLICATION_ID.fullmatch(application_id):
        raise AdapterError("invalid_wisgate_application_id")
    return application_id


def validate_device_euis(device_euis: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(device_euis, Mapping) or not device_euis:
        raise AdapterError("wisgate_devices_required")
    result = {}
    for route, eui in device_euis.items():
        if not isinstance(route, str) or not _ROUTE.fullmatch(route):
            raise AdapterError("invalid_wisgate_route")
        if not isinstance(eui, str) or not _EUI.fullmatch(eui):
            raise AdapterError("invalid_wisgate_dev_eui")
        result[route] = eui.lower()
    if len(set(result.values())) != len(result):
        raise AdapterError("duplicate_wisgate_dev_eui")
    return result


def validate_f_port(f_port: int) -> int:
    # This integration uses an application port, not MAC commands or reserved ports.
    if type(f_port) is not int or not 1 <= f_port <= 223:
        raise AdapterError("invalid_wisgate_f_port")
    return f_port


def validate_connection(host, port, username, *, tls, connect_timeout, publish_timeout):
    if (
        not isinstance(host, str)
        or not 1 <= len(host) <= 253
        or not host.isascii()
        or any(not 33 <= ord(char) <= 126 for char in host)
        or any(char in host for char in "/@?#\\")
    ):
        raise AdapterError("invalid_mqtt_host")
    if type(port) is not int or not 1 <= port <= 65535:
        raise AdapterError("invalid_mqtt_port")
    if type(tls) is not bool:
        raise AdapterError("invalid_mqtt_tls")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        if any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in host.removesuffix(".").split(".")
        ):
            raise AdapterError("invalid_mqtt_host") from None
        loopback = host == "localhost"
    if not tls and not loopback:
        raise AdapterError("remote_mqtt_requires_tls")
    if (
        not isinstance(username, str)
        or not 1 <= len(username) <= 128
        or any(ord(char) < 32 or ord(char) == 127 for char in username)
    ):
        raise AdapterError("invalid_mqtt_username")
    for value in (connect_timeout, publish_timeout):
        if type(value) not in {int, float} or not math.isfinite(value) or not 0 < value <= 300:
            raise AdapterError("invalid_timeout")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError("duplicate_json_key")
        result[key] = value
    return result


def _bounded_json(event: bytes) -> dict:
    if not isinstance(event, bytes) or not 1 <= len(event) <= MAX_EVENT_BYTES:
        raise AdapterError("invalid_wisgate_event_size")
    try:
        value = json.loads(
            event.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
        pending = [(value, 0)]
        visited = 0
        while pending:
            item, depth = pending.pop()
            visited += 1
            if depth > 32 or visited > 4096:
                raise ValueError("structure limit")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
            elif isinstance(item, float) and not math.isfinite(item):
                raise ValueError("nonfinite")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AdapterError("invalid_wisgate_json") from exc
    if not isinstance(value, dict):
        raise AdapterError("invalid_wisgate_envelope")
    return value


def parse_wisgate_uplink(
    topic: str,
    event: bytes,
    *,
    application: str,
    application_id: str,
    device_euis: Mapping[str, str],
    f_port: int = 10,
    max_payload: int = 51,
    retained: bool = False,
) -> Inbound:
    """Bind the configured route, application, DevEUI and FPort before forwarding.

    Gateway timestamps, LoRaWAN frame counters and ACKs do not replace the bridge's
    authenticated application-frame time/counter checks or device outcome.
    """
    validate_application(application)
    validate_application_id(application_id)
    euis = validate_device_euis(device_euis)
    validate_f_port(f_port)
    validate_budget(max_payload, 242)
    if retained:
        raise AdapterError("retained_uplink_refused")
    if not isinstance(topic, str) or len(topic) > 256:
        raise AdapterError("invalid_wisgate_topic")
    parts = topic.split("/")
    if (
        len(parts) != 5
        or parts[0] != "application"
        or parts[1] != application
        or parts[2] != "device"
        or parts[4] != "rx"
    ):
        raise AdapterError("wisgate_topic_mismatch")
    route = next((route for route, eui in euis.items() if eui == parts[3]), None)
    if route is None:
        raise AdapterError("unconfigured_wisgate_source")
    data = _bounded_json(event)
    eui = data.get("devEUI")
    if (
        data.get("applicationName") != application
        or data.get("applicationID") != application_id
        or not isinstance(eui, str)
        or not _EUI.fullmatch(eui)
        or eui.lower() != euis[route]
    ):
        raise AdapterError("wisgate_identity_mismatch")
    if type(data.get("fPort")) is not int or data["fPort"] != f_port:
        raise AdapterError("wisgate_f_port_mismatch")
    if data.get("data_encode") != "base64":
        raise AdapterError("wisgate_raw_base64_required")
    encoded = data.get("data")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((max_payload + 2) // 3):
        raise AdapterError("invalid_wisgate_payload")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AdapterError("invalid_wisgate_base64") from exc
    return Inbound(route, validate_payload(payload, max_payload))


def build_wisgate_downlink(
    application: str,
    dev_eui: str,
    payload: bytes,
    command_id: str,
    *,
    f_port: int = 10,
    max_payload: int = 51,
) -> tuple[str, bytes]:
    validate_application(application)
    if not isinstance(dev_eui, str) or not _EUI.fullmatch(dev_eui):
        raise AdapterError("invalid_wisgate_dev_eui")
    validate_f_port(f_port)
    validate_budget(max_payload, 242)
    validate_payload(payload, max_payload)
    validate_command_id(command_id)
    # The vendor schema has no command-ID field. Correlation stays in the durable
    # bridge journal and the authenticated application command/outcome counters.
    body = {
        "confirmed": True,
        "data": base64.b64encode(payload).decode("ascii"),
        "fPort": f_port,
    }
    return (
        f"application/{application}/device/{dev_eui.lower()}/tx",
        json.dumps(body, separators=(",", ":")).encode("ascii"),
    )


class WisGateMqttTransport(QueuedTransport):
    """Use an authenticated broker; off-host connections always verify TLS.

    A successful send is local MQTT submission only. There are no subscriptions
    to /ack, /tx, /join or /status, and no automatic application-command retries.
    """

    def __init__(
        self,
        host: str,
        *,
        application: str,
        application_id: str,
        device_euis: Mapping[str, str],
        username: str,
        password: str,
        port: int = 8883,
        f_port: int = 10,
        max_payload: int = 51,
        queue_size: int = 128,
        tls: bool = True,
        ca_file: str | None = None,
        client: Any = None,
        connect_timeout: float = 10,
        publish_timeout: float = 5,
    ):
        super().__init__(queue_size)
        self.application = validate_application(application)
        self.application_id = validate_application_id(application_id)
        self.device_euis = validate_device_euis(device_euis)
        validate_connection(
            host,
            port,
            username,
            tls=tls,
            connect_timeout=connect_timeout,
            publish_timeout=publish_timeout,
        )
        if not isinstance(password, str) or not password:
            raise AdapterError("invalid_mqtt_credentials")
        if ca_file is not None and (not isinstance(ca_file, str) or not ca_file):
            raise AdapterError("invalid_mqtt_ca_file")
        self.f_port = validate_f_port(f_port)
        self.max_payload = validate_budget(max_payload, 242)
        self._publish_timeout = publish_timeout
        self._connected = threading.Event()
        self._connection_finished = threading.Event()
        self._connection_error = None
        self._subscription_mid = None
        self._send_lock = threading.Lock()
        if client is None:
            import paho.mqtt.client as mqtt

            client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                protocol=mqtt.MQTTv311,
                clean_session=True,
            )
        self.client = client
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message
        client.on_subscribe = self._on_subscribe
        client.connect_timeout = connect_timeout
        client.username_pw_set(username, password)
        if tls:
            # Paho's default TLS context requires a trusted server certificate and
            # hostname match. No tls_insecure_set or unverifiable fallback exists.
            client.tls_set(ca_certs=ca_file)
        client.reconnect_delay_set(min_delay=1, max_delay=30)
        client.max_queued_messages_set(queue_size)
        try:
            if client.connect(host, port=port, keepalive=60) != 0:
                raise AdapterError("mqtt_connect_failed")
            client.loop_start()
            if not self._connection_finished.wait(connect_timeout):
                raise AdapterError("mqtt_connect_timeout")
            if self._connection_error or not self._connected.is_set():
                raise AdapterError(self._connection_error or "mqtt_connect_failed")
        except Exception:
            self.close()
            raise

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        self._connected.clear()
        self._subscription_mid = None
        if reason_code != 0:
            self._connection_error = "mqtt_connection_refused"
            self._connection_finished.set()
            return
        topics = [
            (f"application/{self.application}/device/{eui}/rx", 0)
            for eui in self.device_euis.values()
        ]
        try:
            result, self._subscription_mid = client.subscribe(topics)
        except Exception:
            result = 1
        if result != 0:
            self._connection_error = "mqtt_subscription_failed"
            self._connection_finished.set()
        else:
            self._connection_error = None

    def _on_subscribe(self, client, userdata, mid, reason_codes, properties):
        if mid != self._subscription_mid:
            return
        if len(reason_codes) != len(self.device_euis) or any(code != 0 for code in reason_codes):
            self._connection_error = "mqtt_subscription_refused"
            self._connected.clear()
        else:
            self._connection_error = None
            self._connected.set()
        self._connection_finished.set()

    def _on_disconnect(self, client, userdata, flags, reason_code, properties):
        self._connected.clear()

    def _on_message(self, client, userdata, message):
        if self.closed:
            return
        try:
            inbound = parse_wisgate_uplink(
                message.topic,
                message.payload,
                application=self.application,
                application_id=self.application_id,
                device_euis=self.device_euis,
                f_port=self.f_port,
                max_payload=self.max_payload,
                retained=message.retain,
            )
        except (AdapterError, AttributeError, TypeError):
            self.rejected_count += 1
            return
        self._offer(inbound)

    def send(self, route: str, payload: bytes, command_id: str) -> str:
        if self.closed:
            raise AdapterError("transport_closed")
        if route not in self.device_euis:
            raise AdapterError("unconfigured_wisgate_destination")
        topic, body = build_wisgate_downlink(
            self.application,
            self.device_euis[route],
            payload,
            command_id,
            f_port=self.f_port,
            max_payload=self.max_payload,
        )
        with self._send_lock:
            if not self._connected.is_set():
                raise AdapterError("mqtt_disconnected")
            try:
                info = self.client.publish(topic, body, qos=0, retain=False)
                if info.rc != 0:
                    raise AdapterError("mqtt_publish_failed")
                info.wait_for_publish(timeout=self._publish_timeout)
                if not info.is_published():
                    raise AdapterError("mqtt_publish_ambiguous")
            except AdapterError:
                raise
            except Exception as exc:
                raise AdapterError("mqtt_publish_ambiguous") from exc
        return f"mqtt-local:{info.mid}"

    def close(self):
        if not self.closed:
            self.closed = True
            self._connected.clear()
            try:
                self.client.disconnect()
            finally:
                self.client.loop_stop()
