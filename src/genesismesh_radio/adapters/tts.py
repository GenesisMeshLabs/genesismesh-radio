"""The Things Stack v3 MQTT application integration, using raw payload bytes."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
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

_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,35}\Z")
_EUI = re.compile(r"[0-9a-fA-F]{16}\Z")
MAX_EVENT_BYTES = 65536


def validate_application(application: str) -> str:
    if not isinstance(application, str):
        raise AdapterError("invalid_tts_application")
    parts = application.split("@")
    if not 1 <= len(parts) <= 2 or any(not _ID.fullmatch(part) for part in parts):
        raise AdapterError("invalid_tts_application")
    return application


def validate_device(device_id: str) -> str:
    if not isinstance(device_id, str) or not _ID.fullmatch(device_id):
        raise AdapterError("invalid_tts_device")
    return device_id


def validate_f_port(f_port: int) -> int:
    if type(f_port) is not int or not 1 <= f_port <= 233:
        raise AdapterError("invalid_tts_f_port")
    return f_port


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise AdapterError("duplicate_json_key")
        obj[key] = value
    return obj


def parse_tts_uplink(
    topic: str,
    event: bytes,
    *,
    application: str,
    device_euis: Mapping[str, str],
    f_port: int = 10,
    max_payload: int = 51,
    retained: bool = False,
) -> Inbound:
    """Require agreement among configured binding, topic and payload identities."""
    if retained:
        raise AdapterError("retained_uplink_refused")
    if not isinstance(topic, str):
        raise AdapterError("invalid_tts_topic")
    parts = topic.split("/")
    if (
        len(parts) != 5
        or parts[0] != "v3"
        or parts[1] != application
        or parts[2] != "devices"
        or parts[4] != "up"
    ):
        raise AdapterError("tts_topic_mismatch")
    route = parts[3]
    if route not in device_euis:
        raise AdapterError("unconfigured_tts_source")
    if not isinstance(event, bytes) or not 1 <= len(event) <= MAX_EVENT_BYTES:
        raise AdapterError("invalid_tts_event_size")
    try:
        data = json.loads(event.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise AdapterError("invalid_tts_json") from exc
    if not isinstance(data, dict):
        raise AdapterError("invalid_tts_envelope")
    ids = data.get("end_device_ids")
    uplink = data.get("uplink_message")
    if not isinstance(ids, dict) or not isinstance(uplink, dict):
        raise AdapterError("invalid_tts_envelope")
    app_ids = ids.get("application_ids")
    dev_eui = ids.get("dev_eui")
    if (
        ids.get("device_id") != route
        or not isinstance(app_ids, dict)
        or app_ids.get("application_id") != application.split("@", 1)[0]
        or not isinstance(dev_eui, str)
        or not _EUI.fullmatch(dev_eui)
        or dev_eui.lower() != device_euis[route].lower()
    ):
        raise AdapterError("tts_identity_mismatch")
    port = uplink.get("f_port")
    if type(port) is not int or port != f_port:
        raise AdapterError("tts_f_port_mismatch")
    encoded = uplink.get("frm_payload")
    if not isinstance(encoded, str) or len(encoded) > 4 * ((max_payload + 2) // 3):
        raise AdapterError("invalid_tts_payload")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AdapterError("invalid_tts_base64") from exc
    return Inbound(route, validate_payload(payload, max_payload))


def build_tts_downlink(
    application: str,
    route: str,
    payload: bytes,
    command_id: str,
    *,
    f_port: int = 10,
    max_payload: int = 51,
) -> tuple[str, bytes]:
    validate_application(application)
    validate_device(route)
    validate_f_port(f_port)
    validate_payload(payload, max_payload)
    validate_command_id(command_id)
    body = {
        "downlinks": [
            {
                "f_port": f_port,
                "frm_payload": base64.b64encode(payload).decode("ascii"),
                "priority": "NORMAL",
                "confirmed": True,
                "correlation_ids": [f"gm-radio:{command_id}"],
            }
        ]
    }
    topic = f"v3/{application}/devices/{route}/down/push"
    return topic, json.dumps(body, separators=(",", ":")).encode("utf-8")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class TtsMqttTransport(QueuedTransport):
    def __init__(
        self,
        host: str,
        *,
        application: str,
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
    ) -> None:
        super().__init__(queue_size)
        self.application = validate_application(application)
        if not device_euis:
            raise AdapterError("tts_devices_required")
        self.device_euis: dict[str, str] = {}
        for device_id, eui in device_euis.items():
            validate_device(device_id)
            if not isinstance(eui, str) or not _EUI.fullmatch(eui):
                raise AdapterError("invalid_tts_dev_eui")
            self.device_euis[device_id] = eui.lower()
        if not isinstance(host, str) or not host or "/" in host or "@" in host:
            raise AdapterError("invalid_mqtt_host")
        if type(port) is not int or not 1 <= port <= 65535:
            raise AdapterError("invalid_mqtt_port")
        if type(tls) is not bool or (not tls and not _is_loopback(host)):
            raise AdapterError("remote_mqtt_requires_tls")
        if username != application or not isinstance(password, str) or not password:
            raise AdapterError("invalid_mqtt_credentials")
        if connect_timeout <= 0 or publish_timeout <= 0:
            raise AdapterError("invalid_timeout")
        self.f_port = validate_f_port(f_port)
        self.max_payload = validate_budget(max_payload, 242)
        self._publish_timeout = publish_timeout
        self._connected = threading.Event()
        self._connection_finished = threading.Event()
        self._connection_error: str | None = None
        self._subscription_mid: int | None = None
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

    def _on_connect(
        self, client: Any, userdata: Any, flags: Any, reason_code: Any, properties: Any
    ) -> None:
        self._connected.clear()
        if reason_code != 0:
            self._connection_error = "mqtt_connection_refused"
            self._connection_finished.set()
        else:
            topics = [
                (f"v3/{self.application}/devices/{device}/up", 0) for device in self.device_euis
            ]
            result, self._subscription_mid = client.subscribe(topics)
            if result != 0:
                self._connection_error = "mqtt_subscription_failed"
                self._connection_finished.set()
            else:
                self._connection_error = None

    def _on_subscribe(
        self, client: Any, userdata: Any, mid: int, reason_codes: list[Any], properties: Any
    ) -> None:
        if mid != self._subscription_mid:
            return
        if len(reason_codes) != len(self.device_euis) or any(code != 0 for code in reason_codes):
            self._connection_error = "mqtt_subscription_refused"
            self._connected.clear()
        else:
            self._connection_error = None
            self._connected.set()
        self._connection_finished.set()

    def _on_disconnect(
        self, client: Any, userdata: Any, flags: Any, reason_code: Any, properties: Any
    ) -> None:
        self._connected.clear()

    def _on_message(self, client: Any, userdata: Any, message: Any) -> None:
        if self.closed:
            return
        try:
            inbound = parse_tts_uplink(
                message.topic,
                message.payload,
                application=self.application,
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
            raise AdapterError("unconfigured_tts_destination")
        topic, body = build_tts_downlink(
            self.application,
            route,
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

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._connected.clear()
            try:
                self.client.disconnect()
            finally:
                self.client.loop_stop()
