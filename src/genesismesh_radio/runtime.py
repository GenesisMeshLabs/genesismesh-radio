"""Construct configured transports without exposing secret values."""

import ipaddress
import math
import os
import re
from contextlib import ExitStack
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .adapters.base import AdapterError, validate_budget
from .adapters.meshtastic import MeshtasticTransport, normalize_node
from .adapters.serial_lora import SerialLoRaTransport, validate_route
from .adapters.tts import (
    TtsMqttTransport,
    validate_application,
    validate_device,
    validate_f_port,
)
from .adapters.wisgate import (
    WisGateMqttTransport,
    validate_application_id,
    validate_device_euis,
)
from .adapters.wisgate import (
    validate_application as validate_wisgate_application,
)
from .adapters.wisgate import (
    validate_connection as validate_wisgate_connection,
)
from .adapters.wisgate import (
    validate_f_port as validate_wisgate_f_port,
)
from .config import Config, ConfigError, validate
from .edge import EdgeClient

_ENVIRONMENT = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_EUI = re.compile(r"[0-9a-fA-F]{16}\Z")
_TRANSPORT_KEYS = {
    "meshtastic": {"kind", "port", "channel", "app_port", "queue_size"},
    "lora_serial": {"kind", "port", "baudrate"},
    "tts": {
        "kind",
        "host",
        "application",
        "device_euis",
        "username",
        "password_env",
        "port",
        "f_port",
        "queue_size",
        "tls",
        "ca_file",
        "connect_timeout",
        "publish_timeout",
    },
    "wisgate": {
        "kind",
        "host",
        "application",
        "application_id",
        "device_euis",
        "username",
        "password_env",
        "port",
        "f_port",
        "queue_size",
        "tls",
        "ca_file",
        "connect_timeout",
        "publish_timeout",
    },
}


def _string(value, code, maximum=1024):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ConfigError(code)
    return value


def _integer(value, code, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(code)


def _timeout(value):
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 < value <= 300:
        raise ConfigError("invalid_timeout")


def _env_reference(value):
    if not isinstance(value, str) or not _ENVIRONMENT.fullmatch(value):
        raise ConfigError("invalid_credential_environment_reference")


def _edge_settings(settings):
    allowed = {"base_url", "token_env", "unix_socket", "timeout"}
    if not isinstance(settings, dict) or settings.keys() - allowed:
        raise ConfigError("unknown_edge_setting")
    base_url = _string(settings.get("base_url", "http://127.0.0.1:17900"), "invalid_edge_url")
    try:
        parsed = urlsplit(base_url)
        loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
        _ = parsed.port
    except ValueError as exc:
        raise ConfigError("invalid_edge_url") from exc
    if (
        not loopback
        or parsed.scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigError("invalid_edge_url")
    _env_reference(settings.get("token_env", "GM_EDGE_TOKEN"))
    _timeout(settings.get("timeout", 10))
    unix_socket = settings.get("unix_socket")
    if unix_socket is not None:
        _string(unix_socket, "invalid_edge_socket")
        if not (os.path.isabs(unix_socket) or PurePosixPath(unix_socket).is_absolute()):
            raise ConfigError("invalid_edge_socket")


def _tts_settings(settings, routes):
    required = {"host", "application", "device_euis", "username"}
    if required - settings.keys():
        raise ConfigError("missing_tts_setting")
    host = _string(settings["host"], "invalid_mqtt_host", 253)
    if "/" in host or "@" in host or any(char.isspace() for char in host):
        raise ConfigError("invalid_mqtt_host")
    application = validate_application(settings["application"])
    if settings["username"] != application:
        raise ConfigError("mqtt_username_application_mismatch")
    euis = settings["device_euis"]
    if not isinstance(euis, dict) or set(euis) != set(routes):
        raise ConfigError("tts_device_route_mismatch")
    for device, eui in euis.items():
        validate_device(device)
        if not isinstance(eui, str) or not _EUI.fullmatch(eui):
            raise ConfigError("invalid_tts_dev_eui")
    if len({eui.lower() for eui in euis.values()}) != len(euis):
        raise ConfigError("duplicate_tts_dev_eui")
    tls = settings.get("tls", True)
    if type(tls) is not bool:
        raise ConfigError("invalid_mqtt_tls")
    if not tls:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise ConfigError("remote_mqtt_requires_tls")
    if "ca_file" in settings:
        _string(settings["ca_file"], "invalid_mqtt_ca_file")
    _integer(settings.get("port", 8883), "invalid_mqtt_port", 1, 65535)
    validate_f_port(settings.get("f_port", 10))
    _env_reference(settings.get("password_env", "GM_TTS_API_KEY"))
    _timeout(settings.get("connect_timeout", 10))
    _timeout(settings.get("publish_timeout", 5))


def _wisgate_settings(settings, routes):
    required = {"host", "application", "application_id", "device_euis", "username"}
    if required - settings.keys():
        raise ConfigError("missing_wisgate_setting")
    validate_wisgate_application(settings["application"])
    validate_application_id(settings["application_id"])
    euis = validate_device_euis(settings["device_euis"])
    if set(euis) != set(routes):
        raise ConfigError("wisgate_device_route_mismatch")
    validate_wisgate_connection(
        settings["host"],
        settings.get("port", 8883),
        settings["username"],
        tls=settings.get("tls", True),
        connect_timeout=settings.get("connect_timeout", 10),
        publish_timeout=settings.get("publish_timeout", 5),
    )
    validate_wisgate_f_port(settings.get("f_port", 10))
    if "ca_file" in settings:
        _string(settings["ca_file"], "invalid_mqtt_ca_file")
    _env_reference(settings.get("password_env", "GM_WISGATE_MQTT_PASSWORD"))


def validate_runtime(config: Config) -> None:
    """Validate every transport and edge setting before any service is opened.

    This is pure configuration validation: no imports of optional drivers, secret
    environment reads, filesystem probes, socket connections, or serial opens.
    """
    validate(config)
    _edge_settings(config.edge)
    if not isinstance(config.transports, dict) or set(config.transports) != {
        device.transport for device in config.devices
    }:
        raise ConfigError("transport_device_binding_mismatch")
    for name, settings in config.transports.items():
        if not isinstance(settings, dict):
            raise ConfigError("invalid_transport_settings")
        kind = settings.get("kind")
        if not isinstance(kind, str) or kind not in _TRANSPORT_KEYS:
            raise ConfigError("unsupported_transport_kind")
        if settings.keys() - _TRANSPORT_KEYS[kind]:
            raise ConfigError("unknown_transport_setting")
        devices = [device for device in config.devices if device.transport == name]
        routes = [device.route for device in devices]
        try:
            for device in devices:
                validate_budget(
                    device.max_payload,
                    {"meshtastic": 200, "tts": 242, "wisgate": 242}.get(kind, 255),
                )
            if kind in {"meshtastic", "lora_serial"}:
                _string(settings.get("port"), "serial_port_required")
            if kind == "meshtastic":
                if any(normalize_node(route) != route for route in routes):
                    raise ConfigError("meshtastic_route_must_be_canonical_lowercase")
                _integer(settings.get("channel", 0), "invalid_meshtastic_channel", 0, 7)
                _integer(settings.get("app_port", 256), "invalid_meshtastic_app_port", 256, 511)
            elif kind == "lora_serial":
                for route in routes:
                    validate_route(route)
                _integer(settings.get("baudrate", 115200), "invalid_baudrate", 1200, 4000000)
            elif kind == "tts":
                _tts_settings(settings, routes)
            else:
                _wisgate_settings(settings, routes)
            if kind in {"meshtastic", "tts", "wisgate"}:
                _integer(settings.get("queue_size", 128), "invalid_queue_size", 1, 65536)
        except AdapterError as exc:
            raise ConfigError("invalid_transport_setting") from exc


def create_edge(config: Config):
    validate_runtime(config)
    settings = config.edge
    token = os.environ.get(settings.get("token_env", "GM_EDGE_TOKEN"))
    return EdgeClient(
        base_url=settings.get("base_url", "http://127.0.0.1:17900"),
        token=token,
        unix_socket=settings.get("unix_socket"),
        timeout=settings.get("timeout", 10),
    )


def create_transports(config: Config, stack: ExitStack):
    validate_runtime(config)
    # Resolve all credentials before constructing even the first adapter.
    passwords = {}
    for name, settings in config.transports.items():
        if settings["kind"] in {"tts", "wisgate"}:
            default = "GM_TTS_API_KEY" if settings["kind"] == "tts" else "GM_WISGATE_MQTT_PASSWORD"
            password = os.environ.get(settings.get("password_env", default))
            if not password:
                raise ConfigError("missing_mqtt_password_environment")
            passwords[name] = password
    result = {}
    for name, supplied in config.transports.items():
        settings = dict(supplied)
        kind = settings.pop("kind", None)
        devices = [d for d in config.devices if d.transport == name]
        routes = [d.route for d in devices]
        budget = min(d.max_payload for d in devices)
        if kind == "meshtastic":
            adapter = MeshtasticTransport(nodes=routes, max_payload=budget, **settings)
        elif kind == "lora_serial":
            adapter = SerialLoRaTransport(routes=routes, max_payload=budget, **settings)
        elif kind == "tts":
            settings.pop("password_env", None)
            adapter = TtsMqttTransport(max_payload=budget, password=passwords[name], **settings)
        elif kind == "wisgate":
            settings.pop("password_env", None)
            adapter = WisGateMqttTransport(max_payload=budget, password=passwords[name], **settings)
        else:
            raise ConfigError("unsupported_transport_kind")
        stack.callback(adapter.close)
        result[name] = adapter
    return result
