"""Strict configuration and explicit device-to-resource provisioning."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class DeviceConfig:
    device_id: int
    route: str
    transport: str
    resource_id: str
    key_env: str
    min_interval: int = 5
    max_interval: int = 3600
    max_payload: int = 51


@dataclass(frozen=True)
class Config:
    audience: str
    devices: tuple[DeviceConfig, ...]
    state_path: Path
    edge: dict = field(default_factory=dict)
    transports: dict[str, dict] = field(default_factory=dict)

    def device(self, device_id: int) -> DeviceConfig:
        if type(device_id) is not int or not 1 <= device_id <= 2**32 - 1:
            raise ConfigError("invalid_device_id")
        for device in self.devices:
            if device.device_id == device_id:
                return device
        raise ConfigError("unknown_device")


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"invalid_{name}")
    return value


def validate(config: Config) -> None:
    if not isinstance(config.audience, str) or not re.fullmatch(r"[!-~]{1,128}", config.audience):
        raise ConfigError("invalid_audience")
    if not config.devices:
        raise ConfigError("no_devices")
    ids, routes, resources, key_envs = set(), set(), set(), set()
    for device in config.devices:
        _integer(device.device_id, "device_id", 1, 2**32 - 1)
        _integer(device.min_interval, "min_interval", 1, 65535)
        _integer(device.max_interval, "max_interval", device.min_interval, 65535)
        _integer(device.max_payload, "max_payload", 35, 255)
        for value, name in ((device.route, "route"), (device.transport, "transport")):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_!.-]{1,64}", value):
                raise ConfigError(f"invalid_{name}")
        if not isinstance(device.resource_id, str) or not re.fullmatch(
            r"edge:[A-Za-z0-9_.:/-]{1,180}", device.resource_id
        ):
            raise ConfigError("invalid_resource_id")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", device.key_env):
            raise ConfigError("invalid_key_env")
        if device.device_id in ids or (device.transport, device.route) in routes:
            raise ConfigError("duplicate_device_or_route")
        if device.resource_id in resources or device.key_env in key_envs:
            raise ConfigError("duplicate_resource_or_key_reference")
        ids.add(device.device_id)
        routes.add((device.transport, device.route))
        resources.add(device.resource_id)
        key_envs.add(device.key_env)
    if config.transports and set(config.transports) != {d.transport for d in config.devices}:
        raise ConfigError("transport_device_binding_mismatch")


def load_config(path: str | Path) -> Config:
    path = Path(path).resolve()
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    if set(raw) - {"bridge", "edge", "devices", "transports"}:
        raise ConfigError("unknown_config_section")
    bridge = raw.get("bridge", {})
    if set(bridge) != {"audience", "state_path"}:
        raise ConfigError("bridge_requires_audience_and_state_path")
    state = Path(bridge["state_path"])
    if not state.is_absolute():
        state = path.parent / state
    try:
        devices = tuple(DeviceConfig(**device) for device in raw.get("devices", []))
    except TypeError as exc:
        raise ConfigError("invalid_device_config") from exc
    config = Config(
        bridge["audience"], devices, state.resolve(), raw.get("edge", {}), raw.get("transports", {})
    )
    validate(config)
    return config


def load_keys(config: Config, environ=None) -> dict[int, bytes]:
    environ = os.environ if environ is None else environ
    keys = {}
    seen = set()
    for device in config.devices:
        value = environ.get(device.key_env, "")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ConfigError(f"key_requires_32_random_bytes_hex:{device.key_env}")
        key = bytes.fromhex(value)
        if key in seen:
            raise ConfigError("device_keys_must_be_distinct")
        seen.add(key)
        keys[device.device_id] = key
    return keys


def binding(config: Config, keys: dict[int, bytes]) -> str:
    """Bind persistent counters to the identity, route, resource, and key, not tuning."""
    validate(config)
    devices = []
    for device in sorted(config.devices, key=lambda d: d.device_id):
        key = keys.get(device.device_id)
        if not isinstance(key, bytes) or len(key) < 32:
            raise ConfigError("missing_device_key")
        devices.append(
            {
                "id": device.device_id,
                "route": device.route,
                "transport": device.transport,
                "resource": device.resource_id,
                "key_digest": hashlib.sha256(key).hexdigest(),
            }
        )
    if len({hashlib.sha256(key).digest() for key in keys.values()}) != len(devices):
        raise ConfigError("device_keys_must_be_distinct")
    raw = json.dumps({"audience": config.audience, "devices": devices}, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()
