"""Create private provisioning bundles for fresh devices, without opening services."""

from __future__ import annotations

import json
import math
import os
import secrets
import stat
import sys
from dataclasses import asdict, replace
from pathlib import Path

from .config import Config, binding, load_config
from .protocol import VERSION
from .runtime import validate_runtime

CONTROL_TOKEN_ENV = "GM_RADIO_CONTROL_TOKEN"
_SHARED_FILESYSTEMS = {"drvfs", "9p", "ntfs", "ntfs3", "fuseblk", "cifs", "smb3"}


class ProvisionError(ValueError):
    """A provisioning refusal with a non-secret, machine-readable reason."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _private_platform() -> None:
    if os.name != "posix" or not all(
        hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "getuid", "fchmod")
    ):
        raise ProvisionError("unsupported_private_permissions")


def _private(fd: int, mode: int) -> None:
    try:
        os.fchmod(fd, mode)
        result = os.fstat(fd)
    except OSError:
        raise ProvisionError("unsupported_private_permissions") from None
    if result.st_uid != os.getuid() or stat.S_IMODE(result.st_mode) != mode:
        raise ProvisionError("unsupported_private_permissions")


def _mount_type(fdinfo: str, mountinfo: str) -> str:
    identifiers = [
        line.split(":", 1)[1].strip() for line in fdinfo.splitlines() if line.startswith("mnt_id:")
    ]
    if len(identifiers) != 1 or not identifiers[0].isascii() or not identifiers[0].isdecimal():
        raise ProvisionError("unverified_private_filesystem")
    found = []
    for line in mountinfo.splitlines():
        prefix, separator, suffix = line.partition(" - ")
        fields = prefix.split()
        if fields and fields[0] == identifiers[0]:
            details = suffix.split()
            if not separator or len(fields) < 6 or len(details) < 3:
                raise ProvisionError("unverified_private_filesystem")
            found.append(details[0])
    if len(found) != 1:
        raise ProvisionError("unverified_private_filesystem")
    return found[0]


def _linux_mount_type(fd: int) -> str:
    """Use the opened directory's mount ID, without guessing from its pathname."""

    def read(path, maximum):
        with open(path, "rb") as stream:
            value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise ProvisionError("unverified_private_filesystem")
        return value.decode("utf-8", errors="surrogateescape")

    try:
        return _mount_type(
            read(f"/proc/self/fdinfo/{fd}", 8192),
            read("/proc/self/mountinfo", 1024 * 1024),
        )
    except (OSError, UnicodeError):
        raise ProvisionError("unverified_private_filesystem") from None


def _private_filesystem(fd: int) -> None:
    if sys.platform.startswith("linux") and _linux_mount_type(fd) in _SHARED_FILESYSTEMS:
        raise ProvisionError("unsupported_private_filesystem")


def _directory(path: Path) -> int:
    """Open every ancestor without following symlinks, including during traversal."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _same(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _write(parent: int, name: str, text: str, created: dict) -> None:
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
    )
    try:
        created[name] = os.fstat(descriptor)
        _private(descriptor, 0o600)
        data = text.encode("utf-8")
        while data:
            written = os.write(descriptor, data)
            if written <= 0:
                raise OSError("write failed")
            data = data[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _json(value: dict) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _value(value) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int or type(value) is float and math.isfinite(value):
        return repr(value)
    raise ProvisionError("unsupported_config_value")


def _toml(config: Config) -> str:
    """Serialize only validated tables and primitive values; quote every table key."""
    lines = []

    def table(path, values):
        lines.append("[" + ".".join(_value(part) for part in path) + "]")
        for key, value in values.items():
            if not isinstance(value, dict):
                lines.append(f"{_value(key)} = {_value(value)}")
        lines.append("")
        for key, value in values.items():
            if isinstance(value, dict):
                table((*path, key), value)

    table(("bridge",), {"audience": config.audience, "state_path": "bridge.db"})
    table(("edge",), config.edge)
    for name, settings in config.transports.items():
        table(("transports", name), settings)
    for device in config.devices:
        lines.append("[[devices]]")
        lines.extend(f"{_value(key)} = {_value(value)}" for key, value in asdict(device).items())
        lines.append("")
    return "\n".join(lines)


def _references(config: Config) -> set[str]:
    references = {config.edge.get("token_env", "GM_EDGE_TOKEN")}
    references.update(
        settings.get(
            "password_env",
            "GM_TTS_API_KEY" if settings["kind"] == "tts" else "GM_WISGATE_MQTT_PASSWORD",
        )
        for settings in config.transports.values()
        if settings["kind"] in {"tts", "wisgate"}
    )
    if CONTROL_TOKEN_ENV in references or references.union({CONTROL_TOKEN_ENV}).intersection(
        device.key_env for device in config.devices
    ):
        raise ProvisionError("credential_reference_collision")
    return references


def _material(count: int) -> list[bytes]:
    values = []
    seen = set()
    for _ in range(count):
        for _attempt in range(8):
            value = secrets.token_bytes(32)
            if value not in seen:
                break
        else:
            raise ProvisionError("random_material_collision")
        seen.add(value)
        values.append(value)
    return values


def _profile(config, device, key):
    settings = config.transports[device.transport]
    kind = settings["kind"]
    metadata = {"kind": kind}
    if kind == "meshtastic":
        metadata.update(channel=settings.get("channel", 0), app_port=settings.get("app_port", 256))
    elif kind in {"tts", "wisgate"}:
        metadata.update(
            application=settings["application"],
            dev_eui=settings["device_euis"][device.route],
            f_port=settings.get("f_port", 10),
        )
        if kind == "wisgate":
            metadata["application_id"] = settings["application_id"]
    else:
        metadata["baudrate"] = settings.get("baudrate", 115200)
    return {
        "schema_version": 1,
        "protocol_version": VERSION,
        "audience": config.audience,
        "device_id": device.device_id,
        "key_hex": key.hex(),
        "limits": {
            "min_interval": device.min_interval,
            "max_interval": device.max_interval,
            "max_payload": device.max_payload,
        },
        "route": device.route,
        "resource_id": device.resource_id,
        "transport": device.transport,
        "transport_metadata": metadata,
    }


def _clean_files(parent: int, created: dict) -> bool:
    clean = True
    for name, original in created.items():
        try:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not _same(current, original):
                clean = False
                continue
            os.unlink(name, dir_fd=parent)
        except FileNotFoundError:
            pass
        except OSError:
            clean = False
    return clean


def provision_bundle(config_path: Path, output_dir: Path) -> dict:
    """Provision a new private directory, returning only non-secret metadata.

    No environment credential values are read. Existing bridge state, an existing
    output directory, and unsupported private permissions are explicit refusals.
    """
    config = load_config(config_path)
    validate_runtime(config)
    references = _references(config)
    try:
        config.state_path.stat()
    except FileNotFoundError:
        pass
    except OSError:
        raise ProvisionError("source_state_unavailable") from None
    else:
        raise ProvisionError("existing_state_requires_explicit_rotation_workflow")
    _private_platform()
    output = Path(output_dir).absolute()
    if ".." in output.parts or output.parent == output:
        raise ProvisionError("invalid_output_directory")
    # resolve() is a preliminary check; descriptor traversal below closes symlink races.
    try:
        resolved_parent = output.parent.resolve()
    except (OSError, RuntimeError):
        raise ProvisionError("output_parent_missing_or_unsafe") from None
    if resolved_parent != output.parent:
        raise ProvisionError("symlink_ancestor_not_allowed")
    try:
        parent = _directory(output.parent)
    except OSError:
        raise ProvisionError("output_parent_missing_or_unsafe") from None
    directory = device_directory = None
    created = {}
    device_files = {}
    original = None
    device_original = None
    completed = False
    try:
        _private_filesystem(parent)
        try:
            os.mkdir(output.name, 0o700, dir_fd=parent)
        except FileExistsError:
            raise ProvisionError("output_directory_exists") from None
        original = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        directory = os.open(
            output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        if not _same(original, os.fstat(directory)):
            raise ProvisionError("output_directory_changed")
        _private(directory, 0o700)
        os.fsync(parent)
        os.mkdir("devices", 0o700, dir_fd=directory)
        device_original = os.stat("devices", dir_fd=directory, follow_symlinks=False)
        device_directory = os.open(
            "devices", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
        )
        _private(device_directory, 0o700)
        fresh = _material(len(config.devices) + 1)
        keys = {device.device_id: fresh[index] for index, device in enumerate(config.devices)}
        copied = replace(config, state_path=output / "bridge.db")
        manifest = {
            "schema_version": 1,
            "protocol_version": VERSION,
            "audience": config.audience,
            "device_ids": [device.device_id for device in config.devices],
            "binding": binding(copied, keys),
            "control_token_env": CONTROL_TOKEN_ENV,
            "external_credential_refs": sorted(references),
            "state_initialized": False,
            "files": [
                {"path": "bridge.toml", "secret": False},
                {"path": "bridge.env", "secret": True},
                *(
                    {"path": f"devices/{device.device_id}.json", "secret": True}
                    for device in config.devices
                ),
                {"path": "manifest.json", "secret": False},
            ],
            "instructions": [
                "Use only with fresh devices; this bundle is not a rotation or recovery tool.",
                "Provision each secret device profile through a trusted local device workflow.",
                "Load bridge.env privately and supply existing edge/MQTT credentials separately.",
                "Initialize bridge state explicitly before starting the service.",
                "Keep profiles and bridge.env out of Git, logs and shared storage.",
            ],
        }
        _write(directory, "bridge.toml", _toml(copied), created)
        environment = "".join(
            f"{device.key_env}={keys[device.device_id].hex()}\n" for device in config.devices
        )
        environment += f"{CONTROL_TOKEN_ENV}={fresh[-1].hex()}\n"
        _write(directory, "bridge.env", environment, created)
        for device in config.devices:
            _write(
                device_directory,
                f"{device.device_id}.json",
                _json(_profile(copied, device, keys[device.device_id])),
                device_files,
            )
        _write(directory, "manifest.json", _json(manifest), created)
        os.fsync(device_directory)
        os.fsync(directory)
        os.fsync(parent)
        if output.resolve() != output or not _same(output.stat(), os.fstat(directory)):
            raise ProvisionError("output_directory_changed")
        completed = True
        return {**manifest, "output_dir": str(output)}
    except OSError:
        raise ProvisionError("provisioning_io_failure") from None
    finally:
        clean = True
        if not completed and directory is not None:
            if device_directory is not None:
                clean &= _clean_files(device_directory, device_files)
            clean &= _clean_files(directory, created)
            if device_original is not None:
                try:
                    current = os.stat("devices", dir_fd=directory, follow_symlinks=False)
                    if _same(current, device_original):
                        os.rmdir("devices", dir_fd=directory)
                    else:
                        clean = False
                except OSError:
                    clean = False
        if not completed and original is not None:
            try:
                current = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
                if _same(current, original):
                    os.rmdir(output.name, dir_fd=parent)
                    os.fsync(parent)
                else:
                    clean = False
            except OSError:
                clean = False
        for descriptor in (device_directory, directory, parent):
            if descriptor is not None:
                os.close(descriptor)
        if not clean:
            raise ProvisionError("provisioning_failed_cleanup_incomplete") from None
