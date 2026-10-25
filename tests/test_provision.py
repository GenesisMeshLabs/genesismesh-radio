import io
import json
import os
import stat
import sys
import uuid
from pathlib import Path

import pytest

from genesismesh_radio.config import ConfigError, binding, load_config, load_keys
from genesismesh_radio.provision import CONTROL_TOKEN_ENV, ProvisionError, provision_bundle
from genesismesh_radio.runtime import validate_runtime

POSIX = pytest.mark.skipif(
    os.name != "posix", reason="Secret bundle creation requires verified POSIX private permissions"
)


@pytest.fixture
def template(tmp_path):
    path = tmp_path / "template.toml"
    path.write_text("""[bridge]
audience = "provision-test"
state_path = "unused-state.db"
[edge]
unix_socket = "/run/genesis-mesh-edge/agent.sock"
timeout = 2.5
[transports.mesh]
kind = "meshtastic"
port = "/dev/ttyUSB0"
channel = 1
app_port = 256
[transports.uart]
kind = "lora_serial"
port = "/dev/ttyUSB1"
baudrate = 9600
[transports.wan]
kind = "tts"
host = "localhost"
port = 1883
tls = false
application = "test@ttn"
username = "test@ttn"
password_env = "EXISTING_TTS_KEY"
f_port = 11
[transports.wan.device_euis]
sensor-3 = "1122334455667788"
[[devices]]
device_id = 1
route = "!aabbccdd"
transport = "mesh"
resource_id = "edge:site/mesh"
key_env = "DEVICE_ONE"
[[devices]]
device_id = 2
route = "sensor-2"
transport = "uart"
resource_id = "edge:site/uart"
key_env = "DEVICE_TWO"
[[devices]]
device_id = 3
route = "sensor-3"
transport = "wan"
resource_id = "edge:site/wan"
key_env = "DEVICE_THREE"
min_interval = 10
max_interval = 300
max_payload = 51
""")
    return path


def _environment(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


@POSIX
def test_roundtrip_unique_keys_binding_and_no_secret_output(
    template, tmp_path, monkeypatch, capsys
):
    for name in ("DEVICE_ONE", "DEVICE_TWO", "DEVICE_THREE", "GM_EDGE_TOKEN", "EXISTING_TTS_KEY"):
        monkeypatch.setenv(name, "ambient-secret-must-not-be-used")
    original = template.read_bytes()
    destination = tmp_path / "bundle"
    result = provision_bundle(template, destination)
    source = load_config(template)
    generated = load_config(destination / "bridge.toml")
    validate_runtime(generated)
    assert generated.edge == source.edge
    assert generated.transports == source.transports
    assert generated.devices == source.devices
    assert generated.state_path == destination / "bridge.db"
    assert not generated.state_path.exists()
    assert template.read_bytes() == original
    environment = _environment(destination / "bridge.env")
    assert set(environment) == {d.key_env for d in source.devices} | {CONTROL_TOKEN_ENV}
    assert len(set(environment.values())) == 4
    assert all(len(bytes.fromhex(value)) == 32 for value in environment.values())
    keys = load_keys(generated, environment)
    assert result["binding"] == binding(generated, keys)
    assert result["state_initialized"] is False
    assert result["external_credential_refs"] == ["EXISTING_TTS_KEY", "GM_EDGE_TOKEN"]
    manifest = json.loads((destination / "manifest.json").read_text())
    assert result == {**manifest, "output_dir": str(destination)}
    for device in source.devices:
        profile = json.loads((destination / "devices" / f"{device.device_id}.json").read_text())
        assert profile["device_id"] == device.device_id
        assert profile["key_hex"] == keys[device.device_id].hex()
        assert profile["protocol_version"] == 1
        assert profile["audience"] == source.audience
        assert profile["route"] == device.route
        assert profile["resource_id"] == device.resource_id
        assert profile["transport"] == device.transport
        assert profile["limits"]["min_interval"] == device.min_interval
        assert profile["limits"]["max_interval"] == device.max_interval
        assert profile["limits"]["max_payload"] == device.max_payload
        assert "session" not in json.dumps(profile)
    assert profile["transport_metadata"] == {
        "kind": "tts",
        "application": "test@ttn",
        "dev_eui": "1122334455667788",
        "f_port": 11,
    }
    assert capsys.readouterr() == ("", "")
    for value in environment.values():
        assert value not in json.dumps(result)
        assert value not in (destination / "manifest.json").read_text()
        assert value not in (destination / "bridge.toml").read_text()
    assert "ambient-secret" not in "".join(
        path.read_text() for path in destination.rglob("*") if path.is_file()
    )


@POSIX
def test_bundle_permissions_are_private(template, tmp_path):
    destination = tmp_path / "bundle"
    provision_bundle(template, destination)
    for path in [destination, *destination.rglob("*")]:
        expected = 0o700 if path.is_dir() else 0o600
        assert stat.S_IMODE(path.stat().st_mode) == expected
        assert path.stat().st_uid == os.getuid()


@pytest.mark.parametrize("filesystem", ["drvfs", "9p", "ntfs", "ntfs3", "fuseblk", "cifs", "smb3"])
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux mount identity enforcement")
def test_known_shared_mount_refused_despite_private_modes(
    template, tmp_path, monkeypatch, filesystem
):
    monkeypatch.setattr("genesismesh_radio.provision._linux_mount_type", lambda _: filesystem)

    def no_keys(_):
        pytest.fail("No secrets may be generated on an unsupported filesystem")

    monkeypatch.setattr("genesismesh_radio.provision.secrets.token_bytes", no_keys)
    with pytest.raises(ProvisionError, match="unsupported_private_filesystem"):
        provision_bundle(template, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


@pytest.mark.parametrize(
    "fdinfo,mountinfo",
    [
        ("pos: 0", "23 1 0:3 / / rw - ext4 /dev/sda rw"),
        ("mnt_id: 23\nmnt_id: 23", "23 1 0:3 / / rw - ext4 /dev/sda rw"),
        ("mnt_id: not-a-number", "23 1 0:3 / / rw - ext4 /dev/sda rw"),
        ("mnt_id: 24", "23 1 0:3 / / rw - ext4 /dev/sda rw"),
        ("mnt_id: 23", "23 1 0:3 / / rw"),
        ("mnt_id: 23", "23 1 - ext4 /dev/sda rw"),
        ("mnt_id: 23", "23 1 0:3 / / rw - ext4"),
        ("mnt_id: 23", "23 1 0:3 / / rw - ext4 /dev/sda rw\n23 1 0:3 / / rw - 9p C: rw"),
    ],
)
def test_unknown_or_ambiguous_mount_identity_is_refused(fdinfo, mountinfo):
    from genesismesh_radio.provision import _mount_type

    with pytest.raises(ProvisionError, match="unverified_private_filesystem"):
        _mount_type(fdinfo, mountinfo)


def test_mount_metadata_uses_descriptor_id_not_mount_path():
    from genesismesh_radio.provision import _mount_type

    mounts = "23 1 0:3 / /unrelated rw - 9p C: rw\n24 1 0:4 / /safe rw - ext4 /dev/sda rw"
    assert _mount_type("pos: 0\nmnt_id:\t24\n", mounts) == "ext4"
    assert _mount_type("mnt_id: 23", mounts) == "9p"


def test_mount_reader_accepts_unrelated_unicode_and_non_utf8_paths(monkeypatch):
    from genesismesh_radio.provision import _linux_mount_type

    mounts = "23 1 0:3 / /共有 rw - 9p C: rw\n".encode()
    mounts += b"25 1 0:5 / /invalid-utf8-\xff rw - tmpfs tmpfs rw\n"
    mounts += b"24 1 0:4 / /safe rw - ext4 /dev/sda rw\n"

    def read_file(path, mode):
        assert mode == "rb"
        if path == "/proc/self/fdinfo/17":
            return io.BytesIO(b"mnt_id: 24\n")
        assert path == "/proc/self/mountinfo"
        return io.BytesIO(mounts)

    monkeypatch.setattr("genesismesh_radio.provision.open", read_file, raising=False)
    assert _linux_mount_type(17) == "ext4"


@pytest.mark.parametrize("oversized", ["fdinfo", "mountinfo"])
def test_mount_metadata_reads_are_bounded(monkeypatch, oversized):
    from genesismesh_radio.provision import _linux_mount_type

    def read_file(path, mode):
        assert mode == "rb"
        if path == "/proc/self/fdinfo/17":
            return io.BytesIO(b"x" * 8193 if oversized == "fdinfo" else b"mnt_id: 24\n")
        assert path == "/proc/self/mountinfo"
        return io.BytesIO(b"x" * (1024 * 1024 + 1))

    monkeypatch.setattr("genesismesh_radio.provision.open", read_file, raising=False)
    with pytest.raises(ProvisionError, match="unverified_private_filesystem"):
        _linux_mount_type(17)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux mount identity enforcement")
def test_unreadable_mount_identity_prevents_creation(template, tmp_path, monkeypatch):
    def unavailable(_):
        raise ProvisionError("unverified_private_filesystem")

    monkeypatch.setattr("genesismesh_radio.provision._linux_mount_type", unavailable)
    with pytest.raises(ProvisionError, match="unverified_private_filesystem"):
        provision_bundle(template, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not Path("/mnt/c").is_dir(),
    reason="Checks the actual Windows drive mount when running in WSL",
)
def test_actual_wsl_windows_mount_is_refused_before_generating_secrets(template, monkeypatch):
    from genesismesh_radio.provision import _linux_mount_type

    descriptor = os.open("/mnt/c", os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert _linux_mount_type(descriptor) in {"drvfs", "9p", "ntfs", "ntfs3", "fuseblk"}
    finally:
        os.close(descriptor)

    def no_keys(_):
        pytest.fail("No secrets may be generated on a Windows drive")

    monkeypatch.setattr("genesismesh_radio.provision.secrets.token_bytes", no_keys)
    destination = Path("/mnt/c") / f"gm-radio-refusal-{uuid.uuid4()}"
    with pytest.raises(ProvisionError, match="unsupported_private_filesystem"):
        provision_bundle(template, destination)
    assert not destination.exists()


@POSIX
@pytest.mark.parametrize("kind", ["file", "directory", "dangling_symlink"])
def test_existing_destination_is_never_overwritten(template, tmp_path, kind):
    destination = tmp_path / "bundle"
    if kind == "directory":
        destination.mkdir()
        (destination / "sentinel").write_text("preserve")
    elif kind == "file":
        destination.write_text("preserve")
    else:
        destination.symlink_to(tmp_path / "missing")
    before = destination.lstat()
    with pytest.raises(ProvisionError, match="output_directory_exists"):
        provision_bundle(template, destination)
    assert destination.lstat() == before
    if kind == "directory":
        assert (destination / "sentinel").read_text() == "preserve"
    elif kind == "file":
        assert destination.read_text() == "preserve"


@POSIX
def test_symlink_ancestor_is_refused(template, tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ProvisionError, match="symlink_ancestor_not_allowed"):
        provision_bundle(template, linked / "bundle")
    assert list(actual.iterdir()) == []


@POSIX
def test_symlink_loop_is_refused_without_path_error(template, tmp_path):
    loop = tmp_path / "loop"
    loop.symlink_to(loop, target_is_directory=True)
    with pytest.raises(ProvisionError, match="output_parent_missing_or_unsafe"):
        provision_bundle(template, loop / "bundle")
    assert loop.is_symlink()


@POSIX
def test_missing_parent_is_not_created(template, tmp_path):
    with pytest.raises(ProvisionError, match="output_parent_missing_or_unsafe"):
        provision_bundle(template, tmp_path / "missing" / "bundle")
    assert not (tmp_path / "missing").exists()


@POSIX
def test_parent_traversal_is_refused(template, tmp_path):
    with pytest.raises(ProvisionError, match="invalid_output_directory"):
        provision_bundle(template, tmp_path / ".." / "bundle")


def test_existing_state_refused_before_platform_or_writes(template, tmp_path):
    state = tmp_path / "unused-state.db"
    state.write_bytes(b"existing-state")
    with pytest.raises(ProvisionError, match="existing_state_requires_explicit_rotation_workflow"):
        provision_bundle(template, tmp_path / "bundle")
    assert state.read_bytes() == b"existing-state"
    assert not (tmp_path / "bundle").exists()


@pytest.mark.parametrize("reference", ["GM_EDGE_TOKEN", "EXISTING_TTS_KEY", CONTROL_TOKEN_ENV])
def test_device_key_reference_collisions_refused(template, tmp_path, reference):
    template.write_text(
        template.read_text().replace('key_env = "DEVICE_ONE"', f'key_env = "{reference}"')
    )
    with pytest.raises(ProvisionError, match="credential_reference_collision"):
        provision_bundle(template, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


def test_control_token_must_not_replace_external_credential(template, tmp_path):
    template.write_text(template.read_text().replace("EXISTING_TTS_KEY", CONTROL_TOKEN_ENV))
    with pytest.raises(ProvisionError, match="credential_reference_collision"):
        provision_bundle(template, tmp_path / "bundle")


def test_runtime_validation_precedes_writes(template, tmp_path):
    template.write_text(
        template.read_text().replace('kind = "meshtastic"', 'kind = "not-supported"')
    )
    with pytest.raises(ConfigError, match="unsupported_transport_kind"):
        provision_bundle(template, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


@POSIX
def test_toml_roundtrip_escapes_values(template, tmp_path):
    audience = 'site["quoted"]\\value'
    port = '/dev/tty"quoted\\USB'
    text = template.read_text().replace('"provision-test"', json.dumps(audience))
    text = text.replace('"/dev/ttyUSB0"', json.dumps(port))
    template.write_text(text)
    destination = tmp_path / "bundle"
    provision_bundle(template, destination)
    result = load_config(destination / "bridge.toml")
    assert result.audience == audience
    assert result.transports["mesh"]["port"] == port


@POSIX
def test_partial_write_failure_cleans_only_own_bundle(template, tmp_path, monkeypatch, capsys):
    real_write = os.write
    calls = 0

    def fail_second_write(descriptor, data):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("sensitive-driver-error")
        return real_write(descriptor, data)

    monkeypatch.setattr("genesismesh_radio.provision.os.write", fail_second_write)
    with pytest.raises(ProvisionError, match="^provisioning_io_failure$"):
        provision_bundle(template, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()
    assert template.exists()
    assert capsys.readouterr() == ("", "")


@POSIX
def test_random_collision_does_not_reuse_a_key(template, tmp_path, monkeypatch):
    monkeypatch.setattr("genesismesh_radio.provision.secrets.token_bytes", lambda _: b"x" * 32)
    with pytest.raises(ProvisionError, match="random_material_collision"):
        provision_bundle(template, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


@POSIX
def test_permission_verification_failure_leaves_no_bundle(template, tmp_path, monkeypatch):
    real_fstat = os.fstat

    def wrong_permissions(descriptor):
        result = list(real_fstat(descriptor))
        result[0] = result[0] | 0o077
        return os.stat_result(result)

    monkeypatch.setattr("genesismesh_radio.provision.os.fstat", wrong_permissions)
    with pytest.raises(ProvisionError, match="unsupported_private_permissions"):
        provision_bundle(template, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


@POSIX
def test_cleanup_does_not_delete_unrecognized_files(template, tmp_path, monkeypatch):
    from genesismesh_radio import provision

    original = provision._write
    destination = tmp_path / "bundle"

    def injected_file(*args):
        original(*args)
        (destination / "unrecognized").write_text("preserve")
        raise OSError("simulated disk failure")

    monkeypatch.setattr(provision, "_write", injected_file)
    with pytest.raises(ProvisionError, match="provisioning_failed_cleanup_incomplete"):
        provision_bundle(template, destination)
    assert (destination / "unrecognized").read_text() == "preserve"
    assert sorted(path.name for path in destination.iterdir()) == ["unrecognized"]


@POSIX
def test_file_stat_failure_closes_descriptor_and_retains_unverified_file(
    template, tmp_path, monkeypatch
):
    real_fstat = os.fstat
    failed = []

    def fail_file_stat(descriptor):
        result = real_fstat(descriptor)
        if stat.S_ISREG(result.st_mode):
            failed.append(descriptor)
            raise OSError("file stat failed")
        return result

    monkeypatch.setattr("genesismesh_radio.provision.os.fstat", fail_file_stat)
    destination = tmp_path / "bundle"
    with pytest.raises(ProvisionError, match="provisioning_failed_cleanup_incomplete") as error:
        provision_bundle(template, destination)
    assert error.value.code == "provisioning_failed_cleanup_incomplete"
    assert len(failed) == 1
    with pytest.raises(OSError):
        real_fstat(failed[0])
    assert (destination / "bridge.toml").read_bytes() == b""
    assert sorted(path.name for path in destination.iterdir()) == ["bridge.toml"]


@pytest.mark.skipif(os.name != "nt", reason="Verifies native Windows fail-closed refusal")
def test_windows_refuses_without_creating_secrets(template, tmp_path, capsys):
    with pytest.raises(ProvisionError, match="unsupported_private_permissions"):
        provision_bundle(template, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()
    assert capsys.readouterr() == ("", "")
