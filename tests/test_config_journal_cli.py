import json
from dataclasses import replace

import pytest

from genesismesh_radio.cli import main
from genesismesh_radio.config import Config, ConfigError, DeviceConfig, load_keys, validate
from genesismesh_radio.journal import Journal, JournalError


def config(tmp_path):
    return Config(
        "site.test",
        (DeviceConfig(1, "s1", "radio", "edge:test/s1", "S1_KEY"),),
        tmp_path / "state.db",
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("device_id", 0),
        ("device_id", True),
        ("route", "../x"),
        ("transport", "a b"),
        ("resource_id", "https://secret"),
        ("key_env", "x key"),
        ("min_interval", 0),
        ("max_interval", 1),
        ("max_payload", 11),
    ],
)
def test_invalid_device_provisioning(tmp_path, field, value):
    original = config(tmp_path)
    modified = replace(original, devices=(replace(original.devices[0], **{field: value}),))
    with pytest.raises(ConfigError):
        validate(modified)


def test_unique_keys_per_device(tmp_path):
    original = config(tmp_path)
    second = DeviceConfig(2, "s2", "radio", "edge:test/s2", "S2_KEY")
    modified = replace(original, devices=(*original.devices, second))
    with pytest.raises(ConfigError, match="distinct"):
        load_keys(modified, {"S1_KEY": "01" * 32, "S2_KEY": "01" * 32})


@pytest.mark.parametrize("secret", ["", "a", "00" * 31, "gg" * 32, "00" * 33])
def test_invalid_key_material(tmp_path, secret):
    with pytest.raises(ConfigError):
        load_keys(config(tmp_path), {"S1_KEY": secret})


def test_state_never_initializes_implicitly(tmp_path):
    with pytest.raises(JournalError, match="state_missing"):
        Journal(tmp_path / "missing.db", "binding")


def test_initialization_never_overwrites(tmp_path):
    path = tmp_path / "state.db"
    Journal.initialize(path, "binding")
    with pytest.raises(FileExistsError):
        Journal.initialize(path, "different")
    with Journal(path, "binding"), pytest.raises(JournalError, match="already_in_use"):
        Journal(path, "binding")


def test_monotonic_state_clock_survives_reopen(tmp_path):
    path = tmp_path / "state.db"
    Journal.initialize(path, "binding")
    with Journal(path, "binding") as journal:
        journal.observe_time(100)
    with Journal(path, "binding") as journal, pytest.raises(JournalError, match="clock_rollback"):
        journal.observe_time(99)


def test_counter_reservation_survives_reopen(tmp_path):
    path = tmp_path / "state.db"
    Journal.initialize(path, "binding")
    with Journal(path, "binding") as journal:
        first = journal.reserve_command("1", 1, 30, 100, 200)
    with Journal(path, "binding") as journal:
        second = journal.reserve_command("2", 1, 30, 100, 200)
    assert (first["counter"], second["counter"]) == (1, 2)


def test_counter_rollover_refused_atomically(tmp_path):
    path = tmp_path / "state.db"
    Journal.initialize(path, "binding")
    with Journal(path, "binding") as journal:
        journal.db.execute("INSERT INTO counters(device_id,tx) VALUES(1,?)", (str(2**64 - 1),))
        journal.db.commit()
        with pytest.raises(JournalError, match="counter_exhausted"):
            journal.reserve_command("1", 1, 30, 100, 200)
        assert not journal.commands()


def test_failed_event_transaction_does_not_advance_counter(tmp_path):
    path = tmp_path / "state.db"
    Journal.initialize(path, "binding")
    with Journal(path, "binding") as journal:
        with pytest.raises(TypeError):
            journal.accept_event(
                device_id=1,
                counter=1,
                digest="d",
                kind="telemetry",
                now=100,
                raw=b"x",
                details={"unserializable": object()},
            )
        result = journal.accept_event(
            device_id=1, counter=1, digest="d", kind="telemetry", now=100, raw=b"x", details={}
        )
        assert not result["duplicate"]


def test_cli_demo_explicitly_identifies_simulation(capsys):
    assert main(["demo"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "simulation"
    assert result["hardware_tested"] is False
    assert result["command"]["state"] == "confirmed"


def test_cli_sanitizes_exception_text(capsys, monkeypatch):
    def fail(*args):
        raise RuntimeError("token=super-secret")

    monkeypatch.setattr("genesismesh_radio.cli.load_config", fail)
    assert main(["check-config", "--config", "missing.toml"]) == 2
    assert "super-secret" not in capsys.readouterr().out
