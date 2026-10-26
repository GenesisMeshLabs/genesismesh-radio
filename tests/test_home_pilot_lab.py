"""Redaction, pinning and private-session checks for the disposable home lab."""

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "home_pilot_lab", Path(__file__).resolve().parents[1] / "scripts/home_pilot_lab.py"
)
assert SPEC is not None and SPEC.loader is not None
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)
import home_pilot_scenario as scenario  # noqa: E402

from genesismesh_radio.config import Config, DeviceConfig  # noqa: E402
from genesismesh_radio.control_client import ControlClient, ControlError  # noqa: E402


def test_check_records_only_named_passes_and_never_echoes_bad_input():
    report = {"checks": []}
    lab.check(report, "home_online_allowed", True)
    assert report == {"checks": ["home_online_allowed"]}
    with pytest.raises(lab.LabError, match="^home_denied$"):
        lab.check(report, "home_denied", False)
    with pytest.raises(lab.LabError, match="^invalid_check_name$"):
        lab.check(report, "private-token=do-not-output", True)
    assert report == {"checks": ["home_online_allowed"]}


def test_runtime_binary_has_exact_version_and_file_hash(tmp_path, monkeypatch):
    binary = tmp_path / "edge"
    binary.write_bytes(b"public fixture, never executed")
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="genesis-mesh-edge 1.8.1\n")

    monkeypatch.setattr(lab.subprocess, "run", run)
    assert lab.binary_info(binary, "genesis-mesh-edge") == {
        "version": "genesis-mesh-edge 1.8.1",
        "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    assert calls[0][0] == [str(binary.resolve()), "--version"]
    assert calls[0][1]["timeout"] == 10


def test_runtime_binary_version_drift_and_empty_file_are_refused(tmp_path, monkeypatch):
    binary = tmp_path / "edge"
    binary.write_bytes(b"fixture")
    monkeypatch.setattr(
        lab.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, stdout="unexpected private text"
        ),
    )
    with pytest.raises(lab.LabError, match="^unexpected_runtime_version$"):
        lab.binary_info(binary, "genesis-mesh-edge")
    binary.write_bytes(b"")
    with pytest.raises(lab.LabError, match="^invalid_runtime_binary$"):
        lab.binary_info(binary, "genesis-mesh-edge")


@pytest.mark.parametrize("dirty,revision", [(" M module.py", lab.CORE_REVISION), ("", "0" * 40)])
def test_modified_or_unpinned_core_source_is_refused(tmp_path, monkeypatch, dirty, revision):
    package = tmp_path / "genesis_mesh"
    package.mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname="genesis-mesh"\nversion="1.8.1"\n')
    monkeypatch.setitem(
        sys.modules,
        "genesis_mesh",
        SimpleNamespace(__file__=str(package / "__init__.py"), __version__="1.8.1"),
    )

    def git_value(path, *args):
        return dirty if args[0] == "status" else revision

    monkeypatch.setattr(lab, "git_value", git_value)
    with pytest.raises(lab.LabError, match="^pinned_core_source_required$"):
        lab.runtime_info("not executed", "not executed")


def test_unsupported_platform_is_a_redacted_failed_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(lab.platform, "system", lambda: "Windows")
    report = tmp_path / "report.json"
    assert lab.main(["--report", str(report)]) == 1
    saved = json.loads(report.read_text())
    assert saved["status"] == "failed"
    assert saved["error"] == "requires_linux_or_wsl"
    assert saved["hardware_rf_tested"] is False
    assert saved["checks"] == []
    assert "token" not in capsys.readouterr().out


def test_unexpected_failure_never_reports_exception_contents(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(lab.platform, "system", lambda: "Linux")

    def failure(*args):
        raise RuntimeError("PRIVATE_TOKEN_AND_ADDRESS_MUST_NOT_APPEAR")

    monkeypatch.setattr(lab, "runtime_info", failure)
    report = tmp_path / "report.json"
    assert (
        lab.main(
            ["--edge-binary", "fixture", "--verify-binary", "fixture", "--report", str(report)]
        )
        == 1
    )
    assert json.loads(report.read_text())["error"] == "RuntimeError"
    assert "PRIVATE_TOKEN" not in report.read_text() + capsys.readouterr().out


def test_console_checks_require_extra_before_starting_private_services(tmp_path, monkeypatch):
    monkeypatch.setattr(lab.platform, "system", lambda: "Linux")

    def missing_extra(name):
        raise ModuleNotFoundError("private environment detail")

    monkeypatch.setattr(lab.importlib, "import_module", missing_extra)
    report = tmp_path / "report.json"
    assert (
        lab.main(
            [
                "--edge-binary",
                "fixture",
                "--verify-binary",
                "fixture",
                "--console-checks",
                "--report",
                str(report),
            ]
        )
        == 1
    )
    saved = json.loads(report.read_text())
    assert saved["error"] == "console_extra_required"
    assert saved["checks"] == [] and saved["private_state_removed"] is None
    assert "private environment detail" not in report.read_text()


@pytest.mark.skipif(os.name != "posix", reason="Linux private-session permission contract")
def test_private_session_has_bounds_expiry_and_never_overwrites(tmp_path):
    tmp_path.chmod(0o700)
    config = Config(
        "home-pilot-lab",
        (DeviceConfig(1, "!aabbccd1", "mesh-1", "edge:radio-lab/home-node-1", "TEST_KEY"),),
        tmp_path / "not-created.db",
    )
    service = SimpleNamespace(address=("127.0.0.1", 12345))
    before = datetime.now(UTC)
    path = scenario.private_session(tmp_path, service, config, "1" * 64, 5)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    session = json.loads(path.read_text())
    assert session["schema"] == "genesismesh-radio-home-session/v1"
    assert session["hardware_rf_tested"] is False
    assert session["radio"] == "simulated_injected_meshtastic"
    assert session["devices"][0]["min_interval"] == 5
    assert 4 <= (datetime.fromisoformat(session["expires_at"]) - before).total_seconds() <= 6
    content = path.read_bytes()
    with pytest.raises(FileExistsError):
        scenario.private_session(tmp_path, service, config, "2" * 64, 5)
    assert path.read_bytes() == content


@pytest.mark.skipif(os.name != "posix", reason="Linux private-session permission contract")
def test_shared_directory_is_refused_before_session_creation(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match="private_session_directory_required"):
        scenario.private_session(tmp_path, None, None, "1" * 64, 5)
    assert not (tmp_path / "session.json").exists()


@pytest.mark.skipif(os.name != "posix", reason="Actual Linux temporary-directory contract")
def test_scenario_failure_cleans_private_state_and_redacts_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(lab, "runtime_info", lambda *args: {"core_version": "fixture"})
    roots = []

    def scenario_failure(root, *args, **kwargs):
        roots.append(root)
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        (root / "private-key.json").write_text("DO_NOT_DISCLOSE_THIS_FIXTURE")
        raise ValueError("DO_NOT_DISCLOSE_THIS_FIXTURE")

    monkeypatch.setattr(scenario, "home_pilot_scenarios", scenario_failure)
    report = tmp_path / "report.json"
    assert (
        lab.main(
            ["--edge-binary", "fixture", "--verify-binary", "fixture", "--report", str(report)]
        )
        == 1
    )
    assert len(roots) == 1 and not roots[0].exists()
    assert "DO_NOT_DISCLOSE" not in report.read_text() + capsys.readouterr().out
    saved = json.loads(report.read_text())
    assert saved["hardware_rf_tested"] is False
    assert saved["error"] == "ValueError"
    assert saved["private_state_removed"] is True


@pytest.mark.parametrize("seconds", [-1, 0, 301, True, 1.0])
def test_session_hold_is_explicitly_bounded_before_any_io(seconds):
    with pytest.raises(ValueError, match="invalid_hold_seconds"):
        scenario.private_session(None, None, None, None, seconds)


@pytest.mark.integration
@pytest.mark.skipif(
    os.name != "posix" or os.environ.get("GM_HOME_PILOT_INTEGRATION") != "1",
    reason="Opt-in disposable real authority/edge home-session test",
)
def test_real_home_session_confirms_once_expires_and_redacts(tmp_path, monkeypatch, capsys):
    from live_support import wait_for

    seen = {}

    def inspect_session(path):
        session = json.loads(path.read_text())
        seen.update(path=path, **session)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        with ControlClient(session["control_url"], session["control_token"]) as client:
            command_id = str(uuid.uuid4())
            pending = client.command(command_id, 1, 45)
            assert pending["state"] == "dispatched"
            result = wait_for(
                lambda: row if (row := client.result(command_id))["state"] == "confirmed" else None,
                timeout=5,
                description="optional home console command",
            )
            duplicate = client.command(command_id, 1, 45)
            assert result["counter"] == duplicate["counter"]
            assert duplicate["state"] == "confirmed"

    monkeypatch.setattr(lab, "announce_session", inspect_session)
    report = tmp_path / "home-result.json"
    arguments = [
        "--edge-binary",
        os.environ["GM_EDGE_BINARY"],
        "--verify-binary",
        os.environ["GM_VERIFY_BINARY"],
        "--hold-seconds",
        "3",
        "--report",
        str(report),
    ]
    console_checks = os.environ.get("GM_HOME_PILOT_CONSOLE_CHECKS") == "1"
    if console_checks:
        arguments.append("--console-checks")
    assert lab.main(arguments) == 0
    assert not seen["path"].exists()
    with (
        ControlClient(seen["control_url"], seen["control_token"], timeout=1) as client,
        pytest.raises(ControlError, match="control_unavailable"),
    ):
        client.health()
    saved = json.loads(report.read_text())
    assert saved["status"] == "passed" and len(saved["checks"]) == 22 + 12 * console_checks
    assert saved["hardware_rf_tested"] is False
    assert saved["private_state_removed"] is True
    assert "home_optional_session_expired" in saved["checks"]
    if console_checks:
        assert saved["console_scope_refusal"] == {
            "core_http_status": 400,
            "core_code": "resource_out_of_scope",
            "bridge_state": "uncertain",
            "simulated_device_dispatched": False,
        }
    output = report.read_text() + capsys.readouterr().out
    assert seen["control_token"] not in output
    assert seen["control_url"] not in output
