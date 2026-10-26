import json
import os
import secrets
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("starlette")

from genesismesh_radio.console import store as storage  # noqa: E402
from genesismesh_radio.console.store import OperatorStore  # noqa: E402
from genesismesh_radio.console_cli import bridge_session, main  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "posix", reason="private CLI state requires POSIX")


def session_file(tmp_path, **changes):
    tmp_path.chmod(0o700)
    data = {
        "schema": "genesismesh-radio-home-session/v1",
        "authority": "real_disposable_genesismesh",
        "hardware_rf_tested": False,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        "control_url": "http://127.0.0.1:17901",
        "control_token": secrets.token_hex(32),
    }
    data.update(changes)
    path = tmp_path / "session.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


@pytest.mark.parametrize(
    "changes",
    [
        {"expires_at": "2000-01-01T00:00:00+00:00"},
        {"expires_at": "2099-01-01T00:00:00"},
        {"expires_at": "not-a-time"},
        {"schema": "wrong"},
        {"authority": "production"},
        {"hardware_rf_tested": True},
    ],
)
def test_handoff_expiry_and_profile_refused(tmp_path, changes):
    with pytest.raises((ValueError, TypeError)):
        bridge_session(session_file(tmp_path, **changes))


def test_handoff_private_permissions_and_size(tmp_path):
    path = session_file(tmp_path)
    assert bridge_session(path)["authority"] == "real_disposable_genesismesh"
    path.chmod(0o644)
    with pytest.raises(ValueError):
        bridge_session(path)
    path.chmod(0o600)
    path.write_text(" " * 16385)
    with pytest.raises(ValueError):
        bridge_session(path)


def test_cli_never_binds_before_tls_or_loopback_validation(tmp_path, monkeypatch, capsys):
    import uvicorn

    tmp_path.chmod(0o700)
    state = tmp_path / "console.db"
    OperatorStore(state, create=True).close()
    monkeypatch.setenv("GM_RADIO_CONTROL_TOKEN", secrets.token_hex(32))

    def forbidden(*args, **kwargs):
        pytest.fail("server must not bind")

    monkeypatch.setattr(uvicorn, "Server", forbidden)
    for extra in (
        ["--origin", "https://192.168.1.2:17902"],
        ["--origin", "http://192.168.1.2:17902", "--development-loopback"],
        ["--control-url", "http://192.168.1.2:17901", "--development-loopback"],
        ["--seconds", "nan", "--development-loopback"],
    ):
        assert main(["serve", "--state", str(state), *extra]) == 2
        assert "console_operation_failed" in capsys.readouterr().err


def test_cli_credential_confirmation_does_not_create_state(tmp_path, monkeypatch):
    import genesismesh_radio.console_cli as cli

    passwords = iter(["first-disposable-password", "different-disposable-password"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda *args: next(passwords))
    state = tmp_path / "new.db"
    assert main(["init", "--state", str(state), "--username", "owner", "--role", "operator"]) == 2
    assert not state.exists()


@pytest.mark.parametrize(
    "username,password",
    [
        ("owner", "short"),
        ("Invalid name", "disposable-console-password"),
        ("owner", "x" * 20 + "\ud800"),
    ],
)
def test_invalid_matching_credentials_do_not_create_state(
    tmp_path, monkeypatch, username, password
):
    import genesismesh_radio.console_cli as cli

    monkeypatch.setattr(cli.getpass, "getpass", lambda *args: password)
    state = tmp_path / "new.db"
    assert main(["init", "--state", str(state), "--username", username, "--role", "operator"]) == 2
    assert not state.exists()


def test_private_state_rejects_symlinks_and_shared_mount(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    state = tmp_path / "actual.db"
    OperatorStore(state, create=True).close()
    link = tmp_path / "linked.db"
    link.symlink_to(state)
    with pytest.raises(OSError):
        OperatorStore(link)
    monkeypatch.setattr(
        storage,
        "_private_filesystem",
        lambda fd: (_ for _ in ()).throw(ValueError("unsupported_private_filesystem")),
    )
    with pytest.raises(ValueError, match="unsupported_private_filesystem"):
        OperatorStore(state)
