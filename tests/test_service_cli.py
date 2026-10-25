"""Lifecycle and operator-facing failures for the continuous-service CLI."""

import json
import signal
from types import SimpleNamespace

import pytest

from genesismesh_radio import cli, provision, service, service_cli


@pytest.mark.parametrize(
    "code,expected",
    [
        ("unsupported_private_permissions", "unsupported_private_permissions"),
        ("unsupported_private_filesystem", "unsupported_private_filesystem"),
        ("unverified_private_filesystem", "unverified_private_filesystem"),
        ("output_directory_exists", "output_directory_exists"),
        ("provisioning_failed_cleanup_incomplete", "provisioning_failed_cleanup_incomplete"),
        ("token=private-value", "operation_failed"),
    ],
)
def test_cli_provisioning_failure_is_actionable_without_arbitrary_exception_text(
    monkeypatch, capsys, code, expected
):
    def fail(*_):
        raise provision.ProvisionError(code)

    monkeypatch.setattr(provision, "provision_bundle", fail)
    assert cli.main(["provision", "--config", "template.toml", "--output", "bundle"]) == 2
    raw = capsys.readouterr().out
    assert "private-value" not in raw
    result = json.loads(raw)
    assert result["code"] == expected
    assert "filesystem" in result["detail"]


def test_cli_provisioning_does_not_read_device_keys(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_keys", lambda *_: pytest.fail("must generate fresh keys"))
    monkeypatch.setattr(provision, "provision_bundle", lambda *_: {"state_initialized": False})
    assert cli.main(["provision", "--config", "template.toml", "--output", "bundle"]) == 0
    assert json.loads(capsys.readouterr().out) == {"state_initialized": False}


@pytest.mark.parametrize("close_raises", [False, True])
def test_serve_restores_sigterm_after_owner_or_cleanup_failure(monkeypatch, close_raises):
    seen = []
    previous = signal.getsignal(signal.SIGTERM)

    class FakeService:
        address = ("127.0.0.1", 17901)

        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            seen.append("start")

        def health(self):
            return {"alive": False}

        def close(self):
            seen.append("close")
            if close_raises:
                raise RuntimeError("close failed")

    monkeypatch.setattr(service, "ControlService", FakeService)
    args = SimpleNamespace(seconds=0, host="127.0.0.1", port=17901, token_env="TEST_CONTROL_TOKEN")
    with pytest.raises(RuntimeError):
        service_cli.serve(args, object(), {}, lambda _: None)
    assert seen == ["start", "close"]
    assert signal.getsignal(signal.SIGTERM) == previous


def test_control_client_cli_reads_only_its_configured_token(monkeypatch):
    seen = []
    monkeypatch.setenv("CUSTOM_CONTROL_TOKEN", "ab" * 32)
    monkeypatch.setenv("GM_RADIO_CONTROL_TOKEN", "not-selected")

    class FakeClient:
        def __init__(self, url, token, *, timeout):
            seen.append((url, token, timeout))

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def health(self):
            return {"ready": True}

    monkeypatch.setattr(service_cli, "ControlClient", FakeClient)
    args = cli.parser().parse_args(["service-health", "--token-env", "CUSTOM_CONTROL_TOKEN"])
    assert service_cli.client_action(args) == {"ready": True}
    assert seen == [("http://127.0.0.1:17901", "ab" * 32, 15)]
