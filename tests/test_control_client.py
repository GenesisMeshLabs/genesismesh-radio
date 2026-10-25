"""The control client cannot widen the network boundary or retry uncertain writes."""

import json
import uuid

import httpx
import pytest

from genesismesh_radio import cli
from genesismesh_radio.control_client import ControlClient, ControlError

TOKEN = "ab" * 32
COMMAND_ID = "11111111-1111-4111-8111-111111111111"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:17901",
        "http://localhost:17901",
        "https://127.0.0.1:17901",
        "http://127.0.0.1:17901/api",
        "http://user:password@127.0.0.1:17901",
        "http://127.0.0.1:17901?secret=value",
        "http://127.0.0.1:17901#fragment",
        "http://[::1]:17901",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
    ],
)
def test_control_origin_rejects_remote_names_credentials_and_paths(url):
    with pytest.raises(ValueError):
        ControlClient(url, TOKEN)


@pytest.mark.parametrize("value", [None, "", "short", "a" * 63, "AB" * 32, "x" * 64])
def test_control_token_requires_canonical_random_key(value):
    with pytest.raises(ValueError):
        ControlClient("http://127.0.0.1:17901", value)


@pytest.mark.parametrize("value", [True, 0, -1, float("nan"), float("inf"), 61])
def test_control_timeout_bounded(value):
    with pytest.raises(ValueError):
        ControlClient("http://127.0.0.1:17901", TOKEN, timeout=value)


def test_control_routes_bearer_and_exact_command_body():
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(202 if request.method == "POST" else 200, json={"ok": True})

    with ControlClient(
        "http://127.0.0.1:17901", TOKEN, transport=httpx.MockTransport(handle)
    ) as client:
        client.health()
        client.status()
        client.result(COMMAND_ID)
        client.command(COMMAND_ID, 7, 120, 30)
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/healthz"),
        ("GET", "/v1/status"),
        ("GET", f"/v1/commands/{COMMAND_ID}"),
        ("POST", "/v1/commands"),
    ]
    assert all(r.headers["authorization"] == f"Bearer {TOKEN}" for r in seen)
    assert all(r.headers["host"] == "127.0.0.1:17901" for r in seen)
    assert json.loads(seen[-1].content) == {
        "command_id": COMMAND_ID,
        "device_id": 7,
        "interval_seconds": 120,
        "ttl": 30,
    }


def test_default_http_port_remains_explicit_in_required_host_header():
    seen = []

    def handle(request):
        seen.append(request.headers["host"])
        return httpx.Response(200, json={"ready": True})

    with ControlClient(
        "http://127.0.0.1:80", TOKEN, transport=httpx.MockTransport(handle)
    ) as client:
        client.health()
    assert seen == ["127.0.0.1:80"]


@pytest.mark.parametrize("failure", ["timeout", "http-504", "bad-json", "huge-response"])
def test_uncertain_command_keeps_id_and_never_retries(failure):
    seen = []

    def handle(request):
        seen.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("sensitive dependency text", request=request)
        if failure == "http-504":
            return httpx.Response(504, text="sensitive dependency text")
        return httpx.Response(200, content=b"bad" if failure == "bad-json" else b"x" * 262145)

    with (
        ControlClient(
            "http://127.0.0.1:17901", TOKEN, transport=httpx.MockTransport(handle)
        ) as client,
        pytest.raises(ControlError) as error,
    ):
        client.command(COMMAND_ID, 1, 60)
    assert len(seen) == 1
    assert error.value.code == "command_result_unknown"
    assert error.value.command_id == COMMAND_ID
    assert "sensitive" not in str(error.value)


@pytest.mark.parametrize("status", [301, 401, 403, 404, 409, 429])
def test_http_errors_are_sanitized_and_redirects_not_followed(status):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(status, headers={"Location": "http://remote.invalid"}, text="secret")

    with (
        ControlClient(
            "http://127.0.0.1:17901", TOKEN, transport=httpx.MockTransport(handle)
        ) as client,
        pytest.raises(ControlError) as error,
    ):
        client.status()
    assert len(seen) == 1
    assert error.value.status_code == status
    assert str(error.value) == "control_http_error"


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1e999}',
        b'{"a":' + b"[" * 100 + b"0" + b"]" * 100 + b"}",
    ],
    ids=["array", "duplicate", "nan", "overflow", "deep"],
)
def test_malformed_response_is_not_trusted(raw):
    with (
        ControlClient(
            "http://127.0.0.1:17901",
            TOKEN,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=raw)),
        ) as client,
        pytest.raises(ControlError, match="control_invalid_response"),
    ):
        client.status()


@pytest.mark.parametrize(
    "values",
    [(True, 60, 60), (1, True, 60), (1, 60, True), (0, 60, 60), (1, 65536, 60), (1, 60, 301)],
)
def test_invalid_command_does_not_contact_service(values):
    with (
        ControlClient("http://127.0.0.1:17901", TOKEN) as client,
        pytest.raises(ValueError),
    ):
        client.command(COMMAND_ID, *values)


def test_cli_control_failure_preserves_request_id_without_secrets(monkeypatch, capsys):
    def fail(_):
        raise ControlError("command_result_unknown", command_id=COMMAND_ID) from RuntimeError(TOKEN)

    monkeypatch.setattr(cli, "client_action", fail)
    assert (
        cli.main(
            ["service-command", "--device-id", "1", "--interval", "60", "--request-id", COMMAND_ID]
        )
        == 2
    )
    raw = capsys.readouterr().out
    assert TOKEN not in raw
    result = json.loads(raw)
    assert result["command_id"] == COMMAND_ID
    assert result["code"] == "command_result_unknown"


def test_cli_control_paths_do_not_open_local_journal(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_config", lambda _: pytest.fail("client must not own state"))
    monkeypatch.setattr(cli, "client_action", lambda _: {"ready": True})
    assert cli.main(["service-health"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ready": True}


def test_command_uuid_is_required_on_cli():
    with pytest.raises(SystemExit):
        cli.parser().parse_args(["service-command", "--device-id", "1", "--interval", "60"])
    assert (
        cli.parser().parse_args(["service-result", "--request-id", str(uuid.uuid4())]).action
        == "service-result"
    )
