"""Contract tests of the actual local API boundary, including malformed decisions."""

import json

import httpx
import pytest

from genesismesh_radio.edge import EdgeClient, EdgeError


def reply(**changes):
    return {
        "allowed": True,
        "authorization_id": "authorization-123",
        "authority": "decision",
        "report_by": "2030-01-01T00:00:00Z",
        "code": None,
        **changes,
    }


def client_for(value, status=200):
    return EdgeClient(
        token="disposable-test-token",
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=value)),
    )


def test_authorization_uses_real_contract_without_operator_credentials():
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json=reply())

    with EdgeClient(token="local-token", transport=httpx.MockTransport(handle)) as edge:
        result = edge.authorize("edge:radio/device1", 60, "command-1")
    assert result.allowed
    assert result.report_by == 1893456000
    assert result.authority == "decision"
    request = seen[0]
    assert request.url.path == "/v1/authorize"
    assert request.headers["authorization"] == "Bearer local-token"
    assert not any(key.startswith("x-admin-") for key in request.headers)
    assert json.loads(request.content) == {
        "capability": "radio.command.dispatch",
        "request_parameters": {"interval_seconds": 60},
        "attributes": {"command_id": "command-1"},
        "resource_id": "edge:radio/device1",
        "resource_action": "update",
    }


@pytest.mark.parametrize("authority", ["decision", "grant", "break_glass"])
def test_client_preserves_authority_for_controller_to_restrict(authority):
    with client_for(reply(authority=authority)) as edge:
        assert edge.authorize("edge:a/device", 60, "cmd").authority == authority


def test_denial_is_not_an_authorization():
    with client_for(reply(allowed=False, authority=None, report_by=None, code="na_denied")) as edge:
        decision = edge.authorize("edge:a/device", 60, "cmd")
    assert not decision.allowed
    assert decision.report_by == 0
    assert decision.code == "na_denied"


@pytest.mark.parametrize(
    "code",
    ["provider_credential-secret", "secret=private value", "x" * 1000],
    ids=["unknown-code", "secret-in-code", "oversized-code"],
)
def test_unknown_denial_codes_are_not_forwarded_to_the_journal(code):
    with client_for(reply(allowed=False, authority=None, report_by=None, code=code)) as edge:
        decision = edge.authorize("edge:a/device", 60, "cmd")
    assert decision.code == "edge_denied"


@pytest.mark.parametrize(
    "changes",
    [
        {"allowed": "true"},
        {"allowed": 1},
        {"authority": "cached_atlas"},
        {"authority": []},
        {"authority": {}},
        {"authority": None},
        {"authorization_id": None},
        {"authorization_id": "../escape"},
        {"report_by": None},
        {"report_by": 1893456000},
        {"report_by": "2030-01-01T00:00:00"},
        {"report_by": "invalid"},
        {"code": []},
        {"allowed": False},
    ],
)
def test_malformed_authorization_fails_closed(changes):
    with client_for(reply(**changes)) as edge, pytest.raises(EdgeError):
        edge.authorize("edge:a/device", 60, "cmd")


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://192.168.1.2:7000",
        "http://localhost:7000",
        "http://127.0.0.1:7000/path",
        "http://token@127.0.0.1:7000",
        "http://127.0.0.1:7000?token=secret",
        "http://127.0.0.1:7000#fragment",
        "ftp://127.0.0.1:7000",
        "http://127.0.0.1:bad",
    ],
)
def test_remote_or_ambiguous_urls_are_rejected(url):
    with pytest.raises(ValueError):
        EdgeClient(url, token="local")


def test_tcp_requires_token_but_unix_uses_peer_credentials(tmp_path):
    with pytest.raises(ValueError):
        EdgeClient()
    with EdgeClient(
        unix_socket=str(tmp_path / "edge.sock"),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"state": "active"})),
    ) as edge:
        assert edge.status() == {"state": "active"}


@pytest.mark.parametrize("status", [301, 307, 401, 403, 409, 410, 429, 500])
def test_http_errors_are_sanitized_and_never_retried(status):
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(status, text="secret upstream response")

    with (
        EdgeClient(token="test-secret", transport=httpx.MockTransport(handle)) as edge,
        pytest.raises(EdgeError, match="edge_http_error") as error,
    ):
        edge.authorize("edge:a/device", 60, "cmd")
    assert len(calls) == 1
    assert error.value.status_code == status
    assert "secret" not in str(error.value)


@pytest.mark.parametrize(
    "payload",
    [b"[]", b"{bad", b'{"allowed":true,"allowed":false}', b'{"value": NaN}', b" " * 65537],
    ids=["array", "malformed", "duplicate-key", "nonfinite", "oversized"],
)
def test_invalid_json_and_oversize_response_fail_closed(payload):
    with (
        EdgeClient(
            token="local",
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=payload)),
        ) as edge,
        pytest.raises(EdgeError),
    ):
        edge.status()


def test_timeout_is_ambiguous_and_not_retried():
    calls = []

    def timeout(request):
        calls.append(request)
        raise httpx.ReadTimeout("private transport details", request=request)

    with (
        EdgeClient(token="local", transport=httpx.MockTransport(timeout)) as edge,
        pytest.raises(EdgeError, match="edge_transport_error"),
    ):
        edge.authorize("edge:a/device", 60, "cmd")
    assert len(calls) == 1


def test_report_distinguishes_queued_from_admitted_evidence():
    seen = []

    def handle(request):
        seen.append(json.loads(request.content))
        return httpx.Response(
            200, json={"record_kind": "grant_execution", "record_id": "record-1", "queued": True}
        )

    with EdgeClient(token="local", transport=httpx.MockTransport(handle)) as edge:
        result = edge.report("auth-1", "success", {"packet_digest": "abc"}, "device confirmed")
    assert result["queued"] is True
    assert seen == [
        {
            "outcome": "success",
            "execution_parameters": {"packet_digest": "abc"},
            "outcome_detail": "device confirmed",
        }
    ]


@pytest.mark.parametrize("outcome", ["pending", "unknown", "queued"])
def test_non_contract_outcomes_are_rejected(outcome):
    with client_for({}) as edge, pytest.raises(ValueError):
        edge.report("auth-1", outcome, {}, "not confirmed")


def test_outcome_response_must_identify_evidence():
    with client_for({"queued": False}) as edge, pytest.raises(EdgeError):
        edge.report("auth-1", "failure", {}, "no device confirmation")


@pytest.mark.parametrize("token", ["contains space", "new\nline", "control\x00", "unicodeé"])
def test_invalid_header_tokens_are_rejected_at_configuration(token):
    with pytest.raises(ValueError, match="bearer token"):
        EdgeClient(token=token)


def test_deep_json_is_a_sanitized_contract_error():
    payload = b'{"nested":' + b"[" * 20000 + b"0" + b"]" * 20000 + b"}"
    with (
        EdgeClient(
            token="local",
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=payload)),
        ) as edge,
        pytest.raises(EdgeError, match="edge_invalid_json"),
    ):
        edge.status()


@pytest.mark.parametrize("payload", [b'{"number":1e999}', b'{"number":-1e999}'])
def test_numeric_overflow_is_refused(payload):
    with (
        EdgeClient(
            token="local",
            transport=httpx.MockTransport(lambda _: httpx.Response(200, content=payload)),
        ) as edge,
        pytest.raises(EdgeError, match="edge_invalid_json"),
    ):
        edge.status()
