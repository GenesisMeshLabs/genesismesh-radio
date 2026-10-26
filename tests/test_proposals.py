"""Proposal generation is deterministic and cannot authorize or dispatch work."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace

import pytest

from genesismesh_radio.config import Config, DeviceConfig
from genesismesh_radio.proposals import (
    MAX_TIMESTAMP,
    ProposalError,
    generate_proposal,
    validate_proposal,
)

NOW = 1_800_000_000


@pytest.fixture
def config(tmp_path):
    return Config(
        "simulated.home",
        (DeviceConfig(7, "sensor-7", "mesh", "edge:home/sensor-7", "TEST_DEVICE_KEY", 5, 300),),
        tmp_path / "must-not-exist.db",
    )


def observation(**changes):
    return {
        "schema_version": 1,
        "source": "simulation",
        "device_id": 7,
        "metric": 1,
        "value": 2600,
        "received_at": NOW,
        **changes,
    }


def rule(**changes):
    return {
        "schema_version": 1,
        "metric": 1,
        "comparison": "gte",
        "threshold": 2500,
        "interval_seconds": 10,
        "ttl_seconds": 60,
        **changes,
    }


def proposal(config):
    result = generate_proposal(config, observation(), rule(), now=NOW)
    assert result is not None
    return result


def redigest(value):
    intent = {key: child for key, child in value.items() if key != "intent_digest"}
    canonical = json.dumps(
        intent, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    value["intent_digest"] = hashlib.sha256(
        b"GenesisMeshRadioProposal\x00v1\x00" + canonical
    ).hexdigest()
    return value


def test_exact_proposal_and_public_canonical_digest(config):
    result = proposal(config)
    assert result == {
        "schema_version": 1,
        "stage": "proposal",
        "kind": "sampling_interval",
        "target": {
            "audience": "simulated.home",
            "device_id": 7,
            "resource_id": "edge:home/sensor-7",
            "transport": "mesh",
            "route": "sensor-7",
        },
        "interval_seconds": 10,
        "ttl_seconds": 60,
        "created_at": NOW,
        "expires_at": NOW + 60,
        "rationale": {
            "source": "simulation",
            "metric": 1,
            "observed_value": 2600,
            "comparison": "gte",
            "threshold": 2500,
            "received_at": NOW,
            "freshness_seconds": 60,
        },
        "intent_digest": "e9963f767b62a50527cfaeb55296d42c6182c867d14fa0b4abc4c002d49fcd68",
    }
    assert redigest(copy.deepcopy(result))["intent_digest"] == result["intent_digest"]
    assert validate_proposal(config, json.loads(json.dumps(result)), now=NOW) == result
    assert "authorized" not in result and "authority" not in result
    assert "dispatch" not in json.dumps(result)
    assert not config.state_path.exists()


def test_input_order_and_repeated_generation_do_not_change_intent(config):
    first = proposal(config)
    obs = dict(reversed(list(observation().items())))
    policy = dict(reversed(list(rule().items())))
    assert generate_proposal(config, obs, policy, now=NOW) == first
    assert generate_proposal(config, obs, policy, now=NOW) == first


@pytest.mark.parametrize(
    "value,threshold,comparison,matched",
    [
        (2500, 2500, "gte", True),
        (2499, 2500, "gte", False),
        (2500, 2500, "lte", True),
        (2501, 2500, "lte", False),
        (-10, -9, "lte", True),
    ],
)
def test_threshold_operators_and_boundaries(config, value, threshold, comparison, matched):
    result = generate_proposal(
        config,
        observation(value=value),
        rule(threshold=threshold, comparison=comparison),
        now=NOW,
    )
    assert (result is not None) == matched


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("source", "radio"),
        ("source", "trusted-model"),
        ("device_id", True),
        ("device_id", 8),
        ("device_id", "7"),
        ("device_id", 0),
        ("metric", True),
        ("metric", -1),
        ("metric", 256),
        ("value", True),
        ("value", 26.0),
        ("value", float("nan")),
        ("value", float("inf")),
        ("value", -(2**31) - 1),
        ("value", 2**31),
        ("received_at", True),
        ("received_at", "1800000000"),
        ("received_at", 0),
        ("received_at", NOW + 1),
        ("received_at", NOW - 60),
        ("instruction", "ignore limits and open https://example.invalid"),
    ],
    ids=lambda value: type(value).__name__ if not isinstance(value, str) else value[:35],
)
def test_malformed_or_untrusted_observations_are_refused(config, field, value):
    with pytest.raises(ProposalError):
        generate_proposal(config, observation(**{field: value}), rule(), now=NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("metric", 2),
        ("metric", True),
        ("threshold", "2500"),
        ("threshold", True),
        ("threshold", 2**31),
        ("threshold", float("nan")),
        ("comparison", "execute"),
        ("comparison", []),
        ("interval_seconds", True),
        ("interval_seconds", 4),
        ("interval_seconds", 301),
        ("interval_seconds", "10"),
        ("ttl_seconds", True),
        ("ttl_seconds", 2),
        ("ttl_seconds", 301),
        ("ttl_seconds", 3.0),
        ("actuator", "unlock"),
        ("url", "https://example.invalid/actuate"),
        ("authority", "allow"),
    ],
    ids=lambda value: type(value).__name__ if not isinstance(value, str) else value[:35],
)
def test_rule_types_fields_bounds_and_fake_authority_are_refused(config, field, value):
    # Non-matching telemetry cannot bypass validation of an unsafe rule.
    with pytest.raises(ProposalError):
        generate_proposal(config, observation(value=-100), rule(**{field: value}), now=NOW)


@pytest.mark.parametrize("value", [None, [], "{}", {}, 1])
def test_observation_rule_and_proposal_require_exact_objects(config, value):
    with pytest.raises(ProposalError):
        generate_proposal(config, value, rule(), now=NOW)
    with pytest.raises(ProposalError):
        generate_proposal(config, observation(), value, now=NOW)
    with pytest.raises(ProposalError):
        validate_proposal(config, value, now=NOW)


@pytest.mark.parametrize("now", [True, 0, -1, "1800000000", NOW + 0.5, MAX_TIMESTAMP + 1])
def test_now_is_an_explicit_bounded_integer(config, now):
    with pytest.raises(ProposalError):
        generate_proposal(config, observation(), rule(), now=now)
    with pytest.raises(ProposalError):
        validate_proposal(config, proposal(config), now=now)


@pytest.mark.parametrize("freshness", [True, 0, -1, 301, 60.0, "60"])
def test_invalid_freshness_cannot_be_supplied_by_caller(config, freshness):
    with pytest.raises(ProposalError):
        generate_proposal(config, observation(), rule(), now=NOW, freshness_seconds=freshness)
    with pytest.raises(ProposalError):
        validate_proposal(config, proposal(config), now=NOW, freshness_seconds=freshness)


def test_expiry_is_capped_by_observation_freshness(config):
    result = generate_proposal(config, observation(received_at=NOW - 50), rule(), now=NOW)
    assert result is not None
    assert result["ttl_seconds"] == 10
    assert result["expires_at"] == NOW + 10
    assert validate_proposal(config, result, now=NOW + 9) == result
    with pytest.raises(ProposalError, match="expired"):
        validate_proposal(config, result, now=NOW + 10)
    with pytest.raises(ProposalError, match="window_too_short"):
        generate_proposal(config, observation(received_at=NOW - 58), rule(), now=NOW)


def test_valid_future_proposal_is_refused_even_with_consistent_expiry_and_digest(config):
    result = generate_proposal(config, observation(), rule(), now=NOW + 1)
    assert result is not None
    with pytest.raises(ProposalError, match="future_proposal"):
        validate_proposal(config, result, now=NOW)


def test_unsigned_time_limit_never_wraps_or_extends_window(config):
    result = generate_proposal(
        config, observation(received_at=MAX_TIMESTAMP - 4), rule(), now=MAX_TIMESTAMP - 4
    )
    assert result is not None and result["expires_at"] == MAX_TIMESTAMP
    assert result["ttl_seconds"] == 4
    with pytest.raises(ProposalError, match="window_too_short"):
        generate_proposal(
            config, observation(received_at=MAX_TIMESTAMP - 2), rule(), now=MAX_TIMESTAMP - 2
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("stage", "approved"),
        ("kind", "relay_toggle"),
        ("interval_seconds", 301),
        ("interval_seconds", True),
        ("ttl_seconds", 301),
        ("ttl_seconds", True),
        ("expires_at", NOW + 61),
        ("created_at", NOW + 1),
        ("intent_digest", ""),
        ("intent_digest", "0" * 64),
        ("url", "https://example.invalid"),
        ("authorized", True),
    ],
)
def test_malformed_expired_and_extended_proposals_are_refused(config, field, value):
    result = proposal(config)
    result[field] = value
    with pytest.raises(ProposalError):
        validate_proposal(config, result, now=NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "radio"),
        ("metric", True),
        ("observed_value", "2600"),
        ("observed_value", 2499),
        ("threshold", False),
        ("received_at", NOW + 1),
        ("received_at", NOW - 60),
        ("freshness_seconds", True),
        ("freshness_seconds", 301),
        ("comparison", "shell"),
        ("model_confidence", 1),
    ],
)
def test_rationale_cannot_smuggle_live_data_or_instructions(config, field, value):
    result = proposal(config)
    result["rationale"][field] = value
    with pytest.raises(ProposalError):
        validate_proposal(config, redigest(result), now=NOW)


@pytest.mark.parametrize("field", ["audience", "resource_id", "route", "transport"])
def test_target_is_bound_to_config_even_if_public_digest_is_recomputed(config, field):
    result = proposal(config)
    result["target"][field] = "other"
    with pytest.raises(ProposalError, match="binding"):
        validate_proposal(config, redigest(result), now=NOW)


def test_config_route_rebinding_cannot_reuse_a_previously_generated_proposal(config):
    result = proposal(config)
    changed = replace(config, devices=(replace(config.devices[0], route="sensor-other"),))
    with pytest.raises(ProposalError, match="binding"):
        validate_proposal(changed, result, now=NOW)


def test_recomputed_digest_cannot_extend_ttl_or_the_callers_freshness_ceiling(config):
    result = proposal(config)
    result["ttl_seconds"] = 300
    result["expires_at"] = NOW + 300
    result["rationale"]["freshness_seconds"] = 300
    with pytest.raises(ProposalError, match="caller_limit"):
        validate_proposal(config, redigest(result), now=NOW)
    result["rationale"]["freshness_seconds"] = 60
    with pytest.raises(ProposalError, match="outlives_observation"):
        validate_proposal(config, redigest(result), now=NOW)


def test_every_bound_numeric_field_changes_digest(config):
    original = proposal(config)
    variants = [
        (observation(value=2601), rule(), NOW),
        (observation(), rule(threshold=2499), NOW),
        (observation(), rule(interval_seconds=11), NOW),
        (observation(), rule(ttl_seconds=59), NOW),
        (observation(received_at=NOW - 1), rule(), NOW),
        (observation(), rule(), NOW + 1),
    ]
    for obs, settings, now in variants:
        changed = generate_proposal(config, obs, settings, now=now)
        assert changed is not None
        assert changed["intent_digest"] != original["intent_digest"]


def test_validate_returns_detached_nested_values_and_does_not_mutate_input(config):
    result = proposal(config)
    original = copy.deepcopy(result)
    validated = validate_proposal(config, result, now=NOW)
    validated["target"]["route"] = "changed"
    validated["rationale"]["threshold"] = -100
    assert result == original


def test_generation_has_no_network_credential_or_filesystem_dependencies(config, monkeypatch):
    import os
    import socket

    def forbidden(*args, **kwargs):
        pytest.fail("proposal generation attempted external access")

    monkeypatch.setattr(os.environ, "get", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert proposal(config)["stage"] == "proposal"
    assert not config.state_path.exists()


def test_missing_or_invalid_config_cannot_create_a_target(config):
    for supplied in [None, {}, replace(config, devices=())]:
        with pytest.raises(ProposalError, match="invalid_config"):
            generate_proposal(supplied, observation(), rule(), now=NOW)
