"""Deterministic sampling proposals from explicitly simulated telemetry.

This module has no transport, credentials, policy engine or physical effects.
A valid proposal is only a bounded request for human review and subsequent
authorization by the existing GenesisMesh core/edge path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re

from .config import Config, ConfigError, validate

MAX_TIMESTAMP = 0xFFFFFFFF
MAX_FRESHNESS_SECONDS = 300
MIN_TTL_SECONDS = 3
MAX_TTL_SECONDS = 300
_DOMAIN = b"GenesisMeshRadioProposal\x00v1\x00"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OBSERVATION = {"schema_version", "source", "device_id", "metric", "value", "received_at"}
_RULE = {
    "schema_version",
    "metric",
    "comparison",
    "threshold",
    "interval_seconds",
    "ttl_seconds",
}
_PROPOSAL = {
    "schema_version",
    "stage",
    "kind",
    "target",
    "interval_seconds",
    "ttl_seconds",
    "created_at",
    "expires_at",
    "rationale",
    "intent_digest",
}
_TARGET = {"audience", "device_id", "resource_id", "transport", "route"}
_RATIONALE = {
    "source",
    "metric",
    "observed_value",
    "comparison",
    "threshold",
    "received_at",
    "freshness_seconds",
}


class ProposalError(ValueError):
    """A non-secret validation reason; no invalid proposal can become dispatch."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _exact(value, keys, code):
    if type(value) is not dict or set(value) != keys:
        raise ProposalError(code)


def _integer(value, code, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ProposalError(code)
    return value


def _literal(value, expected, code):
    if type(value) is not str or value != expected:
        raise ProposalError(code)


def _configuration(config):
    if not isinstance(config, Config):
        raise ProposalError("invalid_config")
    try:
        validate(config)
    except (ConfigError, TypeError, AttributeError):
        raise ProposalError("invalid_config") from None


def _device(config, device_id):
    _integer(device_id, "invalid_device_id", 1, 0xFFFFFFFF)
    try:
        return config.device(device_id)
    except ConfigError:
        raise ProposalError("unknown_device") from None


def _target(config, device):
    return {
        "audience": config.audience,
        "device_id": device.device_id,
        "resource_id": device.resource_id,
        "transport": device.transport,
        "route": device.route,
    }


def _comparison(value, threshold, comparison):
    if type(comparison) is not str or comparison not in {"gte", "lte"}:
        raise ProposalError("invalid_comparison")
    return value >= threshold if comparison == "gte" else value <= threshold


def _freshness(now, received_at, freshness_seconds):
    _integer(now, "invalid_now", 1, MAX_TIMESTAMP)
    _integer(received_at, "invalid_received_at", 1, MAX_TIMESTAMP)
    _integer(freshness_seconds, "invalid_freshness", 1, MAX_FRESHNESS_SECONDS)
    if received_at > now:
        raise ProposalError("future_observation")
    if now - received_at >= freshness_seconds:
        raise ProposalError("stale_observation")


def _digest(intent):
    # This restricted profile contains ASCII strings and integers only. Digest
    # domain separation prevents treating this identifier as a core trust record.
    canonical = json.dumps(
        intent, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return hashlib.sha256(_DOMAIN + canonical).hexdigest()


def generate_proposal(
    config: Config,
    observation: dict,
    rule: dict,
    *,
    now: int,
    freshness_seconds: int = 60,
) -> dict | None:
    """Return a sampling proposal when a numeric threshold matches, else None.

    Validate all inputs even for a non-matching rule. Proposal TTL is shortened
    to the remaining observation freshness and never exceeds the wire's bounds.
    No device, bridge journal, model or authority is consulted or changed.
    """
    _configuration(config)
    _exact(observation, _OBSERVATION, "invalid_observation_fields")
    _exact(rule, _RULE, "invalid_rule_fields")
    _integer(observation["schema_version"], "unsupported_observation_version", 1, 1)
    _integer(rule["schema_version"], "unsupported_rule_version", 1, 1)
    _literal(observation["source"], "simulation", "simulation_required")
    device = _device(config, observation["device_id"])
    metric = _integer(observation["metric"], "invalid_metric", 0, 255)
    if _integer(rule["metric"], "invalid_rule_metric", 0, 255) != metric:
        raise ProposalError("metric_mismatch")
    value = _integer(observation["value"], "invalid_observed_value", -0x80000000, 0x7FFFFFFF)
    threshold = _integer(rule["threshold"], "invalid_threshold", -0x80000000, 0x7FFFFFFF)
    _freshness(now, observation["received_at"], freshness_seconds)
    interval = _integer(
        rule["interval_seconds"],
        "interval_outside_device_limits",
        device.min_interval,
        device.max_interval,
    )
    requested_ttl = _integer(rule["ttl_seconds"], "invalid_ttl", MIN_TTL_SECONDS, MAX_TTL_SECONDS)
    matches = _comparison(value, threshold, rule["comparison"])
    if not matches:
        return None
    expires = min(
        now + requested_ttl, observation["received_at"] + freshness_seconds, MAX_TIMESTAMP
    )
    if expires - now < MIN_TTL_SECONDS:
        raise ProposalError("observation_window_too_short")
    intent = {
        "schema_version": 1,
        "stage": "proposal",
        "kind": "sampling_interval",
        "target": _target(config, device),
        "interval_seconds": interval,
        "ttl_seconds": expires - now,
        "created_at": now,
        "expires_at": expires,
        "rationale": {
            "source": "simulation",
            "metric": metric,
            "observed_value": value,
            "comparison": rule["comparison"],
            "threshold": threshold,
            "received_at": observation["received_at"],
            "freshness_seconds": freshness_seconds,
        },
    }
    proposal = {**intent, "intent_digest": _digest(intent)}
    return validate_proposal(config, proposal, now=now, freshness_seconds=freshness_seconds)


def validate_proposal(
    config: Config,
    proposal: dict,
    *,
    now: int,
    freshness_seconds: int = 60,
) -> dict:
    """Validate and copy an exact proposal for review, never authorize its action.

    The caller supplies its freshness ceiling. A proposal cannot enlarge that
    ceiling by changing its own rationale or recomputing its public digest.
    """
    _configuration(config)
    _integer(now, "invalid_now", 1, MAX_TIMESTAMP)
    _integer(freshness_seconds, "invalid_freshness", 1, MAX_FRESHNESS_SECONDS)
    _exact(proposal, _PROPOSAL, "invalid_proposal_fields")
    _integer(proposal["schema_version"], "unsupported_proposal_version", 1, 1)
    _literal(proposal["stage"], "proposal", "invalid_proposal_stage")
    _literal(proposal["kind"], "sampling_interval", "unsupported_proposal_kind")
    target = proposal["target"]
    _exact(target, _TARGET, "invalid_target_fields")
    device = _device(config, target["device_id"])
    if target != _target(config, device):
        raise ProposalError("target_binding_mismatch")
    _integer(
        proposal["interval_seconds"],
        "interval_outside_device_limits",
        device.min_interval,
        device.max_interval,
    )
    ttl = _integer(proposal["ttl_seconds"], "invalid_ttl", MIN_TTL_SECONDS, MAX_TTL_SECONDS)
    created = _integer(proposal["created_at"], "invalid_created_at", 1, MAX_TIMESTAMP)
    expires = _integer(proposal["expires_at"], "invalid_expires_at", 1, MAX_TIMESTAMP)
    if expires != created + ttl:
        raise ProposalError("expiry_mismatch")
    if created > now:
        raise ProposalError("future_proposal")
    if expires <= now:
        raise ProposalError("expired_proposal")
    rationale = proposal["rationale"]
    _exact(rationale, _RATIONALE, "invalid_rationale_fields")
    _literal(rationale["source"], "simulation", "simulation_required")
    _integer(rationale["metric"], "invalid_metric", 0, 255)
    value = _integer(rationale["observed_value"], "invalid_observed_value", -0x80000000, 0x7FFFFFFF)
    threshold = _integer(rationale["threshold"], "invalid_threshold", -0x80000000, 0x7FFFFFFF)
    age_limit = _integer(
        rationale["freshness_seconds"], "invalid_freshness", 1, MAX_FRESHNESS_SECONDS
    )
    if age_limit > freshness_seconds:
        raise ProposalError("freshness_exceeds_caller_limit")
    _freshness(created, rationale["received_at"], age_limit)
    _freshness(now, rationale["received_at"], age_limit)
    if expires > rationale["received_at"] + age_limit:
        raise ProposalError("proposal_outlives_observation")
    if not _comparison(value, threshold, rationale["comparison"]):
        raise ProposalError("threshold_not_met")
    digest = proposal["intent_digest"]
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ProposalError("invalid_intent_digest")
    intent = {key: value for key, value in proposal.items() if key != "intent_digest"}
    if not hmac.compare_digest(digest, _digest(intent)):
        raise ProposalError("intent_digest_mismatch")
    # Detach nested dictionaries so callers cannot mutate the original validated
    # object's target/rationale through the returned review result.
    return {**proposal, "target": dict(target), "rationale": dict(rationale)}
