# Deterministic simulated telemetry proposals

`genesismesh_radio.proposals` turns an explicitly simulated integer observation
and a threshold rule into a sampling-interval proposal. It performs no network,
credential or journal access. It neither calls a model nor grants permission.
Human review and the existing GenesisMesh core/edge authorization path remain
required before any physical effect. Live autonomous operation is not implemented.

## Small JSON profile

An observation has exactly these fields:

```json
{"schema_version":1,"source":"simulation","device_id":7,"metric":1,"value":2600,"received_at":1800000000}
```

A rule has exactly these fields:

```json
{"schema_version":1,"metric":1,"comparison":"gte","threshold":2500,"interval_seconds":10,"ttl_seconds":60}
```

Metric is an integer 0 through 255. Value and threshold are signed 32-bit integers;
the deployment defines their units and scaling. Comparisons are inclusive `gte`
or `lte`. Floats, booleans, strings standing in for numbers, unknown fields,
unconfigured devices and metric mismatches are refused. The fixed operation is
setting a bounded sampling interval. URLs, actuator verbs, free-form model
instructions, confidence scores and authorization claims have no accepted field.

```python
from genesismesh_radio.proposals import generate_proposal, validate_proposal

proposal = generate_proposal(config, observation, rule, now=1800000000, freshness_seconds=60)
if proposal is not None:
    reviewed_request = validate_proposal(config, proposal, now=1800000001, freshness_seconds=60)
    # Display for human review. This value does not authorize dispatch.
```

`config` is the existing validated `Config`; no transport needs to be connected.
Generation returns `None` if the fully validated rule does not match. Malformed
input raises `ProposalError` with a non-secret reason code.

## Binding and freshness

The exact output contains schema version, `stage="proposal"`,
`kind="sampling_interval"`, target, interval, TTL, creation/expiry times, a typed
numeric rationale and an `intent_digest`. The target binds the configured audience,
device ID, resource, transport and route. Validation against a different target or
changed configuration refuses the old proposal.

The caller supplies `now` and the freshness ceiling; timestamps use unsigned
32-bit UTC seconds. Future and stale observations are refused. Age equal to the
freshness limit is stale. TTL is 3 through 300 seconds and expires no later than
the observation's freshness deadline; generation shortens TTL when necessary.
Less than three seconds remaining refuses generation. Validation also refuses
expired/future proposals, inconsistent expiry, interval-limit violations and a
proposal that attempts to enlarge the caller's freshness ceiling. Wall-clock
trust and the truth of a supplied observation are outside this simulation helper.

The stable digest is lowercase SHA-256 over the bytes
`GenesisMeshRadioProposal\0v1\0` followed by all proposal fields except
`intent_digest`, serialized as ASCII JSON with sorted keys, no whitespace,
`ensure_ascii=True` and no nonfinite numbers. The restricted schema uses ASCII
strings and integers. Reordering input keys changes no digest; changing a bound
target, time, interval or rationale changes it.

This public digest is an identifier for the exact reviewable intent. It is not
a signature, authenticated observation, authority decision or grant. Anyone can
construct and hash another bounded proposal; every such proposal still needs
review and core authorization. A valid proposal must never be interpreted as a
successful physical action, and an acknowledged radio/MQTT submission still
cannot establish an authenticated device outcome.

The module only generates and validates simulated proposals. Connecting verified
live telemetry, persisting review/approval, obtaining scoped authority, dispatching
through the existing bridge and recording actual outcomes remain separate work.
