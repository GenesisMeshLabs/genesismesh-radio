# Architecture and trust boundaries

This experimental integration authorizes **dispatch** of a bounded radio command
under capability `radio.command.dispatch`. The enrolled bridge owns each configured
resource under its edge resource prefix. A local operator initiates commands; remote
uplinks are telemetry or outcomes, never arbitrary requests to execute operations.

## Components

`protocol.py` defines a compact application datagram. `config.py` binds identity,
audience, transport route, key reference, resource and parameter limits.
`journal.py` owns durable counters, command intent, events and report status.
`bridge.py` composes transport with the actual edge local API. `edge.py` never
loads an operator key or evaluates policy. Each transport adapter owns its radio
or MQTT framing. `simulator.py` provides an explicitly simulated device and demo.

## Permission is checked at dispatch

The edge agent decides online or consumes a scoped offline grant. The adapter asks
for `radio.command.dispatch`, `resource_action=update`, and the bounded
`interval_seconds` parameter. A random command ID is correlation metadata in
`attributes`, not a grant parameter. The bridge refuses automatic break-glass.

The edge API's `report_by` is an outcome-reporting timeout. It is **not** the
decision or grant validity deadline. The radio message TTL is an additional bridge
freshness limit, clamped to leave two seconds for outcome reporting. A device does
not receive or independently validate a GenesisMesh grant in this version.
Consequently, v0.1 does not prove that authority is still valid at the instant a
queued remote action executes. Such a guarantee requires a future explicit
execution-deadline/delegation contract and device-side validation.

Permission authorizes dispatch, but evidence reporting is deliberately conservative:
`success` requires an authenticated application result with the expected command
counter and applied value. A missing confirmation is `partial` with an explicit
uncertainty reason. Broker queueing, MQTT publication, LoRa acknowledgments and
LoRaWAN acknowledgments never establish success. Late results are retained as
observations without rewriting earlier evidence.

## Persistence and recovery

The journal is explicitly provisioned and binds counters to the configured device
keys, audience, routes and resources. Runtime refuses missing/rebound state. Counters
are reserved before external actions; received frames and replay counters commit
atomically. One process owns the journal. State uses SQLite WAL with synchronous
FULL and a process lock. On Linux the database must be private to its owner.

After a crash, incomplete commands become uncertain; there is no automatic physical
redispatch. Retrying a request ID returns the stored command. Lost authorization
responses remain unconfirmed. Evidence submission can retry with backoff; a `409`
after a lost response is recorded as uncertain, not assumed successful.

Replay checking is strictly increasing per device. Out-of-order frames are refused;
applications must tolerate a resulting missing confirmation. Device clocks must
be trustworthy and must not move backward. A rollback of the whole database cannot
be detected without an external trusted monotonic anchor. After lost/restored
counter state, rotate device keys and reprovision both endpoints before reuse.

Default journal limits are 100,000 received events and 10,000 commands. Capacity
failure stops new admission without deleting replay counters or evidence. Status
returns the latest 100 entries; polling selects pending work with SQL. This pilot
has no automatic retention or archival procedure. Monitor capacity and securely
archive/migrate state with counters preserved before extending a deployment.

## Device and bridge provenance

Per-device HMAC keys establish a shared-key authentication relationship. The bridge
can produce the same MAC as the device; this is **not** a device digital signature
or independent nonrepudiation. Events retain source identity, route, original frame,
authentication type, bridge audience, receipt time and digest. Governance evidence
links command and outcome digests without placing keys or full telemetry in the NA.

HMAC does not encrypt. Raw LoRa/UART payloads are visible to observers unless the
selected modem protocol supplies encryption. Meshtastic/LoRaWAN security remains
separately configured. Possession of a radio channel key alone does not grant a
GenesisMesh capability. Radio relays need not be GenesisMesh members.

## Scope boundaries

The full edge agent is the existing Linux component. The C codec is a firmware
building block; platform code supplies trusted time, persistent counters, approved
crypto, radio I/O and safe actuation. The current example is an idempotent sampling
interval update. General-purpose remote shells, binary transfer, emergency-service
guarantees and arbitrary actuator commands are outside this release.
