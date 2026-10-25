# LoRa and LoRaWAN integration plan

Status: software implementation complete; final CI verification in progress. This is an experimental integration, not a
claim of production or RF validation.

## Outcome

Build a standalone bridge that receives authenticated telemetry and sends bounded,
governed configuration commands through LoRa and LoRaWAN, using the existing
GenesisMesh edge-agent local API. Preserve provenance, replay state, uncertainty,
and eventual evidence synchronization through interruptions.

## Scope and architecture

1. Python package and CLI with independent protocol, configuration, SQLite journal,
   edge API client, controller, simulator, and transport modules.
2. Meshtastic USB/serial adapter for private application packets over LoRa.
3. Framed UART adapter for custom LoRa modem firmware (host contract, not a new
   Semtech SPI driver).
4. The Things Stack v3 MQTT adapter for LoRaWAN raw application payloads. Validate
   topic, application, device EUI, FPort, and payload length. TLS for remote brokers.
5. A compact, versioned datagram authenticated with a separate provisioned key per
   device. No custom key-exchange handshake. Fixed HMAC-SHA256-128 tags and explicit
   direction/audience separation. Shared-key authentication is a bridge-observed
   claim, not independently verifiable device nonrepudiation. Raw UART/LoRa adds no
   confidentiality; the selected radio transport must supply it when needed.
6. Portable C codec and platform integration examples for Arduino/ESP-IDF and
   bare-metal clients. Crypto supplied by a vetted platform library; host vectors
   exercise interoperability with Python. No claim of RF-tested firmware.

The initial wire profile uses a 19-byte header (version, kind, device ID, 64-bit
counter, expiry, payload length) plus a 16-byte tag and up to 16 payload bytes.
Its maximum is 51 bytes. Actual transport budgets are configurable and must match
regional/data-rate limits; 51 bytes is not globally supported. Oversize messages
are refused, not silently fragmented.

The first command changes a device's sampling interval. It is idempotent and bounded.
Outcomes identify the exact command counter and applied value. Telemetry and device
outcomes live in the bridge journal; governance evidence contains metadata/digests.

## Security and lifecycle requirements

- Explicit provisioning binds a device ID, key environment variable, transport
  address, resource ID, permitted command, and parameter limits.
- Authenticate before advancing receive counters. Persist counters, events, and
  command state atomically. Fail closed on missing/replaced persistent state.
- Reserve and persist a downlink counter before attempting transport send.
- Authenticate remote request identity separately from local operator initiation;
  initial CLI commands are initiated by an authorized local operator.
- Request authorization with the actual edge API; only decision/grant authorities
  are accepted. Clamp command expiry to the authorization report deadline.
- Persist intent before dispatch. Never automatically redispatch an ambiguous send.
- Require an application-authenticated result before recording success. Queued,
  published, radio-ACKed, and executed are distinct states.
- Handle expired authorization, dropped outcomes, late receipts, crashes, database
  reopen, token errors, malformed transport input, and replayed commands explicitly.
- The current edge agent authorizes its enrolled bridge node and resource prefix.
  It is not a local peer-policy engine or a fleet identity authority.

## Delivery sequence

- [x] Establish repository, package layout, and reviewed protocol contract.
- [x] Implement protocol, adapters, persistent journal, edge client, CLI, simulator.
- [x] Add C interoperability client and transport configuration examples.
- [x] Exercise both transport families against disposable real GenesisMesh services.
- [x] Independent security/code review and fixes.
- [x] Create private GitHub repository.
- [x] Complete packaging and clean-install checks.
- [x] Configure implementation PR CI gates for Linux, Windows and real GenesisMesh.

## Review-driven decisions

The current edge agent's report deadline is not a decision/grant expiry. The pilot
therefore requests `radio.command.dispatch`: authorization is checked at dispatch;
device TTL bounds message freshness. Device-side execution-time grant verification
requires a future protocol/API extension. Shared-key authentication remains explicitly
bridge-observed provenance. Review also added journal identity binding, strict device
IDs, bounded storage, pending-only SQL queries, complete preflight before adapter I/O,
and a minimum 46-byte budget for the required command outcome.

## Verification

Unit and property tests cover wire mutations, bounds, audience/direction binding,
replays, duplicate outcomes, command correlation, state reopen, expiry, and failures.
Adapter tests use official payload shapes and real local serial/MQTT interfaces
where available. Live tests start a disposable NA and current Linux edge agent,
exercise online and grant-backed offline commands, reconnect, drain evidence,
and verify evidence integrity. CI repeats software checks and builds the package.

Hardware/RF range, duty-cycle operation, battery life, physical capture resistance,
and live LoRaWAN network-server interoperability require a later hardware pilot.
No connected serial radio was discovered during initial environment inspection.
