# GenesisMesh Radio

LoRa and LoRaWAN integration for governed edge operations. A local operator can
dispatch a bounded device command through the existing GenesisMesh edge agent,
receive an authenticated device result, and synchronize evidence after an outage.

**Status: experimental v0.1.** Real GenesisMesh software integration and radio
protocol contracts are tested. RF hardware, deployed LoRaWAN services, range,
battery life and production operation are not yet validated.

## Supported paths

| Path | Adapter | Device requirement |
| --- | --- | --- |
| LoRa mesh | Meshtastic Python USB/serial, private application port | Application peer producing this repository's payload format |
| Custom LoRa | Bounded UART modem framing | Modem firmware implementing `GM1 <route> <hex>`; radio driver supplied by the platform |
| LoRaWAN | The Things Stack v3 MQTT over TLS | Provisioned LoRaWAN device sending raw bytes on the configured FPort |

The adapters share per-device authentication, source-to-resource bindings, replay
counters, a durable command journal and the same GenesisMesh local API. The first
command updates a bounded sampling interval. [Transport contracts](docs/transports.md)
describe the exact interfaces and payload-budget requirements.

The [continuous local service](docs/service.md) receives telemetry while operators
submit commands and inspect outcomes through an authenticated loopback API.
[Fresh-device provisioning](docs/provisioning.md) generates private configuration
and key bundles; it never enrolls, flashes, rotates or resets existing devices.

## Quick software demo

Python 3.12+:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev,meshtastic,integration]'
gm-radio demo
```

On Windows activate with `.\.venv\Scripts\Activate.ps1`. The demo generates
temporary keys and uses an explicitly simulated authority and device. The output
labels simulation and `hardware_tested: false`. It is not the real-service test.

## Connect a deployment

Start from [Meshtastic](examples/meshtastic.toml), [custom LoRa UART](examples/lora-serial.toml),
or [LoRaWAN/TTS](examples/lorawan-tts.toml). Replace example routes, EUI, application
and port. Provision a distinct random 32-byte device key into its firmware and
the environment variable named by `key_env`. Provision the same audience and
device ID. Keep keys and runtime files outside Git.

The Linux edge agent must already be enrolled for the configured resource prefix,
with policy/attestation for `radio.command.dispatch` and bounded
`request_parameters.interval_seconds`. Offline operation also requires a matching
pre-issued grant. Command IDs are correlation attributes, not grant parameters.
Use its authenticated Unix socket or literal-loopback bearer API.

```sh
gm-radio check-config --config examples/meshtastic.toml
gm-radio init-state --config examples/meshtastic.toml
gm-radio command --config examples/meshtastic.toml --device-id 1 --interval 60 --ttl 60
gm-radio status --config examples/meshtastic.toml
gm-radio run --config examples/meshtastic.toml
```

These direct commands are **mutually exclusive**: one process owns the journal.
`command` receives while waiting for its result; `run` receives continuously and
retries pending evidence reports. Stop `run` before direct `command` or `status`.

For continuous operation, configure a distinct `GM_RADIO_CONTROL_TOKEN`, use
`serve` instead of `run`, and contact it through the service client commands:

```sh
gm-radio serve --config examples/meshtastic.toml
gm-radio service-health
gm-radio service-status
gm-radio service-command --device-id 1 --interval 60 --request-id 11111111-1111-4111-8111-111111111111
gm-radio service-result --request-id 11111111-1111-4111-8111-111111111111
```

Run the client commands in another local terminal. Use a new UUID for a new
operation and retain it before sending. Reusing that ID inspects/retries the
original request without redispatch. An HTTP timeout or interrupted operation
remains uncertain; do not issue another physical command with a new UUID.

## What the evidence means

GenesisMesh authorizes **command dispatch** at the bridge. Its `report_by` is an
outcome-reporting deadline, not a permission-expiry value suitable for independent
device verification. Device TTL is an additional freshness bound. This release
does not claim execution-time validation of GenesisMesh grants on the microcontroller.

A successful report requires an authenticated device outcome matching the command
counter and expected value. MQTT publication, queue acceptance and radio ACKs are
never execution success. Missing confirmation is explicit uncertainty. The bridge
uses shared-key MAC authentication, so a device report is not an independently
verifiable device signature. HMAC supplies no confidentiality for raw LoRa.

See [architecture and recovery](docs/architecture.md), [wire protocol](docs/protocol.md),
and [portable firmware codec](firmware/README.md). The codec supports Arduino/ESP-IDF
and bare-metal integration through a platform crypto callback; it is not complete
RF-tested firmware.

## Verification

```sh
python -m ruff check .
python -m ruff format --check .
python -m pytest -q --cov=genesismesh_radio
python -m build
python firmware/tests/conformance.py
```

The C conformance command needs Linux/WSL, a C compiler and OpenSSL libcrypto.
Adapter tests exercise actual Meshtastic packet encoding, serial loopback/PTY, and
a disposable local MQTT broker. Linux runs the complete test set; PTY checks do
not apply to Windows. Some managed Windows hosts block Hypothesis's native DLL;
run the property suite in WSL rather than changing security settings.

The [live lab](docs/live-lab.md) creates a disposable real Network Authority and
Linux edge agent, tests all three adapter paths online and under offline grants,
then verifies exported evidence with both Python and the standalone Rust verifier.
It uses generated test credentials and never accesses an existing production NA.
Pinned source revisions and measured results are in [validation](docs/validation.md).

CI is configured for Python 3.12/3.14 on Linux, Python 3.12 on Windows, packaging,
C interoperability, dependency audit and the real GenesisMesh integration. Dependencies and distribution
considerations are listed in [third-party notices](THIRD_PARTY_NOTICES.md).
