# Disposable live integration lab

The lab runs the actual GenesisMesh Network Authority and Linux edge agent. It
connects the bridge through the real Unix-socket authorization API, stores signed
execution records in a real SQLite evidence store, disconnects the authority,
uses a scoped offline grant, and verifies the evidence after reconnection.

The three radio adapters run with injected peer interfaces:

| Adapter | Exercised boundary | Outside this test |
| --- | --- | --- |
| Meshtastic | `sendData`, receive callbacks, private port and route validation | Physical USB radio, firmware routing, RF delivery |
| Custom LoRa UART | Byte framing, reads/writes, device messages | Actual modem firmware and RF delivery |
| The Things Stack | MQTT callbacks, application/device/EUI/FPort binding, raw uplink and downlink envelopes | Live TTS server, gateway, device join, RF delivery |

This is a software integration test. It does not establish range, battery life,
airtime compliance, hardware key protection, or production readiness. Separate
adapter tests exercise local MQTT and serial interfaces where available.

## Requirements

- Linux or WSL, Python 3.12+, and this package's development dependencies.
- GenesisMesh core 1.8.1 installed, or a checkout supplied through `GM_CORE_SOURCE`
  with its declared Python dependencies installed in the test environment.
- Built `genesis-mesh-edge` and `genesis-mesh-verify` 1.8.1 executables. Build from a selected
  SDK revision with its lockfile; the lab reports the executable's version.

For example, in a dedicated environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]' 'genesis-mesh==1.8.1'
CARGO_TARGET_DIR=/tmp/gm-radio-target cargo build --locked \
  --manifest-path /path/to/sdk-rust/Cargo.toml -p genesis-mesh-edge -p genesis-mesh-verify
GM_RADIO_PYTHON="$PWD/.venv/bin/python" \
GM_EDGE_BINARY=/tmp/gm-radio-target/debug/genesis-mesh-edge \
  bash scripts/run-live-lab.sh
```

If testing the core checkout, also set `GM_CORE_SOURCE=/path/to/genesismesh`.
The verifier defaults to the executable beside the edge agent; override it with
`GM_VERIFY_BINARY` or `--verify-binary` when it lives elsewhere.
The shell wrapper sets `PYTHONDONTWRITEBYTECODE=1` so imports do not create files
in that source checkout. Build output belongs in a separate target directory.

The harness creates its private temporary directory on the Linux filesystem,
not in `/mnt/c`, because the edge agent enforces POSIX key-directory permissions.
It creates new keys and a new authority database for every run. No existing NA
configuration, operator key, radio key, or live environment is used. Only its own
child edge process and loopback authority listener are stopped.

## Assertions

For each adapter, the lab verifies authenticated telemetry, harmless duplicate
uplinks, tampered-frame refusal, online command authorization, explicit device
confirmation, command replay rejection, and offline grant-backed operation.

It additionally checks:

- A policy denial prevents dispatch.
- A request outside the offline grant is denied.
- Evidence remains queued while the authority is down, then synchronizes with no
  dead letters.
- The authority verifies its stored signatures and chains, with the expected
  online and offline execution counts.
- The standalone Rust verifier independently verifies the exported evidence with
  public keys and held anchors, and rejects a deliberately altered copy. This is
  a separate implementation port maintained by the same project, not a clean-room
  third-party audit.
- A stale cached trust snapshot prevents offline grant use. To keep the test
  bounded, this case stops the disposable agent and ages its local cache's
  `synced_at` timestamp; it does not edit a signed grant or claim elapsed-time
  hardware validation.
- Once a grant revocation has been learned, a subsequent disconnection does not
  restore that grant's authority.
- The bridge's durable command state survives reopening its journal.

The bridge places the command correlation ID in authorization **attributes**;
only `interval_seconds` is an action parameter. Grant parameter envelopes are
closed, so placing arbitrary command IDs among parameters would require granting
those specific IDs before disconnection.

The capability in this lab is `radio.command.dispatch`: the authority or grant
permits the bridge to dispatch a bounded configuration request. The device's TTL
is a local freshness limit. The edge API's `report_by` is an outcome-report
deadline, not the expiry of the underlying decision or grant. The device does not
independently validate a GenesisMesh grant at execution time in this release.

## Results

The default result is `artifacts/live-lab.json`, with actual core/edge/verifier/Python
versions, named checks, evidence-verification counts, elapsed time, and an explicit
`hardware_rf_tested: false` flag. Use `--report /path/to/result.json` to select
another output. A missing dependency, unsupported platform, or failed assertion
exits nonzero; none of those conditions is reported as a passed test.

For a core source checkout, the report takes its version from that checkout's
`pyproject.toml`, records its Git commit, and separately preserves the version
reported by the imported module. This avoids mistaking stale installed package
metadata for the version of the source being exercised.

The evidence proves the integrity of the bridge's signed account of its actions.
The device protocol uses per-device shared-key MACs; a bridge receipt is not an
independent device signature or proof that a physical sensor reading is true.
