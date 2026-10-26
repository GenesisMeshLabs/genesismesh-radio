# Private home pilot rehearsal

This pre-arrival lab runs a real disposable GenesisMesh Network Authority, a real
Linux edge agent and the real authenticated `ControlService` HTTP interface. Two
Python device peers produce authenticated telemetry and outcomes through the
Meshtastic adapter's injected SDK boundary. **RF, board storage, clocks, antennas,
LoRaWAN joins and physical actuation are simulated or absent.** No production
authority, existing device key or operator configuration is opened.

The bounded run checks service startup, token refusal, telemetry from both peers,
online dispatch and matching outcomes, duplicate IDs, command replay, policy
denial, an authority outage with a real signed offline grant, offline bounds,
restart uncertainty without redispatch, evidence resynchronization and an
independent verifier's acceptance/rejection of original/tampered exports. It
does not replace [the complete live lab](live-lab.md) or the
[RAK4631 physical pilot](rak4631-pilot.md).

## Run on Linux or WSL

Use Python 3.12+ with this repository's `dev,meshtastic` extras and the pinned
GenesisMesh core's declared dependencies installed in a dedicated environment.
Keep the core checkout at the clean pinned commit below. Build the edge and
verifier with the SDK lockfile; the actual tool versions and binary SHA-256
hashes are recorded, while build provenance is not independently attested.

| Component | Required source/runtime |
| --- | --- |
| GenesisMesh core | `9e4d5c01e6ba7a22e73c17388796ec274f73a2fc`, version 1.8.1 |
| SDK source for builds | `e554ca482a3ef4bc1e7a2ef205ac1d537daa169d` |
| Edge / verifier executables | `genesis-mesh-edge 1.8.1` / `genesis-mesh-verify 1.8.1` |

From the repository root:

```sh
export GM_CORE_SOURCE=/path/to/clean/pinned/genesismesh
export GM_EDGE_BINARY=/path/to/target/debug/genesis-mesh-edge
export GM_VERIFY_BINARY=/path/to/target/debug/genesis-mesh-verify
/path/to/venv/bin/python scripts/home_pilot_lab.py \
  --report artifacts/home-pilot-lab.json
```

These variables name test sources and executables, not deployed credentials.
No real radio ports or MQTT credentials are required. The script refuses native
Windows, a different core commit, a modified core checkout or unexpected runtime
versions. Its report records the radio source commit and whether that working
tree was clean, so a local development run is distinguishable from a release run.

State is generated under a new `/tmp/gm-home-pilot-*` directory on the private
Linux filesystem, mode `0700`, with a private umask. An inherited `TMPDIR` cannot
redirect it to the shared Windows filesystem. Existing state is never reused.
Cleanup stops only this run's child processes and removes its temporary keys,
databases, raw evidence and logs. It changes no firewall, routing, power settings
or existing deployment. An interrupted/failed run exits nonzero and writes only
redacted failure classification; it never declares unfinished checks successful.

The normal run finishes after its fixed sequence. Every service/request wait has
a finite timeout, but startup failures may take longer than a successful run.
The simulated devices keep their counters in process memory while the bridge
service is restarted; this recovery check is not a microcontroller reset or
proof of physical storage durability.
The [existing service](service.md) remains the deployment interface; this script
is development tooling and is not included in the installed bridge wheel.

## Optional console admission checks

Install the repository's `console` extra in the same test environment, then add
`--console-checks` to the command above. This uses the real console application,
an in-memory operator store and Starlette's ASGI `TestClient`, backed by the same
real local `ControlClient`, authority and edge process. **It does not open or
validate a TLS listener, a phone browser or a LAN path.** Its HTTPS origin is ASGI
test metadata, not an observed encrypted connection.

The extra checks cover an observer's read-only role, an operator's allowed
command and matching authenticated outcome, original-ID retry without another
effect, policy denial, an out-of-scope resource, logout-cookie replay and revoked
local-session refusal. Local users govern console admission; GenesisMesh still
sees the enrolled bridge identity, not a new core identity for each user.

This option creates a third **simulated** peer in the initial configuration
solely for an outside-prefix test. Its resource lies outside the bridge's
enrolled scope. The real edge API returns HTTP 400 `resource_out_of_scope` and
no device command is dispatched. The current radio client conservatively maps
that non-200 authorization response to an **uncertain** journal record. The lab
records both observations instead of describing this case as a confirmed denial
or an execution. A separately tested online policy refusal is `state=denied`.

## Optional local-console session

To inspect the disposable service after the automated baseline:

```sh
/path/to/venv/bin/python scripts/home_pilot_lab.py \
  --hold-seconds 180 --report artifacts/home-pilot-console-lab.json
```

`--hold-seconds` is explicitly bounded to 0..300 seconds. After the baseline,
stdout announces a private `session_file` path without printing its contents.
That file is mode `0600`, inside the private lab directory, with schema
`genesismesh-radio-home-session/v1`. It contains a generated **test control
token**, the literal-loopback control URL, audience, device/resource/route
bindings and local interval bounds, simulation labels and an absolute UTC
`expires_at`. Pass that file to a local console that checks its permissions,
schema, expiry and loopback URL; never paste its token into a page or a report.

During this hold, the authority is online and simulated device outcomes are
delivered automatically. Telemetry arrives approximately every two seconds.
Configured local device bounds are 5..1000 seconds; the disposable online policy
allows at most 600 seconds and its offline grant allows 5..300. A status row or
transport receipt still does not prove execution: inspect the stored outcome.

At expiry, the service endpoint closes and the session file is removed before
final evidence verification and cleanup. Ctrl+C requests cleanup immediately.
The session is neither a reusable enrollment bundle nor a physical radio bridge.

## Shareable result and private run record

The JSON report contains source revisions, binary hashes/versions, named passed
checks, elapsed time, evidence verification counts and explicit simulated-RF
labels. It excludes tokens, device keys, authority keys, session contents,
addresses, raw frames, raw evidence and temporary-state paths. The path printed
for the optional session is a local handoff only and is not included in that
shareable report.

The focused unit/permission tests run with `python -m pytest -q
tests/test_home_pilot_lab.py`. To include the actual optional session, set
`GM_HOME_PILOT_INTEGRATION=1` alongside the three source/binary variables above
and use the environment containing core and pytest. That test creates a command
through the real control API, confirms it once, retries the same ID, then checks
that the endpoint and session file disappear at expiry. It still simulates RF.
Also set `GM_HOME_PILOT_CONSOLE_CHECKS=1` to include the optional ASGI admission
checks in that same opt-in integration test.

Copy [the run record template](home-pilot-run-record.md) into a private lab folder
for observations. Keep hardware results `Pending` until the boards arrive. Use
separate identities/state for real hardware; never convert the disposable peers'
keys or journals into a deployment or describe a rehearsal as RF evidence.
