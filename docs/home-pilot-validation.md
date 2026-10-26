# Home pilot software validation

Recorded on 26 October 2026. This increment prepares the fixed Windows/WSL home
lab while the RAK equipment is in transit. Essential services remain local;
Mac and iPhone participation is optional. No radio hardware, gateway settings,
phone certificate trust, firewall rules, power settings or existing deployment
were changed.

## Checked behaviour

| Local gate | Observed result |
| --- | --- |
| Linux Python 3.12 | 805 passed, 2 expected/opt-in skips; 90.51% branch-inclusive coverage |
| Native Windows Python 3.14 | 758 passed, 49 platform/optional skips; 82.90% branch-inclusive coverage |
| Existing real authority and edge lab | 66 named checks passed; injected RF peers |
| New home lab with console admission | 33 named checks passed; real authority/edge, injected RF and ASGI console |
| Home session and optional console tests | 17 passed in WSL, including actual expiry/cleanup |
| Browser request-state regressions | 5 passed |
| C/OpenSSL and Python/C/Rust codecs | 7 conformance suites passed in each harness |
| Packaging | sdist/wheel built, fresh wheel demo/imports/assets and module CLI help passed |
| Lint, formatting and dependency audit | Passed, with the warning and audit scopes described below |

The managed Windows host blocked its generated console EXE launcher through
Application Control. The installed module CLI help passed using Python;
WSL remains the intended console runtime and no Windows policy was changed.

- The bounded disposable lab uses a real pinned GenesisMesh authority, Linux edge
  agent and verifier, plus simulated radio peers. Its optional console path tests
  observer refusal, an operator's confirmed outcome, original-ID retries, core
  policy refusal, logout and local account revocation. All 33 named checks passed.
- An out-of-scope resource receives core HTTP 400. The bridge conservatively
  records uncertain authorization and sends nothing to the simulated device;
  that is not presented as a confirmed policy-denied outcome.
- A separate real HTTPS socket test uses a disposable trusted certificate,
  actual Uvicorn and actual loopback bridge with a simulated authority/radio. It
  verifies login, Secure cookies, application confirmation, duplicate-ID lookup
  and session revocation. It does not prove Android Wi-Fi connectivity.
- Console security tests cover exact Host/Origin, CSRF, role denial, password
  reset, logout/revocation/expiry, malformed Unicode, body limits, fixed backend
  routing, durable no-redispatch and private storage. CLI tests refuse expired,
  malformed or public handoff files, unsafe origins and missing TLS before bind.
- Five frontend regressions exercise the real application script: a delayed
  response/error for an old request cannot confirm a newer request, mismatched
  IDs cannot signal completion, and terminal states clear safely. Desktop and
  390-pixel browser layouts were inspected; long result text no longer causes
  horizontal overflow. This is browser emulation, not a physical phone test.
- WisGate fixtures and an actual disposable Paho/broker exchange verify source,
  application, FPort and payload binding, retained-message refusal, TLS settings,
  and the separation of gateway ACKs from authenticated application outcomes.
  Gateway firmware and real LoRaWAN joins remain pending.
- Deterministic proposals are simulation-only and have no dispatch authority.
  Their 105 tests cover strict schema/type/target binding, interval bounds,
  freshness, expiry and digest changes. Model integration is not implemented.

## Repeat the software gate

```sh
python -m pip install -e '.[dev,meshtastic,integration,console]'
python -m ruff check .
python -m ruff format --check .
python -m pytest -q --cov=genesismesh_radio --cov-fail-under=80
node --test tests/frontend/console.test.cjs
python -m build
python firmware/tests/conformance.py
python firmware/tests/rust_conformance.py
python -m pip_audit --progress-spinner off
```

Use separate `COVERAGE_FILE` locations when Windows and WSL tests share the same
checkout. The initial concurrent local run shared coverage output; independent
reruns produced the retained reports. Native Windows skips POSIX private-state,
PTY and unavailable optional-broker checks. Linux runs these checks; the actual
home-session exercise is opt-in with the pinned core/edge environment.

The CI software jobs install the console extra, run the frontend regressions,
build the package and audit dependencies. The real-integration job also runs the
33-check home lab and opt-in session-expiry tests, then uploads only its redacted
report. The existing Rust and RAK image jobs remain separate.

The Starlette TestClient currently warns that its HTTPX backend is deprecated;
tests still pass with this repository's pinned HTTPX. AMQTT on Python 3.12 also
emits a test dependency's `crypt` deprecation warning. Dependency audit reported
no known vulnerabilities in the installed dependency inventory; the local
unpublished package itself is not matched to a PyPI advisory entry.

## Evidence and remaining acceptance

Local redacted reports and JUnit/coverage results are written under ignored
`artifacts/`. Private inventory stays in `.local/home-pilot/`; runtime credentials
remain on the private Linux filesystem. See the CI run attached to the PR for
the tested commit and hosted results.

Independent review found and resolved frontend request correlation, terminal
expiry handling, malformed Unicode refusal and invalid-credential initialization
issues. It also repeated proposal/WisGate and real-broker checks.

The remaining physical gates are Android LAN access and certificate trust,
Windows reboot/startup, actual peripheral persistence/time, compatible operational
radio firmware, real packet exchange, LoRaWAN joins and any actuator extension.
The read-only RAK diagnostic is still not operational radio firmware. Local
console identities are not core-enrolled human actors or multi-party approvals.
