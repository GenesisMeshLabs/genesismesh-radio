# Validation record

Software verification on 2026-10-25 (Europe/Stockholm). This record describes the
tested scope; it does not establish RF coverage, hardware or production readiness.

| Check | Result |
| --- | --- |
| Full Python suite, WSL Ubuntu 24.04 / Python 3.12.3 | 359 passed; 90% combined statement/branch coverage |
| Real GenesisMesh integration | 38 checks passed, all three radio adapter paths |
| Independent Rust evidence verifier | Original export accepted; altered export rejected |
| Portable C/OpenSSL interoperability | 7 suites passed, including 300 randomized round trips, golden vectors and mutation checks |
| Ruff lint and formatting | Passed |
| Source distribution and wheel build | Passed |
| Clean wheel installation and CLI demo | Passed |
| Installed dependency audit | No known vulnerabilities after updating the isolated test environment's pip |
| Independent review | 18 controller/persistence regression tests passed; findings fixed |

The full suite includes real PySerial loopback/PTY, actual Meshtastic 2.7.11 packet
encoding, and Paho 2.1.0 sockets against a disposable local AMQTT 0.11.3 broker.
The external broker dependency emits one Python 3.12 `crypt` deprecation warning.
There were no skipped tests in the full Linux run.

Local Windows Python 3.14 ran the bridge/config/CLI and edge contract checks.
Application Control blocks Hypothesis's native extension on this host; its property
tests passed in WSL. Windows CI uses an independent hosted runner. Linux-only PTY
checks are explicitly inapplicable on Windows, rather than claimed as passed there.

## Real-service evidence

- Core source: `9e4d5c01e6ba7a22e73c17388796ec274f73a2fc` (1.8.1).
- Rust SDK/edge/verifier source: `e554ca482a3ef4bc1e7a2ef205ac1d537daa169d` (1.8.1).
- Disposable Network Authority, SQLite evidence store, freshly generated identities,
  authenticated Unix socket, and a newly built Linux edge agent/verifier.
- Export: 19 entries; 4 decisions; 3 online execution records; 3 grant execution
  records; 1 grant. Python verification reported no failures.
- The standalone Rust verifier validated the anchored export offline and rejected
  a deliberately modified payload with `payload_digest_mismatch`.
- Real adapters were driven by injected radio/MQTT/UART peers. No deployed TTS
  service or physical radio was used.
- The lab reports the selected core source version and commit separately from
  installed distribution metadata, which can be stale when importing a checkout.

Reproduce with [the live lab instructions](live-lab.md). Its machine-readable report
is generated at `artifacts/live-lab.json` and deliberately excluded from Git.

## Review changes

Review caught and tests now cover identity-bound journals, strict device IDs,
replay/counter preservation on failed admission, bounded storage, pending-only
polling, ambiguous sends and reports, complete configuration preflight before I/O,
and the minimum budget needed for a 46-byte application outcome.

The permission contract is explicitly **dispatch authorization**. `report_by` is
not a grant-expiry value. A queued device does not independently verify a
GenesisMesh grant at execution time. Shared-key device MACs are preserved as
bridge-observed claims, never represented as device digital signatures.

## CI and remaining validation

The pull request's `Radio integration` workflow runs Linux Python 3.12/3.14,
Windows Python 3.12, packaging and clean-install smoke tests, C interoperability,
dependency audit, and the real-service lab against the immutable revisions above.
Use its check results for the current commit; local results above are a dated record.

The next hardware pilot must validate actual modem firmware, device provisioning,
trusted clocks/persistent counters, deployed TTS joins and downlinks, supported
regional payload budgets, airtime, RF reliability, and device restart behavior.
The C codec and mbedTLS callback are integration building blocks; target boards
have not been compiled or flashed by this run.
