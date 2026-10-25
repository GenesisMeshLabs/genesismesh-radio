# Continuous-service validation

Local verification on 2026-10-25. This record covers the continuous local HTTP
service, fresh-device provisioning and the existing radio bridge. Current hosted
workflow results should be checked for the pull request's exact commit.

| Check | Observed result |
| --- | --- |
| Full Linux Python 3.12 suite | 519 passed, 1 native-Windows-only test skipped; 90% combined coverage |
| Full Linux Python 3.14 suite | 519 passed, the same platform-specific skip |
| Native Windows service tests | 58 passed |
| Real GenesisMesh/edge/HTTP integration | 53 named checks passed |
| C/OpenSSL interoperability | 7 suites passed |
| Ruff lint and formatting | Passed |
| Source distribution and wheel build | Passed |
| Clean wheel installation | CLI demo, service command help, and actual fresh bundle creation passed |
| Dependency audit | No known vulnerabilities found in installed dependencies; unpublished local package cannot be matched to PyPI advisories |
| systemd template | No invalid directives found; service not installed or enabled |

Linux Python 3.12 reports the existing AMQTT dependency's `crypt` deprecation
warning. Native Windows deliberately refuses private-bundle creation: POSIX
secret-write tests are inapplicable there, while its refusal behavior is tested.
Windows serial PTY tests also remain inapplicable. Hosted CI covers the full
appropriate suite on Windows and both Linux Python versions.

## Independent review and regressions

The service tests cover actual loopback sockets, bearer checks, unexpected Host
and Origin headers, duplicate headers, ambiguous HTTP framing, oversized/deep
payloads, read deadlines, mailbox limits, UUID conflicts, report uncertainty,
owner-thread resource access, startup failure, fatal owner failure and shutdown.
An independently reproduced shutdown race was fixed: queued work cannot start
after the shutdown admission boundary. Already-started work may finish, and a
timeout/disconnect never causes a second dispatch or cancels an admitted operation.

Provisioning tests cover independent keys, configuration round trips, explicit
external credential references, symlink traversal, state and output collisions,
permission enforcement, filesystem identity, partial writes, descriptor cleanup,
and refusal to remove unknown/replaced files during cleanup. An independent sweep
covered 24 write/sync/permission failure points. Actual WSL ext4 provisioning
passed; its Windows-mounted 9p filesystem was refused before secrets were created.
The bounded mount-table parser also handles unrelated non-ASCII paths.

The [live lab](live-lab.md) now includes 15 continuous-service checks in addition
to the original 38 radio/authority checks. The HTTP scenario uses a real disposable
Network Authority and Rust edge agent, online decisions, a signed offline grant,
telemetry during an outcome wait, UUID retries, conservative restart recovery,
and synchronized evidence. The independent Rust verifier accepts the original
anchored export and rejects a modified copy. Radio peers are injected; RF is not tested.

## Boundaries

- The control API is for trusted local operators holding a separate shared bearer
  token. It does not implement individual operator identities or remote access.
- Health describes the local service; it does not attest radio delivery or live
  authority connectivity.
- Provisioning creates fresh bundles only. It does not enroll, rotate, reset,
  recover, or flash deployed devices. No production secrets or services were used.
- No target board, LoRaWAN deployment, systemd deployment, RF range, airtime, power
  use or physical key storage was validated.
- Firmware remains a portable C codec. The recorded Rust preference concerns a
  future stateful device application after selecting and validating its hardware.
