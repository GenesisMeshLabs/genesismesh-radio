# Rust device validation

Software verification on 2026-10-25, after merging continuous-service PR #2.
Post-merge `main` at `c8869f2` passed its complete
[workflow](https://github.com/GenesisMeshLabs/genesismesh-radio/actions/runs/40177068675).
Current Rust implementation PR checks are the source for hosted results at its head.

| Check | Observed local result |
| --- | --- |
| Rust protocol/device tests | 31 tests passed on Linux and native Windows |
| Rust Clippy and formatting | Passed; warnings denied |
| Rust minimum compiler | Library check passed on 1.85.0 |
| Bare-metal release libraries | Six ARM/RISC-V targets built with Rust 1.99.0 |
| Three-language conformance | 7 suites passed; five goldens, 300 randomized frames, 992 bit changes and malformed/boundary cases |
| Original C/OpenSSL conformance | 7 suites passed |
| Python bridge suite | 519 passed, 1 expected native-Windows-only skip; 90% combined coverage |
| Real GenesisMesh/edge/device integration | 66 named checks passed |
| Locked Rust dependencies | cargo-audit 0.22.2 reported no vulnerabilities |

The Rust library uses fixed buffers, forbids unsafe code in its own sources and
does not import `std` or `alloc`. Host examples/tests intentionally use `std` and
simulated hardware. Test keys are disposable or explicitly public golden fixtures.

Fault tests cover failed/ambiguous snapshot commits, panic/reset boundaries before
and after actuation/result commit, clock errors and rollback between reads,
time passing during acceptance storage, counter exhaustion, replay after reopen,
local policy refusal, corrupt or mismatched state and failed radio submission.
An uncertain physical result masks the interval as unknown and is never reapplied.
State authentication and profile binding do not detect restoration of an entire
older valid snapshot without a separate monotonic anchor.

Independent review found and reproduced a post-actuation clock rollback gap and
inconsistent authenticated snapshot cases. These were fixed and regression-tested.
The running device also tracks trusted time reads in RAM without flash writes on
invalid packets; only committed floors survive resets. Fresh isolated build
directories were used to verify final state-machine fixes independently.

The live Rust peer uses the real library with process-local in-memory snapshots
and simulated interval changes. It verifies a real authority decision and signed
offline grant through the existing Python gateway, produces Rust-authenticated
device outcomes, refuses replay after an engine reopen, enforces a stricter local
bound and synchronizes evidence accepted by the independent Rust verifier.
The verifier also rejects a tampered export. This adds 13 Rust-engine checks to
the previous 53 software integration checks.

Compiler coverage is not board support. The six release outputs are libraries,
not flashed firmware. No physical radio, vendor HAL, power-loss-safe flash driver,
trusted hardware clock, secure key store, LoRaWAN join or regional RF behavior has
been validated. A real device must implement and validate the documented storage,
clock, actuation and radio contracts before it can use this core.
