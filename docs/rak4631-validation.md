# RAK4631 pre-arrival validation

Software checks recorded on 2026-10-25. Physical boards have not been connected,
flashed or tested. The hosted check suite on the implementation PR's current
head is the source of truth for CI; this table records the local results.

| Check | Observed result |
| --- | --- |
| Linux/WSL Python 3.12 full suite | 548 passed, 1 expected native-Windows-only skip; bridge coverage 90.27% |
| Native Windows Python 3.14 suite | 522 passed, 27 platform/optional-broker skips; bridge coverage 83.53% |
| Image inspection regressions | 29 passed, included in the Python counts above |
| Existing portable Rust core | 31 protocol/device tests passed |
| New WisBlock adapters | 27 tests passed: 10 FRAM, 15 RTC, 2 independent fault models |
| Board layout | 1 host test passed against pinned vendor bounds and generated linker constants |
| Actual ARM diagnostic | `thumbv7em-none-eabihf` release ELF linked; host and target Clippy passed with warnings denied |
| Artifact memory/vector check | Passed; 10,888 flash-load bytes, 1,092 BSS bytes, entry `0x26101` |
| Rust minimum version | WisBlock library checked on 1.85; board crate explicitly requires tested 1.99 |
| C/OpenSSL and Python/C/Rust conformance | 7 suites passed for each harness |
| Disposable real GenesisMesh integration | All 66 named checks passed; real authority/edge/verifier, injected radio peers |
| Packaging | sdist and wheel built; fresh Windows wheel install, demo and service/provision imports passed |
| Python lint and formatting | Passed |
| Dependency audits | No known vulnerable packages reported; board maintenance warning below |

The final board/peripheral script was run in a fresh WSL target directory,
separate from agent builds. An independent reviewer repeated the full script in
another fresh directory. The image check records the actual ELF SHA-256 in its
JSON report; debug metadata/build-path differences can change the complete ELF
hash, so the report accompanies each particular build rather than promising
byte-for-byte reproducibility across build locations.

The independent FRAM model enumerates 174,848 interrupted-byte/value combinations
across first use and three rotations. It separately injects I2C errors before and
after transaction effects, including successful writes whose acknowledgment is
lost. The primary tests inject failures at actual device acceptance/result-write
boundaries, corruption, missing/erased slots, impossible generations, exhaustion,
write protection and end-of-memory bounds. These models assume writes affect
addressed bytes and reads return stored bytes; they do not model every physical
brownout or adversarial rollback.

Review found a recovery ambiguity in an initial two-committed-slot design:
erasing the newer slot could make the previous generation look like fresh first
use. The final design retires and verifies the old record before committing the
new one, checks slot/generation correspondence, and refuses inconsistent pairs.
Complete blanking or malicious restoration/recombination of older authenticated
state still requires an external anchor to detect; there is no reset/repair API.

The board's transitive `bare-metal` 0.2.5 dependency reports
[RUSTSEC-2026-0110](https://rustsec.org/advisories/RUSTSEC-2026-0110), an unmaintained
crate warning. The audit exits zero and the warning is recorded, not suppressed.
The native Python environment's older pip was updated to 26.2.2 before its final
clean audit; CI already upgrades pip. The separate AMQTT adapter-test environment
and real-core lab environment avoid their incompatible `websockets` requirements.

Physical acceptance remains the [pilot checklist](rak4631-pilot.md): actual
bootloader/DFU/SWD behavior, bus timeouts/recovery, FRAM power cuts, RTC UTC and
progression/retention, sensor readings, custom radio-stack integration, EU868 RF
behavior, LoRaWAN OTAA/session persistence, airtime, range and battery life.
The diagnostic supplies no radio stack and no operational command loop.
