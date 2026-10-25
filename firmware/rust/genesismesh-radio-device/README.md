# GenesisMesh radio device core

Allocation-free `no_std` Rust library for the existing v1 application profile.
It provides the codec and conservative device command state machine. Hardware
integrators supply storage, trusted UTC, actuation and radio adapters.

This is a library, not a board firmware image. Library builds do not validate a
board's flash, SPI pins, LoRa drivers, LoRaWAN stack, bootloader or radio operation.

## Modules

| Module | Responsibility |
| --- | --- |
| `protocol` | Exact Python/C wire bytes, payload bounds, freshness and truncated HMAC-SHA256 verification |
| `device` | Provision/open, local bounds, durable intent, replay prevention, outcome and telemetry production |
| Internal `state` | Versioned authenticated 120-byte snapshot bound to identity, key, audience and local configuration |

The crate forbids unsafe code in its own sources and uses fixed-size buffers.
Its runtime dependencies are pinned RustCrypto `hmac` and `sha2`, with default
features disabled. Host examples and tests use `std`, JSON and heap allocation;
they are not part of the MCU library. `Cargo.lock` is committed.

## Test and cross-build

From the repository root with Rust 1.99.0 and Python installed:

```sh
cargo +1.99.0 test --locked --all-targets --manifest-path firmware/rust/genesismesh-radio-device/Cargo.toml
cargo +1.99.0 clippy --locked --all-targets --manifest-path firmware/rust/genesismesh-radio-device/Cargo.toml -- -D warnings
python firmware/tests/rust_conformance.py
```

The interoperability harness needs a C compiler and OpenSSL libcrypto on Linux or
WSL. It compares Rust/Python/C bytes, golden vectors, randomized frames, malformed
inputs, mutation refusal and freshness boundaries. The Rust unit tests exercise
storage errors before/after commit, simulated power cuts, actuator errors, clock
rollback, counter exhaustion, replay refusal and authenticated state corruption.
The declared minimum compiler is Rust 1.85.0, checked separately for the library.

CI builds release `.rlib` libraries for these targets:

| Rust target | Architecture coverage |
| --- | --- |
| `thumbv6m-none-eabi` | ARM Cortex-M0/M0+ |
| `thumbv7em-none-eabi` | ARM Cortex-M4/M7, soft-float ABI |
| `thumbv7em-none-eabihf` | ARM Cortex-M4/M7, hard-float ABI |
| `thumbv8m.main-none-eabihf` | ARMv8-M mainline with hard-float ABI |
| `riscv32imc-unknown-none-elf` | RV32IMC |
| `riscv32imac-unknown-none-elf` | RV32IMAC |

Install the appropriate target with `rustup target add --toolchain 1.99.0 <target>`
then use `cargo +1.99.0 build --locked --release --lib --target <target>` with the
manifest above. This covers compiler/architecture compatibility, not peripheral
support. Xtensa devices need a separate compiler and HAL assessment.

## Hardware integration contract

1. Load a unique provisioned device key, identity, audience, local interval limits
   and application payload allowance. `Profile` borrows the 32-byte key; the
   platform owns its lifetime and protection. Keys are never included in snapshots
   or debug status. This API does not use non-exportable secure-element keys.
2. Implement `Storage::load` and `Storage::commit` for an atomic durable replacement
   of all 120 snapshot bytes. A successful commit must survive reset. A failed
   commit may already have written: the core refuses further work until reopening.
   Flash wear, dual-slot recovery, checksums, synchronization and power-loss behavior
   must be verified on the board. An in-memory implementation cannot meet this contract.
3. Call `Device::provision` only for fresh hardware with no existing snapshot.
   Otherwise call `Device::open`; absent, corrupt or mismatched state fails closed.
   Deleting state and provisioning the same key again is an unsafe counter reset.
4. Implement `Clock` with trustworthy UTC seconds. Every trusted read advances a
   volatile high-water mark, even for refused packets; durable snapshots retain the
   last committed floor across resets. Whole-snapshot rollback cannot be detected
   without an external monotonic anchor. State authentication is not rollback protection.
5. Implement `Actuator` to apply and verify the sampling interval. Returning an
   error may mean the setting changed, so it produces an uncertain result and
   `interval=0` (unknown). Never automatically retry a physical action after an error.
6. Pass a received application frame to `receive_command`. The core authenticates,
   checks identity/replay/freshness/local bounds, durably accepts, rechecks time,
   then calls the actuator. TTL bounds **actuator-call start**, not physical
   completion; the driver must supply a stronger deadline if the action needs one.
7. Obtain `outcome_frame` or call `send_outcome`. Each attempt durably reserves a
   new uplink counter before returning bytes or touching the radio. Failed sends
   burn that counter; outcome retries reuse the command counter with a new uplink
   counter. The latest outcome is retained until a newer authenticated command
   replaces it. There is no multi-command scheduling queue.
8. Feed raw bytes to the configured Meshtastic application port, custom LoRa
   framing or LoRaWAN FPort. LoRaWAN joins, receive windows, network frame counters,
   regional rules and airtime remain the radio stack's responsibility. Keep its
   counters separate from the application counters.

An accepted operation interrupted before a durable result recovers as uncertain;
it is never reapplied. A completed authenticated result survives reopening.
Storage/clock failures after acceptance require recovery; `poisoned` status blocks
all frame production and masks physical state as unknown. A caught panic from a
storage or actuator implementation also leaves the instance poisoned. Reopen from
validated durable state before reuse; normal board panic handling may instead reset.

No radio receipt proves delivery. The gateway still needs the authenticated device
outcome. The shared-key tag provides authentication, not encryption or a device
digital signature. The device does not independently validate GenesisMesh grants;
the gateway's existing permission is command-dispatch authorization.

## Host-only test peers

`examples/codec.rs` is a bounded JSON-lines codec tool. `examples/device_peer.rs`
runs the real Rust engine with simulated actuation and process-local memory. Its
`restart` command reopens the in-memory snapshot; restarting the process loses it.
Every response identifies `hardware_tested: false`. Use only disposable test keys.
The live lab drives this peer against a real disposable authority/edge agent and
verifies signed evidence with the standalone Rust verifier.
