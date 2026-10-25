# Continuous bridge and provisioning

Status: implementation and local verification complete. Hosted check results are
tracked on the implementation pull request; see [validation](service-validation.md).

The next pilot increment lets a local operator inspect a running bridge and
dispatch governed commands without stopping telemetry ingestion. The existing
Python bridge, radio profiles and GenesisMesh authorization semantics remain.

## Delivery

1. A loopback-only, bearer-authenticated local HTTP service with bounded requests,
   a bounded owner-thread mailbox, status/health reads and command lookup by UUID.
   Only the owner thread accesses the journal and bridge. An acknowledged command
   must already have a durable journal record. An HTTP timeout is uncertain and
   never permission to redispatch with a different request ID.
2. CLI service clients and Linux systemd packaging, graceful stop and readiness.
   Existing direct CLI operation remains available while the daemon is stopped.
3. Fresh-device provisioning packages with independently generated device keys,
   explicit transport/resource bindings, private files, no secret console output,
   and refusal to overwrite existing state or enrollment material. This does not
   enroll the bridge into a GenesisMesh authority or flash a device.
4. Real local HTTP tests, adversarial authentication/framing tests, admission and
   crash/restart tests, provisioning isolation tests, and the existing radio/live
   integration checks. Hosted CI must pass before proposing the change for merge.

## Firmware language decision

Keep the small allocation-free C codec as the portable reference for C/C++ and
vendor SDK integration. Prefer Rust for a new device application's state machine
when the selected MCU, LoRa/LoRaWAN stack and persistent-storage drivers support it.
Rust supports `no_std`; a C FFI boundary still requires explicit unsafe review.
Neither language supplies durable counters, reliable time or safe crash recovery
automatically. Board firmware and RF validation remain a subsequent pilot phase.

References: [Embedded Rust](https://docs.rust-embedded.org/book/intro/no-std.html),
[C interoperability](https://docs.rust-embedded.org/book/interoperability/c-with-rust.html),
[Espressif toolchains](https://docs.espressif.com/projects/rust/book/getting-started/toolchain.html).
