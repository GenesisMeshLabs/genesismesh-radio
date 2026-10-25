# Portable Rust device core

Status: portable implementation and local verification complete after merging
the continuous service in PR #2. Hosted results are tracked on the implementation
pull request. Hardware has not been selected.

No board has been selected. This increment builds an allocation-free `no_std`
library, a host interoperability harness and cross-build checks. A compiler target
passing does not establish support for a board's radio, flash, clock or bootloader.

## Scope

- Exact wire compatibility with the existing Python and C v1 codecs, using
  RustCrypto HMAC-SHA256 and constant-time truncated-tag verification.
- Device-side local parameter bounds, authentication, replay checks, trusted-clock
  rollback refusal and atomic durable intent before physical configuration changes.
- Authenticated persistent snapshots tied to device identity and configuration.
  Missing/corrupt state fails closed; a saved snapshot restored in full still needs
  an external monotonic anchor to detect rollback.
- An interrupted accepted command becomes uncertain after restart. It is never
  automatically applied again. Radio-send failure retries reserve a new counter.
- Hardware traits for storage, clock and sampling-interval actuation. Radio drivers
  consume/produce the existing application bytes for LoRa or a LoRaWAN FPort.
- Host tests and fault injection, Python/C/Rust interoperability, and bare-metal
  cross-builds for ARM Cortex-M and RISC-V target families.

Board-specific firmware, LoRaWAN joins, regional scheduling, secure key storage,
physical flashing and RF validation follow once concrete hardware is selected.
The gateway's permission remains dispatch authorization; the device core does not
independently verify GenesisMesh grants at execution time.
