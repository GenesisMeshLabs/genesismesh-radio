# Constrained-device codec

An allocation-free [Rust device core](rust/genesismesh-radio-device/README.md) now
implements the same wire profile plus local command handling and recovery. The C
codec below remains available for C/C++ and vendor-SDK integration.

This directory contains an allocation-free C99 codec for the application profile
in [the protocol specification](../docs/protocol.md). The Python bridge and the
C codec share deterministic vectors and are tested against each other using
OpenSSL HMAC-SHA256 on the host.

The codec is usable from C++ through its `extern "C"` header. It owns neither
the radio driver nor persistent state. It is not complete deployable firmware.

| File | Responsibility |
| --- | --- |
| `include/gmr_protocol.h`, `src/gmr_protocol.c` | Strict framing, payload helpers, tag checks, and freshness checks |
| `platform/mbedtls_hmac.*` | HMAC callback using the platform's mbedTLS SHA-256 implementation |
| `vectors.json` | Public test keys and expected wire bytes, never deployment credentials |
| `tests/conformance.py` | Compile C and check actual OpenSSL-backed interoperability |

## Host validation

On Linux or WSL with `cc`, Python 3.12+, and the OpenSSL `libcrypto` runtime:

```sh
python3 firmware/tests/conformance.py
```

The test compiles with `-std=c99 -Wall -Wextra -Werror -pedantic -O2`. It uses
ctypes to supply a callback calling the actual OpenSSL `HMAC` function, so
OpenSSL development headers are not required. Python's separate encoder and
the committed golden vectors are compared byte-for-byte. No radio hardware is
used by this test.

## Arduino on ESP32 and ESP-IDF

Compile `src/gmr_protocol.c` and `platform/mbedtls_hmac.c`, adding `include/`
and `platform/` to the include path. ESP-IDF components also declare their
dependency on `mbedtls`. Arduino's ESP32 core includes mbedTLS; Arduino boards
without it need a callback backed by an appropriate vetted crypto library.
The provided callback uses the standard `mbedtls_md_hmac` API; the selected
platform must enable SHA-256 and the message-digest/HMAC module.

The integration sequence is:

1. Load provisioned device ID, audience, device-specific secret, transport
   configuration, allowed interval bounds, persistent counters, and clock floor.
2. Refuse operation if any security state is missing, corrupt, or inconsistent.
3. Give the radio application's bytes to `gmr_decode` using trusted current UTC
   time and that transport's actual application payload allowance.
4. Require `GMR_COMMAND`, the configured device ID, and a fresh downlink counter.
5. Atomically persist command acceptance and its intended interval before
   touching the device configuration. Enforce the locally configured limits.
6. Apply the interval, then durably record the actual result. A crash at this
   boundary requires reconciliation; do not automatically execute again.
7. Reserve a new uplink counter durably, use `gmr_outcome_payload`, encode the
   outcome with `gmr_encode`, and send it through the selected radio stack.

Use NVS or another crash-consistent platform store for replay/command state.
Account for flash endurance: an allocator may durably reserve a block of future
outgoing counters and skip unused counters after reboot, but must never reuse
them. Receiving a message must not advance state until its authentication passes.
Protect stored keys using the board's supported provisioning and key-storage
mechanisms. A shared key in ordinary firmware/flash does not establish physical
capture resistance.

For LoRaWAN, pass the raw encoded bytes as the configured application FPort
payload. The LoRaWAN stack still owns joins, session keys, receive windows,
frame counters, regional parameters, and airtime. Keep the application counter
separate from the LoRaWAN frame counter. For Meshtastic, transmit through the
configured private application port. For custom LoRa firmware, implement the
documented UART adapter contract and the board-specific radio driver.

## Bare-metal contract

Supply a `gmr_hmac_sha256` callback that returns zero only after writing the
full 32-byte standard HMAC-SHA256 result. Its context owns a provisioned key of
at least 32 bytes. Errors must return nonzero; never substitute zeros or a mock
digest. The codec truncates the result to 16 bytes for the wire tag.

The platform must additionally supply durable counters and command journaling,
trusted UTC with rollback detection, random secret provisioning, an allowlisted
resource action, and a bounded radio driver. The codec uses fixed-size stack
buffers, no heap allocations, no threads, and no OS calls. Its largest
authentication buffer is 186 bytes; measure the final firmware's total stack
and memory use on the actual target.

Neither this source nor host conformance claims that Arduino, ESP-IDF,
bare-metal radio hardware, battery life, receive-window timing, or physical
actuation has been tested. Those require the documented hardware pilot.
