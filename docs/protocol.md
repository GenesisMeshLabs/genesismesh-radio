# GenesisMesh Radio application profile, version 1

Status: experimental. This is an application datagram carried by a radio
transport. It does not modify LoRa, LoRaWAN, Meshtastic, or GenesisMesh's trust
protocol. It introduces no key-exchange handshake.

## Trust and provisioning

Provision a random secret of at least 32 bytes independently for each device,
along with its numeric device ID, exact audience string, allowed transport route,
and permitted resources. Keep the radio authentication secret separate from
GenesisMesh node/executor keys and LoRaWAN/Meshtastic keys. Never provision the
public test keys from `firmware/vectors.json` to deployed devices.

The device and bridge share the authentication secret. Either endpoint can
construct a valid message. Consequently a bridge receipt is a statement by the
bridge about the device it authenticated, **not an independently verifiable
device signature or proof that a physical measurement is true**.

This profile authenticates but does not encrypt payloads. The raw UART/LoRa
adapter provides no confidentiality. Meshtastic and LoRaWAN have their own
separately configured encryption. Do not transmit secrets through this profile.

## Wire format

All integers are unsigned and big-endian except the telemetry value, which is
signed two's-complement i32. Values outside the stated ranges are rejected.

| Offset | Size | Field | Valid values |
| --- | ---: | --- | --- |
| 0 | 1 | version | 1 |
| 1 | 1 | kind | 1 telemetry; 2 command; 3 outcome |
| 2 | 4 | device ID | 1 through 2^32 - 1 |
| 6 | 8 | counter | 1 through 2^64 - 1 |
| 14 | 4 | expires at | UTC Unix seconds, greater than receiver time |
| 18 | 1 | payload length | Exact typed payload length, at most 16 |
| 19 | variable | payload | Defined below |
| 19 + payload length | 16 | authentication tag | HMAC-SHA256 truncated to its first 16 bytes |

The maximum envelope is 51 bytes, including its tag. Current telemetry,
command, and outcome frames are respectively 40, 38, and 46 bytes. A transport
budget may be lower; oversize frames are rejected. A 51-byte payload is not
available in every LoRaWAN region, data rate, or network configuration. The
adapter must use the applicable configured allowance. This version provides no
fragmentation or reassembly.

## Authentication input

The exact HMAC input is:

```text
b"GenesisMeshRadio\x00v1\x00"
|| audience_length:u16
|| audience:ASCII[audience_length]
|| direction:u8
|| complete_header_and_payload
```

The audience is an exact, case-sensitive string of 1–128 ASCII characters from
0x21 through 0x7e (no spaces or control characters). Its length is encoded in
big-endian form. It identifies the intended bridge/deployment, for example
`lab/site-1`. Direction is 1 for telemetry/outcomes and 2 for commands. The
receiver derives it from the authenticated message kind. The bridge accepts
only uplink kinds; device execution accepts only commands. A provisioned route
must also match; the numeric ID extracted before authentication is only a lookup
hint and must never authorize an action.

The tag is the first 16 bytes of standard HMAC-SHA256. Verify tags with a
constant-time comparison. The C codec delegates full HMAC-SHA256 to the
platform's vetted implementation and performs tag comparison itself.

## Typed payloads

### Telemetry, kind 1

```text
metric:u8 || value:i32
```

Metric IDs and units are defined by the deployment's device schema. This
profile transports the integer and does not infer a sensor's units or validity.

### Set sampling interval, kind 2

```text
opcode:u8 = 1 || interval_seconds:u16
```

The interval is 1–65535 seconds. The provisioned device and bridge additionally
enforce their narrower allowed interval range. This operation sets a value;
it is not a toggle. The command's frame counter is its correlation ID within
that device's downlink stream. The bridge clamps command expiry to the
GenesisMesh authorization's reporting deadline, with a safety margin.

### Outcome, kind 3

```text
command_counter:u64 || status:u8 || applied_interval:u16
```

The referenced command counter must be positive and match a pending command
for the same enrolled device. Status 0 is success, 1 rejected, and 2 uncertain.
A successful outcome must report a positive interval matching the authorized
requested value. The protocol codec checks positivity; the controller checks
that the value matches its command. Rejected/uncertain outcomes may report zero
if the applied value is unknown. The outcome's own frame counter belongs to
the uplink stream; it is separate from the referenced downlink counter.

## Freshness, replay state, and retries

The decoder requires `receiver_now < expires_at <= receiver_now + max_future_seconds`.
The default future window is 300 seconds. The caller must supply trusted time
and persist its clock floor so a reboot cannot make an expired message fresh.
A device without trustworthy time must refuse commands; this profile supplies
no secure time-synchronization protocol.

Each device has one persistent counter stream per direction. Telemetry and
outcomes share its uplink stream. Reserve outbound counters durably before
sending. Authenticate a received message before atomically storing the event
and its accepted counter. Do not reset counters on reconnect, power loss, or
ordinary key rotation; never wrap a counter. Missing or replaced security state
requires explicit reprovisioning/reconciliation, not an automatic reset.

A strict high-water receiver rejects messages whose counter is no greater than
the stored counter, including older messages reordered by the transport. This
is conservative and can lose valid telemetry/confirmations. It must not turn a
missing confirmation into success. A device may send a cached command result
again with a newly reserved uplink counter, without repeating the operation.

Persist a command intent before dispatch. Persist the device's acceptance
before applying the action, and its result before sending the outcome. A crash
between the physical side effect and recording its result is uncertain and
requires reconciliation. This profile does not promise exactly-once physical
execution. MQTT acknowledgments, LoRaWAN delivery acknowledgments, and radio
ACKs are not application outcomes.

## Conformance

`firmware/vectors.json` contains public deterministic interoperability vectors.
Python unit tests cover framing, bounds, freshness, wrong keys/audiences,
direction reflection, malformed payloads, truncation, and every single-bit
mutation of a valid packet. The firmware harness compiles the portable C codec
and exercises it using the actual OpenSSL HMAC implementation against Python,
golden vectors, boundary values, randomized valid messages, and corrupt frames:

```sh
python3 firmware/tests/conformance.py
```

The host test requires a C99 compiler and the OpenSSL `libcrypto` runtime.
It does not establish RF interoperability or validate a board's persistent
storage, trusted time, crypto configuration, or actuator implementation.
