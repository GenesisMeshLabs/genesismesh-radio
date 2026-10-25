# Dependency notices

This experimental repository does not declare a redistribution license for its own code.
Review the applicable licenses before redistributing a combined application.

- Meshtastic Python 2.7.11 (optional adapter dependency): GPL-3.0-only.
  https://github.com/meshtastic/python/blob/master/LICENSE
- Eclipse Paho MQTT Python 2.1.0: EPL-2.0 or BSD-3-Clause.
  https://github.com/eclipse-paho/paho.mqtt.python
- PySerial 3.5: BSD-3-Clause. https://github.com/pyserial/pyserial
- HTTPX 0.28.1: BSD-3-Clause. https://github.com/encode/httpx
- mbedTLS is supplied by the embedded platform, not vendored here.
  https://github.com/Mbed-TLS/mbedtls
- OpenSSL is used by host interoperability tests, not included in the firmware codec.
  https://www.openssl.org/source/license.html

AMQTT is a test-only broker. It is never required by a production bridge installation.

The optional Rust device crate has its own committed Cargo lockfile. RustCrypto
`hmac` 0.12.1 and `sha2` 0.10.9 use MIT OR Apache-2.0 licensing; their `subtle`
dependency uses BSD-3-Clause. Host-only `serde_json` and `hex` use MIT OR Apache-2.0.
These declarations come from the locked packages' Cargo metadata. Review the full
transitive inventory and applicable terms before distributing a combined firmware.

The optional WisBlock and RAK4631 diagnostic crates have separate locked
inventories. Direct board dependencies include `embedded-hal` 1.0.0
(MIT OR Apache-2.0 OR BSD-3-Clause), `nrf52840-hal` 0.19.0 (MIT OR Apache-2.0),
`cortex-m` 0.7.7 (ISC), `cortex-m-rt` 0.7.7 (MIT OR Apache-2.0) and `rtt-target`
0.6.2 (MIT). These are not bridge runtime dependencies. Review transitive HAL,
PAC, USB and debug dependencies before distributing a board image.

The board audit reports the transitive `bare-metal` 0.2.5 maintenance warning
RUSTSEC-2026-0110 through the Cortex-M/HAL dependencies. It is not suppressed;
an audit exit status of zero does not mean there are no maintenance advisories.
