# Dependency notices

This private prototype does not declare a redistribution license for its own code.
Review licensing before publishing or redistributing a combined application.

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
