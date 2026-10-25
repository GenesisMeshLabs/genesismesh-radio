# Radio transport adapters

The adapters carry the same authenticated application frame. They do not evaluate
GenesisMesh policies or convert a delivery acknowledgment into an execution result.
Application authentication, persistent replay checks, and command outcome correlation
belong to the controller. The transport source address is an additional binding, not
an independent cryptographic identity.

Every adapter implements `send(route, payload, command_id) -> str`,
`receive(timeout) -> Inbound | None`, and `close()`. Returned strings identify local
submission only. A failed or timed-out send may already have reached the radio or
broker; the controller must preserve that uncertainty instead of automatically
resending. MQTT and Meshtastic ingress queues are bounded; `overflow_count` and
`rejected_count` expose transport loss/rejection. These in-memory queues do not
provide durable ingestion before the controller commits an event.

## Meshtastic over LoRa

`MeshtasticTransport` uses the official Python `SerialInterface` and private
application ports (default `256`, configurable within `256..511`). Configure the
serial device explicitly. Provision the radio channel, region and encryption using
Meshtastic's own tools; opening the adapter does not reconfigure the radio.

Routes are unicast node numbers such as `!12345678`. Supply the configured nodes,
channel index and application port. Received packets must match all three, and
callbacks from another radio interface are ignored. The official decoded packet
field is `packet["decoded"]["payload"]` as bytes. Named `PRIVATE_APP` and numeric
private port values are supported. Radio packet IDs are diagnostic receipts only.

The bridge sends binary data using `sendData`, requests a radio ACK, and still
requires the separate authenticated application outcome. Existing device firmware
must understand the application's frame; stock Meshtastic firmware does not itself
implement the sampling-interval command.

Install the optional `meshtastic` extra to use this adapter. The pinned Meshtastic
Python dependency is GPL-3.0-only; retain its license and notices when distributing
that dependency. The base package can use the UART and MQTT adapters without it.

Sources: [Python serial interface](https://python.meshtastic.org/serial_interface.html),
[current packet implementation](https://github.com/meshtastic/python/blob/master/meshtastic/mesh_interface.py),
[private application ports](https://github.com/meshtastic/protobufs/blob/master/meshtastic/portnums.proto).

## Custom LoRa modem over UART

`SerialLoRaTransport` is a host-side modem contract. A separate modem firmware must
drive the LoRa transceiver and preserve frame boundaries. This is not a Semtech SPI
driver and does not create a new mesh routing protocol.

One UART line carries one complete radio application frame:

```text
GM1 <route> <hexadecimal-application-frame>\n
```

Routes contain 1–64 ASCII letters/digits or `_.:-`, beginning with a letter/digit.
Use one space between fields and LF termination. Empty payloads, invalid hex,
unconfigured routes, extra fields and oversized lines are rejected. The reader
retains a partial line across timeouts and discards an oversized line through its
next LF before accepting another packet. Hex is UART framing overhead; modem
firmware should transmit the decoded binary application frame over radio.

The `uart:` receipt means that the complete line was accepted by the local serial
driver. It says nothing about RF delivery or device execution. Raw LoRa/UART framing
adds no confidentiality; the provisioned application HMAC provides authentication,
not encryption.

## LoRaWAN through The Things Stack v3

`TtsMqttTransport` connects to the Application Server's MQTT interface. It does not
replace the LoRaWAN network server, perform device joins, or use the Network
Authority as a LoRaWAN gateway.

- MQTT 3.1.1 with QoS 0, matching the TTS server contract.
- Application identifier and username are `app-id@tenant-id` (`app-id@ttn` on TTN),
  or `app-id` for The Things Stack Open Source.
- Configure every allowed device ID and its exact 16-hex-digit DevEUI.
- Ingress topic: `v3/<application>/devices/<device-id>/up`.
- Egress topic: `v3/<application>/devices/<device-id>/down/push`.
- Configure an application FPort in `1..233`; default `10`.

Uplinks must match the configured application/topic device, JSON device/application
identity, DevEUI and FPort. Strictly decode raw `uplink_message.frm_payload` base64.
`decoded_payload` is not trusted as the wire representation. Retained messages,
duplicate JSON keys, invalid JSON, and events over 64 KiB are refused.

Downlinks use `frm_payload`, the configured `f_port`, normal priority, confirmed
delivery and a `gm-radio:<command-id>` correlation ID. The adapter uses `/push`,
never `/replace`, so it does not erase other queued downlinks. A confirmed LoRaWAN
downlink ACK establishes radio reception, not execution. Class A downlinks must wait
for a device receive opportunity; queued commands can arrive after their deadline,
so the device must independently reject expired commands.

Remote brokers require TLS with certificate validation. Plain MQTT is permitted
only for a literal loopback address or `localhost`, for disposable tests. Read the
password/API key from the runtime configuration's environment reference; do not
commit credentials. Subscriptions are re-established on reconnect, and a successful
SUBACK is required before sends. A `mqtt-local:` receipt means Paho finished local
QoS0 publication; it is not confirmation of the application server's acceptance.

Sources: [TTS MQTT contract](https://www.thethingsindustries.com/docs/integrations/other-integrations/mqtt/),
[JSON data formats](https://www.thethingsindustries.com/docs/integrations/data-formats/),
[Paho client API](https://eclipse.dev/paho/files/paho.mqtt.python/html/client.html).

## Payload budgets and validation

The default application-frame budget is 51 bytes. This fits EU868 DR0–DR2 only
when no FOpts reduce the available application space. It is not a global minimum:
US915 DR0 permits only 11 application bytes. Configure the actual permitted budget
for the region, data rate and network; reject an unsupported profile rather than
truncating a tag or silently fragmenting a frame. Radio firmware/network servers
remain responsible for regional transmission scheduling and airtime restrictions.

Sources: [EU868 payload sizes](https://www.thethingsnetwork.org/docs/lorawan/regional-parameters/eu868/),
[US915 payload sizes](https://www.thethingsnetwork.org/docs/lorawan/regional-parameters/us915/).

Adapter tests exercise pure envelope parsing, injected official API contracts,
real PySerial loopback, a Linux pseudo-terminal, and a disposable loopback AMQTT
broker with Paho sockets. Install `amqtt==0.11.3` in the test environment for the MQTT
tests. These establish software transport behavior, not RF performance, hardware
compatibility, or interoperability with a deployed TTS server.
