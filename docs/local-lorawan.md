# Local LoRaWAN through WisGateOS 2

The `wisgate` adapter connects the existing bridge to the RAK7268V2's built-in
LoRaWAN network server through Generic MQTT. It needs no hosted TTS account or
separate ChirpStack server. A broker can run on the local computer or gateway.
The adapter is a software implementation of the documented contract; gateway
firmware, joining, receive-window timing and RF remain untested until arrival.

## Supported contract

This profile follows RAK's current
[Generic MQTT guide](https://learn.rakwireless.com/hc/en-us/articles/35956743083543-configure-generic-mqtt-integration-with-built-in-network-server)
and its
[broker envelope reference](https://learn.rakwireless.com/hc/en-us/articles/26688300221079-How-To-Use-the-MQTT-Broker-Like-a-Pro-Examples).
The [RAK7268V2 integration page](https://docs.rakwireless.com/product-categories/wisgate/rak7268v2/integration-guide/)
links that Generic MQTT contract for its built-in server. These are application
integration messages, not packet-forwarder or gateway-backend MQTT messages.

| Direction | Topic | Required JSON fields |
| --- | --- | --- |
| Uplink | `application/<application_name>/device/<lowercase_dev_eui>/rx` | `applicationName`, `applicationID`, `devEUI`, `fPort`, `data_encode="base64"`, `data` |
| Downlink | `application/<application_name>/device/<lowercase_dev_eui>/tx` | `confirmed=true`, `fPort`, base64 `data` |

The configured `application` is the topic's lowercase application name.
`application_id` is a separate string matching the uplink's `applicationID`.
Both identifiers and the topic/payload DevEUI must agree. The friendly GenesisMesh
route maps to that DevEUI in `device_euis`. LoRaWAN FPort is bound independently
of the authenticated application command. This adapter permits application ports
1 through 223. Raw payload forwarding must be enabled: decoded-object-only or
hex envelopes are refused. A firmware variant missing `data_encode` requires
checking its actual documented format before extending this profile.

The adapter subscribes only to configured `/rx` topics. `/ack`, `/tx`, `/status`
and `/join` notifications cannot become device outcomes. Downlinks contain no
invented vendor command-ID field: correlation remains in the bridge journal and
the authenticated application counter. MQTT submission is never execution proof.

Uplinks are bounded to 64 KiB of JSON, depth 32 and 4,096 visited values. Duplicate
keys, nonfinite numbers, retained messages, invalid base64 and oversized payloads
are refused. Gateway timestamps and LoRaWAN frame counters are untrusted metadata;
the existing MAC, application expiry, replay counters and source/resource binding
still apply. Raw application payload confidentiality depends on the configured
LoRaWAN security; HMAC does not encrypt it.

## Prepare before the radios arrive

Use [the example](../examples/lorawan-wisgate.toml) as a template. Replace the
broker host, application identifiers and DevEUI with your own configuration.
Pure runtime preflight does not connect, read credential values or change gateway
settings:

```sh
python -c "from genesismesh_radio.config import load_config; from genesismesh_radio.runtime import validate_runtime; validate_runtime(load_config('examples/lorawan-wisgate.toml'))"
```

Follow the existing [fresh-device provisioning](provisioning.md) workflow on a
private Linux filesystem. It creates application MAC keys, not LoRaWAN OTAA keys.
Supply the existing edge credential and the MQTT password through their named
environment variables separately. Device profiles preserve the FPort and DevEUI
metadata; they do not join, enroll or flash a board.

After privately loading the provisioned device keys, `gm-radio check-config
--config /path/to/bundle/bridge.toml` additionally checks their identity binding.
That CLI command requires the device-key environment values; it still does not
open MQTT or change gateway settings.

All non-loopback broker connections require TLS, including a private LAN IP.
Use a broker certificate whose SAN matches the configured hostname/IP and a
trusted CA. Set `ca_file` for a local CA; certificate and hostname validation
remain enabled. Plain MQTT is allowed only to literal loopback or `localhost`,
for disposable local tests or the local end of an authenticated tunnel.
Broker credentials belong outside Git. Scope broker ACLs to the exact uplink
subscription topics and downlink publication topics for this application/devices.

The software test fixture follows the vendor's schema with disposable values.
A local broker test exercises actual Paho subscribe/publish and retained-message
refusal. Neither substitutes for packets captured from the purchased gateway.

## First gateway session

1. Record the shipped gateway model and WisGateOS 2 version. Use its local Web UI;
   do not expose management ports or MQTT to the public internet.
2. Select the built-in network server, Sweden/EU868, and configure the application
   and each device's actual OTAA identifiers/keys using the vendor's instructions.
   Those LoRaWAN keys are separate from GenesisMesh application MAC keys.
3. Enable Generic MQTT, authentication and TLS to the local broker. Leave retain
   disabled. Use the documented application-name topics, then capture a real raw
   uplink and compare its identity, encoding and FPort against this profile.
4. Initialize fresh bridge state explicitly, start the service, and first inspect
   authenticated telemetry. Only then issue a bounded interval update through
   the existing GenesisMesh authorization path.
5. Confirm success using the authenticated matching application outcome. A Class A
   device receives a downlink after an uplink; use an uplink cadence compatible
   with the command's bounded TTL. Queued or expired results remain uncertain.

The gateway owns LoRaWAN joins, frame counters, encryption, regional scheduling
and receive windows. The bridge still authorizes dispatch rather than verifying
execution-time authority on the MCU. This adapter does not configure the gateway,
provision its network server or prove airtime compliance.
