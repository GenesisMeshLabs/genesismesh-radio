# RAK4631 / EU868 hardware pilot

The selected bench has two RAK4631 cores with RAK19007 bases, the WisBlock
Connected Box extensions, a RAK15004 FRAM, RAK12002 RTC, RAKDAP1 debug probe,
and a RAK7268V2 EU868 gateway with EU power supply. No customer receipt, shipping
information, device key or operator credential belongs in this repository.

## Before delivery

This increment prepares two `no_std` peripheral drivers and an actual linked
diagnostic image for the selected MCU. The FRAM driver implements the portable
device core's storage contract; the RTC driver implements its clock contract.
Host fault injection and compiler checks are software evidence. Physical power
loss, oscillator accuracy, RF delivery and LoRaWAN joins remain pending.
Observed checks are recorded in [pre-arrival validation](rak4631-validation.md).

The diagnostic enables the sensor rail, reads peripherals and changes the status LEDs. It never
formats FRAM, sets UTC, provisions keys or transmits radio traffic. Its memory
map reserves the stock S140/bootloader areas. The independent ELF check refuses
loadable bytes in those reserved regions, an invalid vector table, an invalid
stack or an entry point outside the image's executable flash.

From the repository root, use the pinned Rust toolchain and a fresh target
directory for the final release build. Build commands and the diagnostic's RTT
messages are in [the board README](../firmware/rust/rak4631-bringup/README.md).
The combined host tests, board build, Clippy and ELF check can be repeated on
Linux/WSL with `bash scripts/check-rak4631.sh` after installing Rust 1.99.0,
its formatting/Clippy components and `thumbv7em-none-eabihf` target. Set
`CARGO_TARGET_DIR` to a fresh directory for an independent final build.
Inspect the resulting ELF without connecting a board:

```sh
python scripts/check_rak4631_image.py \
  --image /path/to/target/thumbv7em-none-eabihf/release/rak4631-bringup \
  --layout firmware/rust/rak4631-bringup/memory-layout.json
```

A successful result includes the image SHA-256 and `hardware_tested: false`.
It is not permission to erase a board, and it does not establish that a
particular programmer preserves the bootloader or configuration registers.

## Arrival and assembly

1. Record board markings, module revisions, bootloader versions and stock
   firmware versions in a private lab notebook. Retain the factory bootloader
   and recovery instructions before changing software. Device EUIs may also be
   kept private; never publish LoRaWAN join keys, device secrets or MQTT tokens.
2. With power disconnected, connect the specified LoRa/BLE antennas and secure
   each module using its screws. Start with USB power. Battery polarity and
   charging behavior must be checked against the baseboard documentation before
   adding a battery.
3. Use one base as the sensor endpoint and the other as the USB-connected radio
   peer. For the endpoint, RAK15004 can use sensor slot A, RAK12002 slot B and
   RAK1901 slot C. Check module orientation/clearance on the received revisions;
   FRAM is documented for slots A/C/D on RAK19007. These peripherals share I2C1.
4. Connect the gateway by Ethernet, using its supplied EU power adapter. Record
   its installed WisGateOS version and follow the vendor's configuration flow.
   Keep its administration interface on the local network.
5. Identify the RAKDAP1 SWD wiring and target voltage reference from the actual
   base/probe documentation. A USB programming cable alone is not SWD wiring.
   Do not use an erase-all operation as a troubleshooting shortcut.

Primary hardware references:
[RAK4631](https://docs.rakwireless.com/product-categories/wisblock/rak4631/datasheet/),
[RAK19007](https://docs.rakwireless.com/product-categories/wisblock/rak19007/datasheet/),
[RAK15004](https://docs.rakwireless.com/product-categories/wisblock/rak15004/datasheet/),
[RAK12002](https://docs.rakwireless.com/product-categories/wisblock/rak12002/datasheet/),
[RAKDAP1](https://docs.rakwireless.com/product-categories/accessories/rakdap1/quickstart/).

## Diagnostic acceptance

Run these checks before any custom command can change a device configuration:

| Check | Required observation | Current physical result |
| --- | --- | --- |
| Boot and SWD | LED heartbeat, RTT output, recovery path works | Pending |
| Sensor bus | Expected FRAM 0x56, RTC 0x52, RAK1901 0x70 respond | Pending |
| FRAM | Write/read and write-protect behavior confirmed in an explicitly reserved scratch region | Pending |
| First-use storage | Inspect unknown contents; explicit offline initialization on a fresh device only | Pending |
| RTC | Correct independently set UTC, PORF handled by an operator, observed seconds advance | Pending |
| RTC backup loss | Lost initialization/backup causes refusal; no received timestamp silently restores trust | Pending |
| Device restart | Old command counter refused; accepted unfinished command stays uncertain | Pending |
| Interrupted write | Interrupt power at intent/result boundaries; no stale successful outcome or counter reuse | Pending |

FRAM has no guaranteed erased factory pattern. The journal treats only its
entire reserved region filled with `0xFF` as unused. The read-only diagnostic
must report unknown/dirty contents instead of clearing them. The low-level FRAM
API permits writes, but there is deliberately no automatic reset/format command.
Once a device has used an identity, clearing storage and reusing its key is not
a recovery procedure: reconcile the device/bridge state or explicitly retire
and reprovision its identity under a reviewed workflow.

The journal reserves 338 bytes, retires the previous record before committing
the next, and rejects dirty/corrupt/erased records beside an inconsistent peer.
It never selects an older valid snapshot in those cases. This sacrifices availability after an
interrupted write to avoid silently reusing replay counters. The core authenticates
its snapshot; neither an unkeyed journal checksum nor FRAM provides a hardware
rollback anchor. Restoring an entire older valid state remains outside the model.

The RTC provides retained time, not authenticated UTC or tamper resistance.
An operator must initialize and check it separately; instantaneous reads cannot
prove the oscillator has kept running. Observe progression against an independent
clock, test backup retention and check board/HAL timeout behavior.

## Three separate radio configurations

Use distinct configuration/state directories for the following experiments.
Do not alternate firmware against the same live journal/keys as a reset method.

| Experiment | Hardware path | Required application work |
| --- | --- | --- |
| Meshtastic | Two RAK4631 nodes running compatible Meshtastic firmware; USB to bridge | Private application-port integration producing this repository's payloads |
| Custom LoRa | Sensor RAK4631 to USB-connected peer RAK4631 | SX1262 driver, EU868 airtime scheduling and the `GM1` UART modem contract |
| LoRaWAN | Sensor RAK4631 to RAK7268V2 to The Things Stack | LoRaWAN stack, OTAA, persistent session/frame counters and raw application FPort |

The read-only diagnostic is separate from all three operational configurations.
It does not contain an SX1262 driver, Meshtastic stack, LoRaWAN MAC or USB modem.
Building it proves that selected board code links, not that the radio application
has been completed. The portable core's application replay counters also do not
replace LoRaWAN MAC/session counters or DevNonce persistence.

For the gateway, select an EU868 frequency plan consistent with the devices and
configure forwarding to the chosen The Things Stack deployment. Its built-in
network server's generic MQTT messages are not the bridge's TTS v3 contract.
The bridge uses [the TTS template](../examples/lorawan-tts.toml), raw bytes on
FPort 10 and a distinct per-device application authentication key. Confirm the
current data rate/MAC overhead leaves at least 46 application bytes for an
outcome. Do not infer that every rate or downlink schedule has enough capacity.

The [Meshtastic](../examples/meshtastic.toml) and
[custom UART](../examples/lora-serial.toml) templates likewise require their
documented application peers; stock firmware does not automatically speak this
repository's protocol. See [transport contracts](transports.md).

## Governed end-to-end acceptance

After the physical radio baseline and device application are available, rerun
the [disposable real GenesisMesh lab](live-lab.md), then repeat the same checks
over each actual radio path: authenticated telemetry, bounded online command,
offline grant, local bound refusal, replay rejection, authority outage/reconnect,
uncertain execution on lost confirmation and independent evidence verification.

Record each run's source commit, ELF hash, bootloader/firmware versions, module
revisions, region, data rate, antenna, distance, supply, injected fault and actual
result. Store device identifiers/keys privately. Do not promote a transport ACK,
MQTT publication, compiled image or successful host simulation to physical
execution evidence. Extend the pilot to GPS, RS485 and analog modules after the
sampling-interval workflow passes; those extension drivers are not in this increment.
