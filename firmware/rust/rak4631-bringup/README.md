# RAK4631 read-only bench diagnostic

This is a linked Rust application for the purchased RAK4631/nRF52840 and
RAK19007 base. **It has not been flashed or tested on hardware.** It contains
no LoRa, LoRaWAN or Meshtastic radio stack and transmits no RF packets.

The diagnostic enables the sensor power rail, pulses the green LED, and reports
through nonblocking RTT over SWD. It reads the RAK15004 FRAM journal and the
RAK12002 RTC using the actual WisBlock adapter crate. It never writes FRAM,
sets the clock, clears RTC faults, initializes device state, or loads keys.
The I2C address-pointer transfers used to select a read register are not writes
to persistent data or clock settings. A present journal is not authenticated by
this diagnostic because it intentionally has no device key.

## Build and inspect

The board crate requires the tested 1.99 compiler: its locked HAL dependencies
include packages requiring newer compilers than the portable core's 1.85 minimum.
From the repository root, with Rust 1.99.0 and the target installed:

```sh
rustup target add --toolchain 1.99.0 thumbv7em-none-eabihf
export CARGO_TARGET_DIR=/tmp/gmr-bringup-target
cargo +1.99.0 test --locked --all-targets \
  --manifest-path firmware/rust/rak4631-bringup/Cargo.toml
cargo +1.99.0 build --locked --release --features board \
  --target thumbv7em-none-eabihf \
  --manifest-path firmware/rust/rak4631-bringup/Cargo.toml
python3 scripts/check_rak4631_image.py \
  --image "$CARGO_TARGET_DIR/thumbv7em-none-eabihf/release/rak4631-bringup" \
  --layout firmware/rust/rak4631-bringup/memory-layout.json
```

The host test checks layout metadata against the linker constants and vendor
reserved ranges. The Python check examines the actual ELF, including vectors
and loadable segments. These commands build/inspect files only. They never
connect to, flash, erase, recover or alter a board. The `board` feature requires
the explicit ARM target; ordinary host tests omit it.

The locked binary uses the stock Arduino BSP's **S140 6.1.1** application window:

| Region | Included range, exclusive end |
| --- | --- |
| Application flash | `0x00026000 .. 0x000ED000` |
| Application RAM | `0x20006000 .. 0x20040000` |

`build.rs` generates `memory.x` from `src/layout.rs`. The machine-readable
`memory-layout.json` is checked independently. Cortex-M startup sets VTOR to
the linked vector table; `--nmagic` avoids an extra ELF-header load segment
below the application window. SoftDevice, bootloader, settings and UICR are
outside this image. **This layout does not verify the bootloader actually
installed on a delivered board.** The diagnostic never enables SoftDevice.
Confirm the physical board's bootloader/SoftDevice layout before choosing a
flash or USB-DFU method; compiling this ELF does not create a validated UF2/DFU
package or prove that the installed bootloader will accept it. Do not use an
erase-all/recover operation as a substitute for that check.

## Connections and observations

| Function | nRF52840 GPIO |
| --- | --- |
| Sensor I2C SDA | P0.13 |
| Sensor I2C SCL | P0.14 |
| Sensor switched rail, enabled high | P1.02 (`WB_IO2`) |
| Green LED, active high | P1.03 |
| Blue LED, active high | P1.04 |

These are the vendor's sensor-slot bus pins. P0.26/P0.27 snippets found for
other nRF52840 boards are not this board's sensor I2C mapping. RAK15004 uses
I2C address `0x56`; RAK12002 uses `0x52`. Start with those two modules in
supported sensor slots, not every module in the Connected Box at once.
This diagnostic does not probe the SHTC3 or other kit sensors.

RTT output distinguishes unreadable/invalid FRAM, unused journal space, and a
present journal without disclosing its bytes. An RTC refusal is expected for a
new clock with its power-on flag set; no automatic clock setting occurs. The
blue LED indicates only that a recent read passed the RTC driver's checks. It
does not establish trusted UTC, a running oscillator over time, tamper resistance
or device readiness. The green heartbeat is evidence of reaching the loop,
not a complete board test. RTT is configured to discard output when no debugger
is listening; host connection does not gate the main loop.

The HAL's blocking TWIM implementation has no transaction timeout. A bus held
low can hang this diagnostic, and an unbounded physical transaction cannot
satisfy the RTC driver's timing contract. Bus-fault timeout/recovery, oscillator
progress, rail timing, bootloader handoff, SWD/RTT operation and physical power
cuts remain mandatory hardware validation. This diagnostic must not be used as
an operational command-receiving device.

## Primary references

- [RAK's exact Arduino linker script](https://github.com/RAKWireless/RAK-nRF52-Arduino/blob/cc4b1bf417541ae4e4b8afb96b4f4e7ff438f355/cores/nRF5/linker/nrf52840_s140_v6.ld).
- [RAK's exact GPIO and I2C variant definitions](https://github.com/RAKWireless/RAK-nRF52-Arduino/blob/cc4b1bf417541ae4e4b8afb96b4f4e7ff438f355/variants/WisCore_RAK4631_Board/variant.h)
  and [identity Arduino-to-GPIO map](https://github.com/RAKWireless/RAK-nRF52-Arduino/blob/cc4b1bf417541ae4e4b8afb96b4f4e7ff438f355/variants/WisCore_RAK4631_Board/variant.cpp).
- [Vendor RAK4631 datasheet](https://docs.rakwireless.com/product-categories/wisblock/rak4631/datasheet/).
- [nrf52840-hal 0.19.0 TWIM API](https://docs.rs/nrf52840-hal/0.19.0/nrf52840_hal/struct.Twim.html).
- [Cortex-M runtime startup and linker requirements](https://docs.rs/cortex-m-rt/0.7.7/cortex_m_rt/).
- [RTT default nonblocking channel behavior](https://docs.rs/rtt-target/0.6.2/rtt_target/).

No vendor implementation source is copied into this crate. The linker bounds
and pin numbers above are hardware facts derived from the cited BSP revision.
