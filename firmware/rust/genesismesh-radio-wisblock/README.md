# Experimental WisBlock peripheral adapters

Allocation-free, `no_std`, safe Rust implementations for the purchased RAK15004
FRAM and RAK12002 RTC. They use `embedded-hal` 1.0 blocking I2C and implement the
existing [device core](../genesismesh-radio-device/README.md) contracts. They do
not provide a radio stack, provision credentials or initialize a new board.

## Storage

```rust,ignore
use genesismesh_radio_wisblock::fram::{Fram, FramJournal};
let storage = FramJournal::new(Fram::new(i2c), 0)?;
// Supply storage to Device::provision (fresh identity only) or Device::open.
```

RAK15004 uses MB85RC512T, I2C address `0x56`, 64 KiB and two-byte big-endian
memory addresses. The adapter bounds every access and transfers at most 16 data
bytes per operation. The journal reserves 338 bytes starting at the supplied
base address, which must not overlap other data.

Each 169-byte slot stores a marker, big-endian generation, the core's 120-byte
authenticated snapshot, SHA-256 checksum and format identifier. A commit marks
the destination as being written and verifies it, writes/verifies the body,
retires/verifies the previous record, then commits/verifies the new record.
Recovery accepts only the initial generation-one record with an unused peer,
or a current record paired with the retired consecutive previous generation in
the expected slot. Any inconsistent pair refuses recovery. A failed commit may
have persisted; the core poisons its instance and must reopen before reuse.

There is no format, automatic repair or destructive retry API. Both slots must
be entirely `0xFF` to report unused state; factory FRAM contents are not assumed
to have that value. `Fram::write` is a low-level non-atomic operation, not a
replacement for the journal. First-use preparation is a separate, physically
controlled workflow for a new identity. Never clear a used journal and reuse
its identity/key as a recovery strategy.

The checksum detects accidental damage; it does not authenticate records. The
device core validates its snapshot HMAC and identity binding. A physical writer
can blank the whole region or restore/recombine older authenticated snapshots;
neither FRAM nor this wrapper supplies a monotonic hardware anchor. With only
the very first record, losing it is indistinguishable from uninitialized media.
After rotation, erasing either whole slot causes refusal. Availability is
deliberately sacrificed on ambiguous intermediate writes.

The host fault model assumes writes affect addressed bytes and reads return
stored bytes. Torn-write tests include error-after-write ambiguity; arbitrary
out-of-spec brownout effects elsewhere in memory, cached/incorrect reads and
physical attack require additional hardware validation. Follow the chip's
voltage, power ramp, write-protect and bus timing requirements.

## Clock

```rust,ignore
use genesismesh_radio_wisblock::rtc::Rv3028;
let clock = Rv3028::new(i2c, independently_provisioned_utc_floor)?;
// Supply clock to the device core; no RTC register is initialized here.
```

RV-3028-C7 is at `0x52`; UNIX seconds occupy registers `0x1B..0x1E` in
little-endian order. The driver brackets two identical counter reads with status
checks, rejects PORF, EEPROM busy, bus errors, invalid/below-floor time and
observed rollback. A rollover retries at most three times. It never sets UTC,
clears faults or substitutes the host/radio timestamp. The minimum supported UTC
is January 1, 2020; use a newer independently established provisioning floor.
The core separately checks its authenticated persistent clock floor.

This is a retained RTC, not a source of authenticated time. A stale but plausible
clock can pass instantaneous reads. Initialization, backup switching, clock
progression, accuracy and backup-loss behavior must be checked on the board.
RV-3028 has no oscillator STOP-status bit. The platform must bound I2C operations
below the chip's 950 ms bus timeout; the read-only board diagnostic currently
uses a HAL with blocking bus operations and does not prove that bound.

## Verification and primary sources

Run `bash scripts/check-rak4631.sh` from the repository root with the pinned
compiler/target installed. Host tests exercise byte-level interrupted journal
writes, state-machine crash boundaries, integrity errors, generation/layout
errors, status flags, counter rollover and real device-core clock refusals.
CI also builds the actual [read-only board diagnostic](../rak4631-bringup/README.md).
These are software/model results; neither module has been physically tested here.

- [RAK15004 module/address](https://docs.rakwireless.com/product-categories/wisblock/rak15004/datasheet/)
- [MB85RC512T chip datasheet](https://www.ramxeed.com/assets/images/products/datasheet/FeRAM/i1/MB85RC512T-DS6v2-E.pdf)
- [RAK12002 module](https://docs.rakwireless.com/product-categories/wisblock/rak12002/datasheet/)
- [RV-3028-C7 application manual](https://www.microcrystal.com/fileadmin/Media/Products/RTC/App.Manual/RV-3028-C7_App-Manual.pdf)
