//! RAK15004 / MB85RC512T I2C FRAM and a conservative two-slot snapshot journal.
//!
//! The manufacturer documents 64 KiB, two address bytes, and address 0x56 on
//! RAK15004. Transfers here use at most 16 data bytes to fit small MCU HAL buffers.
//! Sources: <https://docs.rakwireless.com/product-categories/wisblock/rak15004/datasheet/>
//! and MB85RC512T datasheet DS501-00028-6v2-E:
//! <https://www.ramxeed.com/assets/images/products/datasheet/FeRAM/i1/MB85RC512T-DS6v2-E.pdf>.
//!
//! Each 169-byte slot contains: marker (1), generation BE (8), the core's
//! authenticated snapshot (120), SHA-256 (32), and a fixed format identifier (8).
//! The digest covers the identifier, generation and snapshot. It detects storage
//! faults; only the core authenticates the snapshot. Slots must either both be
//! blank 0xFF, hold generation 1 beside a blank slot, or hold consecutive committed
//! generations with exactly one current marker and one retired marker. The old
//! marker is retired and verified before the new marker is committed. After the
//! first rotation, erasing exactly one whole slot cannot masquerade as initial
//! blank storage. A
//! dirty or corrupt slot always refuses recovery instead of
//! silently restoring an older replay counter. Interrupted writes can therefore
//! require explicit reconciliation. There is no automatic formatting or repair.
//!
//! Fault model: completed I2C byte writes persist, interrupted writes may retain
//! any prefix, and subsequent reads report that memory. Physical power-loss,
//! voltage, write-protection and bus behavior still require board testing. A
//! physical writer can restore/recombine older authenticated snapshots and
//! recalculate the unkeyed wrapper. This is not detected without an external
//! anchor. Neither can complete blanking, including loss of the only initial
//! record. Completed writes depend on meeting the datasheet's
//! power-on/off timing; arbitrary brownout corruption is outside the prefix model.

use embedded_hal::i2c::I2c;
use genesismesh_radio_device::device::{Storage, STATE_BYTES};
use sha2::{Digest, Sha256};

pub const DEFAULT_ADDRESS: u8 = 0x56;
pub const CAPACITY: usize = 65_536;
pub const TRANSFER_BYTES: usize = 16;
pub const SLOT_BYTES: usize = 1 + 8 + STATE_BYTES + 32 + 8;
pub const JOURNAL_BYTES: usize = 2 * SLOT_BYTES;
const WRITING: u8 = 0x5A;
const COMMITTED: u8 = 0xA5;
const RETIRED: u8 = 0x3C;
const FORMAT: &[u8; 8] = b"GMRFRM01";
const BODY_BYTES: usize = SLOT_BYTES - 1;
const DIGEST_START: usize = 8 + STATE_BYTES;
const FORMAT_START: usize = DIGEST_START + 32;

#[derive(Debug, Eq, PartialEq)]
pub enum Error<E> {
    Bus(E),
    Bounds,
    Corrupt,
    Incomplete,
    Verify,
    GenerationExhausted,
}

pub struct Fram<I> {
    i2c: I,
}

impl<I: I2c> Fram<I> {
    pub fn new(i2c: I) -> Self {
        Self { i2c }
    }

    pub fn release(self) -> I {
        self.i2c
    }

    fn check_bounds(offset: u16, length: usize) -> Result<(), Error<I::Error>> {
        if length > CAPACITY - usize::from(offset) {
            return Err(Error::Bounds);
        }
        Ok(())
    }

    pub fn read(&mut self, offset: u16, output: &mut [u8]) -> Result<(), Error<I::Error>> {
        Self::check_bounds(offset, output.len())?;
        for (index, chunk) in output.chunks_mut(TRANSFER_BYTES).enumerate() {
            let address = usize::from(offset) + index * TRANSFER_BYTES;
            self.i2c
                .write_read(DEFAULT_ADDRESS, &(address as u16).to_be_bytes(), chunk)
                .map_err(Error::Bus)?;
        }
        Ok(())
    }

    /// Low-level writes are not atomic. Do not use them to replace live snapshots.
    pub fn write(&mut self, offset: u16, data: &[u8]) -> Result<(), Error<I::Error>> {
        Self::check_bounds(offset, data.len())?;
        let mut packet = [0u8; TRANSFER_BYTES + 2];
        for (index, chunk) in data.chunks(TRANSFER_BYTES).enumerate() {
            let address = usize::from(offset) + index * TRANSFER_BYTES;
            packet[..2].copy_from_slice(&(address as u16).to_be_bytes());
            packet[2..2 + chunk.len()].copy_from_slice(chunk);
            self.i2c
                .write(DEFAULT_ADDRESS, &packet[..2 + chunk.len()])
                .map_err(Error::Bus)?;
        }
        Ok(())
    }
}

struct Record {
    generation: u64,
    snapshot: [u8; STATE_BYTES],
    retired: bool,
}

pub struct FramJournal<I> {
    fram: Fram<I>,
    base: u16,
}

impl<I: I2c> FramJournal<I> {
    /// Reserve `[base, base + JOURNAL_BYTES)` exclusively for this journal.
    pub fn new(fram: Fram<I>, base: u16) -> Result<Self, Error<I::Error>> {
        Fram::<I>::check_bounds(base, JOURNAL_BYTES)?;
        Ok(Self { fram, base })
    }

    pub fn release(self) -> Fram<I> {
        self.fram
    }

    fn slot_address(&self, index: usize) -> u16 {
        (usize::from(self.base) + index * SLOT_BYTES) as u16
    }

    fn read_record(&mut self, index: usize) -> Result<Option<Record>, Error<I::Error>> {
        let mut raw = [0u8; SLOT_BYTES];
        self.fram.read(self.slot_address(index), &mut raw)?;
        if raw.iter().all(|byte| *byte == 0xFF) {
            return Ok(None);
        }
        if raw[0] == WRITING {
            return Err(Error::Incomplete);
        }
        if raw[0] != COMMITTED && raw[0] != RETIRED {
            return Err(Error::Corrupt);
        }
        let body = &raw[1..];
        if &body[FORMAT_START..] != FORMAT {
            return Err(Error::Corrupt);
        }
        let expected = Self::digest(&body[..DIGEST_START]);
        if body[DIGEST_START..FORMAT_START] != expected {
            return Err(Error::Corrupt);
        }
        let mut generation = [0u8; 8];
        generation.copy_from_slice(&body[..8]);
        let generation = u64::from_be_bytes(generation);
        if generation == 0 || (generation - 1) % 2 != index as u64 {
            return Err(Error::Corrupt);
        }
        let mut snapshot = [0u8; STATE_BYTES];
        snapshot.copy_from_slice(&body[8..DIGEST_START]);
        Ok(Some(Record {
            generation,
            snapshot,
            retired: raw[0] == RETIRED,
        }))
    }

    fn digest(data: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(FORMAT);
        digest.update(data);
        digest.finalize().into()
    }

    fn latest(&mut self) -> Result<Option<(usize, Record)>, Error<I::Error>> {
        let left = self.read_record(0)?;
        let right = self.read_record(1)?;
        match (left, right) {
            (None, None) => Ok(None),
            (Some(record), None) if record.generation == 1 && !record.retired => {
                Ok(Some((0, record)))
            }
            (Some(left), Some(right)) => {
                if left.retired
                    && !right.retired
                    && left.generation.checked_add(1) == Some(right.generation)
                {
                    Ok(Some((1, right)))
                } else if right.retired
                    && !left.retired
                    && right.generation.checked_add(1) == Some(left.generation)
                {
                    Ok(Some((0, left)))
                } else {
                    Err(Error::Corrupt)
                }
            }
            _ => Err(Error::Corrupt),
        }
    }
}

impl<I: I2c> Storage for FramJournal<I> {
    type Error = Error<I::Error>;

    fn load(&mut self) -> Result<Option<[u8; STATE_BYTES]>, Self::Error> {
        Ok(self.latest()?.map(|(_, record)| record.snapshot))
    }

    fn commit(&mut self, snapshot: &[u8; STATE_BYTES]) -> Result<(), Self::Error> {
        let (target, generation, previous) = match self.latest()? {
            Some((index, record)) => (
                1 - index,
                record
                    .generation
                    .checked_add(1)
                    .ok_or(Error::GenerationExhausted)?,
                Some(index),
            ),
            None => (0, 1, None),
        };
        let address = self.slot_address(target);
        self.fram.write(address, &[WRITING])?;
        let mut marker = [0u8; 1];
        self.fram.read(address, &mut marker)?;
        if marker != [WRITING] {
            return Err(Error::Verify);
        }
        let mut body = [0u8; BODY_BYTES];
        body[..8].copy_from_slice(&generation.to_be_bytes());
        body[8..DIGEST_START].copy_from_slice(snapshot);
        let digest = Self::digest(&body[..DIGEST_START]);
        body[DIGEST_START..FORMAT_START].copy_from_slice(&digest);
        body[FORMAT_START..].copy_from_slice(FORMAT);
        self.fram.write(address + 1, &body)?;
        let mut readback = [0u8; BODY_BYTES];
        self.fram.read(address + 1, &mut readback)?;
        if readback != body {
            return Err(Error::Verify);
        }
        if let Some(index) = previous {
            let previous_address = self.slot_address(index);
            self.fram.write(previous_address, &[RETIRED])?;
            self.fram.read(previous_address, &mut marker)?;
            if marker != [RETIRED] {
                return Err(Error::Verify);
            }
        }
        self.fram.write(address, &[COMMITTED])?;
        let record = self.read_record(target)?.ok_or(Error::Verify)?;
        if record.generation != generation || record.snapshot != *snapshot || record.retired {
            return Err(Error::Verify);
        }
        Ok(())
    }
}
