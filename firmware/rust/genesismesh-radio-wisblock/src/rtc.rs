//! Read-only RV-3028-C7 UTC adapter for the RAK12002 module.
//!
//! The operator must initialize UTC and backup switching separately, then clear
//! PORF only after checking the clock. This adapter never sets time, clears fault
//! flags, or substitutes a received timestamp. The chip is not tamper resistant:
//! a valid-looking clock cannot prove that UTC was set correctly or kept running.
//!
//! Register and read rules: Micro Crystal RV-3028-C7 Application Manual, rev. 1.4,
//! sections 3.7, 3.10, 4.16.2 and 5.6:
//! <https://www.microcrystal.com/fileadmin/Media/Products/RTC/App.Manual/RV-3028-C7_App-Manual.pdf>.
//! The HAL must impose I2C timeouts below the chip's 950 ms bus timeout. A stalled
//! oscillator requires a separate elapsed-time observation; RV-3028 has no STOP
//! status bit. Its periodic-timer enable bit is not oscillator-health evidence.

use embedded_hal::i2c::I2c;
use genesismesh_radio_device::device::Clock;

pub const DEFAULT_ADDRESS: u8 = 0x52;
/// January 1, 2020 UTC. An operator supplies an equal or newer provisioning floor.
pub const MIN_SUPPORTED_UNIX: u32 = 1_577_836_800;

const STATUS: u8 = 0x0e;
const PORF: u8 = 0x01;
const EEBUSY: u8 = 0x80;
const UNIX_TIME: u8 = 0x1b;
const READ_ATTEMPTS: usize = 3;

#[derive(Debug, Eq, PartialEq)]
pub enum Error<E> {
    I2c(E),
    InvalidMinimum,
    PowerLost,
    Busy,
    InvalidTime,
    Unstable,
    Rollback,
}

/// An RTC with a caller-provisioned lower bound and an in-memory rollback floor.
/// The device core separately persists its own authenticated clock floor.
pub struct Rv3028<I> {
    i2c: I,
    minimum: u32,
    observed: u32,
}

impl<I: I2c> Rv3028<I> {
    /// Does not perform I2C access or initialize the RTC.
    pub fn new(i2c: I, minimum_unix_seconds: u32) -> Result<Self, Error<I::Error>> {
        if !(MIN_SUPPORTED_UNIX..u32::MAX).contains(&minimum_unix_seconds) {
            return Err(Error::InvalidMinimum);
        }
        Ok(Self {
            i2c,
            minimum: minimum_unix_seconds,
            observed: minimum_unix_seconds,
        })
    }

    pub fn release(self) -> I {
        self.i2c
    }

    fn check_status(&mut self) -> Result<(), Error<I::Error>> {
        let mut status = [0u8];
        self.i2c
            .write_read(DEFAULT_ADDRESS, &[STATUS], &mut status)
            .map_err(Error::I2c)?;
        if status[0] & PORF != 0 {
            return Err(Error::PowerLost);
        }
        if status[0] & EEBUSY != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }

    fn read_counter(&mut self) -> Result<u32, Error<I::Error>> {
        let mut bytes = [0u8; 4];
        self.i2c
            .write_read(DEFAULT_ADDRESS, &[UNIX_TIME], &mut bytes)
            .map_err(Error::I2c)?;
        let value = u32::from_le_bytes(bytes);
        // All FF is also the documented RV-3028 bus-timeout read result.
        if value == u32::MAX || value < self.minimum {
            return Err(Error::InvalidTime);
        }
        Ok(value)
    }

    /// Read two identical UNIX values, bracketed by fault-status checks.
    /// A rollover between reads retries a bounded number of times. No cached
    /// value is returned when communication, freshness or consistency fails.
    pub fn read_unix(&mut self) -> Result<u32, Error<I::Error>> {
        for _ in 0..READ_ATTEMPTS {
            self.check_status()?;
            let first = self.read_counter()?;
            let second = self.read_counter()?;
            self.check_status()?;
            if first != second {
                continue;
            }
            if second < self.observed {
                return Err(Error::Rollback);
            }
            self.observed = second;
            return Ok(second);
        }
        Err(Error::Unstable)
    }
}

impl<I: I2c> Clock for Rv3028<I> {
    type Error = Error<I::Error>;

    fn now(&mut self) -> Result<u32, Self::Error> {
        self.read_unix()
    }
}
