//! Pin and reserved-memory bounds from the RAK4631 vendor Arduino board support.
//!
//! This diagnostic is not a radio stack or a deployed GenesisMesh device. The
//! layout is valid only after the actual board's bootloader layout is confirmed.

#![no_std]
#![forbid(unsafe_code)]

mod layout;
pub use layout::{FLASH_LENGTH, FLASH_ORIGIN, RAM_LENGTH, RAM_ORIGIN};

/// Sensor-slot bus (not the IO-slot's second I2C bus).
pub const SENSOR_SDA: (u8, u8) = (0, 13);
pub const SENSOR_SCL: (u8, u8) = (0, 14);
pub const SENSOR_POWER: (u8, u8) = (1, 2);
pub const LED_GREEN: (u8, u8) = (1, 3);
pub const LED_BLUE: (u8, u8) = (1, 4);
