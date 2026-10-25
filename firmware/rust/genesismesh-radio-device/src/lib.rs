//! Allocation-free device logic; board drivers supply durable storage and trusted time.
#![no_std]
#![forbid(unsafe_code)]

pub mod device;
pub mod protocol;
mod state;
