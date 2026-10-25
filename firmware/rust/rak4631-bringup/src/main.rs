//! Read-only board diagnosis; no GenesisMesh keys, state initialization or radio stack.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use cortex_m_rt::entry;
use embedded_hal::{delay::DelayNs, digital::OutputPin};
use genesismesh_radio_device::device::{Clock, Storage};
use genesismesh_radio_wisblock::{
    fram::{Fram, FramJournal},
    rtc::{Rv3028, MIN_SUPPORTED_UNIX},
};
use nrf52840_hal as hal;
use rtt_target::{rprintln, rtt_init_print};

#[entry]
fn main() -> ! {
    // RTT's default NoBlockSkip mode never waits for an attached debugger.
    rtt_init_print!();
    rprintln!("GenesisMesh RAK4631 read-only bench diagnostic");
    rprintln!("hardware_tested=false; RF TX disabled (no radio stack)");
    rprintln!("No keys loaded; no FRAM/RTC writes; no device provisioning");
    let peripherals = match hal::pac::Peripherals::take() {
        Some(value) => value,
        None => halt(),
    };
    let core = match cortex_m::Peripherals::take() {
        Some(value) => value,
        None => halt(),
    };
    let p0 = hal::gpio::p0::Parts::new(peripherals.P0);
    let p1 = hal::gpio::p1::Parts::new(peripherals.P1);
    let mut green = p1.p1_03.into_push_pull_output(hal::gpio::Level::Low);
    let mut blue = p1.p1_04.into_push_pull_output(hal::gpio::Level::Low);
    let _sensor_power = p1.p1_02.into_push_pull_output(hal::gpio::Level::High);
    let mut delay = hal::Delay::new(core.SYST);
    delay.delay_ms(20);
    let bus = hal::Twim::new(
        peripherals.TWIM0,
        hal::twim::Pins {
            scl: p0.p0_14.into_floating_input().degrade(),
            sda: p0.p0_13.into_floating_input().degrade(),
        },
        hal::twim::Frequency::K100,
    );
    rprintln!("Sensor I2C: SDA=P0.13, SCL=P0.14, 100kHz; 3V3_S=P1.02");
    let mut journal = match FramJournal::new(Fram::new(bus), 0) {
        Ok(value) => value,
        Err(_) => halt(),
    };
    match journal.load() {
        Ok(None) => {
            rprintln!("FRAM readable: journal unused; no initialization performed");
        }
        Ok(Some(_)) => {
            rprintln!("FRAM journal present; device MAC not checked (no keys loaded)");
        }
        Err(error) => {
            rprintln!(
                "FRAM unavailable or journal needs investigation: {:?}",
                error
            );
        }
    }
    let bus = journal.release().release();
    let mut rtc = match Rv3028::new(bus, MIN_SUPPORTED_UNIX) {
        Ok(value) => value,
        Err(_) => halt(),
    };
    loop {
        match rtc.now() {
            Ok(seconds) => {
                rprintln!(
                    "RTC UTC seconds={}; external trust/provisioning still required",
                    seconds
                );
                let _ = blue.set_high();
            }
            Err(error) => {
                rprintln!("RTC refused (never auto-cleared or set): {:?}", error);
                let _ = blue.set_low();
            }
        }
        let _ = green.set_high();
        delay.delay_ms(100);
        let _ = green.set_low();
        delay.delay_ms(1900);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    rprintln!("Diagnostic panic: halted, no recovery or state reset attempted");
    halt()
}

fn halt() -> ! {
    loop {
        cortex_m::asm::wfi();
    }
}
