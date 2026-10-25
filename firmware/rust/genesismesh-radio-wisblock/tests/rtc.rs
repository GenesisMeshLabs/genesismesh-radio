#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::rc::Rc;

use embedded_hal::i2c::{Error as I2cError, ErrorKind, ErrorType, I2c, Operation};
use genesismesh_radio_device::device::{
    Clock, Device, Error as DeviceError, Profile, Storage, STATE_BYTES,
};
use genesismesh_radio_wisblock::rtc::{Error, Rv3028, DEFAULT_ADDRESS, MIN_SUPPORTED_UNIX};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fault;

impl I2cError for Fault {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

struct Read {
    register: u8,
    value: Result<Vec<u8>, Fault>,
}

impl Read {
    fn status(value: u8) -> Self {
        Self {
            register: 0x0e,
            value: Ok(vec![value]),
        }
    }

    fn time(value: u32) -> Self {
        Self {
            register: 0x1b,
            value: Ok(value.to_le_bytes().to_vec()),
        }
    }
}

struct Script {
    reads: VecDeque<Read>,
}

impl ErrorType for Script {
    type Error = Fault;
}

impl I2c for Script {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        assert_eq!(address, 0x52);
        let next = self.reads.pop_front().expect("unexpected RTC access");
        // Every operation is a register-pointer write followed by a read. A
        // register-data write would fail this assertion, including fault clears.
        match operations {
            [Operation::Write(register), Operation::Read(output)] => {
                assert_eq!(*register, &[next.register]);
                let bytes = next.value?;
                assert_eq!(output.len(), bytes.len());
                output.copy_from_slice(&bytes);
                Ok(())
            }
            _ => panic!("RTC adapter performed a non-read transaction"),
        }
    }
}

fn clock(reads: Vec<Read>) -> Rv3028<Script> {
    Rv3028::new(
        Script {
            reads: reads.into(),
        },
        MIN_SUPPORTED_UNIX,
    )
    .expect("valid UTC floor")
}

fn stable(time: u32) -> Vec<Read> {
    vec![
        Read::status(0),
        Read::time(time),
        Read::time(time),
        Read::status(0),
    ]
}

fn finish(clock: Rv3028<Script>) {
    assert!(clock.release().reads.is_empty(), "missing RTC access");
}

#[test]
fn reads_little_endian_counter_with_fault_checks_and_no_configuration_writes() {
    assert_eq!(DEFAULT_ADDRESS, 0x52);
    let time = 0x65a1_2345;
    let mut rtc = clock(stable(time));
    assert_eq!(rtc.now(), Ok(time));
    finish(rtc);
}

#[test]
fn refuses_invalid_provisioning_floor_without_touching_bus() {
    for floor in [0, MIN_SUPPORTED_UNIX - 1, u32::MAX] {
        let result = Rv3028::new(
            Script {
                reads: VecDeque::new(),
            },
            floor,
        );
        assert!(matches!(result, Err(Error::InvalidMinimum)));
    }
}

#[test]
fn rejects_power_loss_and_refresh_busy_before_using_time() {
    for (status, expected) in [(0x01, Error::PowerLost), (0x80, Error::Busy)] {
        let mut rtc = clock(vec![Read::status(status)]);
        assert_eq!(rtc.now(), Err(expected));
        finish(rtc);
    }
}

#[test]
fn unrelated_interrupt_flags_are_not_clock_faults() {
    let time = MIN_SUPPORTED_UNIX + 10;
    let mut rtc = clock(vec![
        Read::status(0x7e),
        Read::time(time),
        Read::time(time),
        Read::status(0x7e),
    ]);
    assert_eq!(rtc.now(), Ok(time));
    finish(rtc);
}

#[test]
fn power_loss_or_refresh_between_reads_cannot_return_time() {
    let time = MIN_SUPPORTED_UNIX + 1;
    for (status, expected) in [(0x01, Error::PowerLost), (0x80, Error::Busy)] {
        let mut reads = stable(time);
        reads[3] = Read::status(status);
        let mut rtc = clock(reads);
        assert_eq!(rtc.now(), Err(expected));
        finish(rtc);
    }
}

#[test]
fn rejects_zero_uninitialized_pre_floor_and_timeout_all_ff_values() {
    for time in [0, MIN_SUPPORTED_UNIX - 1, u32::MAX] {
        let mut rtc = clock(vec![Read::status(0), Read::time(time)]);
        assert_eq!(rtc.now(), Err(Error::InvalidTime));
        finish(rtc);
    }
    let mut rtc = clock(vec![
        Read::status(0),
        Read::time(MIN_SUPPORTED_UNIX),
        Read::time(u32::MAX),
    ]);
    assert_eq!(rtc.now(), Err(Error::InvalidTime));
    finish(rtc);
}

#[test]
fn custom_floor_rejects_apparently_plausible_but_old_clock() {
    let floor = MIN_SUPPORTED_UNIX + 20_000;
    let mut rtc = Rv3028::new(
        Script {
            reads: vec![Read::status(0), Read::time(floor - 1)].into(),
        },
        floor,
    )
    .expect("valid floor");
    assert_eq!(rtc.now(), Err(Error::InvalidTime));
    finish(rtc);
}

#[test]
fn rollover_between_reads_retries_then_returns_only_a_stable_value() {
    // Crossing a low-byte boundary would expose a torn, apparently plausible
    // value if the driver combined bytes read in unrelated transactions.
    let time = 0x65a1_23ff;
    let mut reads = vec![
        Read::status(0),
        Read::time(time),
        Read::time(time + 1),
        Read::status(0),
    ];
    reads.extend(stable(time + 1));
    let mut rtc = clock(reads);
    assert_eq!(rtc.now(), Ok(time + 1));
    finish(rtc);
}

#[test]
fn unstable_counter_has_bounded_retries() {
    let mut reads = Vec::new();
    for tick in 0..3 {
        reads.extend([
            Read::status(0),
            Read::time(MIN_SUPPORTED_UNIX + tick),
            Read::time(MIN_SUPPORTED_UNIX + tick + 1),
            Read::status(0),
        ]);
    }
    let mut rtc = clock(reads);
    assert_eq!(rtc.now(), Err(Error::Unstable));
    finish(rtc);
}

#[test]
fn propagates_each_bus_failure_and_never_uses_a_cached_value() {
    let time = MIN_SUPPORTED_UNIX + 10;
    for fault_position in 0..4 {
        let mut failing = stable(time + 1);
        failing[fault_position].value = Err(Fault);
        failing.truncate(fault_position + 1);
        let mut reads = stable(time);
        reads.extend(failing);
        let mut rtc = clock(reads);
        assert_eq!(rtc.now(), Ok(time));
        assert_eq!(rtc.now(), Err(Error::I2c(Fault)));
        finish(rtc);
    }
}

#[test]
fn observed_clock_floor_refuses_rollback_and_remains_after_refusal() {
    let time = MIN_SUPPORTED_UNIX + 100;
    let mut reads = stable(time);
    reads.extend(stable(time - 1));
    reads.extend(stable(time - 2));
    reads.extend(stable(time));
    let mut rtc = clock(reads);
    assert_eq!(rtc.now(), Ok(time));
    assert_eq!(rtc.now(), Err(Error::Rollback));
    assert_eq!(rtc.now(), Err(Error::Rollback));
    assert_eq!(rtc.now(), Ok(time));
    finish(rtc);
}

#[test]
fn counter_wrap_cannot_be_accepted_as_new_time() {
    let mut reads = stable(u32::MAX - 1);
    reads.extend([Read::status(0), Read::time(0)]);
    let mut rtc = clock(reads);
    assert_eq!(rtc.now(), Ok(u32::MAX - 1));
    assert_eq!(rtc.now(), Err(Error::InvalidTime));
    finish(rtc);
}

#[derive(Clone, Default)]
struct MemoryStore {
    value: Rc<RefCell<Option<[u8; STATE_BYTES]>>>,
    commits: Rc<Cell<usize>>,
}

impl Storage for MemoryStore {
    type Error = Infallible;

    fn load(&mut self) -> Result<Option<[u8; STATE_BYTES]>, Self::Error> {
        Ok(*self.value.borrow())
    }

    fn commit(&mut self, snapshot: &[u8; STATE_BYTES]) -> Result<(), Self::Error> {
        *self.value.borrow_mut() = Some(*snapshot);
        self.commits.set(self.commits.get() + 1);
        Ok(())
    }
}

#[test]
fn real_device_provisioning_never_writes_state_when_rtc_reports_power_loss() {
    let key = [0x37; 32]; // Public host-only fixture.
    let profile = Profile::new(1, "rtc-test", &key, 10, 600, 255).unwrap();
    let store = MemoryStore::default();
    let mut rtc = clock(vec![Read::status(1)]);
    assert!(matches!(
        Device::provision(profile, store.clone(), &mut rtc, 60),
        Err(DeviceError::ClockUnavailable)
    ));
    assert_eq!(*store.value.borrow(), None);
    assert_eq!(store.commits.get(), 0);
    finish(rtc);
}

#[test]
fn real_device_reopen_with_lost_clock_preserves_snapshot_without_reset_or_commit() {
    let key = [0x37; 32]; // Public host-only fixture.
    let profile = Profile::new(1, "rtc-test", &key, 10, 600, 255).unwrap();
    let store = MemoryStore::default();
    let mut good_rtc = clock(stable(MIN_SUPPORTED_UNIX + 100));
    let device = Device::provision(profile, store.clone(), &mut good_rtc, 60).unwrap();
    drop(device);
    finish(good_rtc);
    let before = *store.value.borrow();

    let mut failed_rtc = clock(vec![Read::status(1)]);
    assert!(matches!(
        Device::open(profile, store.clone(), &mut failed_rtc),
        Err(DeviceError::ClockUnavailable)
    ));
    assert_eq!(*store.value.borrow(), before);
    assert_eq!(store.commits.get(), 1);
    finish(failed_rtc);
}

#[test]
fn real_device_persisted_floor_refuses_new_clock_instance_at_older_time() {
    let key = [0x37; 32]; // Public host-only fixture.
    let profile = Profile::new(1, "rtc-test", &key, 10, 600, 255).unwrap();
    let store = MemoryStore::default();
    let time = MIN_SUPPORTED_UNIX + 100;
    let mut good_rtc = clock(stable(time));
    let device = Device::provision(profile, store.clone(), &mut good_rtc, 60).unwrap();
    drop(device);
    finish(good_rtc);
    let before = *store.value.borrow();

    let mut old_rtc = clock(stable(time - 1));
    assert!(matches!(
        Device::open(profile, store.clone(), &mut old_rtc),
        Err(DeviceError::ClockRollback)
    ));
    assert_eq!(*store.value.borrow(), before);
    assert_eq!(store.commits.get(), 1);
    finish(old_rtc);
}
