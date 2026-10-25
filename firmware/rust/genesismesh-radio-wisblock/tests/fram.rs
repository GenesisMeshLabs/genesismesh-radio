#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::rc::Rc;

use embedded_hal::i2c::{ErrorKind, ErrorType, I2c, Operation};
use genesismesh_radio_device::device::{
    Actuator, Clock, Device, Error as DeviceError, Profile, Storage, STATE_BYTES,
};
use genesismesh_radio_device::protocol::{self, Frame, Kind, OutcomeStatus, MAX_FRAME};
use genesismesh_radio_wisblock::fram::{
    Error, Fram, FramJournal, CAPACITY, DEFAULT_ADDRESS, JOURNAL_BYTES, SLOT_BYTES, TRANSFER_BYTES,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BusError;

impl embedded_hal::i2c::Error for BusError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

struct Memory {
    data: Box<[u8; CAPACITY]>,
    writes: usize,
    cut: Option<usize>,
    read_error: bool,
    ignore_all_writes: bool,
    ignore_body_writes: bool,
    ignore_commit_marker: bool,
}

impl Memory {
    fn blank() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            data: Box::new([0xFF; CAPACITY]),
            writes: 0,
            cut: None,
            read_error: false,
            ignore_all_writes: false,
            ignore_body_writes: false,
            ignore_commit_marker: false,
        }))
    }

    fn cut_after(&mut self, count: usize) {
        self.writes = 0;
        self.cut = Some(count);
    }
}

#[derive(Clone)]
struct Bus(Rc<RefCell<Memory>>);

impl ErrorType for Bus {
    type Error = BusError;
}

impl I2c for Bus {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        assert_eq!(address, DEFAULT_ADDRESS);
        let mut memory = self.0.borrow_mut();
        let mut cursor = 0;
        for operation in operations {
            match operation {
                Operation::Write(bytes) => {
                    assert!((2..=TRANSFER_BYTES + 2).contains(&bytes.len()));
                    cursor = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                    for &value in &bytes[2..] {
                        if memory.cut == Some(0) {
                            return Err(BusError);
                        }
                        let marker = cursor % SLOT_BYTES == 0;
                        if !(memory.ignore_all_writes
                            || memory.ignore_body_writes && !marker
                            || memory.ignore_commit_marker && marker && value == 0xA5)
                        {
                            memory.data[cursor] = value;
                        }
                        cursor += 1;
                        memory.writes += 1;
                        if memory.cut == Some(memory.writes) {
                            // The byte has persisted, but the host sees a bus error.
                            return Err(BusError);
                        }
                    }
                }
                Operation::Read(bytes) => {
                    assert!(bytes.len() <= TRANSFER_BYTES);
                    if memory.read_error {
                        return Err(BusError);
                    }
                    bytes.copy_from_slice(&memory.data[cursor..cursor + bytes.len()]);
                    cursor += bytes.len();
                }
            }
        }
        Ok(())
    }
}

fn journal(memory: &Rc<RefCell<Memory>>) -> FramJournal<Bus> {
    FramJournal::new(Fram::new(Bus(Rc::clone(memory))), 0).unwrap()
}

#[test]
fn fram_bounds_chunking_and_big_endian_addresses() {
    let memory = Memory::blank();
    let mut fram = Fram::new(Bus(Rc::clone(&memory)));
    let data = [0x31; 47];
    fram.write(0x1234, &data).unwrap();
    let mut readback = [0; 47];
    fram.read(0x1234, &mut readback).unwrap();
    assert_eq!(readback, data);
    assert_eq!(memory.borrow().data[0x1233], 0xFF);
    assert_eq!(memory.borrow().data[0x1263], 0xFF);
    fram.write(u16::MAX, &[7]).unwrap();
    assert_eq!(memory.borrow().data[CAPACITY - 1], 7);
    assert_eq!(fram.write(u16::MAX, &[1, 2]), Err(Error::Bounds));
    assert_eq!(fram.read(u16::MAX, &mut [0; 2]), Err(Error::Bounds));
    fram.write(u16::MAX, &[]).unwrap();
    fram.read(u16::MAX, &mut []).unwrap();
    assert!(matches!(
        FramJournal::new(Fram::new(Bus(Rc::clone(&memory))), u16::MAX),
        Err(Error::Bounds)
    ));
}

#[test]
fn only_all_ff_is_blank_and_commits_rotate_without_touching_other_memory() {
    let memory = Memory::blank();
    let mut store = journal(&memory);
    assert_eq!(store.load().unwrap(), None);
    for value in 1..=8 {
        store.commit(&[value; STATE_BYTES]).unwrap();
        assert_eq!(journal(&memory).load().unwrap(), Some([value; STATE_BYTES]));
    }
    assert!(memory.borrow().data[JOURNAL_BYTES..]
        .iter()
        .all(|byte| *byte == 0xFF));
    let zeroed = Memory::blank();
    zeroed.borrow_mut().data[..JOURNAL_BYTES].fill(0);
    assert_eq!(journal(&zeroed).load(), Err(Error::Corrupt));
}

#[test]
fn every_byte_power_cut_refuses_partial_commits_including_reused_slot() {
    for previous in 0..=3 {
        let commit_writes = SLOT_BYTES + 1 + usize::from(previous != 0);
        for cut in 0..=commit_writes {
            let memory = Memory::blank();
            let mut store = journal(&memory);
            for value in 1..=previous {
                store.commit(&[value; STATE_BYTES]).unwrap();
            }
            memory.borrow_mut().cut_after(cut);
            assert!(store.commit(&[9; STATE_BYTES]).is_err());
            memory.borrow_mut().cut = None;
            let loaded = journal(&memory).load();
            if cut == 0 {
                assert_eq!(
                    loaded.unwrap(),
                    (previous != 0).then_some([previous; STATE_BYTES]),
                    "cut before first byte must preserve previous state"
                );
            } else if cut == commit_writes {
                assert_eq!(loaded.unwrap(), Some([9; STATE_BYTES]));
            } else {
                assert_eq!(loaded, Err(Error::Incomplete));
            }
        }
    }
}

#[test]
fn corrupt_new_or_old_committed_slot_never_falls_back() {
    for slot in 0..2 {
        for position in 0..SLOT_BYTES {
            let memory = Memory::blank();
            journal(&memory).commit(&[1; STATE_BYTES]).unwrap();
            journal(&memory).commit(&[2; STATE_BYTES]).unwrap();
            memory.borrow_mut().data[slot * SLOT_BYTES + position] ^= 1;
            assert!(journal(&memory).load().is_err());
            let before = memory.borrow().data.clone();
            assert!(journal(&memory).commit(&[3; STATE_BYTES]).is_err());
            assert_eq!(memory.borrow().data, before);
        }
    }
}

#[test]
fn missing_old_slot_is_not_treated_as_fresh_storage() {
    for missing in 0..2 {
        let memory = Memory::blank();
        journal(&memory).commit(&[1; STATE_BYTES]).unwrap();
        journal(&memory).commit(&[2; STATE_BYTES]).unwrap();
        memory.borrow_mut().data[missing * SLOT_BYTES..(missing + 1) * SLOT_BYTES].fill(0xFF);
        assert_eq!(journal(&memory).load(), Err(Error::Corrupt));
    }
}

#[test]
fn read_errors_and_write_protection_are_not_success() {
    let memory = Memory::blank();
    memory.borrow_mut().read_error = true;
    assert_eq!(journal(&memory).load(), Err(Error::Bus(BusError)));
    assert_eq!(
        journal(&memory).commit(&[1; STATE_BYTES]),
        Err(Error::Bus(BusError))
    );
    memory.borrow_mut().read_error = false;
    memory.borrow_mut().ignore_all_writes = true;
    assert_eq!(
        journal(&memory).commit(&[1; STATE_BYTES]),
        Err(Error::Verify)
    );
    memory.borrow_mut().ignore_all_writes = false;
    memory.borrow_mut().ignore_body_writes = true;
    assert_eq!(
        journal(&memory).commit(&[1; STATE_BYTES]),
        Err(Error::Verify)
    );
    assert_eq!(journal(&memory).load(), Err(Error::Incomplete));

    let memory = Memory::blank();
    memory.borrow_mut().ignore_commit_marker = true;
    assert_eq!(
        journal(&memory).commit(&[1; STATE_BYTES]),
        Err(Error::Incomplete)
    );
}

fn record(generation: u64, marker: u8) -> [u8; SLOT_BYTES] {
    let mut raw = [0x2D; SLOT_BYTES];
    raw[0] = marker;
    raw[1..9].copy_from_slice(&generation.to_be_bytes());
    let mut digest = Sha256::new();
    digest.update(b"GMRFRM01");
    digest.update(&raw[1..9 + STATE_BYTES]);
    raw[9 + STATE_BYTES..41 + STATE_BYTES].copy_from_slice(&digest.finalize());
    raw[41 + STATE_BYTES..].copy_from_slice(b"GMRFRM01");
    raw
}

#[test]
fn rejects_valid_checksums_with_impossible_generations_or_marker_combinations() {
    let impossible = [
        (Some(record(0, 0xA5)), None),
        (None, Some(record(1, 0xA5))),
        (Some(record(1, 0x3C)), None),
        (Some(record(1, 0x3C)), Some(record(4, 0xA5))),
        (Some(record(3, 0xA5)), Some(record(2, 0xA5))),
        (Some(record(1, 0x3C)), Some(record(2, 0x3C))),
    ];
    for (left, right) in impossible {
        let memory = Memory::blank();
        if let Some(left) = left {
            memory.borrow_mut().data[..SLOT_BYTES].copy_from_slice(&left);
        }
        if let Some(right) = right {
            memory.borrow_mut().data[SLOT_BYTES..JOURNAL_BYTES].copy_from_slice(&right);
        }
        assert_eq!(journal(&memory).load(), Err(Error::Corrupt));
    }
}

#[test]
fn generation_exhaustion_does_not_write_or_wrap() {
    let memory = Memory::blank();
    memory.borrow_mut().data[..SLOT_BYTES].copy_from_slice(&record(u64::MAX, 0xA5));
    memory.borrow_mut().data[SLOT_BYTES..JOURNAL_BYTES]
        .copy_from_slice(&record(u64::MAX - 1, 0x3C));
    let before = memory.borrow().data.clone();
    assert!(journal(&memory).load().unwrap().is_some());
    assert_eq!(
        journal(&memory).commit(&[1; STATE_BYTES]),
        Err(Error::GenerationExhausted)
    );
    assert_eq!(memory.borrow().data, before);
}

#[test]
fn last_possible_base_address_is_bounded_and_preserves_its_prefix() {
    let memory = Memory::blank();
    let base = (CAPACITY - JOURNAL_BYTES) as u16;
    let mut store = FramJournal::new(Fram::new(Bus(Rc::clone(&memory))), base).unwrap();
    store.commit(&[1; STATE_BYTES]).unwrap();
    store.commit(&[2; STATE_BYTES]).unwrap();
    store.commit(&[3; STATE_BYTES]).unwrap();
    assert_eq!(store.load().unwrap(), Some([3; STATE_BYTES]));
    assert!(memory.borrow().data[..usize::from(base)]
        .iter()
        .all(|byte| *byte == 0xFF));
}

struct TestClock;
impl Clock for TestClock {
    type Error = ();
    fn now(&mut self) -> Result<u32, Self::Error> {
        Ok(1_800_000_000)
    }
}

#[derive(Default)]
struct TestActuator {
    calls: usize,
}

impl Actuator for TestActuator {
    type Error = ();
    fn apply_sampling_interval(&mut self, interval: u16) -> Result<u16, Self::Error> {
        self.calls += 1;
        Ok(interval)
    }
}

#[test]
fn real_core_never_reapplies_after_any_acceptance_or_outcome_write_cut() {
    let key = [0x42; 32]; // Public host-only fixture.
    let profile = Profile::new(1, "fram-test", &key, 10, 300, 255).unwrap();
    let frame = Frame::new(
        Kind::Command,
        1,
        1,
        1_800_000_100,
        &protocol::command_payload(60).unwrap(),
    )
    .unwrap();
    let mut raw = [0; MAX_FRAME];
    let length = protocol::encode(&frame, &key, "fram-test", &mut raw).unwrap();
    for cut in 0..=2 * (SLOT_BYTES + 2) {
        let memory = Memory::blank();
        let mut clock = TestClock;
        let mut device = Device::provision(profile, journal(&memory), &mut clock, 30).unwrap();
        let mut actuator = TestActuator::default();
        memory.borrow_mut().cut_after(cut);
        assert_eq!(
            device.receive_command(&raw[..length], &mut clock, &mut actuator),
            Err(DeviceError::Storage)
        );
        assert!(device.status().poisoned);
        assert!(actuator.calls <= 1);
        memory.borrow_mut().cut = None;
        if let Ok(mut recovered) = Device::open(profile, journal(&memory), &mut clock) {
            let status = recovered.status();
            if cut == 0 {
                assert_eq!(status.received_counter, 0);
                assert_eq!(actuator.calls, 0);
            } else {
                assert_eq!(status.received_counter, 1);
                assert_eq!(
                    recovered.receive_command(&raw[..length], &mut clock, &mut actuator),
                    Err(DeviceError::Replay)
                );
                let outcome = status.outcome.unwrap();
                if outcome.status == OutcomeStatus::Success {
                    assert_eq!(actuator.calls, 1);
                    assert_eq!(outcome.applied_interval, 60);
                } else {
                    assert_eq!(outcome.status, OutcomeStatus::Uncertain);
                }
            }
        }
        assert!(actuator.calls <= 1);
    }
}
