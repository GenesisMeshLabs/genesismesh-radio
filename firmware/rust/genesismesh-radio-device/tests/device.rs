#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

use genesismesh_radio_device::device::{
    Actuator, Clock, Device, Error, Profile, Radio, Storage, STATE_BYTES,
};
use genesismesh_radio_device::protocol::{self, Frame, Kind, OutcomeStatus};

const KEY: [u8; 32] = [0x42; 32];
const AUDIENCE: &str = "device-test";

#[derive(Clone, Copy)]
enum Failure {
    Before,
    After,
    PowerCut,
}

#[derive(Default)]
struct Memory {
    raw: Option<[u8; STATE_BYTES]>,
    commits: usize,
    failure: Option<(usize, Failure)>,
}

#[derive(Clone, Default)]
struct Store(Rc<RefCell<Memory>>);
impl Storage for Store {
    type Error = ();
    fn load(&mut self) -> Result<Option<[u8; STATE_BYTES]>, ()> {
        Ok(self.0.borrow().raw)
    }
    fn commit(&mut self, raw: &[u8; STATE_BYTES]) -> Result<(), ()> {
        let mut memory = self.0.borrow_mut();
        memory.commits += 1;
        let failure = memory
            .failure
            .filter(|(step, _)| *step == memory.commits)
            .map(|(_, mode)| mode);
        if matches!(failure, Some(Failure::Before)) {
            return Err(());
        }
        memory.raw = Some(*raw);
        match failure {
            Some(Failure::After) => Err(()),
            Some(Failure::PowerCut) => panic!("simulated loss of power"),
            _ => Ok(()),
        }
    }
}

struct Time {
    current: u32,
    readings: VecDeque<Result<u32, ()>>,
}
impl Time {
    fn fixed(now: u32) -> Self {
        Self {
            current: now,
            readings: VecDeque::new(),
        }
    }
    fn sequence(values: &[Result<u32, ()>]) -> Self {
        Self {
            current: 1000,
            readings: values.iter().copied().collect(),
        }
    }
}
impl Clock for Time {
    type Error = ();
    fn now(&mut self) -> Result<u32, ()> {
        self.readings.pop_front().unwrap_or(Ok(self.current))
    }
}

struct Setting {
    calls: usize,
    result: Result<u16, ()>,
    power_cut: bool,
}
impl Setting {
    fn success(value: u16) -> Self {
        Self {
            calls: 0,
            result: Ok(value),
            power_cut: false,
        }
    }
}
impl Actuator for Setting {
    type Error = ();
    fn apply_sampling_interval(&mut self, _: u16) -> Result<u16, ()> {
        self.calls += 1;
        if self.power_cut {
            panic!("power cut after physical action");
        }
        self.result
    }
}

#[derive(Default)]
struct Link {
    fail: bool,
    frames: Vec<Vec<u8>>,
}
impl Radio for Link {
    type Error = ();
    fn send(&mut self, packet: &[u8]) -> Result<(), ()> {
        self.frames.push(packet.to_vec());
        if self.fail {
            Err(())
        } else {
            Ok(())
        }
    }
}

fn profile() -> Profile<'static> {
    Profile::new(7, AUDIENCE, &KEY, 5, 3600, 51).unwrap()
}
fn provision(store: Store) -> Device<'static, Store> {
    Device::provision(profile(), store, &mut Time::fixed(1000), 60).unwrap()
}
fn command(counter: u64, interval: u16, expiry: u32) -> Vec<u8> {
    frame(
        Kind::Command,
        7,
        counter,
        expiry,
        &protocol::command_payload(interval).unwrap(),
    )
}
fn frame(kind: Kind, id: u32, counter: u64, expiry: u32, payload: &[u8]) -> Vec<u8> {
    let value = Frame::new(kind, id, counter, expiry, payload).unwrap();
    let mut raw = [0; 51];
    let length = protocol::encode(&value, &KEY, AUDIENCE, &mut raw).unwrap();
    raw[..length].to_vec()
}

#[test]
fn normal_command_outcome_and_replay_survive_reopen() {
    let store = Store::default();
    let mut device = provision(store.clone());
    let mut clock = Time::fixed(1001);
    let mut actuator = Setting::success(120);
    let raw = command(1, 120, 1060);
    let outcome = device
        .receive_command(&raw, &mut clock, &mut actuator)
        .unwrap();
    assert_eq!(
        (outcome.status, outcome.applied_interval, actuator.calls),
        (OutcomeStatus::Success, 120, 1)
    );
    let packet = device.outcome_frame(&mut clock, 60).unwrap();
    let decoded = protocol::decode(packet.as_bytes(), &KEY, AUDIENCE, 1001, 300, 51).unwrap();
    assert_eq!(
        protocol::parse_outcome(&decoded.payload[..decoded.payload_len]).unwrap(),
        (1, OutcomeStatus::Success, 120)
    );
    drop(device);
    let mut reopened = Device::open(profile(), store, &mut clock).unwrap();
    assert_eq!(reopened.status().interval, 120);
    assert_eq!(
        reopened.receive_command(&raw, &mut clock, &mut actuator),
        Err(Error::Replay)
    );
    assert_eq!(actuator.calls, 1);
    assert_eq!(
        reopened.outcome_frame(&mut clock, 60).unwrap().counter,
        packet.counter + 1
    );
}

#[test]
fn invalid_or_unbound_input_never_writes_or_actuates() {
    let store = Store::default();
    let mut device = provision(store.clone());
    let mut bad_mac = command(1, 120, 1060);
    *bad_mac.last_mut().unwrap() ^= 1;
    let cases = [
        bad_mac,
        command(1, 120, 1000),
        command(1, 120, 1400),
        frame(
            Kind::Command,
            8,
            1,
            1060,
            &protocol::command_payload(120).unwrap(),
        ),
        frame(
            Kind::Telemetry,
            7,
            1,
            1060,
            &protocol::telemetry_payload(1, 10),
        ),
    ];
    let mut actuator = Setting::success(120);
    for raw in cases {
        assert!(device
            .receive_command(&raw, &mut Time::fixed(1000), &mut actuator)
            .is_err());
        assert_eq!(store.0.borrow().commits, 1);
        assert_eq!(device.status().received_counter, 0);
    }
    assert_eq!(actuator.calls, 0);
}

#[test]
fn local_policy_refusal_consumes_authenticated_counter_without_actuation() {
    let mut device = provision(Store::default());
    let mut clock = Time::fixed(1000);
    let mut actuator = Setting::success(5000);
    let raw = command(1, 5000, 1060);
    assert_eq!(
        device
            .receive_command(&raw, &mut clock, &mut actuator)
            .unwrap()
            .status,
        OutcomeStatus::Rejected
    );
    assert_eq!(
        device.receive_command(&raw, &mut clock, &mut actuator),
        Err(Error::Replay)
    );
    assert_eq!(device.status().interval, 60);
    assert_eq!(actuator.calls, 0);
}

#[test]
fn failure_to_commit_acceptance_never_actuates_and_poisons_instance() {
    for failure in [Failure::Before, Failure::After] {
        let store = Store::default();
        let mut device = provision(store.clone());
        store.0.borrow_mut().failure = Some((2, failure));
        let mut actuator = Setting::success(120);
        let mut clock = Time::fixed(1001);
        assert_eq!(
            device.receive_command(&command(1, 120, 1060), &mut clock, &mut actuator),
            Err(Error::Storage)
        );
        assert_eq!(actuator.calls, 0);
        assert!(device.status().poisoned);
        assert!(matches!(
            device.telemetry_frame(1, 1, &mut clock, 60),
            Err(Error::Poisoned)
        ));
        assert!(matches!(
            device.outcome_frame(&mut clock, 60),
            Err(Error::Poisoned)
        ));
        drop(device);
        let reopened = Device::open(profile(), store, &mut clock).unwrap();
        if matches!(failure, Failure::After) {
            assert_eq!(
                reopened.status().outcome.unwrap().status,
                OutcomeStatus::Uncertain
            );
            assert_eq!(reopened.status().interval, 0);
        } else {
            assert_eq!(reopened.status().received_counter, 0);
        }
    }
}

#[test]
fn loss_of_power_after_acceptance_or_during_actuation_recovers_uncertain() {
    for during_actuation in [false, true] {
        let store = Store::default();
        let mut device = provision(store.clone());
        if !during_actuation {
            store.0.borrow_mut().failure = Some((2, Failure::PowerCut));
        }
        let mut actuator = Setting::success(120);
        actuator.power_cut = during_actuation;
        let raw = command(1, 120, 1060);
        assert!(catch_unwind(AssertUnwindSafe(|| device.receive_command(
            &raw,
            &mut Time::fixed(1001),
            &mut actuator
        )))
        .is_err());
        assert!(device.status().poisoned);
        assert_eq!(device.status().interval, 0);
        assert!(matches!(
            device.telemetry_frame(1, 1, &mut Time::fixed(1002), 60),
            Err(Error::Poisoned)
        ));
        drop(device); // Recover through authenticated storage before reuse.
        let mut reopened = Device::open(profile(), store, &mut Time::fixed(1002)).unwrap();
        assert_eq!(
            reopened.status().outcome.unwrap().status,
            OutcomeStatus::Uncertain
        );
        assert_eq!(reopened.status().interval, 0);
        assert_eq!(
            reopened.receive_command(&raw, &mut Time::fixed(1002), &mut Setting::success(120)),
            Err(Error::Replay)
        );
        assert_eq!(actuator.calls, usize::from(during_actuation));
    }
}

#[test]
fn result_commit_failure_never_reapplies_and_loaded_record_controls_recovery() {
    for failure in [Failure::Before, Failure::After] {
        let store = Store::default();
        let mut device = provision(store.clone());
        store.0.borrow_mut().failure = Some((3, failure));
        let mut actuator = Setting::success(120);
        assert_eq!(
            device.receive_command(
                &command(1, 120, 1060),
                &mut Time::fixed(1001),
                &mut actuator
            ),
            Err(Error::Storage)
        );
        assert_eq!(actuator.calls, 1);
        drop(device);
        let recovered = Device::open(profile(), store, &mut Time::fixed(1002)).unwrap();
        assert_eq!(
            recovered.status().outcome.unwrap().status,
            if matches!(failure, Failure::After) {
                OutcomeStatus::Success
            } else {
                OutcomeStatus::Uncertain
            }
        );
    }
}

#[test]
fn actuator_error_or_different_actual_value_is_uncertain() {
    for actual in [Err(()), Ok(90), Ok(0)] {
        let mut device = provision(Store::default());
        let mut actuator = Setting {
            calls: 0,
            result: actual,
            power_cut: false,
        };
        let outcome = device
            .receive_command(
                &command(1, 120, 1060),
                &mut Time::fixed(1001),
                &mut actuator,
            )
            .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Uncertain);
        assert_eq!(outcome.applied_interval, actual.unwrap_or(0));
        assert_eq!(device.status().interval, 0);
        assert_eq!(actuator.calls, 1);
    }
}

#[test]
fn clock_rollback_before_during_and_after_actuation_fails_closed() {
    for readings in [
        vec![Ok(999)],
        vec![Ok(1000), Ok(999)],
        vec![Ok(1000), Ok(1010), Ok(1005)],
    ] {
        let store = Store::default();
        let mut device = provision(store.clone());
        let mut actuator = Setting::success(120);
        let result = device.receive_command(
            &command(1, 120, 1060),
            &mut Time::sequence(&readings),
            &mut actuator,
        );
        assert_eq!(result, Err(Error::ClockRollback));
        if readings.len() == 1 {
            assert_eq!(store.0.borrow().commits, 1);
            assert_eq!(actuator.calls, 0);
        } else {
            assert!(device.status().poisoned);
            drop(device);
            let recovered = Device::open(profile(), store, &mut Time::fixed(1020)).unwrap();
            assert_eq!(
                recovered.status().outcome.unwrap().status,
                OutcomeStatus::Uncertain
            );
            assert_eq!(actuator.calls, usize::from(readings.len() == 3));
        }
    }
}

#[test]
fn command_that_expires_during_acceptance_commit_is_not_applied() {
    let mut device = provision(Store::default());
    let mut clock = Time::sequence(&[Ok(1000), Ok(1060)]);
    let mut actuator = Setting::success(120);
    let outcome = device
        .receive_command(&command(1, 120, 1060), &mut clock, &mut actuator)
        .unwrap();
    assert_eq!(outcome.status, OutcomeStatus::Rejected);
    assert_eq!(actuator.calls, 0);
    assert_eq!(device.status().clock_floor, 1060);
}

#[test]
fn slow_successful_actuator_reports_actual_result_after_command_expiry() {
    let mut device = provision(Store::default());
    let mut actuator = Setting::success(120);
    let outcome = device
        .receive_command(
            &command(1, 120, 1060),
            &mut Time::sequence(&[Ok(1000), Ok(1001), Ok(1100)]),
            &mut actuator,
        )
        .unwrap();
    assert_eq!(outcome.status, OutcomeStatus::Success);
    assert_eq!(device.status().clock_floor, 1100); // Fresh at call start, no physical completion deadline.
}

#[test]
fn unavailable_clock_after_admission_preserves_uncertainty() {
    for readings in [vec![Ok(1000), Err(())], vec![Ok(1000), Ok(1001), Err(())]] {
        let store = Store::default();
        let mut device = provision(store.clone());
        let mut actuator = Setting::success(120);
        assert_eq!(
            device.receive_command(
                &command(1, 120, 1060),
                &mut Time::sequence(&readings),
                &mut actuator
            ),
            Err(Error::ClockUnavailable)
        );
        assert!(device.status().poisoned);
        drop(device);
        let recovered = Device::open(profile(), store, &mut Time::fixed(1010)).unwrap();
        assert_eq!(
            recovered.status().outcome.unwrap().status,
            OutcomeStatus::Uncertain
        );
        assert_eq!(actuator.calls, usize::from(readings.len() == 3));
    }
}

#[test]
fn radio_failure_burns_counter_and_retry_uses_new_authenticated_counter() {
    let mut device = provision(Store::default());
    let mut clock = Time::fixed(1001);
    device
        .receive_command(
            &command(1, 120, 1060),
            &mut clock,
            &mut Setting::success(120),
        )
        .unwrap();
    let mut radio = Link {
        fail: true,
        ..Link::default()
    };
    assert_eq!(
        device.send_outcome(&mut clock, &mut radio, 60),
        Err(Error::RadioSend)
    );
    radio.fail = false;
    assert_eq!(device.send_outcome(&mut clock, &mut radio, 60), Ok(2));
    for (index, raw) in radio.frames.iter().enumerate() {
        assert_eq!(
            protocol::decode(raw, &KEY, AUDIENCE, 1001, 300, 51)
                .unwrap()
                .counter,
            index as u64 + 1
        );
    }
}

#[test]
fn failed_counter_reservation_never_emits_frame_even_if_storage_wrote_it() {
    for failure in [Failure::Before, Failure::After] {
        let store = Store::default();
        let mut device = provision(store.clone());
        store.0.borrow_mut().failure = Some((2, failure));
        assert!(matches!(
            device.telemetry_frame(1, 2, &mut Time::fixed(1001), 60),
            Err(Error::Storage)
        ));
        drop(device);
        let mut recovered = Device::open(profile(), store, &mut Time::fixed(1002)).unwrap();
        let packet = recovered
            .telemetry_frame(1, 2, &mut Time::fixed(1002), 60)
            .unwrap();
        assert_eq!(
            packet.counter,
            if matches!(failure, Failure::After) {
                2
            } else {
                1
            }
        );
    }
}

#[test]
fn missing_corrupt_replaced_and_reprovisioned_state_is_refused() {
    assert!(matches!(
        Device::open(profile(), Store::default(), &mut Time::fixed(1000)),
        Err(Error::MissingState)
    ));
    let store = Store::default();
    drop(provision(store.clone()));
    assert!(matches!(
        Device::provision(profile(), store.clone(), &mut Time::fixed(1000), 60),
        Err(Error::ExistingState)
    ));
    let different = Profile::new(8, AUDIENCE, &KEY, 5, 3600, 51).unwrap();
    assert!(matches!(
        Device::open(different, store.clone(), &mut Time::fixed(1000)),
        Err(Error::StateMismatch)
    ));
    let different = Profile::new(7, AUDIENCE, &KEY, 10, 3600, 51).unwrap();
    assert!(matches!(
        Device::open(different, store.clone(), &mut Time::fixed(1000)),
        Err(Error::StateMismatch)
    ));
    let original = store.0.borrow().raw.unwrap();
    for offset in 0..STATE_BYTES {
        let mut raw = original;
        raw[offset] ^= 1;
        store.0.borrow_mut().raw = Some(raw);
        assert!(matches!(
            Device::open(profile(), store.clone(), &mut Time::fixed(1000)),
            Err(Error::InvalidState)
        ));
    }
}

#[test]
fn persisted_clock_floor_survives_reopen_and_freshness_overflow_never_emits() {
    let store = Store::default();
    let mut device = provision(store.clone());
    device
        .telemetry_frame(1, 2, &mut Time::fixed(2000), 60)
        .unwrap();
    drop(device);
    assert!(matches!(
        Device::open(profile(), store, &mut Time::fixed(1999)),
        Err(Error::ClockRollback)
    ));
    let mut device = Device::provision(
        profile(),
        Store::default(),
        &mut Time::fixed(u32::MAX - 2),
        60,
    )
    .unwrap();
    assert!(matches!(
        device.telemetry_frame(1, 2, &mut Time::fixed(u32::MAX - 2), 60),
        Err(Error::InvalidFreshness)
    ));
    assert_eq!(device.status().transmitted_counter, 0);
}

#[test]
fn narrow_radio_budget_or_invalid_local_profile_is_refused() {
    assert!(matches!(
        Profile::new(7, AUDIENCE, &KEY, 5, 3600, 45),
        Err(Error::InvalidConfig)
    ));
    assert!(Profile::new(7, AUDIENCE, &KEY, 5, 3600, 46).is_ok());
    assert!(Profile::new(0, AUDIENCE, &KEY, 5, 3600, 51).is_err());
    assert!(Profile::new(7, "bad audience", &KEY, 5, 3600, 51).is_err());
    assert!(Profile::new(7, AUDIENCE, &KEY, 0, 3600, 51).is_err());
    assert!(Profile::new(7, AUDIENCE, &KEY, 10, 5, 51).is_err());
}

fn resign_snapshot(raw: &mut [u8; STATE_BYTES]) {
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(b"GenesisMeshRadioDeviceState\0v1\0");
    mac.update(&raw[..88]);
    raw[88..].copy_from_slice(&mac.finalize().into_bytes());
}

#[test]
fn authenticated_but_inconsistent_snapshot_fields_are_refused() {
    let store = Store::default();
    let mut device = provision(store.clone());
    device
        .receive_command(
            &command(1, 5000, 1060),
            &mut Time::fixed(1001),
            &mut Setting::success(5000),
        )
        .unwrap();
    drop(device);
    let original = store.0.borrow().raw.unwrap();
    for (offset, value) in [(71, 1), (73, 1), (55, 9), (70, 9)] {
        let mut raw = original;
        raw[offset] = value;
        resign_snapshot(&mut raw);
        store.0.borrow_mut().raw = Some(raw);
        assert!(matches!(
            Device::open(profile(), store.clone(), &mut Time::fixed(1001)),
            Err(Error::InvalidState)
        ));
    }
}

#[test]
fn counter_exhaustion_never_wraps_or_emits() {
    let store = Store::default();
    drop(provision(store.clone()));
    let mut raw = store.0.borrow().raw.unwrap();
    raw[41..49].copy_from_slice(&u64::MAX.to_be_bytes());
    resign_snapshot(&mut raw);
    store.0.borrow_mut().raw = Some(raw);
    let mut device = Device::open(profile(), store.clone(), &mut Time::fixed(1001)).unwrap();
    let before = store.0.borrow().commits;
    assert!(matches!(
        device.telemetry_frame(1, 2, &mut Time::fixed(1001), 60),
        Err(Error::CounterExhausted)
    ));
    assert_eq!(store.0.borrow().commits, before);
    assert_eq!(device.status().transmitted_counter, u64::MAX);
    let command = command(u64::MAX, 120, 1060);
    let mut actuator = Setting::success(120);
    device
        .receive_command(&command, &mut Time::fixed(1001), &mut actuator)
        .unwrap();
    assert_eq!(
        device.receive_command(&command, &mut Time::fixed(1001), &mut actuator),
        Err(Error::Replay)
    );
    assert_eq!(actuator.calls, 1);
}

#[test]
fn trusted_time_read_on_rejected_input_still_detects_later_clock_rollback() {
    let store = Store::default();
    let mut device = provision(store.clone());
    let mut damaged = command(1, 120, 1160);
    *damaged.last_mut().unwrap() ^= 1;
    let mut actuator = Setting::success(120);
    assert!(device
        .receive_command(&damaged, &mut Time::fixed(1100), &mut actuator)
        .is_err());
    assert_eq!(store.0.borrow().commits, 1);
    assert_eq!(device.status().clock_floor, 1000);
    assert_eq!(device.status().observed_clock_floor, 1100);
    assert_eq!(
        device.receive_command(
            &command(1, 120, 1160),
            &mut Time::fixed(1050),
            &mut actuator
        ),
        Err(Error::ClockRollback)
    );
    assert_eq!(actuator.calls, 0);
    assert_eq!(store.0.borrow().commits, 1);
}

#[test]
fn power_cut_after_result_commit_preserves_success_without_reapplication() {
    let store = Store::default();
    let mut device = provision(store.clone());
    store.0.borrow_mut().failure = Some((3, Failure::PowerCut));
    let raw = command(1, 120, 1060);
    let mut actuator = Setting::success(120);
    assert!(catch_unwind(AssertUnwindSafe(|| device.receive_command(
        &raw,
        &mut Time::fixed(1001),
        &mut actuator
    )))
    .is_err());
    assert!(device.status().poisoned);
    assert_eq!(device.status().interval, 0);
    drop(device);
    let mut recovered = Device::open(profile(), store, &mut Time::fixed(1002)).unwrap();
    assert_eq!(
        recovered.status().outcome.unwrap().status,
        OutcomeStatus::Success
    );
    assert_eq!(
        recovered.receive_command(&raw, &mut Time::fixed(1002), &mut actuator),
        Err(Error::Replay)
    );
    assert_eq!(actuator.calls, 1);
}
