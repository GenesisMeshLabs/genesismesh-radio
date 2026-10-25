//! Local device bounds and conservative power-loss recovery around physical actions.

use sha2::{Digest, Sha256};

use crate::protocol::{self, Frame, Kind, OutcomeStatus, MAX_FRAME};
pub use crate::state::STATE_BYTES;
use crate::state::{Pending, State};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    MissingState,
    ExistingState,
    InvalidState,
    StateMismatch,
    Storage,
    Poisoned,
    ClockUnavailable,
    ClockRollback,
    InvalidFreshness,
    Protocol(protocol::Error),
    WrongDeviceOrKind,
    Replay,
    RecoveryRequired,
    NoOutcome,
    CounterExhausted,
    RadioSend,
}

/// A commit must atomically and durably replace the entire snapshot. A failed
/// commit may have written it: the device is poisoned and must reopen before reuse.
pub trait Storage {
    type Error;
    fn load(&mut self) -> Result<Option<[u8; STATE_BYTES]>, Self::Error>;
    fn commit(&mut self, snapshot: &[u8; STATE_BYTES]) -> Result<(), Self::Error>;
}

impl<S: Storage + ?Sized> Storage for &mut S {
    type Error = S::Error;
    fn load(&mut self) -> Result<Option<[u8; STATE_BYTES]>, Self::Error> {
        (**self).load()
    }
    fn commit(&mut self, snapshot: &[u8; STATE_BYTES]) -> Result<(), Self::Error> {
        (**self).commit(snapshot)
    }
}

/// Board adapter must provide trustworthy UTC seconds, not an untrusted radio timestamp.
pub trait Clock {
    type Error;
    fn now(&mut self) -> Result<u32, Self::Error>;
}

/// Success must report the actual verified/persisted interval. An error may mean
/// the action took effect, so it produces an uncertain outcome rather than a retry.
pub trait Actuator {
    type Error;
    fn apply_sampling_interval(&mut self, interval: u16) -> Result<u16, Self::Error>;
}

/// Accept raw application bytes for a configured LoRa link or LoRaWAN FPort.
/// Ok means local submission only; it is not proof of gateway receipt.
pub trait Radio {
    type Error;
    fn send(&mut self, packet: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy)]
pub struct Profile<'a> {
    device_id: u32,
    audience: &'a str,
    key: &'a [u8; 32],
    min_interval: u16,
    max_interval: u16,
    max_frame: usize,
}

impl<'a> Profile<'a> {
    pub fn new(
        device_id: u32,
        audience: &'a str,
        key: &'a [u8; 32],
        min_interval: u16,
        max_interval: u16,
        max_frame: usize,
    ) -> Result<Self, Error> {
        if device_id == 0
            || audience.is_empty()
            || audience.len() > 128
            || !audience.bytes().all(|byte| (33..=126).contains(&byte))
            || min_interval == 0
            || max_interval < min_interval
            || !(46..=255).contains(&max_frame)
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            device_id,
            audience,
            key,
            min_interval,
            max_interval,
            max_frame,
        })
    }

    fn binding(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"GenesisMeshRadioDeviceProfile\0v1\0");
        digest.update(self.device_id.to_be_bytes());
        digest.update((self.audience.len() as u16).to_be_bytes());
        digest.update(self.audience.as_bytes());
        digest.update(Sha256::digest(self.key));
        digest.update(self.min_interval.to_be_bytes());
        digest.update(self.max_interval.to_be_bytes());
        digest.update((self.max_frame as u16).to_be_bytes());
        digest.finalize().into()
    }

    fn permits(self, interval: u16) -> bool {
        (self.min_interval..=self.max_interval).contains(&interval)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub command_counter: u64,
    pub status: OutcomeStatus,
    pub applied_interval: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    pub received_counter: u64,
    pub transmitted_counter: u64,
    pub clock_floor: u32,
    pub observed_clock_floor: u32,
    /// Zero means the current physical interval is unknown.
    pub interval: u16,
    pub outcome: Option<Outcome>,
    pub poisoned: bool,
}

pub struct Packet {
    bytes: [u8; MAX_FRAME],
    length: usize,
    pub counter: u64,
}
impl Packet {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

pub struct Device<'a, S: Storage> {
    profile: Profile<'a>,
    storage: S,
    state: State,
    poisoned: bool,
    observed_floor: u32,
}

impl<'a, S: Storage> Device<'a, S> {
    pub fn provision(
        profile: Profile<'a>,
        mut storage: S,
        clock: &mut impl Clock,
        initial_interval: u16,
    ) -> Result<Self, Error> {
        if !profile.permits(initial_interval) {
            return Err(Error::InvalidConfig);
        }
        if storage.load().map_err(|_| Error::Storage)?.is_some() {
            return Err(Error::ExistingState);
        }
        let state = State {
            binding: profile.binding(),
            rx: 0,
            tx: 0,
            floor: clock.now().map_err(|_| Error::ClockUnavailable)?,
            interval: initial_interval,
            pending: None,
        };
        storage
            .commit(&state.encode(profile.key)?)
            .map_err(|_| Error::Storage)?;
        Ok(Self {
            profile,
            storage,
            state,
            poisoned: false,
            observed_floor: state.floor,
        })
    }

    pub fn open(
        profile: Profile<'a>,
        mut storage: S,
        clock: &mut impl Clock,
    ) -> Result<Self, Error> {
        let raw = storage
            .load()
            .map_err(|_| Error::Storage)?
            .ok_or(Error::MissingState)?;
        let mut state = State::decode(&raw, profile.key)?;
        if state.binding != profile.binding() {
            return Err(Error::StateMismatch);
        }
        if state.interval != 0 && !profile.permits(state.interval) {
            return Err(Error::InvalidState);
        }
        if state.pending.is_some_and(|p| {
            (p.accepted || p.status == OutcomeStatus::Uncertain) && !profile.permits(p.requested)
        }) {
            return Err(Error::InvalidState);
        }
        let now = clock.now().map_err(|_| Error::ClockUnavailable)?;
        if now < state.floor {
            return Err(Error::ClockRollback);
        }
        state.floor = now;
        if let Some(pending) = state.pending.as_mut() {
            if pending.accepted {
                pending.accepted = false;
                pending.status = OutcomeStatus::Uncertain;
                pending.applied = 0;
                state.interval = 0;
            }
        }
        storage
            .commit(&state.encode(profile.key)?)
            .map_err(|_| Error::Storage)?;
        Ok(Self {
            profile,
            storage,
            state,
            poisoned: false,
            observed_floor: state.floor,
        })
    }

    pub fn status(&self) -> Status {
        Status {
            received_counter: self.state.rx,
            transmitted_counter: self.state.tx,
            clock_floor: self.state.floor,
            observed_clock_floor: self.observed_floor,
            interval: if self.poisoned {
                0
            } else {
                self.state.interval
            },
            outcome: self
                .state
                .pending
                .filter(|p| !self.poisoned && !p.accepted)
                .map(|p| Outcome {
                    command_counter: p.counter,
                    status: p.status,
                    applied_interval: p.applied,
                }),
            poisoned: self.poisoned,
        }
    }

    fn now(&mut self, clock: &mut impl Clock) -> Result<u32, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let now = clock.now().map_err(|_| Error::ClockUnavailable)?;
        if now < self.observed_floor {
            return Err(Error::ClockRollback);
        }
        self.observed_floor = now;
        Ok(now)
    }

    fn persist(&mut self, next: State) -> Result<(), Error> {
        let raw = next.encode(self.profile.key)?;
        self.poisoned = true;
        self.storage.commit(&raw).map_err(|_| Error::Storage)?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }

    fn finish(
        &mut self,
        mut pending: Pending,
        status: OutcomeStatus,
        applied: u16,
        now: u32,
    ) -> Result<Outcome, Error> {
        pending.accepted = false;
        pending.status = status;
        pending.applied = applied;
        let mut next = self.state;
        next.floor = now;
        next.pending = Some(pending);
        if status == OutcomeStatus::Success {
            next.interval = applied;
        }
        if status == OutcomeStatus::Uncertain {
            next.interval = 0;
        }
        self.persist(next)?;
        Ok(Outcome {
            command_counter: pending.counter,
            status,
            applied_interval: applied,
        })
    }

    pub fn receive_command(
        &mut self,
        raw: &[u8],
        clock: &mut impl Clock,
        actuator: &mut impl Actuator,
    ) -> Result<Outcome, Error> {
        let now = self.now(clock)?;
        let frame = protocol::decode(
            raw,
            self.profile.key,
            self.profile.audience,
            now,
            300,
            self.profile.max_frame,
        )
        .map_err(Error::Protocol)?;
        if frame.kind != Kind::Command || frame.device_id != self.profile.device_id {
            return Err(Error::WrongDeviceOrKind);
        }
        if frame.counter <= self.state.rx {
            return Err(Error::Replay);
        }
        if self.state.pending.is_some_and(|pending| pending.accepted) {
            return Err(Error::RecoveryRequired);
        }
        let interval = protocol::parse_command(&frame.payload[..frame.payload_len])
            .map_err(Error::Protocol)?;
        let pending = Pending {
            counter: frame.counter,
            requested: interval,
            expires_at: frame.expires_at,
            accepted: true,
            status: OutcomeStatus::Uncertain,
            applied: 0,
        };
        let mut next = self.state;
        next.rx = frame.counter;
        next.floor = now;
        next.pending = Some(pending);
        if !self.profile.permits(interval) {
            // Refused local-policy commands consume their authenticated counter as well.
            next.pending = Some(Pending {
                accepted: false,
                status: OutcomeStatus::Rejected,
                applied: next.interval,
                ..pending
            });
            self.persist(next)?;
            return self.status().outcome.ok_or(Error::InvalidState);
        }
        self.persist(next)?; // Durable acceptance precedes any physical action.
        let action_now = match self.now(clock) {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        if action_now >= pending.expires_at {
            return self.finish(
                pending,
                OutcomeStatus::Rejected,
                self.state.interval,
                action_now,
            );
        }
        self.poisoned = true;
        let result = actuator.apply_sampling_interval(interval);
        self.poisoned = false;
        let finished_now = match self.now(clock) {
            Ok(value) if value >= action_now => value,
            Ok(_) => {
                self.poisoned = true;
                return Err(Error::ClockRollback);
            }
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let (status, applied) = match result {
            Ok(actual) if actual == interval => (OutcomeStatus::Success, actual),
            Ok(actual) => (OutcomeStatus::Uncertain, actual),
            Err(_) => (OutcomeStatus::Uncertain, 0),
        };
        self.finish(pending, status, applied, finished_now)
    }

    fn packet(
        &mut self,
        kind: Kind,
        payload: &[u8],
        clock: &mut impl Clock,
        lifetime: u32,
    ) -> Result<Packet, Error> {
        let now = self.now(clock)?;
        if !(1..=300).contains(&lifetime) {
            return Err(Error::InvalidFreshness);
        }
        let expires = now.checked_add(lifetime).ok_or(Error::InvalidFreshness)?;
        let mut next = self.state;
        next.tx = next.tx.checked_add(1).ok_or(Error::CounterExhausted)?;
        next.floor = now;
        let frame = Frame::new(kind, self.profile.device_id, next.tx, expires, payload)
            .map_err(Error::Protocol)?;
        self.persist(next)?; // A failed radio send must never reuse this counter.
        let mut packet = Packet {
            bytes: [0; MAX_FRAME],
            length: 0,
            counter: next.tx,
        };
        packet.length = protocol::encode(
            &frame,
            self.profile.key,
            self.profile.audience,
            &mut packet.bytes,
        )
        .map_err(Error::Protocol)?;
        Ok(packet)
    }

    pub fn outcome_frame(
        &mut self,
        clock: &mut impl Clock,
        lifetime: u32,
    ) -> Result<Packet, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let outcome = self.status().outcome.ok_or(Error::NoOutcome)?;
        let payload = protocol::outcome_payload(
            outcome.command_counter,
            outcome.status,
            outcome.applied_interval,
        )
        .map_err(Error::Protocol)?;
        self.packet(Kind::Outcome, &payload, clock, lifetime)
    }

    pub fn telemetry_frame(
        &mut self,
        metric: u8,
        value: i32,
        clock: &mut impl Clock,
        lifetime: u32,
    ) -> Result<Packet, Error> {
        self.packet(
            Kind::Telemetry,
            &protocol::telemetry_payload(metric, value),
            clock,
            lifetime,
        )
    }

    pub fn send_outcome(
        &mut self,
        clock: &mut impl Clock,
        radio: &mut impl Radio,
        lifetime: u32,
    ) -> Result<u64, Error> {
        let packet = self.outcome_frame(clock, lifetime)?;
        radio
            .send(packet.as_bytes())
            .map_err(|_| Error::RadioSend)?;
        Ok(packet.counter)
    }
}
