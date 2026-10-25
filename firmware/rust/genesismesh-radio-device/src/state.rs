//! Authenticated snapshot format; an intact old snapshot still requires an external rollback anchor.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::device::Error;
use crate::protocol::OutcomeStatus;

pub const STATE_BYTES: usize = 120;
const BODY: usize = 88;
const DOMAIN: &[u8] = b"GenesisMeshRadioDeviceState\0v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pending {
    pub counter: u64,
    pub requested: u16,
    pub expires_at: u32,
    pub accepted: bool,
    pub status: OutcomeStatus,
    pub applied: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct State {
    pub binding: [u8; 32],
    pub rx: u64,
    pub tx: u64,
    pub floor: u32,
    pub interval: u16,
    pub pending: Option<Pending>,
}

impl State {
    pub fn encode(&self, key: &[u8; 32]) -> Result<[u8; STATE_BYTES], Error> {
        let mut raw = [0u8; STATE_BYTES];
        raw[0] = 1;
        raw[1..33].copy_from_slice(&self.binding);
        raw[33..41].copy_from_slice(&self.rx.to_be_bytes());
        raw[41..49].copy_from_slice(&self.tx.to_be_bytes());
        raw[49..53].copy_from_slice(&self.floor.to_be_bytes());
        raw[53..55].copy_from_slice(&self.interval.to_be_bytes());
        if let Some(pending) = self.pending {
            raw[55] = if pending.accepted { 1 } else { 2 };
            raw[56..64].copy_from_slice(&pending.counter.to_be_bytes());
            raw[64..66].copy_from_slice(&pending.requested.to_be_bytes());
            raw[66..70].copy_from_slice(&pending.expires_at.to_be_bytes());
            raw[70] = pending.status as u8;
            raw[71..73].copy_from_slice(&pending.applied.to_be_bytes());
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidConfig)?;
        mac.update(DOMAIN);
        mac.update(&raw[..BODY]);
        raw[BODY..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(raw)
    }

    pub fn decode(raw: &[u8; STATE_BYTES], key: &[u8; 32]) -> Result<Self, Error> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidConfig)?;
        mac.update(DOMAIN);
        mac.update(&raw[..BODY]);
        mac.verify_slice(&raw[BODY..])
            .map_err(|_| Error::InvalidState)?;
        if raw[0] != 1 || raw[73..BODY].iter().any(|value| *value != 0) {
            return Err(Error::InvalidState);
        }
        let u64_at = |offset| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&raw[offset..offset + 8]);
            u64::from_be_bytes(bytes)
        };
        let u32_at = |offset| {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&raw[offset..offset + 4]);
            u32::from_be_bytes(bytes)
        };
        let u16_at = |offset| u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let rx = u64_at(33);
        let interval = u16_at(53);
        let pending = match raw[55] {
            0 if raw[56..73].iter().all(|value| *value == 0) && rx == 0 && interval != 0 => None,
            phase @ (1 | 2) => {
                let status = match raw[70] {
                    0 => OutcomeStatus::Success,
                    1 => OutcomeStatus::Rejected,
                    2 => OutcomeStatus::Uncertain,
                    _ => return Err(Error::InvalidState),
                };
                let pending = Pending {
                    counter: u64_at(56),
                    requested: u16_at(64),
                    expires_at: u32_at(66),
                    accepted: phase == 1,
                    status,
                    applied: u16_at(71),
                };
                if pending.counter == 0
                    || pending.counter != rx
                    || pending.requested == 0
                    || pending.expires_at == 0
                    || pending.accepted
                        && (status != OutcomeStatus::Uncertain || pending.applied != 0)
                    || !pending.accepted
                        && status == OutcomeStatus::Success
                        && (pending.applied != pending.requested || interval != pending.applied)
                    || !pending.accepted && status == OutcomeStatus::Uncertain && interval != 0
                    || !pending.accepted
                        && status == OutcomeStatus::Rejected
                        && pending.applied != interval
                {
                    return Err(Error::InvalidState);
                }
                Some(pending)
            }
            _ => return Err(Error::InvalidState),
        };
        let mut binding = [0u8; 32];
        binding.copy_from_slice(&raw[1..33]);
        Ok(Self {
            binding,
            rx,
            tx: u64_at(41),
            floor: u32_at(49),
            interval,
            pending,
        })
    }
}
