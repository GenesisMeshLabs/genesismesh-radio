//! Allocation-free version-one authenticated radio frames.
//!
//! Authentication uses a per-device shared key, not a device signature. Payloads
//! are not encrypted. The caller owns trusted time and durable replay counters.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 51;
const HEADER: usize = 19;
const TAG: usize = 16;
const MAX_PAYLOAD: usize = 16;
const DOMAIN: &[u8] = b"GenesisMeshRadio\0v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Telemetry = 1,
    Command = 2,
    Outcome = 3,
}

impl TryFrom<u8> for Kind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Telemetry),
            2 => Ok(Self::Command),
            3 => Ok(Self::Outcome),
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OutcomeStatus {
    Success = 0,
    Rejected = 1,
    Uncertain = 2,
}

impl TryFrom<u8> for OutcomeStatus {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::Rejected),
            2 => Ok(Self::Uncertain),
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Authentication,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: Kind,
    pub device_id: u32,
    pub counter: u64,
    pub expires_at: u32,
    pub payload: [u8; MAX_PAYLOAD],
    pub payload_len: usize,
}

impl Frame {
    pub fn new(
        kind: Kind,
        device_id: u32,
        counter: u64,
        expires_at: u32,
        payload: &[u8],
    ) -> Result<Self, Error> {
        if device_id == 0 || counter == 0 || expires_at == 0 {
            return Err(Error::Invalid);
        }
        validate_payload(kind, payload)?;
        let mut frame = Self {
            kind,
            device_id,
            counter,
            expires_at,
            payload: [0; MAX_PAYLOAD],
            payload_len: payload.len(),
        };
        frame.payload[..payload.len()].copy_from_slice(payload);
        Ok(frame)
    }
}

fn validate_payload(kind: Kind, payload: &[u8]) -> Result<(), Error> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::Invalid);
    }
    match kind {
        Kind::Telemetry => parse_telemetry(payload).map(|_| ()),
        Kind::Command => parse_command(payload).map(|_| ()),
        Kind::Outcome => parse_outcome(payload).map(|_| ()),
    }
}

fn authenticated_body(
    body: &[u8],
    key: &[u8],
    audience: &str,
    kind: Kind,
) -> Result<Hmac<Sha256>, Error> {
    if key.len() < 32
        || audience.is_empty()
        || audience.len() > 128
        || !audience.bytes().all(|byte| (33..=126).contains(&byte))
    {
        return Err(Error::Invalid);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Invalid)?;
    mac.update(DOMAIN);
    mac.update(&(audience.len() as u16).to_be_bytes());
    mac.update(audience.as_bytes());
    mac.update(&[if kind == Kind::Command { 2 } else { 1 }]);
    mac.update(body);
    Ok(mac)
}

/// Encode after the caller has durably reserved the outgoing counter.
///
/// Any error leaves the entire caller-provided output buffer unchanged.
pub fn encode(
    frame: &Frame,
    key: &[u8],
    audience: &str,
    output: &mut [u8],
) -> Result<usize, Error> {
    if frame.device_id == 0
        || frame.counter == 0
        || frame.expires_at == 0
        || frame.payload_len > MAX_PAYLOAD
    {
        return Err(Error::Invalid);
    }
    let payload = &frame.payload[..frame.payload_len];
    validate_payload(frame.kind, payload)?;
    let body_len = HEADER + payload.len();
    let frame_len = body_len + TAG;
    if output.len() < frame_len {
        return Err(Error::Invalid);
    }
    let mut encoded = [0; MAX_FRAME];
    encoded[0] = VERSION;
    encoded[1] = frame.kind as u8;
    encoded[2..6].copy_from_slice(&frame.device_id.to_be_bytes());
    encoded[6..14].copy_from_slice(&frame.counter.to_be_bytes());
    encoded[14..18].copy_from_slice(&frame.expires_at.to_be_bytes());
    encoded[18] = payload.len() as u8;
    encoded[HEADER..body_len].copy_from_slice(payload);
    let tag = authenticated_body(&encoded[..body_len], key, audience, frame.kind)?
        .finalize()
        .into_bytes();
    encoded[body_len..frame_len].copy_from_slice(&tag[..TAG]);
    output[..frame_len].copy_from_slice(&encoded[..frame_len]);
    Ok(frame_len)
}

/// Authenticate and validate a frame without changing replay state.
///
/// `max_frame` is the full transport allowance, including the authentication tag.
/// The caller must reject replayed counters and provide trusted `now` separately.
pub fn decode(
    raw: &[u8],
    key: &[u8],
    audience: &str,
    now: u32,
    max_future: u32,
    max_frame: usize,
) -> Result<Frame, Error> {
    if max_future == 0
        || !(HEADER + TAG..=MAX_FRAME).contains(&raw.len())
        || raw.len() > max_frame
        || raw[0] != VERSION
    {
        return Err(Error::Invalid);
    }
    let kind = Kind::try_from(raw[1])?;
    let payload_len = usize::from(raw[18]);
    if payload_len > MAX_PAYLOAD || raw.len() != HEADER + payload_len + TAG {
        return Err(Error::Invalid);
    }
    let body_len = raw.len() - TAG;
    authenticated_body(&raw[..body_len], key, audience, kind)?
        .verify_truncated_left(&raw[body_len..])
        .map_err(|_| Error::Authentication)?;
    let device_id = u32::from_be_bytes(raw[2..6].try_into().map_err(|_| Error::Invalid)?);
    let counter = u64::from_be_bytes(raw[6..14].try_into().map_err(|_| Error::Invalid)?);
    let expires_at = u32::from_be_bytes(raw[14..18].try_into().map_err(|_| Error::Invalid)?);
    if device_id == 0 || counter == 0 {
        return Err(Error::Invalid);
    }
    validate_payload(kind, &raw[HEADER..body_len])?;
    // Widen before adding so validity near the u32 clock limit does not wrap.
    if expires_at <= now || u64::from(expires_at) > u64::from(now) + u64::from(max_future) {
        return Err(Error::Expired);
    }
    Frame::new(kind, device_id, counter, expires_at, &raw[HEADER..body_len])
}

pub fn command_payload(interval_seconds: u16) -> Result<[u8; 3], Error> {
    if interval_seconds == 0 {
        return Err(Error::Invalid);
    }
    let interval = interval_seconds.to_be_bytes();
    Ok([1, interval[0], interval[1]])
}

pub fn parse_command(payload: &[u8]) -> Result<u16, Error> {
    let [1, high, low] = payload else {
        return Err(Error::Invalid);
    };
    let interval = u16::from_be_bytes([*high, *low]);
    if interval == 0 {
        return Err(Error::Invalid);
    }
    Ok(interval)
}

pub fn telemetry_payload(metric: u8, value: i32) -> [u8; 5] {
    let value = value.to_be_bytes();
    [metric, value[0], value[1], value[2], value[3]]
}

pub fn parse_telemetry(payload: &[u8]) -> Result<(u8, i32), Error> {
    let [metric, a, b, c, d] = payload else {
        return Err(Error::Invalid);
    };
    Ok((*metric, i32::from_be_bytes([*a, *b, *c, *d])))
}

pub fn outcome_payload(
    command_counter: u64,
    status: OutcomeStatus,
    applied_interval: u16,
) -> Result<[u8; 11], Error> {
    if command_counter == 0 || (status == OutcomeStatus::Success && applied_interval == 0) {
        return Err(Error::Invalid);
    }
    let mut payload = [0; 11];
    payload[..8].copy_from_slice(&command_counter.to_be_bytes());
    payload[8] = status as u8;
    payload[9..].copy_from_slice(&applied_interval.to_be_bytes());
    Ok(payload)
}

pub fn parse_outcome(payload: &[u8]) -> Result<(u64, OutcomeStatus, u16), Error> {
    if payload.len() != 11 {
        return Err(Error::Invalid);
    }
    let counter = u64::from_be_bytes(payload[..8].try_into().map_err(|_| Error::Invalid)?);
    let status = OutcomeStatus::try_from(payload[8])?;
    let interval = u16::from_be_bytes(payload[9..].try_into().map_err(|_| Error::Invalid)?);
    if counter == 0 || (status == OutcomeStatus::Success && interval == 0) {
        return Err(Error::Invalid);
    }
    Ok((counter, status, interval))
}
