//! Host-only software peer for bridge integration tests, not board firmware.
//! The real device engine uses simulated actuation and process-local memory.
//! MemoryStorage is NOT durable storage; restarting this process loses its state.
//! Use only disposable test keys. No operation opens files, radios, or devices.

use genesismesh_radio_device::device::{
    Actuator, Clock, Device, Error, Profile, Storage, STATE_BYTES,
};
use genesismesh_radio_device::protocol::{self, OutcomeStatus};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::io::{self, BufRead, Write};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LINE: usize = 4096;

#[derive(Clone, Default)]
struct MemoryStorage(Rc<RefCell<Option<[u8; STATE_BYTES]>>>);

impl Storage for MemoryStorage {
    type Error = ();

    fn load(&mut self) -> Result<Option<[u8; STATE_BYTES]>, Self::Error> {
        self.0
            .try_borrow()
            .map(|snapshot| *snapshot)
            .map_err(|_| ())
    }

    fn commit(&mut self, snapshot: &[u8; STATE_BYTES]) -> Result<(), Self::Error> {
        *self.0.try_borrow_mut().map_err(|_| ())? = Some(*snapshot);
        Ok(())
    }
}

struct SystemClock;

impl Clock for SystemClock {
    type Error = ();

    fn now(&mut self) -> Result<u32, Self::Error> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs();
        u32::try_from(seconds).map_err(|_| ())
    }
}

struct SimulatedActuator {
    interval: u16,
}

impl Actuator for SimulatedActuator {
    type Error = ();

    fn apply_sampling_interval(&mut self, interval: u16) -> Result<u16, Self::Error> {
        self.interval = interval;
        Ok(self.interval)
    }
}

struct Settings {
    device_id: u32,
    key: [u8; 32],
    audience: String,
    min_interval: u16,
    max_interval: u16,
    max_frame: usize,
    initial_interval: u16,
}

fn unsigned(value: &Value, name: &str) -> Result<u64, &'static str> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or("invalid_request")
}

fn optional_unsigned(value: &Value, name: &str, default: u64) -> Result<u64, &'static str> {
    if value.get(name).is_some() {
        unsigned(value, name)
    } else {
        Ok(default)
    }
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, &'static str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or("invalid_request")
}

fn fields(value: &Value, allowed: &[&str]) -> Result<(), &'static str> {
    let object = value.as_object().ok_or("invalid_request")?;
    if object.keys().any(|name| !allowed.contains(&name.as_str())) {
        return Err("invalid_request");
    }
    Ok(())
}

fn settings(value: &Value) -> Result<Settings, &'static str> {
    fields(
        value,
        &[
            "op",
            "device_id",
            "key_hex",
            "audience",
            "min_interval",
            "max_interval",
            "max_frame",
            "initial_interval",
        ],
    )?;
    if text(value, "op")? != "init" {
        return Err("init_required");
    }
    let key = hex::decode(text(value, "key_hex")?).map_err(|_| "invalid_request")?;
    Ok(Settings {
        device_id: u32::try_from(unsigned(value, "device_id")?).map_err(|_| "invalid_request")?,
        key: key.try_into().map_err(|_| "invalid_key_length")?,
        audience: text(value, "audience")?.to_owned(),
        min_interval: u16::try_from(unsigned(value, "min_interval")?)
            .map_err(|_| "invalid_request")?,
        max_interval: u16::try_from(unsigned(value, "max_interval")?)
            .map_err(|_| "invalid_request")?,
        max_frame: usize::try_from(optional_unsigned(value, "max_frame", 51)?)
            .map_err(|_| "invalid_request")?,
        initial_interval: u16::try_from(optional_unsigned(value, "initial_interval", 60)?)
            .map_err(|_| "invalid_request")?,
    })
}

fn error_code(error: Error) -> &'static str {
    match error {
        Error::InvalidConfig => "invalid_config",
        Error::MissingState => "missing_state",
        Error::ExistingState => "existing_state",
        Error::InvalidState => "invalid_state",
        Error::StateMismatch => "state_mismatch",
        Error::Storage => "storage_failed",
        Error::Poisoned => "device_poisoned",
        Error::ClockUnavailable => "clock_unavailable",
        Error::ClockRollback => "clock_rollback",
        Error::InvalidFreshness => "invalid_freshness",
        Error::Protocol(protocol::Error::Invalid) => "invalid_frame",
        Error::Protocol(protocol::Error::Authentication) => "authentication_failed",
        Error::Protocol(protocol::Error::Expired) => "expired",
        Error::WrongDeviceOrKind => "wrong_device_or_kind",
        Error::Replay => "replay",
        Error::RecoveryRequired => "recovery_required",
        Error::NoOutcome => "no_outcome",
        Error::CounterExhausted => "counter_exhausted",
        Error::RadioSend => "radio_send_failed",
    }
}

fn metadata(device: &Device<'_, MemoryStorage>) -> Value {
    let status = device.status();
    json!({
        "ok": true,
        "rx": status.received_counter,
        "tx": status.transmitted_counter,
        "interval": status.interval,
        "hardware_tested": false,
    })
}

fn operate<'a>(
    value: &Value,
    device: &mut Device<'a, MemoryStorage>,
    profile: Profile<'a>,
    storage: &MemoryStorage,
    clock: &mut SystemClock,
    actuator: &mut SimulatedActuator,
) -> Result<Value, &'static str> {
    match text(value, "op")? {
        "command" => {
            fields(value, &["op", "wire_hex"])?;
            let wire = hex::decode(text(value, "wire_hex")?).map_err(|_| "invalid_request")?;
            let outcome = device
                .receive_command(&wire, clock, actuator)
                .map_err(error_code)?;
            let packet = device.outcome_frame(clock, 60).map_err(error_code)?;
            let status = match outcome.status {
                OutcomeStatus::Success => "success",
                OutcomeStatus::Rejected => "rejected",
                OutcomeStatus::Uncertain => "uncertain",
            };
            Ok(json!({
                "ok": true,
                "wire_hex": hex::encode(packet.as_bytes()),
                "applied_interval": outcome.applied_interval,
                "status": status,
                "hardware_tested": false,
            }))
        }
        "telemetry" => {
            fields(value, &["op", "metric", "value"])?;
            let metric = u8::try_from(unsigned(value, "metric")?).map_err(|_| "invalid_request")?;
            let reading = value
                .get("value")
                .and_then(Value::as_i64)
                .ok_or("invalid_request")?;
            let reading = i32::try_from(reading).map_err(|_| "invalid_request")?;
            let packet = device
                .telemetry_frame(metric, reading, clock, 60)
                .map_err(error_code)?;
            Ok(json!({
                "ok": true,
                "wire_hex": hex::encode(packet.as_bytes()),
                "hardware_tested": false,
            }))
        }
        "restart" => {
            fields(value, &["op"])?;
            *device = Device::open(profile, storage.clone(), clock).map_err(error_code)?;
            Ok(metadata(device))
        }
        "status" => {
            fields(value, &["op"])?;
            Ok(metadata(device))
        }
        _ => Err("invalid_request"),
    }
}

/// Drain an oversized line without retaining it; later requests remain usable.
fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<Option<bool>> {
    line.clear();
    let mut oversized = false;
    let mut seen = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(seen.then_some(!oversized));
        }
        seen = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let length = newline.unwrap_or(available.len());
        if !oversized && line.len() + length <= MAX_LINE {
            line.extend_from_slice(&available[..length]);
        } else {
            oversized = true;
            line.clear();
        }
        reader.consume(length + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(!oversized));
        }
    }
}

fn request(line: &[u8]) -> Result<Value, &'static str> {
    serde_json::from_slice(line).map_err(|_| "invalid_request")
}

fn emit(writer: &mut impl Write, response: Result<Value, &'static str>) -> io::Result<()> {
    let response = match response {
        Ok(response) => response,
        Err(code) => json!({"ok": false, "error": code, "hardware_tested": false}),
    };
    serde_json::to_writer(&mut *writer, &response)
        .map_err(|_| io::Error::other("response_write_failed"))?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn run_session(
    settings: Settings,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> io::Result<()> {
    // Settings owns the key and audience for the full lifetime of the profile/device.
    let profile = match Profile::new(
        settings.device_id,
        &settings.audience,
        &settings.key,
        settings.min_interval,
        settings.max_interval,
        settings.max_frame,
    ) {
        Ok(profile) => profile,
        Err(error) => return emit(writer, Err(error_code(error))),
    };
    let storage = MemoryStorage::default();
    let mut clock = SystemClock;
    let mut actuator = SimulatedActuator {
        interval: settings.initial_interval,
    };
    let mut device = match Device::provision(
        profile,
        storage.clone(),
        &mut clock,
        settings.initial_interval,
    ) {
        Ok(device) => device,
        Err(error) => return emit(writer, Err(error_code(error))),
    };
    emit(writer, Ok(metadata(&device)))?;
    let mut line = Vec::with_capacity(MAX_LINE);
    while let Some(within_limit) = read_line(reader, &mut line)? {
        let response = if within_limit {
            request(&line).and_then(|value| {
                operate(
                    &value,
                    &mut device,
                    profile,
                    &storage,
                    &mut clock,
                    &mut actuator,
                )
            })
        } else {
            Err("request_too_large")
        };
        emit(writer, response)?;
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut line = Vec::with_capacity(MAX_LINE);
    match read_line(&mut reader, &mut line)? {
        Some(true) => match request(&line).and_then(|value| settings(&value)) {
            Ok(settings) => run_session(settings, &mut reader, &mut writer),
            Err(code) => emit(&mut writer, Err(code)),
        },
        Some(false) => emit(&mut writer, Err("request_too_large")),
        None => Ok(()),
    }
}
