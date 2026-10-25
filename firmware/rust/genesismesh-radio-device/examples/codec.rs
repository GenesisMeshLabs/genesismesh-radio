//! Host-only JSON-lines conformance tool, not deployable device firmware.
//! Inputs contain disposable test keys. Errors never echo input or key material.

use genesismesh_radio_device::protocol::{decode, encode, Frame, Kind, MAX_FRAME};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const MAX_LINE: usize = 4096;

fn unsigned(value: &Value, name: &str) -> Result<u64, &'static str> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or("invalid_request")
}

fn number(value: &Value, name: &str) -> Result<u32, &'static str> {
    u32::try_from(unsigned(value, name)?).map_err(|_| "invalid_request")
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, &'static str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or("invalid_request")
}

fn bytes(value: &Value, name: &str) -> Result<Vec<u8>, &'static str> {
    hex::decode(text(value, name)?).map_err(|_| "invalid_request")
}

fn handle(line: &[u8]) -> Result<Value, &'static str> {
    let value: Value = serde_json::from_slice(line).map_err(|_| "invalid_request")?;
    let fields = value.as_object().ok_or("invalid_request")?;
    let operation = text(&value, "op")?;
    let allowed: &[&str] = match operation {
        "encode" => &[
            "op",
            "key_hex",
            "audience",
            "kind",
            "device_id",
            "counter",
            "expires_at",
            "payload_hex",
        ],
        "decode" => &[
            "op",
            "key_hex",
            "audience",
            "wire_hex",
            "now",
            "max_future",
            "max_frame",
        ],
        _ => return Err("invalid_request"),
    };
    if fields.keys().any(|name| !allowed.contains(&name.as_str())) {
        return Err("invalid_request");
    }
    let key = bytes(&value, "key_hex")?;
    let audience = text(&value, "audience")?;
    if operation == "encode" {
        let kind = match unsigned(&value, "kind")? {
            1 => Kind::Telemetry,
            2 => Kind::Command,
            3 => Kind::Outcome,
            _ => return Err("invalid_request"),
        };
        let payload = bytes(&value, "payload_hex")?;
        let frame = Frame::new(
            kind,
            number(&value, "device_id")?,
            unsigned(&value, "counter")?,
            number(&value, "expires_at")?,
            &payload,
        )
        .map_err(|_| "invalid_frame")?;
        let mut wire = [0; MAX_FRAME];
        let size = encode(&frame, &key, audience, &mut wire).map_err(|_| "invalid_frame")?;
        Ok(json!({"ok": true, "wire_hex": hex::encode(&wire[..size])}))
    } else {
        let wire = bytes(&value, "wire_hex")?;
        let frame = decode(
            &wire,
            &key,
            audience,
            number(&value, "now")?,
            number(&value, "max_future")?,
            usize::try_from(unsigned(&value, "max_frame")?).map_err(|_| "invalid_request")?,
        )
        .map_err(|_| "invalid_frame")?;
        Ok(json!({
            "ok": true,
            "kind": frame.kind as u8,
            "device_id": frame.device_id,
            "counter": frame.counter,
            "expires_at": frame.expires_at,
            "payload_hex": hex::encode(&frame.payload[..frame.payload_len]),
        }))
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

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut line = Vec::with_capacity(MAX_LINE);
    while let Some(within_limit) = read_line(&mut reader, &mut line)? {
        let response = if within_limit {
            match handle(&line) {
                Ok(response) => response,
                Err(code) => json!({"ok": false, "error": code}),
            }
        } else {
            json!({"ok": false, "error": "request_too_large"})
        };
        serde_json::to_writer(&mut writer, &response)
            .map_err(|_| io::Error::other("response_write_failed"))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}
