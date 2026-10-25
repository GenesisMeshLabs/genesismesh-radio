#![allow(clippy::unwrap_used)]

use genesismesh_radio_device::protocol::{
    command_payload, decode, encode, outcome_payload, parse_command, parse_outcome,
    parse_telemetry, telemetry_payload, Error, Frame, Kind, OutcomeStatus, MAX_FRAME, VERSION,
};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

const KEY: [u8; 32] = [0x52; 32];
const AUDIENCE: &str = "test/site-1";
const NOW: u32 = 1_700_000_000;

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn packet(frame: &Frame) -> Vec<u8> {
    let mut output = [0; MAX_FRAME];
    let length = encode(frame, &KEY, AUDIENCE, &mut output).unwrap();
    output[..length].to_vec()
}

fn frame() -> Frame {
    Frame::new(Kind::Command, 7, 1, NOW + 60, &command_payload(60).unwrap()).unwrap()
}

fn read(raw: &[u8]) -> Result<Frame, Error> {
    decode(raw, &KEY, AUDIENCE, NOW, 300, MAX_FRAME)
}

/// Independently sign bytes that normal encoding refuses to construct.
fn resign(raw: &mut [u8], direction: u8, domain: &[u8]) {
    let body_length = raw.len() - 16;
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(domain);
    mac.update(&(AUDIENCE.len() as u16).to_be_bytes());
    mac.update(AUDIENCE.as_bytes());
    mac.update(&[direction]);
    mac.update(&raw[..body_length]);
    raw[body_length..].copy_from_slice(&mac.finalize().into_bytes()[..16]);
}

#[test]
fn all_five_shared_python_and_c_golden_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors.json"
    )))
    .unwrap();
    let vectors = vectors["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5);
    for vector in vectors {
        let raw = unhex(vector["wire_hex"].as_str().unwrap());
        let key = unhex(vector["test_key_hex"].as_str().unwrap());
        let audience = vector["audience"].as_str().unwrap();
        let now = vector["now"].as_u64().unwrap() as u32;
        let decoded = decode(&raw, &key, audience, now, 300, MAX_FRAME).unwrap();
        assert_eq!(decoded.expires_at, now + 60);
        let payload = &decoded.payload[..decoded.payload_len];
        match vector["name"].as_str().unwrap() {
            "telemetry-negative" => {
                assert_eq!(
                    (decoded.kind, decoded.device_id, decoded.counter),
                    (Kind::Telemetry, 0x01020304, 42)
                );
                assert_eq!(parse_telemetry(payload), Ok((1, -12345)));
            }
            "command-interval" => {
                assert_eq!(
                    (decoded.kind, decoded.device_id, decoded.counter),
                    (Kind::Command, 0x01020304, 42)
                );
                assert_eq!(parse_command(payload), Ok(60));
            }
            "outcome-success" => {
                assert_eq!(
                    (decoded.kind, decoded.device_id, decoded.counter),
                    (Kind::Outcome, 0x01020304, 43)
                );
                assert_eq!(parse_outcome(payload), Ok((42, OutcomeStatus::Success, 60)));
            }
            "outcome-rejected" => {
                assert_eq!(
                    (decoded.kind, decoded.device_id, decoded.counter),
                    (Kind::Outcome, 1, 1)
                );
                assert_eq!(parse_outcome(payload), Ok((99, OutcomeStatus::Rejected, 0)));
            }
            "telemetry-minimum" => {
                assert_eq!(
                    (decoded.kind, decoded.device_id, decoded.counter),
                    (Kind::Telemetry, u32::MAX, u64::MAX)
                );
                assert_eq!(parse_telemetry(payload), Ok((u8::MAX, i32::MIN)));
            }
            _ => unreachable!("fixture contract changed"),
        }
        let mut encoded = [0xa5; MAX_FRAME];
        let length = encode(&decoded, &key, audience, &mut encoded).unwrap();
        assert_eq!(&encoded[..length], raw, "{}", vector["name"]);
        assert!(encoded[length..].iter().all(|byte| *byte == 0xa5));
        assert!(decoded.payload[decoded.payload_len..]
            .iter()
            .all(|byte| *byte == 0));
    }
}

#[test]
fn every_single_bit_change_and_truncation_is_rejected() {
    let frames = [
        frame(),
        Frame::new(Kind::Telemetry, 7, 2, NOW + 60, &telemetry_payload(3, -200)).unwrap(),
        Frame::new(
            Kind::Outcome,
            7,
            3,
            NOW + 60,
            &outcome_payload(1, OutcomeStatus::Success, 60).unwrap(),
        )
        .unwrap(),
    ];
    for frame in frames {
        let raw = packet(&frame);
        for index in 0..raw.len() {
            for bit in 0..8 {
                let mut changed = raw.clone();
                changed[index] ^= 1 << bit;
                assert!(read(&changed).is_err(), "byte {index} bit {bit}");
            }
        }
        for length in 0..raw.len() {
            assert!(read(&raw[..length]).is_err());
        }
        let mut appended = raw;
        appended.push(0);
        assert_eq!(read(&appended), Err(Error::Invalid));
    }
}

#[test]
fn wrong_key_audience_direction_and_domain_fail_authentication() {
    let raw = packet(&frame());
    assert_eq!(
        decode(&raw, &[0x53; 32], AUDIENCE, NOW, 300, MAX_FRAME),
        Err(Error::Authentication)
    );
    assert_eq!(
        decode(&raw, &KEY, "other/site", NOW, 300, MAX_FRAME),
        Err(Error::Authentication)
    );
    for (direction, domain) in [
        (1, b"GenesisMeshRadio\0v1\0".as_slice()),
        (2, b"GenesisMeshRadio\0v1".as_slice()),
        (2, b"GenesisMeshRadio\0v2\0".as_slice()),
    ] {
        let mut changed = raw.clone();
        resign(&mut changed, direction, domain);
        assert_eq!(read(&changed), Err(Error::Authentication));
    }
}

#[test]
fn signed_invalid_commands_identity_and_framing_fail() {
    for (offset, bytes) in [
        (19, vec![2]),
        (20, vec![0, 0]),
        (2, vec![0; 4]),
        (6, vec![0; 8]),
        (0, vec![VERSION + 1]),
        (1, vec![0]),
        (18, vec![16]),
    ] {
        let mut raw = packet(&frame());
        raw[offset..offset + bytes.len()].copy_from_slice(&bytes);
        resign(&mut raw, 2, b"GenesisMeshRadio\0v1\0");
        assert_eq!(read(&raw), Err(Error::Invalid));
    }
}

#[test]
fn signed_invalid_outcomes_fail() {
    let valid = Frame::new(
        Kind::Outcome,
        7,
        2,
        NOW + 60,
        &outcome_payload(1, OutcomeStatus::Success, 60).unwrap(),
    )
    .unwrap();
    for (offset, bytes) in [(19, vec![0; 8]), (27, vec![3]), (28, vec![0, 0])] {
        let mut raw = packet(&valid);
        raw[offset..offset + bytes.len()].copy_from_slice(&bytes);
        resign(&mut raw, 1, b"GenesisMeshRadio\0v1\0");
        assert_eq!(read(&raw), Err(Error::Invalid));
    }
}

#[test]
fn authenticated_payload_lengths_must_match_each_message_contract() {
    for (kind, correct_length) in [
        (Kind::Command, 3),
        (Kind::Telemetry, 5),
        (Kind::Outcome, 11),
    ] {
        for length in 0..=16 {
            if length == correct_length {
                continue;
            }
            let mut raw = packet(&frame());
            raw.truncate(19);
            raw[1] = kind as u8;
            raw[18] = length;
            raw.resize(19 + usize::from(length) + 16, 0);
            resign(
                &mut raw,
                if kind == Kind::Command { 2 } else { 1 },
                b"GenesisMeshRadio\0v1\0",
            );
            assert_eq!(read(&raw), Err(Error::Invalid));
        }
    }
}

#[test]
fn freshness_boundaries_and_clock_addition_do_not_wrap() {
    let raw = packet(&frame());
    assert_eq!(
        decode(&raw, &KEY, AUDIENCE, NOW + 60, 300, MAX_FRAME),
        Err(Error::Expired)
    );
    assert_eq!(
        decode(&raw, &KEY, AUDIENCE, NOW, 59, MAX_FRAME),
        Err(Error::Expired)
    );
    assert!(decode(&raw, &KEY, AUDIENCE, NOW, 60, MAX_FRAME).is_ok());
    assert_eq!(
        decode(&raw, &KEY, AUDIENCE, NOW, 0, MAX_FRAME),
        Err(Error::Invalid)
    );
    let maximum = Frame::new(
        Kind::Command,
        u32::MAX,
        u64::MAX,
        u32::MAX,
        &command_payload(u16::MAX).unwrap(),
    )
    .unwrap();
    let raw = packet(&maximum);
    assert_eq!(
        decode(&raw, &KEY, AUDIENCE, u32::MAX - 1, u32::MAX, MAX_FRAME),
        Ok(maximum)
    );
    assert_eq!(
        decode(&raw, &KEY, AUDIENCE, u32::MAX, u32::MAX, MAX_FRAME),
        Err(Error::Expired)
    );
    let minimum = Frame::new(Kind::Command, 1, 1, 1, &command_payload(1).unwrap()).unwrap();
    assert_eq!(
        decode(&packet(&minimum), &KEY, AUDIENCE, 0, 1, MAX_FRAME),
        Ok(minimum)
    );
}

#[test]
fn decode_authenticates_before_exposing_signed_payload_or_expiry_validation() {
    let mut raw = packet(&frame());
    raw[19] = 2;
    raw[14..18].copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(read(&raw), Err(Error::Authentication));
    resign(&mut raw, 2, b"GenesisMeshRadio\0v1\0");
    assert_eq!(read(&raw), Err(Error::Invalid));
    raw[19] = 1;
    resign(&mut raw, 2, b"GenesisMeshRadio\0v1\0");
    assert_eq!(read(&raw), Err(Error::Expired));
}

#[test]
fn buffer_transport_and_parameter_bounds_are_strict() {
    let valid = frame();
    let raw = packet(&valid);
    for capacity in 0..raw.len() {
        let mut output = [0xa5; MAX_FRAME];
        assert_eq!(
            encode(&valid, &KEY, AUDIENCE, &mut output[..capacity]),
            Err(Error::Invalid)
        );
        assert_eq!(output, [0xa5; MAX_FRAME]);
        assert_eq!(
            decode(&raw, &KEY, AUDIENCE, NOW, 300, capacity),
            Err(Error::Invalid)
        );
    }
    assert_eq!(decode(&raw, &KEY, AUDIENCE, NOW, 300, raw.len()), Ok(valid));
    for audience in [
        "".to_owned(),
        " ".to_owned(),
        "é".to_owned(),
        "a\0b".to_owned(),
        "a".repeat(129),
    ] {
        let mut output = [0xa5; MAX_FRAME];
        assert_eq!(
            encode(&valid, &KEY, &audience, &mut output),
            Err(Error::Invalid)
        );
        assert_eq!(output, [0xa5; MAX_FRAME]);
        assert_eq!(
            decode(&raw, &KEY, &audience, NOW, 300, MAX_FRAME),
            Err(Error::Invalid)
        );
    }
    for length in 0..32 {
        let mut output = [0xa5; MAX_FRAME];
        assert_eq!(
            encode(&valid, &KEY[..length], AUDIENCE, &mut output),
            Err(Error::Invalid)
        );
        assert_eq!(output, [0xa5; MAX_FRAME]);
        assert_eq!(
            decode(&raw, &KEY[..length], AUDIENCE, NOW, 300, MAX_FRAME),
            Err(Error::Invalid)
        );
    }
    let audience = "!".repeat(128);
    let long_key = [0x55; 129];
    let mut output = [0; MAX_FRAME];
    let length = encode(&valid, &long_key, &audience, &mut output).unwrap();
    assert_eq!(
        decode(&output[..length], &long_key, &audience, NOW, 300, MAX_FRAME),
        Ok(valid)
    );
}

#[test]
fn mutated_public_frames_cannot_bypass_constructor_validation_or_modify_output() {
    let valid = frame();
    let mut bad_payload = valid;
    bad_payload.payload[0] = 2;
    for invalid in [
        Frame {
            device_id: 0,
            ..valid
        },
        Frame {
            counter: 0,
            ..valid
        },
        Frame {
            expires_at: 0,
            ..valid
        },
        Frame {
            payload_len: 0,
            ..valid
        },
        Frame {
            payload_len: 17,
            ..valid
        },
        Frame {
            payload_len: usize::MAX,
            ..valid
        },
        bad_payload,
    ] {
        let mut output = [0xa5; MAX_FRAME];
        assert_eq!(
            encode(&invalid, &KEY, AUDIENCE, &mut output),
            Err(Error::Invalid)
        );
        assert_eq!(output, [0xa5; MAX_FRAME]);
    }
    for (id, counter, expiry) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        assert_eq!(
            Frame::new(Kind::Command, id, counter, expiry, &[1, 0, 1]),
            Err(Error::Invalid)
        );
    }
    for payload in [&[][..], &[0; 17][..], &[0; 16][..]] {
        assert_eq!(
            Frame::new(Kind::Telemetry, 1, 1, 1, payload),
            Err(Error::Invalid)
        );
    }
}

#[test]
fn helper_roundtrips_cover_integer_extremes() {
    for metric in [0, 1, u8::MAX] {
        for value in [i32::MIN, -1, 0, 1, i32::MAX] {
            assert_eq!(
                parse_telemetry(&telemetry_payload(metric, value)),
                Ok((metric, value))
            );
        }
    }
    for interval in [1, 255, 256, u16::MAX] {
        assert_eq!(
            parse_command(&command_payload(interval).unwrap()),
            Ok(interval)
        );
    }
    for counter in [1, u64::MAX] {
        for status in [
            OutcomeStatus::Success,
            OutcomeStatus::Rejected,
            OutcomeStatus::Uncertain,
        ] {
            for interval in [0, 1, u16::MAX] {
                let result = outcome_payload(counter, status, interval);
                if status == OutcomeStatus::Success && interval == 0 {
                    assert_eq!(result, Err(Error::Invalid));
                } else {
                    assert_eq!(
                        parse_outcome(&result.unwrap()),
                        Ok((counter, status, interval))
                    );
                }
            }
        }
    }
    assert_eq!(command_payload(0), Err(Error::Invalid));
    assert_eq!(
        outcome_payload(0, OutcomeStatus::Rejected, 0),
        Err(Error::Invalid)
    );
    for size in 0..20 {
        if size != 5 {
            assert_eq!(parse_telemetry(&vec![0; size]), Err(Error::Invalid));
        }
        assert_eq!(parse_command(&vec![0; size]), Err(Error::Invalid));
        assert_eq!(parse_outcome(&vec![0; size]), Err(Error::Invalid));
    }
}
