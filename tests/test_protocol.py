"""Wire-level tests independent of adapters and the GenesisMesh controller."""

import hashlib
import hmac
import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from genesismesh_radio.protocol import (
    DOMAIN,
    Frame,
    Kind,
    OutcomeStatus,
    ProtocolError,
    decode,
    decode_command,
    decode_outcome,
    decode_telemetry,
    encode,
    encode_command,
    encode_outcome,
    encode_telemetry,
    peek_device_id,
)

KEY = bytes(range(32))
AUDIENCE = "lab/site-1"
NOW = 1700000000


@pytest.mark.parametrize(
    ("kind", "payload", "length"),
    [
        (Kind.TELEMETRY, encode_telemetry(1, -12345), 40),
        (Kind.COMMAND, encode_command(60), 38),
        (Kind.OUTCOME, encode_outcome(42, OutcomeStatus.SUCCESS, 60), 46),
    ],
)
def test_round_trip_and_transport_budget(kind, payload, length):
    frame = Frame(kind, 0x01020304, 42, NOW + 60, payload)
    packet = encode(frame, KEY, AUDIENCE)
    assert len(packet) == length <= 51
    assert peek_device_id(packet) == frame.device_id
    assert decode(packet, KEY, AUDIENCE, NOW) == frame
    assert decode(packet, KEY, AUDIENCE, NOW, max_payload=length) == frame
    with pytest.raises(ProtocolError, match="budget"):
        decode(packet, KEY, AUDIENCE, NOW, max_payload=length - 1)


def test_independent_hmac_construction():
    body = struct.pack(">BBIQIB", 1, 2, 0x01020304, 42, NOW + 60, 3) + b"\x01\x00\x3c"
    audience = AUDIENCE.encode("ascii")
    mac = hmac.new(
        KEY,
        DOMAIN + len(audience).to_bytes(2, "big") + audience + b"\x02" + body,
        hashlib.sha256,
    ).digest()[:16]
    frame = Frame(Kind.COMMAND, 0x01020304, 42, NOW + 60, encode_command(60))
    assert encode(frame, KEY, AUDIENCE) == body + mac


def test_every_single_bit_mutation_is_rejected():
    frame = Frame(Kind.TELEMETRY, 0x01020304, 42, NOW + 60, encode_telemetry(1, -12))
    packet = encode(frame, KEY, AUDIENCE)
    for index in range(len(packet)):
        for bit in range(8):
            changed = bytearray(packet)
            changed[index] ^= 1 << bit
            with pytest.raises(ProtocolError):
                decode(bytes(changed), KEY, AUDIENCE, NOW)


def test_wrong_key_audience_and_direction_are_rejected():
    packet = encode(Frame(Kind.COMMAND, 1, 1, NOW + 1, encode_command(1)), KEY, AUDIENCE)
    with pytest.raises(ProtocolError, match="authentication"):
        decode(packet, bytes(reversed(KEY)), AUDIENCE, NOW)
    with pytest.raises(ProtocolError, match="authentication"):
        decode(packet, KEY, "lab/site-2", NOW)
    body = packet[:-16]
    audience = AUDIENCE.encode("ascii")
    wrong_direction = hmac.new(
        KEY,
        DOMAIN + len(audience).to_bytes(2, "big") + audience + b"\x01" + body,
        hashlib.sha256,
    ).digest()[:16]
    with pytest.raises(ProtocolError, match="authentication"):
        decode(body + wrong_direction, KEY, AUDIENCE, NOW)


@pytest.mark.parametrize("extra", [b"\x00", b"a" * 20])
def test_no_trailing_bytes(extra):
    packet = encode(Frame(Kind.COMMAND, 1, 1, NOW + 60, encode_command(30)), KEY, AUDIENCE)
    with pytest.raises(ProtocolError):
        decode(packet + extra, KEY, AUDIENCE, NOW)


def test_all_truncated_frames_are_rejected():
    packet = encode(Frame(Kind.COMMAND, 1, 1, NOW + 60, encode_command(30)), KEY, AUDIENCE)
    for length in range(len(packet)):
        with pytest.raises(ProtocolError):
            decode(packet[:length], KEY, AUDIENCE, NOW)


@pytest.mark.parametrize("expiry", [NOW - 1, NOW, NOW + 301])
def test_expiry_window(expiry):
    packet = encode(Frame(Kind.COMMAND, 1, 1, expiry, encode_command(30)), KEY, AUDIENCE)
    with pytest.raises(ProtocolError):
        decode(packet, KEY, AUDIENCE, NOW)


def test_future_window_boundary():
    packet = encode(Frame(Kind.COMMAND, 1, 1, NOW + 300, encode_command(30)), KEY, AUDIENCE)
    assert decode(packet, KEY, AUDIENCE, NOW).expires_at == NOW + 300


@pytest.mark.parametrize("field", ["device_id", "counter", "expires_at"])
@pytest.mark.parametrize("value", [True, False, 0, -1, 1.0, "1", None, 1 << 65])
def test_frame_integer_types_and_ranges(field, value):
    values = dict(
        kind=Kind.COMMAND, device_id=1, counter=1, expires_at=NOW + 60, payload=encode_command(30)
    )
    values[field] = value
    with pytest.raises(ProtocolError):
        encode(Frame(**values), KEY, AUDIENCE)


@pytest.mark.parametrize("kind", [True, 1, "1", None])
def test_kind_requires_enum(kind):
    with pytest.raises(ProtocolError):
        encode(Frame(kind, 1, 1, NOW + 60, encode_telemetry(1, 1)), KEY, AUDIENCE)


@pytest.mark.parametrize("key", [b"", b"x" * 31, "x" * 32, bytearray(32), None])
def test_bad_keys(key):
    with pytest.raises(ProtocolError):
        encode(Frame(Kind.COMMAND, 1, 1, NOW + 60, encode_command(30)), key, AUDIENCE)


@pytest.mark.parametrize("audience", ["", "a b", "a\x00b", "é", "x" * 129, None, 1])
def test_bad_audiences(audience):
    with pytest.raises(ProtocolError):
        encode(Frame(Kind.COMMAND, 1, 1, NOW + 60, encode_command(30)), KEY, audience)


@pytest.mark.parametrize("name", ["now", "max_future_seconds", "max_payload"])
@pytest.mark.parametrize("value", [True, -1, 1.0, "1", None, 1 << 33])
def test_decode_parameter_types(name, value):
    packet = encode(Frame(Kind.COMMAND, 1, 1, NOW + 60, encode_command(30)), KEY, AUDIENCE)
    kwargs = dict(now=NOW, max_future_seconds=300, max_payload=51)
    kwargs[name] = value
    with pytest.raises(ProtocolError):
        decode(packet, KEY, AUDIENCE, **kwargs)


def test_payload_helpers():
    assert decode_telemetry(encode_telemetry(255, -2147483648)) == (255, -2147483648)
    assert decode_telemetry(encode_telemetry(0, 2147483647)) == (0, 2147483647)
    assert decode_command(encode_command(65535)) == 65535
    assert decode_outcome(encode_outcome(2**64 - 1, OutcomeStatus.REJECTED, 0)) == (
        2**64 - 1,
        OutcomeStatus.REJECTED,
        0,
    )


@pytest.mark.parametrize("payload", [b"", b"\x01\x00\x00", b"\x02\x00\x3c", b"1234"])
def test_invalid_commands(payload):
    with pytest.raises(ProtocolError):
        decode_command(payload)


@pytest.mark.parametrize("interval", [True, 0, -1, 65536, 1.5])
def test_invalid_command_intervals(interval):
    with pytest.raises(ProtocolError):
        encode_command(interval)


def test_invalid_outcomes():
    for args in [
        (0, OutcomeStatus.SUCCESS, 30),
        (1, 0, 30),
        (1, True, 30),
        (1, OutcomeStatus.SUCCESS, 0),
        (1, OutcomeStatus.REJECTED, True),
    ]:
        with pytest.raises(ProtocolError):
            encode_outcome(*args)
    with pytest.raises(ProtocolError):
        decode_outcome(struct.pack(">QBH", 1, 3, 30))


def test_kind_payload_mismatch_is_rejected_even_with_valid_authentication():
    body = struct.pack(">BBIQIB", 1, 2, 1, 1, NOW + 60, 5) + encode_telemetry(1, 3)
    audience = AUDIENCE.encode("ascii")
    tag = hmac.new(
        KEY,
        DOMAIN + len(audience).to_bytes(2, "big") + audience + b"\x02" + body,
        hashlib.sha256,
    ).digest()[:16]
    with pytest.raises(ProtocolError, match="three bytes"):
        decode(body + tag, KEY, AUDIENCE, NOW)


def test_peek_is_not_authentication():
    packet = encode(Frame(Kind.COMMAND, 12, 1, NOW + 60, encode_command(30)), KEY, AUDIENCE)
    corrupt = packet[:-1] + bytes([packet[-1] ^ 1])
    assert peek_device_id(corrupt) == 12
    with pytest.raises(ProtocolError):
        decode(corrupt, KEY, AUDIENCE, NOW)


@st.composite
def valid_frames(draw):
    kind = draw(st.sampled_from(list(Kind)))
    if kind is Kind.TELEMETRY:
        payload = encode_telemetry(
            draw(st.integers(0, 255)), draw(st.integers(-(2**31), 2**31 - 1))
        )
    elif kind is Kind.COMMAND:
        payload = encode_command(draw(st.integers(1, 65535)))
    else:
        status = draw(st.sampled_from(list(OutcomeStatus)))
        payload = encode_outcome(
            draw(st.integers(1, 2**64 - 1)),
            status,
            draw(st.integers(1 if status is OutcomeStatus.SUCCESS else 0, 65535)),
        )
    return Frame(
        kind,
        draw(st.integers(1, 2**32 - 1)),
        draw(st.integers(1, 2**64 - 1)),
        NOW + draw(st.integers(1, 300)),
        payload,
    )


@given(
    valid_frames(),
    st.binary(min_size=32, max_size=64),
    st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=1, max_size=128),
)
def test_property_round_trip(frame, key, audience):
    packet = encode(frame, key, audience)
    assert len(packet) <= 51
    assert decode(packet, key, audience, NOW) == frame


@given(st.binary(min_size=0, max_size=100))
def test_property_arbitrary_wire_input_is_bounded(data):
    try:
        frame = decode(data, KEY, AUDIENCE, NOW)
    except ProtocolError:
        return
    assert encode(frame, KEY, AUDIENCE) == data
