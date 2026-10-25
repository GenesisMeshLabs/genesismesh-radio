"""Host-only Rust/Python/C wire conformance with disposable test credentials.

Run on Linux/WSL: python3 firmware/tests/rust_conformance.py
Requires Cargo, a C99 compiler, and OpenSSL libcrypto. C crypto/build helpers are
shared with conformance.py. CARGO_TARGET_DIR and other Cargo environment settings
are honored; no board, radio, persistent device state, or production key is used.
"""

from __future__ import annotations

import json
import os
import random
import shlex
import subprocess
import unittest

import conformance as ccodec
from conformance import (
    AUDIENCE,
    KEY,
    NOW,
    ROOT,
    Frame,
    Kind,
    OutcomeStatus,
    decode,
    encode,
    encode_command,
    encode_outcome,
    encode_telemetry,
)

from genesismesh_radio.protocol import ProtocolError

MANIFEST = ROOT / "firmware/rust/genesismesh-radio-device/Cargo.toml"


def encode_request(frame, key=KEY, audience=AUDIENCE):
    return {
        "op": "encode",
        "key_hex": key.hex(),
        "audience": audience,
        "kind": int(frame.kind),
        "device_id": frame.device_id,
        "counter": frame.counter,
        "expires_at": frame.expires_at,
        "payload_hex": frame.payload.hex(),
    }


def decode_request(packet, key=KEY, audience=AUDIENCE, now=NOW, future=300, limit=51):
    return {
        "op": "decode",
        "key_hex": key.hex(),
        "audience": audience,
        "wire_hex": packet.hex(),
        "now": now,
        "max_future": future,
        "max_frame": limit,
    }


def decoded_response(frame):
    return {
        "ok": True,
        "kind": int(frame.kind),
        "device_id": frame.device_id,
        "counter": frame.counter,
        "expires_at": frame.expires_at,
        "payload_hex": frame.payload.hex(),
    }


class RustConformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the independently compiled C codec and real OpenSSL callback,
        # without duplicating its crypto adapter or inheriting its test cases.
        cls.addClassCleanup(ccodec.Conformance.doClassCleanups)
        ccodec.Conformance.setUpClass()
        cls.c = ccodec.Conformance()
        command = shlex.split(os.environ.get("CARGO", "cargo")) + [
            "build",
            "--locked",
            "--manifest-path",
            str(MANIFEST),
            "--example",
            "codec",
            "--message-format=json-render-diagnostics",
        ]
        result = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, timeout=180, check=False
        )
        if result.returncode:
            raise RuntimeError(f"Rust host example build failed:\n{result.stderr}")
        executables = []
        for line in result.stdout.splitlines():
            message = json.loads(line)
            if (
                message.get("reason") == "compiler-artifact"
                and message.get("target", {}).get("name") == "codec"
                and message.get("executable")
            ):
                executables.append(message["executable"])
        if len(executables) != 1:
            raise RuntimeError("Rust host example executable was not uniquely identified")
        cls.executable = executables[0]

    def raw_requests(self, data):
        result = subprocess.run(
            [self.executable], input=data, capture_output=True, timeout=30, check=False
        )
        self.assertEqual(result.returncode, 0, "Rust host example terminated unexpectedly")
        self.assertEqual(result.stderr, b"", "Rust host example wrote diagnostic data")
        return [json.loads(line) for line in result.stdout.splitlines()]

    def rust(self, requests):
        lines = [json.dumps(request, separators=(",", ":")).encode() for request in requests]
        self.assertTrue(all(len(line) <= 4096 for line in lines))
        results = self.raw_requests(b"\n".join(lines) + b"\n")
        self.assertEqual(len(results), len(requests))
        return results

    def valid_cases(self, cases):
        requests, expected = [], []
        for frame, key, audience, now in cases:
            packet = encode(frame, key, audience)
            self.assertEqual(decode(packet, key, audience, now), frame)
            self.assertEqual(self.c.c_encode(frame, key, audience), (0, packet))
            self.assertEqual(self.c.c_decode(packet, key, audience, now), (0, frame))
            requests.extend(
                [encode_request(frame, key, audience), decode_request(packet, key, audience, now)]
            )
            expected.extend([{"ok": True, "wire_hex": packet.hex()}, decoded_response(frame)])
        self.assertEqual(self.rust(requests), expected)

    def rejected_cases(self, cases):
        requests = []
        for packet, options in cases:
            key, audience = options.get("key", KEY), options.get("audience", AUDIENCE)
            now = options.get("now", NOW)
            future, limit = options.get("future", 300), options.get("limit", 51)
            with self.assertRaises(ProtocolError):
                decode(packet, key, audience, now, future, limit)
            self.assertNotEqual(self.c.c_decode(packet, key, audience, now, future, limit)[0], 0)
            requests.append(decode_request(packet, key, audience, now, future, limit))
        self.assertEqual(
            self.rust(requests), [{"ok": False, "error": "invalid_frame"}] * len(requests)
        )

    def test_five_golden_vectors(self):
        vectors = json.loads((ROOT / "firmware/vectors.json").read_text())["vectors"]
        self.assertEqual(len(vectors), 5)
        cases = []
        for vector in vectors:
            key, wire = bytes.fromhex(vector["test_key_hex"]), bytes.fromhex(vector["wire_hex"])
            frame = decode(wire, key, vector["audience"], vector["now"])
            self.assertEqual(encode(frame, key, vector["audience"]), wire)
            cases.append((frame, key, vector["audience"], vector["now"]))
        self.valid_cases(cases)

    def test_300_random_frames_across_all_three_implementations(self):
        rng = random.Random(850014)
        cases = []
        for index in range(300):
            kind = list(Kind)[index % 3]
            if kind is Kind.TELEMETRY:
                payload = encode_telemetry(rng.randrange(256), rng.randrange(-(2**31), 2**31))
            elif kind is Kind.COMMAND:
                payload = encode_command(rng.randrange(1, 65536))
            else:
                status = OutcomeStatus((index // 3) % 3)
                payload = encode_outcome(rng.randrange(1, 2**64), status, rng.randrange(1, 65536))
            now = rng.randrange(0, 2**32 - 301)
            frame = Frame(
                kind,
                rng.randrange(1, 2**32),
                rng.randrange(1, 2**64),
                now + rng.randrange(1, 301),
                payload,
            )
            key = rng.randbytes(rng.choice((32, 64, 96)))
            audience = "".join(chr(rng.randrange(33, 127)) for _ in range(rng.randrange(1, 129)))
            cases.append((frame, key, audience, now))
        self.valid_cases(cases)

    def test_every_bit_flip_in_all_message_kinds(self):
        cases = []
        for kind, payload in (
            (Kind.TELEMETRY, encode_telemetry(255, -(2**31))),
            (Kind.COMMAND, encode_command(65535)),
            (Kind.OUTCOME, encode_outcome(2**64 - 1, OutcomeStatus.SUCCESS, 60)),
        ):
            wire = encode(Frame(kind, 7, 8, NOW + 60, payload), KEY, AUDIENCE)
            for offset in range(len(wire)):
                for bit in range(8):
                    changed = bytearray(wire)
                    changed[offset] ^= 1 << bit
                    cases.append((bytes(changed), {}))
        self.rejected_cases(cases)

    def test_truncations_extensions_wrong_key_audience_and_limits(self):
        packet = encode(Frame(Kind.COMMAND, 1, 2, NOW + 60, encode_command(30)), KEY, AUDIENCE)
        cases = [(packet[:length], {}) for length in range(len(packet))]
        cases.extend((packet + extra, {}) for extra in (b"\0", b"x" * 64))
        cases.extend(
            (packet, options)
            for options in (
                {"key": b"x" * 32},
                {"audience": "another/bridge"},
                {"audience": ""},
                {"audience": "bad audience"},
                {"audience": "a" * 129},
                {"future": 0},
                {"limit": 0},
                {"limit": len(packet) - 1},
            )
        )
        self.rejected_cases(cases)

    def test_freshness_and_integer_boundaries(self):
        self.rejected_cases(
            [
                (
                    encode(Frame(Kind.COMMAND, 1, 1, expiry, encode_command(1)), KEY, AUDIENCE),
                    {},
                )
                for expiry in (NOW - 1, NOW, NOW + 301)
            ]
        )
        cases = []
        for now, expiry in ((0, 1), (NOW, NOW + 300), (2**32 - 2, 2**32 - 1)):
            for kind, payload in (
                (Kind.TELEMETRY, encode_telemetry(0, -(2**31))),
                (Kind.TELEMETRY, encode_telemetry(255, 2**31 - 1)),
                (Kind.COMMAND, encode_command(1)),
                (Kind.COMMAND, encode_command(65535)),
                (Kind.OUTCOME, encode_outcome(1, OutcomeStatus.REJECTED, 0)),
                (Kind.OUTCOME, encode_outcome(2**64 - 1, OutcomeStatus.UNCERTAIN, 65535)),
            ):
                cases.append(
                    (Frame(kind, 2**32 - 1, 2**64 - 1, expiry, payload), KEY, "A" * 128, now)
                )
        self.valid_cases(cases)

    def test_invalid_encoding_and_short_key_contract(self):
        frames = [
            Frame(Kind.COMMAND, 0, 1, NOW + 60, encode_command(1)),
            Frame(Kind.COMMAND, 1, 0, NOW + 60, encode_command(1)),
            Frame(Kind.COMMAND, 1, 1, 0, encode_command(1)),
            Frame(Kind.COMMAND, 1, 1, NOW + 60, b"\x02\0\x01"),
            Frame(Kind.COMMAND, 1, 1, NOW + 60, b"\x01\0\0"),
            Frame(Kind.TELEMETRY, 1, 1, NOW + 60, b"\0" * 6),
            Frame(Kind.OUTCOME, 1, 1, NOW + 60, b"\0" * 11),
        ]
        for frame in frames:
            with self.assertRaises(ProtocolError):
                encode(frame, KEY, AUDIENCE)
            self.assertNotEqual(self.c.c_encode(frame)[0], 0)
        self.assertEqual(
            self.rust([encode_request(frame) for frame in frames]),
            [{"ok": False, "error": "invalid_frame"}] * len(frames),
        )
        frame = Frame(Kind.COMMAND, 1, 1, NOW + 60, encode_command(30))
        packet = encode(frame, KEY, AUDIENCE)
        # The C callback owns the key and its minimum-length check. The generic
        # codec cannot inspect opaque callback key material; test Rust/Python here.
        for key in (b"", b"x" * 31):
            with self.assertRaises(ProtocolError):
                encode(frame, key, AUDIENCE)
            with self.assertRaises(ProtocolError):
                decode(packet, key, AUDIENCE, NOW)
            self.assertEqual(
                self.rust([encode_request(frame, key), decode_request(packet, key)]),
                [{"ok": False, "error": "invalid_frame"}] * 2,
            )

    def test_host_input_limits_recovery_and_sanitized_errors(self):
        frame = Frame(Kind.COMMAND, 1, 1, NOW + 60, encode_command(30))
        valid = json.dumps(encode_request(frame), separators=(",", ":")).encode()
        padded = valid + b" " * (4096 - len(valid))
        expected = {"ok": True, "wire_hex": encode(frame, KEY, AUDIENCE).hex()}
        requests = b"\n".join(
            (padded, b"x" * 100_000, valid, b'{"key_hex":"sensitive-test-value"}', b"\xff", valid)
        )
        self.assertEqual(
            self.raw_requests(requests),
            [
                expected,
                {"ok": False, "error": "request_too_large"},
                expected,
                {"ok": False, "error": "invalid_request"},
                {"ok": False, "error": "invalid_request"},
                expected,
            ],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
