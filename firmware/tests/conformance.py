"""Compile the portable C codec and compare it with Python using real OpenSSL.

Run on Linux/WSL: python3 firmware/tests/conformance.py
Requires a C99 compiler and the OpenSSL libcrypto runtime, not its headers.
All keys in this harness and vectors.json are public test fixtures.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from genesismesh_radio.protocol import (  # noqa: E402
    Frame,
    Kind,
    OutcomeStatus,
    decode,
    encode,
    encode_command,
    encode_outcome,
    encode_telemetry,
)

U8 = ctypes.c_uint8
U8P = ctypes.POINTER(U8)
MAC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, U8P, ctypes.c_size_t, U8P)
KEY = bytes(range(32))
AUDIENCE = "lab/site-1"
NOW = 1700000000


class CFrame(ctypes.Structure):
    _fields_ = [
        ("kind", U8),
        ("device_id", ctypes.c_uint32),
        ("counter", ctypes.c_uint64),
        ("expires_at", ctypes.c_uint32),
        ("payload_len", U8),
        ("payload", U8 * 16),
    ]


def buf(data):
    return (U8 * len(data)).from_buffer_copy(data)


class Conformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="gmr-codec-")
        cls.addClassCleanup(cls.temp.cleanup)
        compiler = os.environ.get("CC", "cc")
        if not shutil.which(shlex.split(compiler)[0]):
            raise RuntimeError("C99 compiler required; run this suite on Linux or WSL")
        library = Path(cls.temp.name) / "libgmr.so"
        subprocess.run(
            shlex.split(compiler)
            + [
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                "-fPIC",
                "-shared",
                "-O2",
                "-I",
                str(ROOT / "firmware/include"),
                str(ROOT / "firmware/src/gmr_protocol.c"),
                "-o",
                str(library),
            ],
            check=True,
        )
        cls.codec = ctypes.CDLL(str(library))
        cls.codec.gmr_encode.argtypes = [
            ctypes.POINTER(CFrame),
            U8P,
            ctypes.c_size_t,
            MAC,
            ctypes.c_void_p,
            U8P,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        cls.codec.gmr_encode.restype = ctypes.c_int
        cls.codec.gmr_decode.argtypes = [
            U8P,
            ctypes.c_size_t,
            U8P,
            ctypes.c_size_t,
            MAC,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_size_t,
            ctypes.POINTER(CFrame),
        ]
        cls.codec.gmr_decode.restype = ctypes.c_int
        cls.codec.gmr_telemetry_payload.argtypes = [U8, ctypes.c_int32, U8P]
        cls.codec.gmr_parse_telemetry.argtypes = [
            U8P,
            ctypes.c_size_t,
            ctypes.POINTER(U8),
            ctypes.POINTER(ctypes.c_int32),
        ]
        cls.codec.gmr_command_payload.argtypes = [ctypes.c_uint16, U8P]
        cls.codec.gmr_outcome_payload.argtypes = [
            ctypes.c_uint64,
            U8,
            ctypes.c_uint16,
            U8P,
        ]
        crypto_name = ctypes.util.find_library("crypto")
        if not crypto_name:
            raise RuntimeError("OpenSSL libcrypto is required for actual HMAC conformance")
        cls.crypto = ctypes.CDLL(crypto_name)
        cls.crypto.EVP_sha256.argtypes = []
        cls.crypto.EVP_sha256.restype = ctypes.c_void_p
        cls.crypto.HMAC.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            U8P,
            ctypes.c_size_t,
            U8P,
            ctypes.POINTER(ctypes.c_uint),
        ]
        cls.crypto.HMAC.restype = ctypes.c_void_p

    def callback(self, key=KEY):
        retained_key = ctypes.create_string_buffer(key)

        @MAC
        def openssl_hmac(_context, message, length, output):
            size = ctypes.c_uint()
            result = self.crypto.HMAC(
                self.crypto.EVP_sha256(),
                retained_key,
                len(key),
                message,
                length,
                output,
                ctypes.byref(size),
            )
            return 0 if result and size.value == 32 else -1

        return openssl_hmac

    def c_encode(self, frame, key=KEY, audience=AUDIENCE, capacity=51):
        source = CFrame()
        source.kind = int(frame.kind)
        source.device_id = frame.device_id
        source.counter = frame.counter
        source.expires_at = frame.expires_at
        source.payload_len = len(frame.payload)
        for index, value in enumerate(frame.payload):
            source.payload[index] = value
        audience = audience.encode("ascii")
        result = (U8 * 51)()
        written = ctypes.c_size_t()
        status = self.codec.gmr_encode(
            ctypes.byref(source),
            buf(audience),
            len(audience),
            self.callback(key),
            None,
            result,
            capacity,
            ctypes.byref(written),
        )
        return status, bytes(result[: written.value])

    def c_decode(self, packet, key=KEY, audience=AUDIENCE, now=NOW, future=300, limit=51):
        target = CFrame()
        audience = audience.encode("ascii")
        status = self.codec.gmr_decode(
            buf(packet),
            len(packet),
            buf(audience),
            len(audience),
            self.callback(key),
            None,
            now,
            future,
            limit,
            ctypes.byref(target),
        )
        if status:
            return status, None
        return status, Frame(
            Kind(target.kind),
            target.device_id,
            target.counter,
            target.expires_at,
            bytes(target.payload[: target.payload_len]),
        )

    def test_golden_vectors(self):
        vectors = json.loads((ROOT / "firmware/vectors.json").read_text())
        for vector in vectors["vectors"]:
            with self.subTest(name=vector["name"]):
                key = bytes.fromhex(vector["test_key_hex"])
                packet = bytes.fromhex(vector["wire_hex"])
                frame = decode(packet, key, vector["audience"], vector["now"])
                self.assertEqual(self.c_encode(frame, key, vector["audience"]), (0, packet))
                self.assertEqual(
                    self.c_decode(packet, key, vector["audience"], vector["now"]),
                    (0, frame),
                )

    def test_random_valid_python_c_interoperability(self):
        rng = random.Random(850013)
        for index in range(300):
            kind = list(Kind)[index % 3]
            if kind is Kind.TELEMETRY:
                payload = encode_telemetry(rng.randrange(256), rng.randrange(-(2**31), 2**31))
            elif kind is Kind.COMMAND:
                payload = encode_command(rng.randrange(1, 65536))
            else:
                payload = encode_outcome(
                    rng.randrange(1, 2**64),
                    OutcomeStatus(index % 3),
                    rng.randrange(1, 65536),
                )
            frame = Frame(kind, rng.randrange(1, 2**32), rng.randrange(1, 2**64), NOW + 60, payload)
            packet = encode(frame, KEY, AUDIENCE)
            self.assertEqual(self.c_encode(frame), (0, packet))
            self.assertEqual(self.c_decode(packet), (0, frame))

    def test_c_rejects_all_single_bit_changes(self):
        packet = encode(
            Frame(Kind.OUTCOME, 7, 8, NOW + 60, encode_outcome(12, OutcomeStatus.SUCCESS, 45)),
            KEY,
            AUDIENCE,
        )
        for offset in range(len(packet)):
            for bit in range(8):
                changed = bytearray(packet)
                changed[offset] ^= 1 << bit
                self.assertNotEqual(self.c_decode(bytes(changed))[0], 0)

    def test_c_rejects_truncation_extension_wrong_key_and_audience(self):
        packet = encode(Frame(Kind.COMMAND, 1, 2, NOW + 60, encode_command(30)), KEY, AUDIENCE)
        for length in range(len(packet)):
            self.assertNotEqual(self.c_decode(packet[:length])[0], 0)
        for extra in (b"\0", b"x" * 64):
            self.assertNotEqual(self.c_decode(packet + extra)[0], 0)
        self.assertEqual(self.c_decode(packet, key=b"x" * 32)[0], -2)
        self.assertEqual(self.c_decode(packet, audience="another/bridge")[0], -2)

    def test_c_freshness_limits_and_integer_extremes(self):
        for expiry in (NOW - 1, NOW, NOW + 301):
            packet = encode(Frame(Kind.COMMAND, 1, 1, expiry, encode_command(30)), KEY, AUDIENCE)
            self.assertEqual(self.c_decode(packet)[0], -3)
        frame = Frame(Kind.COMMAND, 2**32 - 1, 2**64 - 1, 2**32 - 1, encode_command(65535))
        packet = encode(frame, KEY, AUDIENCE)
        self.assertEqual(self.c_encode(frame), (0, packet))
        self.assertEqual(self.c_decode(packet, now=2**32 - 2), (0, frame))
        self.assertNotEqual(self.c_decode(packet, now=2**32 - 2, limit=len(packet) - 1)[0], 0)

    def test_c_rejects_invalid_encode_and_crypto_failure(self):
        frame = Frame(Kind.COMMAND, 1, 1, NOW + 60, encode_command(30))
        self.assertNotEqual(self.c_encode(frame, capacity=37)[0], 0)
        self.assertNotEqual(self.c_encode(frame, audience="bad audience")[0], 0)
        source = CFrame(kind=2, device_id=1, counter=1, expires_at=NOW + 60, payload_len=3)
        source.payload[0:3] = b"\x01\x00\x3c"
        output = (U8 * 51)()
        size = ctypes.c_size_t(51)

        @MAC
        def failed_crypto(_context, _data, _length, _output):
            return -1

        self.assertEqual(
            self.codec.gmr_encode(
                ctypes.byref(source),
                buf(b"site"),
                4,
                failed_crypto,
                None,
                output,
                51,
                ctypes.byref(size),
            ),
            -4,
        )
        self.assertEqual(size.value, 0)

    def test_c_payload_helpers_match_python(self):
        for value in (-(2**31), -123, -1, 0, 1, 2**31 - 1):
            result = (U8 * 5)()
            self.assertEqual(self.codec.gmr_telemetry_payload(255, value, result), 0)
            self.assertEqual(bytes(result), encode_telemetry(255, value))
            metric = U8()
            decoded = ctypes.c_int32()
            self.assertEqual(
                self.codec.gmr_parse_telemetry(
                    result,
                    5,
                    ctypes.byref(metric),
                    ctypes.byref(decoded),
                ),
                0,
            )
            self.assertEqual((metric.value, decoded.value), (255, value))
        result = (U8 * 3)()
        self.assertEqual(self.codec.gmr_command_payload(60, result), 0)
        self.assertEqual(bytes(result), encode_command(60))
        result = (U8 * 11)()
        self.assertEqual(self.codec.gmr_outcome_payload(2**64 - 1, 1, 0, result), 0)
        self.assertEqual(bytes(result), encode_outcome(2**64 - 1, OutcomeStatus.REJECTED, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
