"""Memory protection checks for the actual board-image inspection tool."""

import importlib.util
import json
import struct
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "check_rak4631_image", Path(__file__).resolve().parents[1] / "scripts/check_rak4631_image.py"
)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def elf(*, physical=0x26000, virtual=0x26000, size=32, stack=0x20040000, entry=0x26009):
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + bytes(9),
        2,
        40,
        1,
        entry,
        52,
        0,
        0,
        52,
        32,
        1,
        0,
        0,
        0,
    )
    program = struct.pack("<IIIIIIII", 1, 84, virtual, physical, size, size, 5, 4)
    return header + program + struct.pack("<II", stack, entry) + bytes(max(0, size - 8))


def test_valid_image_is_an_artifact_check_not_hardware_evidence():
    report = checker.check_image(elf(), checker.EXPECTED_LAYOUT)
    assert report["flash_load_bytes"] == 32
    assert report["initial_stack"] == 0x20040000
    assert report["hardware_tested"] is False
    assert report["flashed"] is False


@pytest.mark.parametrize("physical", [0, 0x1000, 0x25FFF, 0xED000, 0xF4000, 0x10001000, 0x20006000])
def test_refuses_softdevice_bootloader_uicr_and_direct_ram_programming(physical):
    with pytest.raises(checker.ImageError):
        checker.check_image(elf(physical=physical), checker.EXPECTED_LAYOUT)


@pytest.mark.parametrize("stack", [0x20000000, 0x20006000, 0x20040008, 0x2003FFFF])
def test_stack_must_fit_application_ram_and_be_aligned(stack):
    with pytest.raises(checker.ImageError, match="initial_stack"):
        checker.check_image(elf(stack=stack), checker.EXPECTED_LAYOUT)


@pytest.mark.parametrize("entry", [0x26008, 0x26001, 0x25FFF, 0x26041, 0xED001])
def test_thumb_entry_must_point_to_real_executable_bytes(entry):
    with pytest.raises(checker.ImageError):
        checker.check_image(elf(entry=entry), checker.EXPECTED_LAYOUT)


def test_rejects_truncated_load_and_overlapping_program_headers():
    with pytest.raises(checker.ImageError, match="load_segment"):
        checker.check_image(elf()[:-1], checker.EXPECTED_LAYOUT)
    raw = bytearray(elf())
    struct.pack_into("<I", raw, 28, 40)
    with pytest.raises(checker.ImageError, match="program_headers"):
        checker.check_image(bytes(raw), checker.EXPECTED_LAYOUT)


def test_rejects_conflicting_load_segments():
    raw = bytearray(elf())
    raw[44:46] = struct.pack("<H", 2)
    # First segment's data is shifted to leave space for another program header.
    struct.pack_into("<I", raw, 56, 116)
    raw[84:84] = struct.pack("<IIIIIIII", 1, 116, 0x26000, 0x26000, 32, 32, 5, 4)
    with pytest.raises(checker.ImageError, match="overlapping"):
        checker.check_image(bytes(raw), checker.EXPECTED_LAYOUT)


@pytest.mark.parametrize("offset,value", [(4, 2), (5, 2), (18, 3), (40, 0), (44, 0)])
def test_rejects_wrong_elf_format(offset, value):
    raw = bytearray(elf())
    raw[offset] = value
    with pytest.raises(checker.ImageError):
        checker.check_image(bytes(raw), checker.EXPECTED_LAYOUT)


def test_layout_cannot_expand_reserved_regions():
    layout = dict(checker.EXPECTED_LAYOUT, flash_origin=0)
    with pytest.raises(checker.ImageError, match="unsupported_layout"):
        checker.check_image(elf(), layout)


def test_cli_is_read_only_and_reports_a_failed_check(tmp_path, capsys):
    image, layout = tmp_path / "test.elf", tmp_path / "layout.json"
    original = elf()
    image.write_bytes(original)
    layout.write_text(json.dumps(checker.EXPECTED_LAYOUT))
    args = ["--image", str(image), "--layout", str(layout)]
    assert checker.main(args) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert image.read_bytes() == original
    image.write_bytes(b"truncated")
    assert checker.main(args) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False


def elf_with_initialized_ram(*, data_load=0x26020, bss_virtual=0x20006004, bss_size=16):
    header = bytearray(elf()[:52])
    struct.pack_into("<H", header, 44, 3)
    programs = b"".join(
        [
            struct.pack("<IIIIIIII", 1, 148, 0x26000, 0x26000, 32, 32, 5, 4),
            struct.pack("<IIIIIIII", 1, 180, 0x20006000, data_load, 4, 4, 6, 4),
            struct.pack("<IIIIIIII", 1, 184, bss_virtual, bss_virtual, 0, bss_size, 6, 4),
        ]
    )
    return bytes(header) + programs + elf()[84:] + b"data"


def test_accepts_ram_data_with_flash_load_address_and_zero_file_byte_bss():
    report = checker.check_image(elf_with_initialized_ram(), checker.EXPECTED_LAYOUT)
    assert report["flash_load_bytes"] == 36
    assert report["segments"][1] == {
        "address": 0x20006000,
        "load_address": 0x26020,
        "file_bytes": 4,
        "memory_bytes": 4,
    }
    assert report["segments"][2]["file_bytes"] == 0
    assert report["segments"][2]["memory_bytes"] == 16


def test_ram_data_cannot_hide_a_reserved_or_overlapping_flash_load_address():
    with pytest.raises(checker.ImageError, match="writes_reserved"):
        checker.check_image(elf_with_initialized_ram(data_load=0xED000), checker.EXPECTED_LAYOUT)
    with pytest.raises(checker.ImageError, match="overlapping"):
        checker.check_image(elf_with_initialized_ram(data_load=0x2601C), checker.EXPECTED_LAYOUT)


def test_zero_file_byte_bss_still_cannot_overlap_or_escape_application_ram():
    with pytest.raises(checker.ImageError, match="overlapping"):
        checker.check_image(
            elf_with_initialized_ram(bss_virtual=0x20006000), checker.EXPECTED_LAYOUT
        )
    with pytest.raises(checker.ImageError, match="outside_application"):
        checker.check_image(
            elf_with_initialized_ram(bss_virtual=0x2003FFFC), checker.EXPECTED_LAYOUT
        )
