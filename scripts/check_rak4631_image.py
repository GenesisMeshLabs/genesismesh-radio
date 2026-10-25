#!/usr/bin/env python3
"""Reject ELF images that escape the stock RAK4631 application memory map.

This checks a build artifact only. It never connects to, flashes or erases a board.
The reserved areas follow RAK's nrf52840_s140_v6.ld (S140 6.1.1).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED_LAYOUT = {
    "board": "RAK4631",
    "target": "thumbv7em-none-eabihf",
    "flash_origin": 0x26000,
    "flash_length": 0xC7000,
    "ram_origin": 0x20006000,
    "ram_length": 0x3A000,
}
MAX_IMAGE_BYTES = 2 * 1024 * 1024


class ImageError(ValueError):
    """The image cannot be established to fit this specific application layout."""


def _inside(start: int, size: int, origin: int, length: int) -> bool:
    return size > 0 and origin <= start < origin + length and start + size <= origin + length


def check_image(image: bytes, layout: dict) -> dict:
    for key, expected in EXPECTED_LAYOUT.items():
        actual = layout.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise ImageError(f"unsupported_layout:{key}")
    if not 52 <= len(image) <= MAX_IMAGE_BYTES:
        raise ImageError("invalid_image_size")
    if image[:7] != b"\x7fELF\x01\x01\x01":
        raise ImageError("requires_elf32_little_endian")
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", image)
    _, kind, machine, version, entry, phoff, _, _, ehsize, phsize, phnum, _, _, _ = header
    if (kind, machine, version, ehsize, phsize) != (2, 40, 1, 52, 32):
        raise ImageError("invalid_arm_executable_header")
    if not 1 <= phnum <= 32 or phoff < ehsize or phoff + phsize * phnum > len(image):
        raise ImageError("invalid_program_headers")
    flash = (layout["flash_origin"], layout["flash_length"])
    ram = (layout["ram_origin"], layout["ram_length"])
    segments = []
    vectors = []
    physical_ranges = []
    virtual_ranges = []
    executable_ranges = []
    for index in range(phnum):
        segment = struct.unpack_from("<IIIIIIII", image, phoff + index * phsize)
        segment_type, offset, vaddr, paddr, filesz, memsz, flags, _ = segment
        if segment_type != 1:  # PT_LOAD: the bytes a programmer can write.
            continue
        if memsz == 0 or filesz > memsz or offset + filesz > len(image):
            raise ImageError("invalid_load_segment")
        if not (_inside(vaddr, memsz, *flash) or _inside(vaddr, memsz, *ram)):
            raise ImageError("load_outside_application_memory")
        if filesz:
            if not _inside(paddr, filesz, *flash):
                raise ImageError("writes_reserved_flash_or_ram")
            # Flash VMA and LMA must agree; RAM .data may have a flash LMA.
            if _inside(vaddr, memsz, *flash) and (vaddr != paddr or memsz != filesz):
                raise ImageError("inconsistent_flash_segment")
            physical_ranges.append((paddr, paddr + filesz))
        virtual_ranges.append((vaddr, vaddr + memsz))
        if flags & 1 and filesz and _inside(vaddr, filesz, *flash):
            executable_ranges.append((vaddr, vaddr + filesz))
        if paddr == flash[0] and vaddr == flash[0] and filesz >= 8:
            vectors.append(struct.unpack_from("<II", image, offset))
        segments.append(
            {"address": vaddr, "load_address": paddr, "file_bytes": filesz, "memory_bytes": memsz}
        )
    for ranges in (physical_ranges, virtual_ranges):
        ordered = sorted(ranges)
        if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:], strict=False)):
            raise ImageError("overlapping_load_segments")
    if len(vectors) != 1:
        raise ImageError("missing_or_ambiguous_vector_table")
    stack, reset = vectors[0]
    if stack % 8 or not ram[0] < stack <= ram[0] + ram[1]:
        raise ImageError("invalid_initial_stack")
    if not reset & 1 or not entry & 1 or reset != entry:
        raise ImageError("invalid_reset_vector_or_entry")
    if reset - 1 < flash[0] + 8 or not any(
        start <= reset - 1 < end for start, end in executable_ranges
    ):
        raise ImageError("reset_handler_not_in_executable_flash")
    return {
        "board": layout["board"],
        "target": layout["target"],
        "mode": "artifact_memory_check",
        "hardware_tested": False,
        "flashed": False,
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "entry": entry,
        "initial_stack": stack,
        "flash_load_bytes": sum(end - start for start, end in physical_ranges),
        "segments": segments,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--layout", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.layout.open("rb") as stream:
            raw_layout = stream.read(16385)
        if len(raw_layout) > 16384:
            raise ImageError("layout_too_large")
        layout = json.loads(raw_layout)
        if not isinstance(layout, dict):
            raise ImageError("invalid_layout")
        with args.image.open("rb") as stream:
            image = stream.read(MAX_IMAGE_BYTES + 1)
        result = check_image(image, layout)
    except (OSError, ValueError, struct.error) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, **result}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
