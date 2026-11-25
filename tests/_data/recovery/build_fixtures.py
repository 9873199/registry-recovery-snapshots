from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from dissect.regf.hive_format import (
    BASE_BLOCK_SIZE,
    HVLE_HEADER_SIZE,
    MARVIN32_SEED,
    SECTOR_SIZE,
    base_block_checksum,
    marvin32,
)

ROOT = Path(__file__).parent
TIMESTAMP = 132_000_000_000_000_000
FILE_NAME = "NTUSER.DAT"
DIRTY_SEQUENCE = 12
DIRTY_SECONDARY = 11


@dataclass(frozen=True)
class HiveLayout:
    data: bytes
    root_cell: int
    lf_cell: int
    lf_entries_absolute: int
    value_data_absolute: int


def _align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _pack_u32(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buffer, offset, value)


def _put_cell(bin_data: bytearray, position: int, payload: bytes, *, allocated: bool = True) -> int:
    size = _align(4 + len(payload))
    _pack_u32(bin_data, position, (-size) & 0xFFFFFFFF if allocated else size)
    bin_data[position + 4 : position + 4 + len(payload)] = payload
    return size


def _key_node(
    *,
    flags: int,
    parent: int,
    subkey_count: int,
    subkey_list: int,
    value_count: int,
    value_list: int,
    name: str,
) -> bytes:
    name_bytes = name.encode("latin1")
    payload = bytearray(76 + len(name_bytes))
    payload[0:2] = b"nk"
    struct.pack_into("<H", payload, 2, flags)
    struct.pack_into("<Q", payload, 4, TIMESTAMP)
    _pack_u32(payload, 12, 0)
    _pack_u32(payload, 16, parent)
    _pack_u32(payload, 20, subkey_count)
    _pack_u32(payload, 24, 0)
    _pack_u32(payload, 28, subkey_list)
    _pack_u32(payload, 32, 0xFFFFFFFF)
    _pack_u32(payload, 36, value_count)
    _pack_u32(payload, 40, value_list)
    _pack_u32(payload, 44, 0xFFFFFFFF)
    _pack_u32(payload, 48, 0xFFFFFFFF)
    _pack_u32(payload, 52, 0)
    _pack_u32(payload, 56, 0)
    _pack_u32(payload, 60, 0)
    _pack_u32(payload, 64, 0)
    _pack_u32(payload, 68, 0)
    struct.pack_into("<H", payload, 72, len(name_bytes))
    struct.pack_into("<H", payload, 74, 0)
    payload[76:] = name_bytes
    return bytes(payload)


def _build_base_block(bin_size: int, root_cell: int, *, sequence1: int, sequence2: int, file_type: int = 0) -> bytes:
    block = bytearray(BASE_BLOCK_SIZE)
    block[0:4] = b"regf"
    _pack_u32(block, 4, sequence1)
    _pack_u32(block, 8, sequence2)
    struct.pack_into("<Q", block, 12, TIMESTAMP)
    _pack_u32(block, 20, 1)
    _pack_u32(block, 24, 5)
    _pack_u32(block, 28, file_type)
    _pack_u32(block, 32, 1)
    _pack_u32(block, 36, root_cell)
    _pack_u32(block, 40, bin_size)
    _pack_u32(block, 44, 1)
    name = FILE_NAME.encode("utf-16-le")
    block[48 : 48 + len(name)] = name
    _pack_u32(block, 508, base_block_checksum(block))
    return bytes(block)


def build_hive() -> HiveLayout:
    bin_data = bytearray(BASE_BLOCK_SIZE)
    bin_data[0:4] = b"hbin"
    _pack_u32(bin_data, 4, 0)
    _pack_u32(bin_data, 8, BASE_BLOCK_SIZE)
    struct.pack_into("<Q", bin_data, 20, TIMESTAMP)

    position = 32
    root_cell = position
    root_payload = _key_node(
        flags=0x0004 | 0x0020,
        parent=0xFFFFFFFF,
        subkey_count=2,
        subkey_list=0,
        value_count=1,
        value_list=0,
        name="ROOT",
    )
    position += _put_cell(bin_data, position, root_payload)

    lf_cell = position
    lf_payload = bytearray(4 + 2 * 8)
    lf_payload[0:2] = b"lf"
    struct.pack_into("<H", lf_payload, 2, 2)
    lf_payload[4 + 4 : 4 + 8] = b"Alph"
    lf_payload[4 + 12 : 4 + 16] = b"Beta"
    position += _put_cell(bin_data, position, bytes(lf_payload))
    lf_entries_absolute = BASE_BLOCK_SIZE + lf_cell + 4 + 4

    alpha_cell = position
    alpha_payload = _key_node(
        flags=0x0020,
        parent=root_cell,
        subkey_count=0,
        subkey_list=0xFFFFFFFF,
        value_count=0,
        value_list=0,
        name="Alpha",
    )
    position += _put_cell(bin_data, position, alpha_payload)

    beta_cell = position
    beta_payload = _key_node(
        flags=0x0020,
        parent=root_cell,
        subkey_count=0,
        subkey_list=0xFFFFFFFF,
        value_count=0,
        value_list=0,
        name="Beta",
    )
    position += _put_cell(bin_data, position, beta_payload)

    value_list_cell = position
    value_list_payload = bytearray(4)
    position += _put_cell(bin_data, position, bytes(value_list_payload))

    value_cell = position
    value_payload = bytearray(20 + len(b"RootV"))
    value_payload[0:2] = b"vk"
    struct.pack_into("<H", value_payload, 2, len(b"RootV"))
    _pack_u32(value_payload, 4, 16)
    _pack_u32(value_payload, 8, 0)
    _pack_u32(value_payload, 12, 3)
    struct.pack_into("<H", value_payload, 16, 0x0001)
    struct.pack_into("<H", value_payload, 18, 0)
    value_payload[20:] = b"RootV"
    position += _put_cell(bin_data, position, bytes(value_payload))

    data_cell = position
    position += _put_cell(bin_data, position, b"ORIGINAL--------")

    free_size = BASE_BLOCK_SIZE - position
    _pack_u32(bin_data, position, free_size)

    root_data = root_cell + 4
    _pack_u32(bin_data, root_data + 28, lf_cell)
    _pack_u32(bin_data, root_data + 40, value_list_cell)
    _pack_u32(bin_data, lf_cell + 4 + 4, alpha_cell)
    _pack_u32(bin_data, lf_cell + 4 + 12, beta_cell)
    _pack_u32(bin_data, value_list_cell + 4, value_cell)
    _pack_u32(bin_data, value_cell + 4 + 8, data_cell)

    base = _build_base_block(
        BASE_BLOCK_SIZE,
        root_cell,
        sequence1=DIRTY_SEQUENCE,
        sequence2=DIRTY_SECONDARY,
    )
    data = base + bytes(bin_data)
    return HiveLayout(
        data=data,
        root_cell=root_cell,
        lf_cell=lf_cell,
        lf_entries_absolute=lf_entries_absolute,
        value_data_absolute=BASE_BLOCK_SIZE + data_cell + 4,
    )


def _log_base(hive: HiveLayout, sequence: int, *, file_type: int = 6) -> bytes:
    block = bytearray(hive.data[:SECTOR_SIZE])
    _pack_u32(block, 4, sequence)
    _pack_u32(block, 8, sequence)
    _pack_u32(block, 28, file_type)
    _pack_u32(block, 508, base_block_checksum(block))
    return bytes(block)


def _entry(sequence: int, page_offset: int, page_data: bytes) -> bytes:
    page_size = len(page_data)
    references = struct.pack("<II", page_offset, page_size)
    payload = references + page_data
    size = _align(HVLE_HEADER_SIZE + len(payload), SECTOR_SIZE)
    entry = bytearray(size)
    entry[0:4] = b"HvLE"
    _pack_u32(entry, 4, size)
    _pack_u32(entry, 8, 0)
    _pack_u32(entry, 12, sequence)
    _pack_u32(entry, 16, BASE_BLOCK_SIZE)
    _pack_u32(entry, 20, 1)
    entry[HVLE_HEADER_SIZE : HVLE_HEADER_SIZE + len(payload)] = payload
    _pack_u64(entry, 24, marvin32(MARVIN32_SEED, entry[HVLE_HEADER_SIZE:size]))
    _pack_u64(entry, 32, marvin32(MARVIN32_SEED, entry[:32]))
    return bytes(entry)


def _pack_u64(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", buffer, offset, value)


def _page(hive: HiveLayout, generation: str) -> tuple[int, bytes]:
    page_offset = (hive.value_data_absolute - BASE_BLOCK_SIZE) & ~(SECTOR_SIZE - 1)
    page_start = BASE_BLOCK_SIZE + page_offset
    page = bytearray(hive.data[page_start : page_start + SECTOR_SIZE])
    value_in_page = hive.value_data_absolute - page_start
    marker = (generation.encode("ascii") + b"." * 16)[:16]
    page[value_in_page : value_in_page + 16] = marker
    return page_offset, bytes(page)


def _cycle_page(hive: HiveLayout) -> tuple[int, bytes]:
    page_offset = (hive.lf_entries_absolute - BASE_BLOCK_SIZE) & ~(SECTOR_SIZE - 1)
    page_start = BASE_BLOCK_SIZE + page_offset
    page = bytearray(hive.data[page_start : page_start + SECTOR_SIZE])
    first_entry_in_page = hive.lf_entries_absolute - page_start
    _pack_u32(page, first_entry_in_page, hive.root_cell)
    return page_offset, bytes(page)


def _write_case(name: str, hive: HiveLayout, logs: dict[str, bytes]) -> None:
    case = ROOT / name
    case.mkdir(parents=True, exist_ok=True)
    (case / FILE_NAME).write_bytes(hive.data)
    for suffix, data in logs.items():
        (case / f"{FILE_NAME}.{suffix}").write_bytes(data)


def generate() -> dict[str, object]:
    hive = build_hive()
    page_offset_12, page_12 = _page(hive, "GEN12")
    page_offset_13, page_13 = _page(hive, "GEN13")
    page_offset_14, page_14 = _page(hive, "GEN14")

    log1_12 = _entry(12, page_offset_12, page_12)
    log1_14 = _entry(14, page_offset_14, page_14)
    log2_13 = _entry(13, page_offset_13, page_13)

    _write_case(
        "minimal",
        hive,
        {
            "LOG1": _log_base(hive, 12) + log1_12 + log1_14,
            "LOG2": _log_base(hive, 13) + log2_13,
        },
    )
    _write_case(
        "trailing",
        hive,
        {
            "LOG1": _log_base(hive, 12) + log1_12 + log1_14 + b"\xde\xad\xbe\xefTRAILER",
            "LOG2": _log_base(hive, 13) + log2_13,
        },
    )
    _write_case(
        "truncated",
        hive,
        {
            "LOG1": (_log_base(hive, 12) + log1_12 + log2_13)[:-128],
        },
    )
    _write_case(
        "conflict",
        hive,
        {
            "LOG1": _log_base(hive, 12) + log1_12 + _entry(13, page_offset_13, page_13),
            "LOG2": _log_base(hive, 13) + _entry(13, page_offset_13, page_14),
        },
    )
    _write_case(
        "missing",
        hive,
        {
            "LOG1": _log_base(hive, 13) + log2_13,
        },
    )
    _write_case(
        "old",
        hive,
        {
            "LOG1": _log_base(hive, 12, file_type=2) + b"DIRT" + b"\x00" * 508,
            "LOG2": _log_base(hive, 12, file_type=2) + log1_12,
        },
    )
    cycle_offset, cycle_page = _cycle_page(hive)
    _write_case(
        "cycle",
        hive,
        {
            "LOG1": _log_base(hive, 12) + _entry(12, cycle_offset, cycle_page),
        },
    )

    files: dict[str, object] = {}
    for path in sorted(ROOT.glob("*/*")):
        if path.is_file():
            files[path.relative_to(ROOT).as_posix()] = {
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

    manifest = {
        "provenance": {
            "kind": "synthetic",
            "note": "Generated by build_fixtures.py; no live system registry data was read or mounted.",
            "format_source": (
                "Maxim Suhanov, Windows registry file format specification, "
                "'Format of transaction log files' / 'New format'"
            ),
            "hash_source": "HvLE Hash-1/Hash-2: Marvin32 with seed 82 EF 4D 88 7A 4E 55 C5",
        },
        "dirty_sequence": {"primary": DIRTY_SEQUENCE, "secondary": DIRTY_SECONDARY},
        "layout": {
            "base_block_size": BASE_BLOCK_SIZE,
            "root_cell": hive.root_cell,
            "lf_cell": hive.lf_cell,
            "lf_entries_absolute": hive.lf_entries_absolute,
            "value_data_absolute": hive.value_data_absolute,
            "dirty_page_offset": page_offset_12,
            "dirty_page_size": SECTOR_SIZE,
        },
        "cases": {
            "minimal": "LOG2 is passed before LOG1; entries recover 12, 13, 14 in sequence order.",
            "trailing": "LOG1 has a corrupt tail after the last valid entry.",
            "truncated": "The entry for sequence 13 is cut short; only sequence 12 is complete.",
            "conflict": "Sequence 13 appears in both logs with different page content.",
            "missing": "The earliest available entry is 13 while the hive needs 12.",
            "old": "Base block file type 2 with a DIRT vector; old format is unsupported.",
            "cycle": "Recovered lf index points back to the root key node.",
        },
        "files": files,
    }
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    manifest = generate()
    print(f"generated {len(manifest['files'])} files under {ROOT}")
