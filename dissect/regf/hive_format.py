from __future__ import annotations

import struct
from dataclasses import dataclass

SECTOR_SIZE = 512
BASE_BLOCK_SIZE = 4096
LOG_HEADER_SIZE = 512
HVLE_HEADER_SIZE = 40

FILE_TYPE_PRIMARY = 0
FILE_TYPE_OLD_LOG = (1, 2)
FILE_TYPE_NEW_LOG = 6

HVLE_SIGNATURE = b"HvLE"
DIRT_SIGNATURE = b"DIRT"
REGF_SIGNATURE = b"regf"
HBIN_SIGNATURE = b"hbin"

# Seed used by Windows for HvLE Hash-1 and Hash-2. See MSuhanov's registry file
# format specification, "Format of transaction log files", new format.
MARVIN32_SEED = 0x82EF4D887A4E55C5


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _marvin_block(p0: int, p1: int) -> tuple[int, int]:
    p1 ^= p0
    p0 = ((p0 << 20) | (p0 >> 12)) & 0xFFFFFFFF
    p0 = (p0 + p1) & 0xFFFFFFFF
    p1 = ((p1 << 9) | (p1 >> 23)) & 0xFFFFFFFF
    p1 ^= p0
    p0 = ((p0 << 27) | (p0 >> 5)) & 0xFFFFFFFF
    p0 = (p0 + p1) & 0xFFFFFFFF
    p1 = ((p1 << 19) | (p1 >> 13)) & 0xFFFFFFFF
    return p0, p1


def marvin32(seed: int, data: bytes) -> int:
    """Return the 64-bit Marvin state Windows stores in an HvLE hash field."""
    p0 = seed & 0xFFFFFFFF
    p1 = (seed >> 32) & 0xFFFFFFFF

    full = len(data) & ~3
    for offset in range(0, full, 4):
        p0 = (p0 + u32(data, offset)) & 0xFFFFFFFF
        p0, p1 = _marvin_block(p0, p1)

    remainder = data[full:]
    if not remainder:
        final = 0x80
    elif len(remainder) == 1:
        final = 0x8000 | remainder[0]
    elif len(remainder) == 2:
        final = 0x800000 | remainder[0] | (remainder[1] << 8)
    else:
        final = 0x80000000 | remainder[0] | (remainder[1] << 8) | (remainder[2] << 16)

    p0 = (p0 + final) & 0xFFFFFFFF
    p0, p1 = _marvin_block(p0, p1)
    p0, p1 = _marvin_block(p0, p1)
    return ((p1 << 32) | p0) & 0xFFFFFFFFFFFFFFFF


def base_block_checksum(data: bytes) -> int:
    """Calculate the XOR-32 checksum over the first 508 bytes of a base block."""
    checksum = 0
    for offset in range(0, 508, 4):
        checksum ^= u32(data, offset)

    if checksum == 0xFFFFFFFF:
        checksum = 0xFFFFFFFE
    elif checksum == 0:
        checksum = 1
    return checksum


@dataclass(frozen=True)
class BaseBlock:
    raw: bytes
    signature: bytes
    sequence1: int
    sequence2: int
    timestamp: int
    major: int
    minor: int
    file_type: int
    root_cell: int
    hive_bins_data_size: int
    file_name: str
    checksum: int
    checksum_valid: bool
    flags: int

    @property
    def signature_valid(self) -> bool:
        return self.signature == REGF_SIGNATURE

    @property
    def dirty(self) -> bool:
        return not self.checksum_valid or self.sequence1 != self.sequence2


def parse_base_block(data: bytes) -> BaseBlock | None:
    if len(data) < SECTOR_SIZE:
        return None

    raw = bytes(data[:SECTOR_SIZE])
    file_name_raw = raw[48:112]
    try:
        file_name = file_name_raw.decode("utf-16-le", "replace").rstrip("\x00")
    except UnicodeDecodeError:
        file_name = ""

    checksum = u32(raw, 508)
    return BaseBlock(
        raw=raw,
        signature=raw[:4],
        sequence1=u32(raw, 4),
        sequence2=u32(raw, 8),
        timestamp=u64(raw, 12),
        major=u32(raw, 20),
        minor=u32(raw, 24),
        file_type=u32(raw, 28),
        root_cell=u32(raw, 36),
        hive_bins_data_size=u32(raw, 40),
        file_name=file_name,
        checksum=checksum,
        checksum_valid=checksum == base_block_checksum(raw),
        flags=u32(raw, 144) if len(raw) >= 148 else 0,
    )
