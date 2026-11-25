from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from dissect.regf.hive_format import (
    BASE_BLOCK_SIZE,
    HBIN_SIGNATURE,
    BaseBlock,
    i32,
    parse_base_block,
    u16,
    u32,
)

MAX_REFERENCE_DEPTH = 1024
KEY_SIGNATURE = b"nk"
INDEX_SIGNATURES = (b"ri", b"li", b"lf", b"lh")
VALUE_SIGNATURE = b"vk"
SECURITY_SIGNATURE = b"sk"
BIG_DATA_SIGNATURE = b"db"

KEY_HIVE_ENTRY = 0x0004
KEY_COMP_NAME = 0x0020
VALUE_BIG_DATA_THRESHOLD = 0x3FD8
CM_KEY_VALUE_BIG = 16344


@dataclass(frozen=True)
class ByteRange:
    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict[str, int]:
        return {"start": self.start, "end": self.end, "length": self.length}


@dataclass(frozen=True)
class StructureIssue:
    code: str
    message: str
    offset: int | None = None
    cell_offset: int | None = None

    def to_dict(self) -> dict[str, int | str | None]:
        return {
            "code": self.code,
            "message": self.message,
            "offset": self.offset,
            "cell_offset": self.cell_offset,
        }


@dataclass(frozen=True)
class CellCycle:
    path: tuple[int, ...]
    message: str

    def to_dict(self) -> dict[str, object]:
        return {"path": list(self.path), "message": self.message}


@dataclass
class StructureReport:
    header_valid: bool
    header_checksum_valid: bool
    sequence_consistent: bool
    hive_bins_data_size: int | None
    hbin_count: int
    cell_count: int
    allocated_cells: int
    free_cells: int
    cell_type_counts: dict[str, int]
    root_cell: int | None
    root_valid: bool
    reachable_keys: int
    trustworthy: bool
    errors: list[StructureIssue] = field(default_factory=list)
    warnings: list[StructureIssue] = field(default_factory=list)
    cycles: list[CellCycle] = field(default_factory=list)
    safe_ranges: list[ByteRange] = field(default_factory=list)
    reachable_ranges: list[ByteRange] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "header_valid": self.header_valid,
            "header_checksum_valid": self.header_checksum_valid,
            "sequence_consistent": self.sequence_consistent,
            "hive_bins_data_size": self.hive_bins_data_size,
            "hbin_count": self.hbin_count,
            "cell_count": self.cell_count,
            "allocated_cells": self.allocated_cells,
            "free_cells": self.free_cells,
            "cell_type_counts": dict(self.cell_type_counts),
            "root_cell": self.root_cell,
            "root_valid": self.root_valid,
            "reachable_keys": self.reachable_keys,
            "trustworthy": self.trustworthy,
            "errors": [issue.to_dict() for issue in self.errors],
            "warnings": [issue.to_dict() for issue in self.warnings],
            "cycles": [cycle.to_dict() for cycle in self.cycles],
            "safe_ranges": [span.to_dict() for span in self.safe_ranges],
            "reachable_ranges": [span.to_dict() for span in self.reachable_ranges],
        }


@dataclass(frozen=True)
class _CellInfo:
    offset: int
    file_offset: int
    size: int
    allocated: bool
    signature: bytes
    data_start: int
    data_end: int

    @property
    def data_length(self) -> int:
        return self.data_end - self.data_start


def merge_ranges(ranges: list[ByteRange]) -> list[ByteRange]:
    if not ranges:
        return []

    ordered = sorted(ranges, key=lambda item: (item.start, item.end))
    merged = [ordered[0]]
    for item in ordered[1:]:
        previous = merged[-1]
        if item.start <= previous.end:
            merged[-1] = ByteRange(previous.start, max(previous.end, item.end))
        else:
            merged.append(item)
    return merged


class HiveStructureValidator:
    def __init__(self, data: bytes):
        self.data = data
        self.base: BaseBlock | None = parse_base_block(data)
        self.cells: dict[int, _CellInfo] = {}
        self.errors: list[StructureIssue] = []
        self.warnings: list[StructureIssue] = []
        self.cycles: list[CellCycle] = []
        self.safe_ranges: list[ByteRange] = []
        self.reachable: set[int] = set()
        self.visited_keys: set[int] = set()
        self.visited_indexes: set[int] = set()
        self.reachable_keys = 0
        self.hbin_count = 0
        self.allocated_cells = 0
        self.free_cells = 0
        self.cell_type_counts: Counter[str] = Counter()
        self.root_valid = False
        self.hive_end = 0

    def _error(
        self,
        code: str,
        message: str,
        offset: int | None = None,
        cell_offset: int | None = None,
    ) -> None:
        self.errors.append(StructureIssue(code, message, offset, cell_offset))

    def _warning(
        self,
        code: str,
        message: str,
        offset: int | None = None,
        cell_offset: int | None = None,
    ) -> None:
        self.warnings.append(StructureIssue(code, message, offset, cell_offset))

    def run(self) -> StructureReport:
        base = self.base
        if base is None:
            self._error("short_base_block", "Input is shorter than a 512-byte base block")
            return self._report(False)

        header_valid = base.signature_valid and base.checksum_valid
        if not base.signature_valid:
            self._error("invalid_base_block_signature", f"Expected b'regf', got {base.signature!r}", offset=0)
        if not base.checksum_valid:
            self._error(
                "base_block_checksum_mismatch",
                f"Stored checksum 0x{base.checksum:08x} does not match the base block",
                offset=508,
            )
        if base.major != 1:
            self._error("unsupported_major_version", f"Unsupported hive major version {base.major}", offset=20)
        if base.minor not in (3, 4, 5, 6):
            self._warning("unusual_minor_version", f"Unusual hive minor version {base.minor}", offset=24)
        if base.file_type != 0:
            self._error("not_a_primary_hive", f"Base block file type is {base.file_type}, expected 0", offset=28)
        if base.hive_bins_data_size == 0 or base.hive_bins_data_size % BASE_BLOCK_SIZE:
            self._error(
                "invalid_hive_bins_size",
                f"Hive bins data size {base.hive_bins_data_size} is not a positive multiple of 4096",
                offset=40,
            )

        if header_valid:
            self.safe_ranges.append(ByteRange(0, BASE_BLOCK_SIZE))

        self.hive_end = BASE_BLOCK_SIZE + base.hive_bins_data_size
        if base.hive_bins_data_size and self.hive_end > len(self.data):
            self._error(
                "hive_bins_truncated",
                f"Header declares {base.hive_bins_data_size} bytes of hive bins but only "
                f"{max(0, len(self.data) - BASE_BLOCK_SIZE)} are present",
                offset=40,
            )
            self.hive_end = min(self.hive_end, len(self.data))

        try:
            self._parse_hbins()
            self._validate_root()
        except Exception as exc:
            self._error(
                "structure_validator_exception",
                f"{type(exc).__name__}: {exc}",
            )

        trustworthy = bool(header_valid and self.root_valid and not self.errors and not self.cycles)
        return self._report(trustworthy)

    def _report(self, trustworthy: bool) -> StructureReport:
        base = self.base
        return StructureReport(
            header_valid=bool(base and base.signature_valid and base.checksum_valid),
            header_checksum_valid=bool(base and base.checksum_valid),
            sequence_consistent=bool(base and base.sequence1 == base.sequence2),
            hive_bins_data_size=base.hive_bins_data_size if base else None,
            hbin_count=self.hbin_count,
            cell_count=len(self.cells),
            allocated_cells=self.allocated_cells,
            free_cells=self.free_cells,
            cell_type_counts=dict(sorted(self.cell_type_counts.items())),
            root_cell=base.root_cell if base else None,
            root_valid=self.root_valid,
            reachable_keys=self.reachable_keys,
            trustworthy=trustworthy,
            errors=self.errors,
            warnings=self.warnings,
            cycles=self.cycles,
            safe_ranges=merge_ranges(self.safe_ranges),
            reachable_ranges=merge_ranges(
                [
                    ByteRange(self.cells[offset].file_offset, self.cells[offset].file_offset + self.cells[offset].size)
                    for offset in self.reachable
                    if offset in self.cells
                ]
            ),
        )

    def _parse_hbins(self) -> None:
        position = BASE_BLOCK_SIZE
        expected_bin_offset = 0

        while position < self.hive_end:
            if position + 32 > len(self.data):
                self._error("hbin_header_truncated", "Truncated hive bin header", offset=position)
                break

            signature = bytes(self.data[position : position + 4])
            file_offset = u32(self.data, position + 4)
            size = u32(self.data, position + 8)
            if signature != HBIN_SIGNATURE:
                self._error("invalid_hbin_signature", f"Expected b'hbin', got {signature!r}", offset=position)
                break
            if file_offset != expected_bin_offset:
                self._error(
                    "hbin_offset_mismatch",
                    f"Hive bin at 0x{position:x} declares offset 0x{file_offset:x}, expected 0x{expected_bin_offset:x}",
                    offset=position + 4,
                )
            if size < BASE_BLOCK_SIZE or size % BASE_BLOCK_SIZE:
                self._error(
                    "invalid_hbin_size",
                    f"Hive bin at 0x{position:x} has invalid size {size}",
                    offset=position + 8,
                )
                break
            if position + size > len(self.data):
                self._error(
                    "hbin_out_of_bounds",
                    f"Hive bin at 0x{position:x} extends beyond the input",
                    offset=position + 8,
                )
                break
            if position + size > self.hive_end:
                self._error(
                    "hbin_beyond_declared_size",
                    f"Hive bin at 0x{position:x} extends beyond the declared hive bins data size",
                    offset=position + 8,
                )
                break

            self.hbin_count += 1
            bin_end = position + size
            bin_ok = True
            cell_position = position + 32

            while cell_position < bin_end:
                remaining = bin_end - cell_position
                if remaining < 4:
                    self._warning(
                        "hbin_trailing_slack",
                        f"{remaining} trailing byte(s) at the end of hive bin 0x{position:x}",
                        offset=cell_position,
                    )
                    break

                raw_size = i32(self.data, cell_position)
                if raw_size == 0:
                    self._error("zero_cell_size", "Cell size is zero", offset=cell_position)
                    bin_ok = False
                    break

                cell_size = abs(raw_size)
                if cell_size < 4 or cell_size % 8:
                    self._error(
                        "invalid_cell_size",
                        f"Cell at 0x{cell_position:x} has invalid size {cell_size}",
                        offset=cell_position,
                    )
                    bin_ok = False
                    break
                if cell_position + cell_size > bin_end:
                    self._error(
                        "cell_crosses_hbin",
                        f"Cell at 0x{cell_position:x} crosses the end of hive bin 0x{position:x}",
                        offset=cell_position,
                    )
                    bin_ok = False
                    break

                allocated = raw_size < 0
                data_start = cell_position + 4
                data_end = cell_position + cell_size
                signature = bytes(self.data[data_start : min(data_start + 2, data_end)])
                relative_offset = cell_position - BASE_BLOCK_SIZE
                self.cells[relative_offset] = _CellInfo(
                    offset=relative_offset,
                    file_offset=cell_position,
                    size=cell_size,
                    allocated=allocated,
                    signature=signature,
                    data_start=data_start,
                    data_end=data_end,
                )

                if allocated:
                    self.allocated_cells += 1
                    if signature in (
                        KEY_SIGNATURE,
                        VALUE_SIGNATURE,
                        SECURITY_SIGNATURE,
                        BIG_DATA_SIGNATURE,
                        *INDEX_SIGNATURES,
                    ):
                        self.cell_type_counts[signature.decode("latin1")] += 1
                    else:
                        self.cell_type_counts["data"] += 1
                else:
                    self.free_cells += 1

                cell_position += cell_size

            if cell_position < bin_end:
                bin_ok = False
            if bin_ok:
                self.safe_ranges.append(ByteRange(position, bin_end))

            position = bin_end
            expected_bin_offset += size

        if self.hive_end > len(self.data):
            return
        if position < self.hive_end:
            self._error(
                "hive_bins_incomplete",
                f"Parsed hive bins end at 0x{position:x}, declared data ends at 0x{self.hive_end:x}",
                offset=position,
            )
        elif position > self.hive_end:
            self._error(
                "hive_bins_overrun",
                f"Parsed hive bins end at 0x{position:x}, beyond declared end 0x{self.hive_end:x}",
                offset=position,
            )

    def _validate_root(self) -> None:
        base = self.base
        if base is None:
            return
        if base.root_cell == 0xFFFFFFFF:
            self._error("root_cell_missing", "RootCell is 0xffffffff")
            return

        root = self.cells.get(base.root_cell)
        if root is None:
            self._error("root_cell_invalid", f"Root cell 0x{base.root_cell:x} is outside parsed cells")
            return
        if not root.allocated:
            self._error("root_cell_free", f"Root cell 0x{base.root_cell:x} is unallocated")
            return
        if root.signature != KEY_SIGNATURE or root.data_length < 76:
            self._error(
                "root_cell_not_key",
                f"Root cell 0x{base.root_cell:x} has signature {root.signature!r}",
                cell_offset=base.root_cell,
            )
            return

        self.root_valid = True
        self._walk_key(base.root_cell, (), set(), 0)

    def _key_name(self, info: _CellInfo) -> str:
        if info.data_length < 76:
            return "?"
        name_length = u16(self.data, info.data_start + 72)
        flags = u16(self.data, info.data_start + 2)
        start = info.data_start + 76
        end = min(start + name_length, info.data_end)
        blob = self.data[start:end]
        try:
            if flags & KEY_COMP_NAME:
                return blob.decode("latin1")
            return blob.decode("utf-16-le")
        except UnicodeDecodeError:
            return f"<0x{info.offset:x}>"

    def _walk_key(self, offset: int, path: tuple[str, ...], visiting: set[int], depth: int) -> None:
        if depth > MAX_REFERENCE_DEPTH:
            self._error("reference_depth_exceeded", "Cell reference depth limit exceeded", cell_offset=offset)
            return
        if offset in visiting:
            cycle_path = tuple(sorted(visiting)) + (offset,)
            self.cycles.append(CellCycle(cycle_path, "Cell reference cycle through a key node"))
            self._error(
                "cell_reference_cycle",
                "Cell reference cycle through key nodes",
                cell_offset=offset,
            )
            return

        info = self.cells.get(offset)
        if info is None:
            self._error("missing_cell_reference", f"Referenced cell 0x{offset:x} does not exist", cell_offset=offset)
            return
        if not info.allocated:
            self._error("reference_to_free_cell", f"Referenced cell 0x{offset:x} is unallocated", cell_offset=offset)
            return
        if info.signature != KEY_SIGNATURE or info.data_length < 76:
            self._error(
                "key_signature_mismatch",
                f"Referenced cell 0x{offset:x} is not a valid nk cell",
                cell_offset=offset,
            )
            return
        if offset in self.visited_keys:
            self._warning(
                "key_referenced_twice",
                f"Key cell 0x{offset:x} is reachable more than once",
                cell_offset=offset,
            )
            return

        self.visited_keys.add(offset)
        self.reachable.add(offset)
        self.reachable_keys += 1
        visiting.add(offset)
        try:
            data_start = info.data_start
            flags = u16(self.data, data_start + 2)
            name = self._key_name(info)
            key_path = path + (name,)

            parent = u32(self.data, data_start + 16)
            if not flags & KEY_HIVE_ENTRY:
                if parent == 0xFFFFFFFF:
                    self._error(
                        "key_missing_parent",
                        f"Non-root key 0x{offset:x} has no parent",
                        cell_offset=offset,
                    )
                else:
                    parent_info = self.cells.get(parent)
                    if parent_info is None or not parent_info.allocated or parent_info.signature != KEY_SIGNATURE:
                        self._error(
                            "invalid_parent_reference",
                            f"Key 0x{offset:x} has invalid parent 0x{parent:x}",
                            cell_offset=offset,
                        )
                    elif parent == offset:
                        self._error(
                            "parent_reference_cycle",
                            f"Key 0x{offset:x} is its own parent",
                            cell_offset=offset,
                        )

            subkey_count = u32(self.data, data_start + 20)
            subkey_list = u32(self.data, data_start + 28)
            if subkey_count:
                if subkey_list in (0, 0xFFFFFFFF):
                    self._error(
                        "missing_subkey_index",
                        f"Key 0x{offset:x} declares {subkey_count} subkey(s) but has no index",
                        cell_offset=offset,
                    )
                else:
                    self._walk_index(subkey_list, key_path, visiting, depth + 1)
            elif subkey_list not in (0, 0xFFFFFFFF):
                self._warning(
                    "stale_subkey_index",
                    f"Key 0x{offset:x} has an index but no stable subkeys",
                    cell_offset=offset,
                )

            value_count = u32(self.data, data_start + 36)
            value_list = u32(self.data, data_start + 40)
            if value_count:
                self._walk_value_list(value_list, value_count, key_path, offset)
            elif value_list not in (0, 0xFFFFFFFF):
                self._warning(
                    "stale_value_list",
                    f"Key 0x{offset:x} has a value list but no values",
                    cell_offset=offset,
                )

            security = u32(self.data, data_start + 44)
            if security != 0xFFFFFFFF:
                security_info = self.cells.get(security)
                if (
                    security_info is None
                    or not security_info.allocated
                    or security_info.signature != SECURITY_SIGNATURE
                ):
                    self._error(
                        "invalid_security_reference",
                        f"Key 0x{offset:x} has invalid security cell 0x{security:x}",
                        cell_offset=offset,
                    )
                else:
                    self.reachable.add(security)

            class_cell = u32(self.data, data_start + 48)
            class_length = u16(self.data, data_start + 74)
            if class_cell != 0xFFFFFFFF:
                class_info = self.cells.get(class_cell)
                if class_info is None or not class_info.allocated:
                    self._error(
                        "invalid_class_reference",
                        f"Key 0x{offset:x} has invalid class cell 0x{class_cell:x}",
                        cell_offset=offset,
                    )
                elif class_info.size - 4 < class_length:
                    self._error(
                        "class_data_short",
                        f"Class cell 0x{class_cell:x} is shorter than the declared class length",
                        cell_offset=offset,
                    )
                else:
                    self.reachable.add(class_cell)
        finally:
            visiting.discard(offset)

    def _walk_value_list(
        self,
        list_offset: int,
        value_count: int,
        key_path: tuple[str, ...],
        key_offset: int,
    ) -> None:
        info = self.cells.get(list_offset)
        if info is None or not info.allocated:
            self._error(
                "invalid_value_list",
                f"Key 0x{key_offset:x} has invalid value list 0x{list_offset:x}",
                cell_offset=key_offset,
            )
            return
        self.reachable.add(list_offset)

        capacity = info.data_length // 4
        if capacity < value_count:
            self._error(
                "value_list_short",
                f"Value list 0x{list_offset:x} holds {capacity} entries, key declares {value_count}",
                cell_offset=key_offset,
            )
            value_count = capacity

        for index in range(value_count):
            value_offset = u32(self.data, info.data_start + index * 4)
            if value_offset == 0xFFFFFFFF:
                self._error(
                    "invalid_value_reference",
                    f"Value list 0x{list_offset:x} contains a null reference",
                    cell_offset=key_offset,
                )
                continue
            self._walk_value(value_offset, key_path)

    def _walk_value(self, offset: int, key_path: tuple[str, ...]) -> None:
        info = self.cells.get(offset)
        if info is None or not info.allocated:
            self._error("invalid_value_cell", f"Value cell 0x{offset:x} is missing or free", cell_offset=offset)
            return
        if info.signature != VALUE_SIGNATURE or info.data_length < 20:
            self._error(
                "value_signature_mismatch",
                f"Referenced cell 0x{offset:x} is not a valid vk cell",
                cell_offset=offset,
            )
            return

        self.reachable.add(offset)
        data_start = info.data_start
        name_length = u16(self.data, data_start + 2)
        data_length = u32(self.data, data_start + 4)
        data_offset = u32(self.data, data_start + 8)

        if 20 + name_length > info.data_length:
            self._error(
                "value_name_short",
                f"Value cell 0x{offset:x} name is longer than the cell",
                cell_offset=offset,
            )

        size = data_length & 0x7FFFFFFF
        inline = bool(data_length & 0x80000000)
        if inline or size == 0:
            return

        base = self.base
        if base is not None and base.minor > 4 and size > VALUE_BIG_DATA_THRESHOLD:
            self._walk_big_value(offset, data_offset, size)
            return

        data_info = self.cells.get(data_offset)
        if data_info is None or not data_info.allocated:
            self._error(
                "invalid_value_data_reference",
                f"Value cell 0x{offset:x} points at missing/free data cell 0x{data_offset:x}",
                cell_offset=offset,
            )
            return
        if data_info.size - 4 < size:
            self._error(
                "value_data_short",
                f"Value data cell 0x{data_offset:x} is shorter than the declared {size} bytes",
                cell_offset=offset,
            )
        if data_offset == offset:
            self._error(
                "value_data_cycle",
                f"Value cell 0x{offset:x} points at itself for data",
                cell_offset=offset,
            )
        self.reachable.add(data_offset)

    def _walk_big_value(self, value_offset: int, big_data_offset: int, size: int) -> None:
        info = self.cells.get(big_data_offset)
        if info is None or not info.allocated or info.signature != BIG_DATA_SIGNATURE or info.data_length < 8:
            self._error(
                "invalid_big_data",
                f"Value cell 0x{value_offset:x} points at invalid big-data cell 0x{big_data_offset:x}",
                cell_offset=value_offset,
            )
            return
        if big_data_offset == value_offset:
            self._error(
                "big_data_cycle",
                f"Value cell 0x{value_offset:x} points at itself as big data",
                cell_offset=value_offset,
            )
            return
        self.reachable.add(big_data_offset)

        segment_count = u16(self.data, info.data_start + 2)
        segment_list = u32(self.data, info.data_start + 4)
        list_info = self.cells.get(segment_list)
        if list_info is None or not list_info.allocated:
            self._error(
                "invalid_big_data_list",
                f"Big-data cell 0x{big_data_offset:x} has invalid segment list 0x{segment_list:x}",
                cell_offset=value_offset,
            )
            return
        self.reachable.add(segment_list)

        capacity = list_info.data_length // 4
        if capacity < segment_count:
            self._error(
                "big_data_list_short",
                f"Big-data list 0x{segment_list:x} holds {capacity} entries, declares {segment_count}",
                cell_offset=value_offset,
            )
            segment_count = capacity

        remaining = size
        for index in range(segment_count):
            segment_offset = u32(self.data, list_info.data_start + index * 4)
            segment_info = self.cells.get(segment_offset)
            expected = min(CM_KEY_VALUE_BIG, remaining)
            if segment_info is None or not segment_info.allocated:
                self._error(
                    "invalid_big_data_segment",
                    f"Big-data segment 0x{segment_offset:x} is missing or free",
                    cell_offset=value_offset,
                )
            elif segment_info.size - 4 < expected:
                self._error(
                    "big_data_segment_short",
                    f"Big-data segment 0x{segment_offset:x} is shorter than {expected} bytes",
                    cell_offset=value_offset,
                )
            else:
                self.reachable.add(segment_offset)
            remaining = max(0, remaining - CM_KEY_VALUE_BIG)

        if remaining:
            self._error(
                "big_data_incomplete",
                f"Big-data segments leave {remaining} byte(s) unaccounted for",
                cell_offset=value_offset,
            )

    def _walk_index(self, offset: int, path: tuple[str, ...], visiting: set[int], depth: int) -> None:
        if depth > MAX_REFERENCE_DEPTH:
            self._error("reference_depth_exceeded", "Cell reference depth limit exceeded", cell_offset=offset)
            return
        if offset in visiting:
            self.cycles.append(
                CellCycle(tuple(sorted(visiting)) + (offset,), "Cell reference cycle through an index")
            )
            self._error(
                "cell_reference_cycle",
                "Cell reference cycle through an index",
                cell_offset=offset,
            )
            return
        if offset in self.visited_indexes:
            self._warning(
                "index_referenced_twice",
                f"Index cell 0x{offset:x} is reachable more than once",
                cell_offset=offset,
            )
            return

        info = self.cells.get(offset)
        if info is None or not info.allocated:
            self._error("invalid_index_reference", f"Index cell 0x{offset:x} is missing or free", cell_offset=offset)
            return
        if info.signature not in INDEX_SIGNATURES or info.data_length < 4:
            self._error(
                "index_signature_mismatch",
                f"Referenced cell 0x{offset:x} is not a valid index",
                cell_offset=offset,
            )
            return

        self.visited_indexes.add(offset)
        self.reachable.add(offset)
        visiting.add(offset)
        try:
            count = u16(self.data, info.data_start + 2)
            if info.signature == b"ri":
                capacity = max(0, (info.data_length - 4) // 4)
                if capacity < count:
                    self._error(
                        "index_short",
                        f"Index root 0x{offset:x} holds {capacity} entries, declares {count}",
                        cell_offset=offset,
                    )
                    count = capacity
                for index in range(count):
                    child = u32(self.data, info.data_start + 4 + index * 4)
                    child_info = self.cells.get(child)
                    if child_info is None or not child_info.allocated:
                        self._error(
                            "invalid_index_reference",
                            f"Index root 0x{offset:x} references missing/free cell 0x{child:x}",
                            cell_offset=offset,
                        )
                        continue
                    if child_info.signature == b"ri":
                        self._error(
                            "index_root_points_to_index_root",
                            f"Index root 0x{offset:x} references another index root 0x{child:x}",
                            cell_offset=offset,
                        )
                        continue
                    if child_info.signature not in (b"li", b"lf", b"lh"):
                        self._error(
                            "invalid_subkey_index",
                            f"Index root 0x{offset:x} references non-index cell 0x{child:x}",
                            cell_offset=offset,
                        )
                        continue
                    self._walk_index(child, path, visiting, depth + 1)
            else:
                unit = 8 if info.signature in (b"lf", b"lh") else 4
                capacity = max(0, (info.data_length - 4) // unit)
                if capacity < count:
                    self._error(
                        "index_short",
                        f"Index 0x{offset:x} holds {capacity} entries, declares {count}",
                        cell_offset=offset,
                    )
                    count = capacity
                for index in range(count):
                    child = u32(self.data, info.data_start + 4 + index * unit)
                    self._walk_key(child, path, visiting, depth + 1)
        finally:
            visiting.discard(offset)


def validate_hive_structure(data: bytes) -> StructureReport:
    return HiveStructureValidator(data).run()
