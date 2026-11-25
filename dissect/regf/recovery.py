from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import BinaryIO, Iterable, Sequence

from dissect.regf.hive_format import (
    BASE_BLOCK_SIZE,
    FILE_TYPE_NEW_LOG,
    FILE_TYPE_OLD_LOG,
    HVLE_HEADER_SIZE,
    HVLE_SIGNATURE,
    LOG_HEADER_SIZE,
    MARVIN32_SEED,
    SECTOR_SIZE,
    BaseBlock,
    base_block_checksum,
    marvin32,
    parse_base_block,
    u32,
    u64,
)
from dissect.regf.regf import RegistryHive
from dissect.regf.structure import StructureReport, validate_hive_structure


class RecoveryStatus(str, Enum):
    CLEAN = "clean"
    RECOVERED = "recovered"
    RECOVERED_PARTIAL = "recovered_partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


@dataclass
class Evidence:
    name: str
    fh: BinaryIO


@dataclass(frozen=True)
class DirtyPageSummary:
    offset: int
    size: int
    sha256: str

    def to_dict(self) -> dict[str, int | str]:
        return {"offset": self.offset, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class HvleEntrySummary:
    log: str
    file_offset: int
    size: int
    flags: int
    sequence: int
    hive_bins_data_size: int
    dirty_pages_count: int
    pages: tuple[DirtyPageSummary, ...]
    hash1: int
    hash2: int
    fingerprint: str
    applied: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "log": self.log,
            "file_offset": self.file_offset,
            "size": self.size,
            "flags": self.flags,
            "sequence": self.sequence,
            "hive_bins_data_size": self.hive_bins_data_size,
            "dirty_pages_count": self.dirty_pages_count,
            "pages": [page.to_dict() for page in self.pages],
            "hash1": self.hash1,
            "hash2": self.hash2,
            "fingerprint": self.fingerprint,
            "applied": self.applied,
        }


@dataclass
class LogSummary:
    name: str
    format: str
    supported: bool
    reason: str | None = None
    base_block: dict[str, object] | None = None
    paired: bool | None = None
    pairing_notes: list[str] = field(default_factory=list)
    entries: list[HvleEntrySummary] = field(default_factory=list)
    rejected_entries: int = 0
    truncated: str | None = None
    trailing_corruption: str | None = None
    zero_padding: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def first_sequence(self) -> int | None:
        return self.entries[0].sequence if self.entries else None

    @property
    def last_sequence(self) -> int | None:
        return self.entries[-1].sequence if self.entries else None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "format": self.format,
            "supported": self.supported,
            "reason": self.reason,
            "base_block": self.base_block,
            "paired": self.paired,
            "pairing_notes": self.pairing_notes,
            "entries": [entry.to_dict() for entry in self.entries],
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "rejected_entries": self.rejected_entries,
            "truncated": self.truncated,
            "trailing_corruption": self.trailing_corruption,
            "zero_padding": self.zero_padding,
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass(frozen=True)
class InputIntegrity:
    name: str
    role: str
    size: int | None
    sha256_before: str | None
    sha256_after: str | None
    unchanged: bool | None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "role": self.role,
            "size": self.size,
            "sha256_before": self.sha256_before,
            "sha256_after": self.sha256_after,
            "unchanged": self.unchanged,
            "error": self.error,
        }


@dataclass(frozen=True)
class ProvenanceSpan:
    start: int
    end: int
    source: str
    log: str | None = None
    sequence: int | None = None
    detail: str | None = None

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict[str, object]:
        return {
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "source": self.source,
            "log": self.log,
            "sequence": self.sequence,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class OverlapSummary:
    start: int
    end: int
    incoming: str
    previous: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "start": self.start,
            "end": self.end,
            "incoming": self.incoming,
            "previous": list(self.previous),
        }


@dataclass
class RecoveryReport:
    status: RecoveryStatus
    reason: str | None
    hive: dict[str, object] | None
    logs: list[LogSummary]
    selected_chain: list[HvleEntrySummary]
    expected_start_sequence: int | None
    selected_start_sequence: int | None
    selected_end_sequence: int | None
    continuous: bool
    missing_sequence: int | None
    duplicate_conflicts: list[str]
    overlaps: list[OverlapSummary]
    warnings: list[str]
    errors: list[str]
    inputs: list[InputIntegrity]
    provenance: list[ProvenanceSpan]
    structure: StructureReport | None
    recovered_sha256: str | None
    header_recovered_from_log: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "hive": self.hive,
            "logs": [log.to_dict() for log in self.logs],
            "selected_chain": [entry.to_dict() for entry in self.selected_chain],
            "expected_start_sequence": self.expected_start_sequence,
            "selected_start_sequence": self.selected_start_sequence,
            "selected_end_sequence": self.selected_end_sequence,
            "continuous": self.continuous,
            "missing_sequence": self.missing_sequence,
            "duplicate_conflicts": self.duplicate_conflicts,
            "overlaps": [overlap.to_dict() for overlap in self.overlaps],
            "warnings": self.warnings,
            "errors": self.errors,
            "inputs": [item.to_dict() for item in self.inputs],
            "provenance": [span.to_dict() for span in self.provenance],
            "structure": self.structure.to_dict() if self.structure else None,
            "recovered_sha256": self.recovered_sha256,
            "header_recovered_from_log": self.header_recovered_from_log,
        }


@dataclass
class RecoveredHive:
    data: bytes
    hive: RegistryHive | None

    @classmethod
    def from_bytes(cls, data: bytes) -> RecoveredHive:
        try:
            hive = RegistryHive(io.BytesIO(data))
        except Exception:
            hive = None
        return cls(data=data, hive=hive)


@dataclass
class RecoveryResult:
    report: RecoveryReport
    recovered: RecoveredHive | None

    @property
    def status(self) -> RecoveryStatus:
        return self.report.status

    @property
    def recovered_bytes(self) -> bytes | None:
        return self.recovered.data if self.recovered else None

    def to_dict(self) -> dict[str, object]:
        return self.report.to_dict()


@dataclass(frozen=True)
class _DirtyPage:
    offset: int
    size: int
    data: bytes


@dataclass(frozen=True)
class _HvleEntry:
    log: str
    file_offset: int
    size: int
    flags: int
    sequence: int
    hive_bins_data_size: int
    pages: tuple[_DirtyPage, ...]
    hash1: int
    hash2: int
    fingerprint: str

    def summary(self, *, applied: bool = False) -> HvleEntrySummary:
        return HvleEntrySummary(
            log=self.log,
            file_offset=self.file_offset,
            size=self.size,
            flags=self.flags,
            sequence=self.sequence,
            hive_bins_data_size=self.hive_bins_data_size,
            dirty_pages_count=len(self.pages),
            pages=tuple(
                DirtyPageSummary(page.offset, page.size, hashlib.sha256(page.data).hexdigest())
                for page in self.pages
            ),
            hash1=self.hash1,
            hash2=self.hash2,
            fingerprint=self.fingerprint,
            applied=applied,
        )


@dataclass
class _ParsedLog:
    summary: LogSummary
    base: BaseBlock | None
    entries: list[_HvleEntry]


@dataclass
class _Snapshot:
    data: bytes | None
    sha256: str | None
    size: int | None
    error: str | None
    replayable: bool = True


@dataclass
class _ChainSelection:
    status: RecoveryStatus
    reason: str | None
    chain: list[_HvleEntry]
    expected_start_sequence: int | None
    missing_sequence: int | None
    continuous: bool
    duplicate_conflicts: list[str]
    warnings: list[str]
    errors: list[str]
    header_override: bytes | None = None
    header_log: str | None = None


def _snapshot_stream(fh: BinaryIO) -> _Snapshot:
    position: int | None = None
    seekable = True
    try:
        position = fh.tell()
    except Exception:
        position = None

    try:
        try:
            fh.seek(0)
        except Exception:
            seekable = False

        chunks: list[bytes] = []
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            if not isinstance(chunk, (bytes, bytearray, memoryview)):
                return _Snapshot(
                    None,
                    None,
                    None,
                    f"Stream returned {type(chunk).__name__}, expected bytes",
                    seekable,
                )
            chunks.append(bytes(chunk))

        data = b"".join(chunks)
        return _Snapshot(data, hashlib.sha256(data).hexdigest(), len(data), None, seekable)
    except Exception as exc:
        return _Snapshot(None, None, None, f"{type(exc).__name__}: {exc}", seekable)
    finally:
        if position is not None:
            try:
                fh.seek(position)
            except Exception:
                pass


def _coerce_logs(logs: Iterable[BinaryIO | Evidence], names: Sequence[str] | None) -> list[Evidence]:
    result: list[Evidence] = []
    for index, item in enumerate(logs):
        if isinstance(item, Evidence):
            result.append(item)
            continue

        if names is not None and index < len(names):
            name = names[index]
        else:
            name = getattr(item, "name", None)
            if not isinstance(name, str) or not name:
                name = f"LOG{index + 1}"
        result.append(Evidence(name=name, fh=item))
    return result


def _base_summary(base: BaseBlock | None) -> dict[str, object] | None:
    if base is None:
        return None
    return {
        "signature": base.signature.decode("latin1"),
        "sequence1": base.sequence1,
        "sequence2": base.sequence2,
        "timestamp": base.timestamp,
        "major": base.major,
        "minor": base.minor,
        "file_type": base.file_type,
        "root_cell": base.root_cell,
        "hive_bins_data_size": base.hive_bins_data_size,
        "file_name": base.file_name,
        "checksum": base.checksum,
        "checksum_valid": base.checksum_valid,
        "flags": base.flags,
        "dirty": base.dirty,
    }


def _normalize_file_name(name: str) -> str:
    return name.replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()


def _entry_fingerprint(
    sequence: int,
    flags: int,
    hive_bins_data_size: int,
    pages: Sequence[_DirtyPage],
) -> str:
    hasher = hashlib.sha256()
    hasher.update(struct.pack("<III", sequence, flags, hive_bins_data_size))
    for page in pages:
        hasher.update(struct.pack("<II", page.offset, page.size))
        hasher.update(page.data)
    return hasher.hexdigest()


def _parse_hvle_entries(log: _ParsedLog, data: bytes) -> None:
    summary = log.summary
    position = LOG_HEADER_SIZE
    entry_index = 0

    while position < len(data):
        if position + 4 > len(data):
            summary.truncated = f"trailing bytes at 0x{position:x} do not contain a full signature"
            break
        if data[position : position + 4] != HVLE_SIGNATURE:
            trailing = data[position:]
            if trailing and not any(trailing):
                summary.zero_padding = True
                summary.warnings.append(f"zero-filled tail at 0x{position:x}")
            else:
                preview = trailing[:8].hex()
                summary.trailing_corruption = f"non-HvLE data at 0x{position:x} (preview {preview})"
            break
        if position + HVLE_HEADER_SIZE > len(data):
            summary.truncated = f"HvLE header at 0x{position:x} is cut short"
            break

        entry_size = u32(data, position + 4)
        flags = u32(data, position + 8)
        sequence = u32(data, position + 12)
        hive_bins_data_size = u32(data, position + 16)
        dirty_pages_count = u32(data, position + 20)
        stored_hash1 = u64(data, position + 24)
        stored_hash2 = u64(data, position + 32)

        if entry_size < HVLE_HEADER_SIZE or entry_size % SECTOR_SIZE:
            summary.rejected_entries += 1
            summary.errors.append(
                f"entry at 0x{position:x} has invalid size {entry_size} (must be >= 40 and a multiple of 512)"
            )
            break
        if position + entry_size > len(data):
            summary.rejected_entries += 1
            summary.truncated = (
                f"entry at 0x{position:x} declares {entry_size} bytes but only "
                f"{len(data) - position} bytes remain"
            )
            break
        if hive_bins_data_size == 0 or hive_bins_data_size % BASE_BLOCK_SIZE:
            summary.rejected_entries += 1
            summary.errors.append(
                f"entry at 0x{position:x} has invalid hive bins data size {hive_bins_data_size}"
            )
            break

        calculated_hash1 = marvin32(MARVIN32_SEED, data[position + HVLE_HEADER_SIZE : position + entry_size])
        calculated_hash2 = marvin32(MARVIN32_SEED, data[position : position + 32])
        if calculated_hash1 != stored_hash1:
            summary.rejected_entries += 1
            summary.errors.append(
                f"entry at 0x{position:x} failed Hash-1 "
                f"(stored 0x{stored_hash1:016x}, calculated 0x{calculated_hash1:016x})"
            )
            break
        if calculated_hash2 != stored_hash2:
            summary.rejected_entries += 1
            summary.errors.append(
                f"entry at 0x{position:x} failed Hash-2 "
                f"(stored 0x{stored_hash2:016x}, calculated 0x{calculated_hash2:016x})"
            )
            break

        references_end = position + HVLE_HEADER_SIZE + dirty_pages_count * 8
        entry_end = position + entry_size
        if references_end > entry_end:
            summary.rejected_entries += 1
            summary.errors.append(
                f"entry at 0x{position:x} declares {dirty_pages_count} pages but the reference table "
                f"does not fit in the entry"
            )
            break

        pages: list[_DirtyPage] = []
        page_data_offset = references_end
        page_ranges: list[tuple[int, int]] = []
        valid = True
        for page_index in range(dirty_pages_count):
            reference_offset = position + HVLE_HEADER_SIZE + page_index * 8
            page_offset = u32(data, reference_offset)
            page_size = u32(data, reference_offset + 4)
            if page_size == 0:
                summary.errors.append(f"entry at 0x{position:x} has a zero-sized dirty page")
                valid = False
                break
            if page_offset + page_size > hive_bins_data_size:
                summary.errors.append(
                    f"entry at 0x{position:x} page {page_index} range "
                    f"0x{page_offset:x}+0x{page_size:x} exceeds hive bins data size 0x{hive_bins_data_size:x}"
                )
                valid = False
                break
            if page_data_offset + page_size > entry_end:
                summary.errors.append(
                    f"entry at 0x{position:x} page {page_index} data does not fit in the entry"
                )
                valid = False
                break
            for previous_start, previous_end in page_ranges:
                if page_offset < previous_end and page_offset + page_size > previous_start:
                    summary.warnings.append(
                        f"entry at 0x{position:x} has overlapping dirty pages "
                        f"0x{page_offset:x}+0x{page_size:x}"
                    )
                    break
            page_ranges.append((page_offset, page_offset + page_size))
            pages.append(
                _DirtyPage(
                    offset=page_offset,
                    size=page_size,
                    data=bytes(data[page_data_offset : page_data_offset + page_size]),
                )
            )
            page_data_offset += page_size

        if not valid:
            summary.rejected_entries += 1
            break

        if page_data_offset < entry_end and any(data[page_data_offset:entry_end]):
            summary.warnings.append(f"entry at 0x{position:x} has non-zero trailing padding")

        fingerprint = _entry_fingerprint(sequence, flags, hive_bins_data_size, pages)
        log.entries.append(
            _HvleEntry(
                log=summary.name,
                file_offset=position,
                size=entry_size,
                flags=flags,
                sequence=sequence,
                hive_bins_data_size=hive_bins_data_size,
                pages=tuple(pages),
                hash1=stored_hash1,
                hash2=stored_hash2,
                fingerprint=fingerprint,
            )
        )
        entry_index += 1
        position += entry_size

    summary.entries = [entry.summary() for entry in log.entries]
    if log.entries and log.base is not None:
        first = log.entries[0].sequence
        if first != log.base.sequence1:
            summary.warnings.append(
                f"first entry sequence {first} differs from log base block primary sequence {log.base.sequence1}"
            )
        if log.base.sequence1 != log.base.sequence2:
            summary.warnings.append(
                f"log base block sequences differ ({log.base.sequence1} != {log.base.sequence2})"
            )
    if entry_index == 0 and summary.trailing_corruption is None and summary.truncated is None:
        summary.warnings.append("log contains no HvLE entries")


def _parse_log(name: str, data: bytes | None, hive_base: BaseBlock | None, error: str | None) -> _ParsedLog:
    summary = LogSummary(name=name, format="unknown", supported=False)
    if data is None:
        summary.format = "invalid"
        summary.reason = error or "stream could not be read"
        summary.errors.append(summary.reason)
        return _ParsedLog(summary, None, [])

    if len(data) < LOG_HEADER_SIZE:
        summary.format = "invalid"
        summary.reason = f"log is shorter than the {LOG_HEADER_SIZE}-byte base block"
        summary.errors.append(summary.reason)
        return _ParsedLog(summary, None, [])

    base = parse_base_block(data)
    if base is None:
        summary.format = "invalid"
        summary.reason = "log base block could not be parsed"
        summary.errors.append(summary.reason)
        return _ParsedLog(summary, None, [])

    summary.base_block = _base_summary(base)
    if not base.signature_valid:
        summary.format = "invalid"
        summary.reason = f"invalid log signature {base.signature!r}"
        summary.errors.append(summary.reason)
        return _ParsedLog(summary, base, [])

    if base.file_type in FILE_TYPE_OLD_LOG:
        summary.format = "old_dirt"
        summary.reason = "old-format DIRT transaction logs are unsupported"
        summary.errors.append(summary.reason)
        return _ParsedLog(summary, base, [])
    if base.file_type != FILE_TYPE_NEW_LOG:
        summary.format = "unknown"
        summary.reason = f"unsupported log base block file type {base.file_type}"
        summary.errors.append(summary.reason)
        return _ParsedLog(summary, base, [])

    summary.format = "modern_hvle"
    if data[LOG_HEADER_SIZE : LOG_HEADER_SIZE + 4] == b"DIRT":
        summary.reason = "log declares HvLE but its first entry starts with DIRT"
        summary.errors.append(summary.reason)
        return _ParsedLog(summary, base, [])

    paired = True
    if hive_base is None:
        paired = None
        summary.pairing_notes.append("primary hive base block unavailable")
    else:
        if base.major != hive_base.major:
            paired = False
            summary.pairing_notes.append(f"major version mismatch ({base.major} != {hive_base.major})")
        if base.minor != hive_base.minor:
            paired = False
            summary.pairing_notes.append(f"minor version mismatch ({base.minor} != {hive_base.minor})")
        hive_name = _normalize_file_name(hive_base.file_name)
        log_name = _normalize_file_name(base.file_name)
        if hive_name and log_name and hive_name != log_name:
            summary.pairing_notes.append(f"file name mismatch ({base.file_name!r} != {hive_base.file_name!r})")
        if base.timestamp != hive_base.timestamp:
            summary.pairing_notes.append(
                f"last-written timestamp differs (log {base.timestamp}, hive {hive_base.timestamp})"
            )
        if base.hive_bins_data_size != hive_base.hive_bins_data_size:
            summary.pairing_notes.append(
                f"hive bins data size differs (log {base.hive_bins_data_size}, "
                f"hive {hive_base.hive_bins_data_size})"
            )
        if base.root_cell != hive_base.root_cell:
            summary.pairing_notes.append(
                f"root cell differs (log 0x{base.root_cell:x}, hive 0x{hive_base.root_cell:x})"
            )
        if not base.checksum_valid:
            summary.warnings.append("log base block checksum is invalid")

    summary.paired = paired
    if paired is False:
        summary.reason = "log base block does not pair with the primary hive"
        summary.errors.append(summary.reason)
        return _ParsedLog(summary, base, [])

    summary.supported = True
    parsed = _ParsedLog(summary, base, [])
    _parse_hvle_entries(parsed, data)
    return parsed


def _select_chain(hive_base: BaseBlock | None, logs: list[_ParsedLog]) -> _ChainSelection:
    if hive_base is None:
        return _ChainSelection(
            RecoveryStatus.FAILED,
            "primary hive base block could not be parsed",
            [],
            None,
            None,
            False,
            [],
            [],
            ["primary hive base block could not be parsed"],
        )
    if not hive_base.signature_valid:
        return _ChainSelection(
            RecoveryStatus.FAILED,
            f"primary hive has invalid signature {hive_base.signature!r}",
            [],
            hive_base.sequence1,
            None,
            False,
            [],
            [],
            ["primary hive has an invalid base block signature"],
        )
    if hive_base.checksum_valid and hive_base.sequence1 == hive_base.sequence2:
        return _ChainSelection(
            RecoveryStatus.CLEAN,
            "primary hive base block is valid and its sequence numbers match",
            [],
            hive_base.sequence1,
            None,
            True,
            [],
            [],
            [],
        )

    modern = [log for log in logs if log.summary.format == "modern_hvle"]
    supported = [log for log in modern if log.summary.supported and log.base is not None]
    if not supported:
        if any(log.summary.format == "old_dirt" for log in logs):
            return _ChainSelection(
                RecoveryStatus.UNSUPPORTED,
                "old-format DIRT transaction logs are unsupported; "
                "no supported modern HvLE chain is available",
                [],
                hive_base.sequence1,
                None,
                False,
                [],
                [],
                ["old-format transaction log"],
            )
        if any(log.summary.format == "unknown" for log in logs):
            return _ChainSelection(
                RecoveryStatus.UNSUPPORTED,
                "unknown transaction log format is unsupported; no supported modern HvLE chain is available",
                [],
                hive_base.sequence1,
                None,
                False,
                [],
                [],
                ["old/unknown transaction log format"],
            )
        return _ChainSelection(
            RecoveryStatus.FAILED,
            "primary hive is dirty but no valid modern HvLE log was supplied",
            [],
            hive_base.sequence1,
            None,
            False,
            [],
            [],
            ["no usable transaction log"],
        )

    header_override: bytes | None = None
    header_log: str | None = None
    warnings: list[str] = []
    errors: list[str] = []

    if hive_base.checksum_valid:
        expected_start = hive_base.sequence1
        minimum_base_sequence = hive_base.sequence2
        eligible = [
            log
            for log in supported
            if log.base is not None and log.base.sequence1 >= minimum_base_sequence
        ]
        eligible_ids = {id(log) for log in eligible}
        stale = [log.summary.name for log in supported if id(log) not in eligible_ids]
        if stale:
            warnings.append(f"ignored stale log(s) whose base sequence predates the hive: {', '.join(stale)}")
    else:
        candidates = [
            log
            for log in supported
            if log.base is not None and log.base.checksum_valid
        ]
        if not candidates:
            return _ChainSelection(
                RecoveryStatus.FAILED,
                "primary base block checksum is invalid and no candidate log has a valid base block",
                [],
                None,
                None,
                False,
                [],
                warnings,
                ["primary base block checksum mismatch"],
            )

        highest = max(log.base.sequence1 for log in candidates if log.base is not None)
        latest = [log for log in candidates if log.base is not None and log.base.sequence1 == highest]
        distinct_headers = {log.base.raw for log in latest if log.base is not None}
        if len(distinct_headers) > 1:
            return _ChainSelection(
                RecoveryStatus.FAILED,
                f"cannot determine which log carries the latest base block (sequence {highest})",
                [],
                highest,
                None,
                False,
                [],
                warnings,
                ["ambiguous base block recovery candidates"],
            )
        with_entries = [
            log
            for log in latest
            if any(entry.sequence >= highest for entry in log.entries)
        ]
        if len(with_entries) > 1:
            signatures = {
                tuple(
                    sorted(
                        (entry.sequence, entry.fingerprint)
                        for entry in log.entries
                        if entry.sequence >= highest
                    )
                )
                for log in with_entries
            }
            if len(signatures) > 1:
                return _ChainSelection(
                    RecoveryStatus.FAILED,
                    f"cannot determine which log carries the latest entries (sequence {highest})",
                    [],
                    highest,
                    None,
                    False,
                    [],
                    warnings,
                    ["ambiguous base block recovery candidates"],
                )
        selected = with_entries[0] if with_entries else latest[0]
        if selected.base is None:
            return _ChainSelection(
                RecoveryStatus.FAILED,
                "selected log has no base block",
                [],
                highest,
                None,
                False,
                [],
                warnings,
                errors,
            )
        header_override = selected.base.raw
        header_log = selected.summary.name
        expected_start = highest
        eligible = [selected]
        warnings.append(
            f"primary base block checksum is invalid; using the base block from {selected.summary.name}"
        )

    conflicts: list[str] = []
    by_sequence: dict[int, _HvleEntry] = {}
    for log in eligible:
        seen_in_log: set[int] = set()
        for entry in log.entries:
            if entry.sequence < expected_start:
                continue
            if entry.sequence in seen_in_log:
                conflicts.append(
                    f"duplicate sequence {entry.sequence} inside {log.summary.name} "
                    f"at 0x{entry.file_offset:x}"
                )
                continue
            seen_in_log.add(entry.sequence)

            previous = by_sequence.get(entry.sequence)
            if previous is None:
                by_sequence[entry.sequence] = entry
            elif previous.fingerprint != entry.fingerprint:
                conflicts.append(
                    f"sequence {entry.sequence} has conflicting content in "
                    f"{previous.log} and {entry.log}"
                )
            else:
                warnings.append(
                    f"sequence {entry.sequence} is duplicated identically in {previous.log} and {entry.log}"
                )

    if conflicts:
        return _ChainSelection(
            RecoveryStatus.FAILED,
            "duplicate sequence numbers carry conflicting content",
            [],
            expected_start,
            None,
            False,
            conflicts,
            warnings,
            ["recovery chain is ambiguous", *conflicts],
        )

    if expected_start not in by_sequence:
        higher = sorted(sequence for sequence in by_sequence if sequence > expected_start)
        if higher:
            reason = (
                f"missing predecessor sequence {expected_start}; the earliest available entry is {higher[0]}"
            )
            missing_sequence: int | None = expected_start
        else:
            reason = "no log entry applies to the dirty hive generation"
            missing_sequence = None
        return _ChainSelection(
            RecoveryStatus.FAILED,
            reason,
            [],
            expected_start,
            missing_sequence,
            False,
            [],
            warnings,
            [reason],
        )

    chain: list[_HvleEntry] = []
    sequence = expected_start
    while sequence in by_sequence:
        chain.append(by_sequence[sequence])
        sequence += 1

    last_sequence = chain[-1].sequence
    later = sorted(item for item in by_sequence if item > last_sequence)
    continuous = not later
    partial_reasons: list[str] = []
    if later:
        partial_reasons.append(
            f"sequence gap after {last_sequence}; next available entry is {later[0]}"
        )

    contributing_logs = {entry.log for entry in chain}
    for log in eligible:
        if log.summary.name not in contributing_logs:
            continue
        if log.summary.truncated:
            partial_reasons.append(f"{log.summary.name}: {log.summary.truncated}")
        if log.summary.trailing_corruption:
            partial_reasons.append(f"{log.summary.name}: {log.summary.trailing_corruption}")
        if log.summary.rejected_entries:
            partial_reasons.append(f"{log.summary.name}: {log.summary.rejected_entries} rejected entry/entries")

    status = RecoveryStatus.RECOVERED_PARTIAL if partial_reasons else RecoveryStatus.RECOVERED
    reason = "; ".join(partial_reasons) if partial_reasons else None
    if partial_reasons:
        warnings.extend(partial_reasons)

    return _ChainSelection(
        status,
        reason,
        chain,
        expected_start,
        None,
        continuous,
        [],
        warnings,
        errors,
        header_override,
        header_log,
    )


def _replace_span(
    spans: list[ProvenanceSpan],
    start: int,
    end: int,
    replacement: ProvenanceSpan,
) -> list[ProvenanceSpan]:
    result: list[ProvenanceSpan] = []
    for span in spans:
        if span.end <= start or span.start >= end:
            result.append(span)
            continue
        if span.start < start:
            result.append(replace(span, end=start))
        if span.end > end:
            result.append(replace(span, start=end))
    result.append(replacement)
    result.sort(key=lambda item: (item.start, item.end))
    return _merge_spans(result)


def _merge_spans(spans: list[ProvenanceSpan]) -> list[ProvenanceSpan]:
    merged: list[ProvenanceSpan] = []
    for span in spans:
        if span.start >= span.end:
            continue
        if (
            merged
            and merged[-1].end == span.start
            and merged[-1].source == span.source
            and merged[-1].log == span.log
            and merged[-1].sequence == span.sequence
            and merged[-1].detail == span.detail
        ):
            previous = merged[-1]
            merged[-1] = replace(previous, end=span.end)
        else:
            merged.append(span)
    return merged


def _overlapping_log_spans(
    spans: list[ProvenanceSpan],
    start: int,
    end: int,
    incoming: str,
) -> list[OverlapSummary]:
    overlaps: list[OverlapSummary] = []
    for span in spans:
        if span.end <= start or span.start >= end or span.source != "log_page":
            continue
        previous = f"{span.log}#seq={span.sequence}:{span.detail}"
        if previous == incoming:
            continue
        overlaps.append(
            OverlapSummary(
                start=max(start, span.start),
                end=min(end, span.end),
                incoming=incoming,
                previous=(previous,),
            )
        )
    return overlaps


def _apply_chain(
    hive_data: bytes,
    chain: list[_HvleEntry],
    header_override: bytes | None,
    header_log: str | None = None,
) -> tuple[bytes, list[ProvenanceSpan], list[OverlapSummary], int, list[str]]:
    if not chain:
        raise ValueError("cannot apply an empty recovery chain")

    final_bins_size = chain[-1].hive_bins_data_size
    final_length = max(len(hive_data), BASE_BLOCK_SIZE + final_bins_size)
    buffer = bytearray(hive_data)
    if len(buffer) < final_length:
        buffer.extend(b"\x00" * (final_length - len(buffer)))

    spans: list[ProvenanceSpan] = [ProvenanceSpan(0, len(hive_data), "primary_hive")]
    if final_length > len(hive_data):
        spans.append(ProvenanceSpan(len(hive_data), final_length, "zero_extension"))

    warnings: list[str] = []
    if header_override is not None:
        if len(header_override) < SECTOR_SIZE:
            raise ValueError("base block override is shorter than 512 bytes")
        buffer[:SECTOR_SIZE] = header_override[:SECTOR_SIZE]
        struct.pack_into("<I", buffer, 28, 0)
        spans = _replace_span(
            spans,
            0,
            SECTOR_SIZE,
            ProvenanceSpan(0, SECTOR_SIZE, "log_base_block", log=header_log),
        )

    overlaps: list[OverlapSummary] = []
    applied_pages = 0
    previous_entry: _HvleEntry | None = None
    for entry in chain:
        if previous_entry is not None and entry.hive_bins_data_size < previous_entry.hive_bins_data_size:
            warnings.append(
                f"hive bins data size shrinks from {previous_entry.hive_bins_data_size} "
                f"at sequence {previous_entry.sequence} to {entry.hive_bins_data_size} "
                f"at sequence {entry.sequence}"
            )
        previous_entry = entry

        for page_index, page in enumerate(entry.pages):
            target = BASE_BLOCK_SIZE + page.offset
            end = target + page.size
            if end > final_length:
                raise ValueError(
                    f"page {page_index} of sequence {entry.sequence} targets 0x{end:x}, "
                    f"beyond final hive size 0x{final_length:x}"
                )
            detail = f"page@{page.offset:#x}+{page.size:#x}"
            incoming = f"{entry.log}#seq={entry.sequence}:{detail}"
            overlaps.extend(_overlapping_log_spans(spans, target, end, incoming))
            buffer[target:end] = page.data
            spans = _replace_span(
                spans,
                target,
                end,
                ProvenanceSpan(
                    start=target,
                    end=end,
                    source="log_page",
                    log=entry.log,
                    sequence=entry.sequence,
                    detail=detail,
                ),
            )
            applied_pages += 1

    last_entry = chain[-1]
    sequence_bytes = struct.pack("<I", last_entry.sequence)
    buffer[4:8] = sequence_bytes
    buffer[8:12] = sequence_bytes
    struct.pack_into("<I", buffer, 40, final_bins_size)
    if len(buffer) >= 148:
        flags = u32(buffer, 144)
        flags = (flags & ~1) | (last_entry.flags & 1)
        struct.pack_into("<I", buffer, 144, flags)

    checksum = base_block_checksum(buffer)
    struct.pack_into("<I", buffer, 508, checksum)

    spans = _replace_span(
        spans,
        4,
        12,
        ProvenanceSpan(4, 12, "recovered_header", detail="sequence1/sequence2"),
    )
    spans = _replace_span(
        spans,
        40,
        44,
        ProvenanceSpan(40, 44, "recovered_header", detail="hive_bins_data_size"),
    )
    if len(buffer) >= 148:
        spans = _replace_span(
            spans,
            144,
            148,
            ProvenanceSpan(144, 148, "recovered_header", detail="flags"),
        )
    spans = _replace_span(
        spans,
        508,
        512,
        ProvenanceSpan(508, 512, "recovered_header", detail="checksum"),
    )

    data = bytes(buffer)
    spans = _merge_spans(spans)
    _assert_provenance_covers(spans, len(data))
    return data, spans, overlaps, applied_pages, warnings


def _assert_provenance_covers(spans: list[ProvenanceSpan], length: int) -> None:
    position = 0
    for span in spans:
        if span.start != position:
            raise ValueError(f"provenance gap or overlap at 0x{position:x}")
        position = span.end
    if position != length:
        raise ValueError(f"provenance ends at 0x{position:x}, expected 0x{length:x}")


def recover_hive(
    hive: BinaryIO,
    logs: Iterable[BinaryIO | Evidence] = (),
    *,
    hive_name: str = "primary",
    log_names: Sequence[str] | None = None,
) -> RecoveryResult:
    """Recover a dirty hive into an independent in-memory view.

    The caller's streams are read only. They are never written to or closed.
    """
    evidence_logs = _coerce_logs(logs, log_names)
    hive_snapshot = _snapshot_stream(hive)
    log_snapshots: list[tuple[Evidence, _Snapshot]] = [
        (evidence, _snapshot_stream(evidence.fh)) for evidence in evidence_logs
    ]

    hive_base = parse_base_block(hive_snapshot.data) if hive_snapshot.data is not None else None
    parsed_logs = [
        _parse_log(evidence.name, snapshot.data, hive_base, snapshot.error)
        for evidence, snapshot in log_snapshots
    ]

    selection = _select_chain(hive_base, parsed_logs)
    global_warnings = list(selection.warnings)
    global_errors = list(selection.errors)
    provenance: list[ProvenanceSpan] = []
    overlaps: list[OverlapSummary] = []
    structure: StructureReport | None = None
    recovered_data: bytes | None = None
    recovered_sha256: str | None = None
    recovered: RecoveredHive | None = None
    reason = selection.reason
    status = selection.status
    applied_sequences: set[int] = set()

    if status == RecoveryStatus.CLEAN and hive_snapshot.data is not None:
        recovered_data = hive_snapshot.data
        recovered_sha256 = hive_snapshot.sha256
        structure = validate_hive_structure(recovered_data)
        provenance = [ProvenanceSpan(0, len(recovered_data), "primary_hive")]
        recovered = RecoveredHive.from_bytes(recovered_data)
        if parsed_logs:
            global_warnings.append("primary hive is clean; transaction logs were ignored as specified")
    elif status in (RecoveryStatus.RECOVERED, RecoveryStatus.RECOVERED_PARTIAL) and hive_snapshot.data is not None:
        try:
            recovered_data, provenance, overlaps, applied_pages, apply_warnings = _apply_chain(
                hive_snapshot.data,
                selection.chain,
                selection.header_override,
                selection.header_log,
            )
        except ValueError as exc:
            status = RecoveryStatus.FAILED
            reason = f"recovery chain could not be applied: {exc}"
            global_errors.append(reason)
        else:
            recovered_sha256 = hashlib.sha256(recovered_data).hexdigest()
            structure = validate_hive_structure(recovered_data)
            recovered = RecoveredHive.from_bytes(recovered_data)
            applied_sequences = {entry.sequence for entry in selection.chain}
            global_warnings.extend(apply_warnings)
            global_warnings.append(f"applied {len(selection.chain)} entr(ies), {applied_pages} dirty page(s)")
    else:
        if hive_snapshot.data is None:
            global_errors.append(hive_snapshot.error or "primary hive stream could not be read")
        global_warnings.extend(log.summary.reason for log in parsed_logs if log.summary.reason)

    inputs: list[InputIntegrity] = []
    for role, name, stream, before in [
        ("primary", hive_name, hive, hive_snapshot),
        *[
            ("log", evidence.name, evidence.fh, snapshot)
            for evidence, snapshot in log_snapshots
        ],
    ]:
        after = _snapshot_stream(stream)
        unchanged: bool | None
        if before.sha256 is None or after.sha256 is None or not before.replayable or not after.replayable:
            unchanged = None
        else:
            unchanged = before.sha256 == after.sha256
        if unchanged is False:
            message = f"{role} input {name!r} changed while recovery was running"
            global_errors.append(message)
            if status in (RecoveryStatus.RECOVERED, RecoveryStatus.RECOVERED_PARTIAL):
                status = RecoveryStatus.FAILED
                reason = message
                recovered = None
                recovered_data = None
                recovered_sha256 = None
                structure = None
                provenance = []
                applied_sequences = set()
        inputs.append(
            InputIntegrity(
                name=name,
                role=role,
                size=before.size,
                sha256_before=before.sha256,
                sha256_after=after.sha256,
                unchanged=unchanged,
                error=before.error or after.error,
            )
        )

    selected_chain = [entry.summary(applied=entry.sequence in applied_sequences) for entry in selection.chain]
    if recovered_data is None:
        provenance = []

    report = RecoveryReport(
        status=status,
        reason=reason,
        hive=_base_summary(hive_base),
        logs=[log.summary for log in parsed_logs],
        selected_chain=selected_chain,
        expected_start_sequence=selection.expected_start_sequence,
        selected_start_sequence=selection.chain[0].sequence if selection.chain else None,
        selected_end_sequence=selection.chain[-1].sequence if selection.chain else None,
        continuous=selection.continuous,
        missing_sequence=selection.missing_sequence,
        duplicate_conflicts=selection.duplicate_conflicts,
        overlaps=overlaps,
        warnings=global_warnings,
        errors=global_errors,
        inputs=inputs,
        provenance=provenance,
        structure=structure,
        recovered_sha256=recovered_sha256,
        header_recovered_from_log=selection.header_log,
    )
    return RecoveryResult(report=report, recovered=recovered)


def provenance_for(
    spans: Iterable[ProvenanceSpan],
    start: int,
    length: int,
) -> list[ProvenanceSpan]:
    end = start + length
    result: list[ProvenanceSpan] = []
    for span in spans:
        if span.end <= start or span.start >= end:
            continue
        result.append(
            ProvenanceSpan(
                start=max(span.start, start),
                end=min(span.end, end),
                source=span.source,
                log=span.log,
                sequence=span.sequence,
                detail=span.detail,
            )
        )
    return result
