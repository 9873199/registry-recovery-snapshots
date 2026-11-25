from __future__ import annotations

import hashlib
import io
import json
import struct
from pathlib import Path

from dissect.regf.hive_format import marvin32
from dissect.regf.recovery import (
    Evidence,
    RecoveryStatus,
    provenance_for,
    recover_hive,
)
from dissect.regf.regf import RegistryHive
from dissect.regf.structure import validate_hive_structure

DATA = Path(__file__).parent / "_data" / "recovery"
MANIFEST = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))


def test_marvin32_matches_dotnet_reference_vectors() -> None:
    # Vectors from Notatin's marvin32.rs, transcribed from the .NET coreclr
    # MarvinTests corpus. They pin both the algorithm and the 64-bit layout.
    vectors = [
        (0x4FB61A001BDBCC, b"", 0x30ED35C100CD3C7D),
        (0x4FB61A001BDBCC, b"\xaf", 0x48E73FC77D75DDC1),
        (0x4FB61A001BDBCC, b"\xe7\x0f", 0xB5F6E1FC485DBFF8),
        (0x4FB61A001BDBCC, b"\x37\xf4\x95", 0xF0B07C789B8CF7E8),
        (0x4FB61A001BDBCC, b"\x86\x42\xdc\x59", 0x7008F2E87E9CF556),
        (0x4FB61A001BDBCC, b"\x15\x3f\xb7\x98\x26", 0xE6C08C6DA2AFA997),
        (0x4FB61A001BDBCC, b"\x09\x32\xe6\x24\x6c\x47", 0x6F04BF1A5EA24060),
        (0x4FB61A001BDBCC, b"\xab\x42\x7e\xa8\xd1\x0f\xc7", 0xE11847E4F0678C41),
        (0x4FB61A001BDBCC, bytes(range(256)), 0x7DFCAB33FCEAD72C),
        (0x804FB61A001BDBCC, b"", 0x10A9D5D3996FD65D),
        (0x804FB61A801BDBCC, b"\x00\xff", 0xA638E75700048880),
    ]
    for seed, data, expected in vectors:
        assert marvin32(seed, data) == expected


def case_files(name: str) -> dict[str, bytes]:
    case = DATA / name
    return {path.name: path.read_bytes() for path in case.iterdir() if path.is_file()}


def run_case(
    name: str,
    *,
    order: tuple[str, ...] = ("LOG2", "LOG1"),
    streams: dict[str, io.BytesIO] | None = None,
) -> tuple[object, dict[str, object], dict[str, bytes]]:
    files = case_files(name)
    hive_stream = (streams or {}).get("NTUSER.DAT") or io.BytesIO(files["NTUSER.DAT"])
    log_evidence = []
    for suffix in order:
        filename = f"NTUSER.DAT.{suffix}"
        if filename not in files:
            continue
        stream = (streams or {}).get(filename) or io.BytesIO(files[filename])
        log_evidence.append(Evidence(filename, stream))

    result = recover_hive(hive_stream, log_evidence, hive_name="NTUSER.DAT")
    all_streams = {"NTUSER.DAT": hive_stream}
    all_streams.update({evidence.name: evidence.fh for evidence in log_evidence})
    return result, all_streams, files


def assert_inputs_unchanged(result, files: dict[str, bytes]) -> None:
    by_name = {item.name: item for item in result.report.inputs}
    for name, data in files.items():
        integrity = by_name[name]
        expected = hashlib.sha256(data).hexdigest()
        assert integrity.size == len(data)
        assert integrity.sha256_before == expected
        assert integrity.sha256_after == expected
        assert integrity.unchanged is True


def test_manifest_hashes_match_files() -> None:
    for relative, expected in MANIFEST["files"].items():
        data = (DATA / relative).read_bytes()
        assert len(data) == expected["size"]
        assert hashlib.sha256(data).hexdigest() == expected["sha256"]


def test_modern_logs_are_reordered_and_overlap_in_sequence_order() -> None:
    result, streams, files = run_case("minimal", order=("LOG2", "LOG1"))

    assert result.status is RecoveryStatus.RECOVERED
    assert result.recovered is not None
    assert result.report.reason is None
    assert result.report.continuous is True
    assert result.report.expected_start_sequence == 12
    assert [entry.sequence for entry in result.report.selected_chain] == [12, 13, 14]
    assert [entry.log for entry in result.report.selected_chain] == [
        "NTUSER.DAT.LOG1",
        "NTUSER.DAT.LOG2",
        "NTUSER.DAT.LOG1",
    ]
    assert all(entry.applied for entry in result.report.selected_chain)

    value = result.recovered.hive.root().value("RootV")
    assert value.data == b"GEN14..........."

    assert len(result.report.overlaps) >= 2
    assert result.report.overlaps[-1].incoming.startswith("NTUSER.DAT.LOG1#seq=14")

    value_offset = MANIFEST["layout"]["value_data_absolute"]
    spans = provenance_for(result.report.provenance, value_offset, 16)
    assert len(spans) == 1
    assert spans[0].source == "log_page"
    assert spans[0].log == "NTUSER.DAT.LOG1"
    assert spans[0].sequence == 14

    structure = result.report.structure
    assert structure is not None
    assert structure.trustworthy is True
    assert structure.root_valid is True
    assert structure.errors == []
    assert structure.safe_ranges[0].start == 0
    assert structure.safe_ranges[-1].end == len(files["NTUSER.DAT"])

    assert_inputs_unchanged(result, files)
    json.dumps(result.to_dict())
    assert all(not stream.closed for stream in streams.values())

    assert RegistryHive(io.BytesIO(files["NTUSER.DAT"])).dirty is True
    assert result.recovered.hive.dirty is False


def test_trailing_corruption_is_reported_without_guessing() -> None:
    result, streams, files = run_case("trailing")

    assert result.status is RecoveryStatus.RECOVERED_PARTIAL
    assert result.recovered is not None
    assert [entry.sequence for entry in result.report.selected_chain] == [12, 13, 14]
    assert result.recovered.hive.root().value("RootV").data == b"GEN14..........."

    log1 = next(log for log in result.report.logs if log.name == "NTUSER.DAT.LOG2")
    assert log1.trailing_corruption is None
    log1 = next(log for log in result.report.logs if log.name == "NTUSER.DAT.LOG1")
    assert log1.trailing_corruption is not None
    assert "non-HvLE data" in log1.trailing_corruption
    assert any("non-HvLE data" in warning for warning in result.report.warnings)

    assert result.report.structure is not None
    assert result.report.structure.trustworthy is True
    assert_inputs_unchanged(result, files)
    assert all(not stream.closed for stream in streams.values())


def test_truncated_entry_is_not_partially_applied() -> None:
    result, streams, files = run_case("truncated")

    assert result.status is RecoveryStatus.RECOVERED_PARTIAL
    assert result.recovered is not None
    assert [entry.sequence for entry in result.report.selected_chain] == [12]
    assert result.recovered.hive.root().value("RootV").data == b"GEN12..........."

    log = result.report.logs[0]
    assert log.truncated is not None
    assert log.rejected_entries == 1
    assert log.first_sequence == 12
    assert log.last_sequence == 12
    assert result.report.selected_end_sequence == 12
    assert_inputs_unchanged(result, files)
    assert all(not stream.closed for stream in streams.values())


def test_log_truncated_before_first_complete_entry_publishes_nothing() -> None:
    files = case_files("minimal")
    hive_stream = io.BytesIO(files["NTUSER.DAT"])
    truncated_log = io.BytesIO(files["NTUSER.DAT.LOG1"][:700])

    result = recover_hive(
        hive_stream,
        [Evidence("NTUSER.DAT.LOG1", truncated_log)],
        hive_name="NTUSER.DAT",
    )

    assert result.status is RecoveryStatus.FAILED
    assert result.recovered is None
    assert result.report.selected_chain == []
    assert result.report.logs[0].truncated is not None
    assert result.report.logs[0].rejected_entries == 1
    assert hive_stream.closed is False
    assert truncated_log.closed is False


def test_duplicate_sequence_with_different_content_publishes_nothing() -> None:
    result, streams, files = run_case("conflict")

    assert result.status is RecoveryStatus.FAILED
    assert result.recovered is None
    assert result.report.selected_chain == []
    assert result.report.duplicate_conflicts
    assert "sequence 13" in result.report.duplicate_conflicts[0]
    assert any("conflicting content" in error for error in result.report.errors)
    assert result.report.provenance == []
    assert_inputs_unchanged(result, files)
    assert all(not stream.closed for stream in streams.values())


def test_missing_predecessor_publishes_nothing() -> None:
    result, streams, files = run_case("missing")

    assert result.status is RecoveryStatus.FAILED
    assert result.recovered is None
    assert result.report.missing_sequence == 12
    assert "missing predecessor sequence 12" in result.report.reason
    assert result.report.selected_chain == []
    assert_inputs_unchanged(result, files)
    assert all(not stream.closed for stream in streams.values())


def test_old_format_is_unsupported_even_when_hvle_shaped_bytes_are_present() -> None:
    result, streams, files = run_case("old")

    assert result.status is RecoveryStatus.UNSUPPORTED
    assert result.recovered is None
    assert "old-format" in result.report.reason
    assert all(log.format == "old_dirt" for log in result.report.logs)
    assert all(log.supported is False for log in result.report.logs)
    assert result.report.selected_chain == []
    assert_inputs_unchanged(result, files)
    assert all(not stream.closed for stream in streams.values())


def test_cell_reference_cycle_is_reported_after_successful_replay() -> None:
    result, streams, files = run_case("cycle")

    assert result.status is RecoveryStatus.RECOVERED
    assert result.recovered is not None
    assert result.report.structure is not None
    assert result.report.structure.trustworthy is False
    assert result.report.structure.cycles
    assert any(issue.code == "cell_reference_cycle" for issue in result.report.structure.errors)
    assert result.report.structure.safe_ranges
    assert_inputs_unchanged(result, files)
    assert all(not stream.closed for stream in streams.values())


def test_structure_validator_checks_hbin_and_cell_boundaries() -> None:
    data = bytearray(case_files("minimal")["NTUSER.DAT"])
    struct.pack_into("<I", data, 4096 + 8, 8192)
    report = validate_hive_structure(bytes(data))
    assert report.trustworthy is False
    assert any(
        issue.code in ("hbin_out_of_bounds", "hbin_beyond_declared_size")
        for issue in report.errors
    )

    data = bytearray(case_files("minimal")["NTUSER.DAT"])
    root_absolute = 4096 + MANIFEST["layout"]["root_cell"]
    struct.pack_into("<i", data, root_absolute, -0x2000)
    report = validate_hive_structure(bytes(data))
    assert report.trustworthy is False
    assert any(issue.code == "cell_crosses_hbin" for issue in report.errors)


def test_structure_validator_checks_allocation_state_and_index_references() -> None:
    data = bytearray(case_files("minimal")["NTUSER.DAT"])
    root_absolute = 4096 + MANIFEST["layout"]["root_cell"]
    root_size = struct.unpack_from("<i", data, root_absolute)[0]
    struct.pack_into("<i", data, root_absolute, abs(root_size))
    report = validate_hive_structure(bytes(data))
    assert report.root_valid is False
    assert any(issue.code == "root_cell_free" for issue in report.errors)

    data = bytearray(case_files("minimal")["NTUSER.DAT"])
    lf_entries = MANIFEST["layout"]["lf_entries_absolute"]
    struct.pack_into("<I", data, lf_entries, 0xFFFFF000)
    report = validate_hive_structure(bytes(data))
    assert report.trustworthy is False
    assert any(issue.code == "missing_cell_reference" for issue in report.errors)


def test_tampered_entry_fails_hash_and_stops_at_previous_sequence() -> None:
    files = case_files("minimal")
    tampered = bytearray(files["NTUSER.DAT.LOG2"])
    tampered[512 + 40 + 8 + 100] ^= 0x01
    tampered_files = dict(files)
    tampered_files["NTUSER.DAT.LOG2"] = bytes(tampered)
    streams = {
        name: io.BytesIO(data)
        for name, data in tampered_files.items()
    }

    result, all_streams, _ = run_case(
        "minimal",
        order=("LOG2", "LOG1"),
        streams=streams,
    )

    assert result.status is RecoveryStatus.RECOVERED_PARTIAL
    assert result.recovered is not None
    assert [entry.sequence for entry in result.report.selected_chain] == [12]
    assert result.recovered.hive.root().value("RootV").data == b"GEN12..........."
    log2 = next(log for log in result.report.logs if log.name == "NTUSER.DAT.LOG2")
    assert log2.rejected_entries == 1
    assert any("failed Hash" in error for error in log2.errors)
    assert all(not stream.closed for stream in all_streams.values())


class ShortReadStream(io.BytesIO):
    def __init__(self, data: bytes, maximum: int = 7):
        super().__init__(data)
        self.maximum = maximum

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0 or size > self.maximum:
            size = self.maximum
        return super().read(size)


class NonSeekableStream:
    def __init__(self, data: bytes):
        self._stream = io.BytesIO(data)
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0 or size > 11:
            size = 11
        return self._stream.read(size)

    def tell(self) -> int:
        raise OSError("not seekable")

    def seek(self, offset: int, whence: int = 0) -> int:
        raise OSError("not seekable")

    def close(self) -> None:
        self.closed = True


def test_short_reads_are_supported() -> None:
    files = case_files("minimal")
    streams = {
        "NTUSER.DAT": ShortReadStream(files["NTUSER.DAT"]),
        "NTUSER.DAT.LOG2": ShortReadStream(files["NTUSER.DAT.LOG2"]),
        "NTUSER.DAT.LOG1": ShortReadStream(files["NTUSER.DAT.LOG1"]),
    }

    result, all_streams, _ = run_case("minimal", streams=streams)

    assert result.status is RecoveryStatus.RECOVERED
    assert result.recovered is not None
    assert result.recovered.hive.root().value("RootV").data == b"GEN14..........."
    assert all(not stream.closed for stream in all_streams.values())


def test_non_seekable_input_is_read_without_being_closed() -> None:
    files = case_files("minimal")
    streams = {
        "NTUSER.DAT": NonSeekableStream(files["NTUSER.DAT"]),
        "NTUSER.DAT.LOG2": NonSeekableStream(files["NTUSER.DAT.LOG2"]),
        "NTUSER.DAT.LOG1": NonSeekableStream(files["NTUSER.DAT.LOG1"]),
    }

    result, all_streams, _ = run_case("minimal", streams=streams)

    assert result.status is RecoveryStatus.RECOVERED
    assert result.recovered is not None
    assert result.recovered.hive.root().value("RootV").data == b"GEN14..........."
    assert all(item.unchanged is None for item in result.report.inputs)
    assert all(not stream.closed for stream in all_streams.values())


class ExplodingStream(io.BytesIO):
    def __init__(self, data: bytes, fail_after: int = 1):
        super().__init__(data)
        self.fail_after = fail_after
        self.reads = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        if self.reads > self.fail_after:
            raise OSError("simulated read failure")
        if size is None or size < 0 or size > 5:
            size = 5
        return super().read(size)


def test_exception_path_does_not_close_caller_streams() -> None:
    files = case_files("minimal")
    hive_stream = io.BytesIO(files["NTUSER.DAT"])
    exploding_log = ExplodingStream(files["NTUSER.DAT.LOG1"])
    normal_log = io.BytesIO(files["NTUSER.DAT.LOG2"])

    result = recover_hive(
        hive_stream,
        [Evidence("NTUSER.DAT.LOG1", exploding_log), Evidence("NTUSER.DAT.LOG2", normal_log)],
        hive_name="NTUSER.DAT",
    )

    assert result.status is RecoveryStatus.FAILED
    assert result.recovered is None
    assert exploding_log.closed is False
    assert normal_log.closed is False
    assert hive_stream.closed is False
    integrity = next(item for item in result.report.inputs if item.name == "NTUSER.DAT.LOG1")
    assert integrity.error is not None
    assert "simulated read failure" in integrity.error


def test_hive_read_exception_does_not_close_streams() -> None:
    files = case_files("minimal")
    exploding_hive = ExplodingStream(files["NTUSER.DAT"])
    normal_log = io.BytesIO(files["NTUSER.DAT.LOG1"])

    result = recover_hive(
        exploding_hive,
        [Evidence("NTUSER.DAT.LOG1", normal_log)],
        hive_name="NTUSER.DAT",
    )

    assert result.status is RecoveryStatus.FAILED
    assert result.recovered is None
    assert exploding_hive.closed is False
    assert normal_log.closed is False
    hive_integrity = next(item for item in result.report.inputs if item.role == "primary")
    assert hive_integrity.error is not None
    assert "simulated read failure" in hive_integrity.error
