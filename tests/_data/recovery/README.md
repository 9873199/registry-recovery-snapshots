# Synthetic registry recovery fixtures

These files are **synthetic**. They were produced by `build_fixtures.py`; no live
system registry was read, exported, mounted, or modified.

## Format sources

* Primary hive and transaction-log layouts: Maxim Suhanov, *Windows registry file
  format specification*, sections "Format of primary files", "Format of
  transaction log files", and "New format".
  <https://github.com/msuhanov/regf>
* Modern log entries use the `HvLE` signature, a 40-byte header, 8-byte dirty
  page references, and two 64-bit Marvin hashes. Hash-1 covers the entry after
  the 40-byte header; Hash-2 covers the first 32 bytes. The Windows seed is
  `82 EF 4D 88 7A 4E 55 C5`.
* The Marvin32 state update and `(p1 << 32) | p0` on-disk layout follow the
  implementation in `blockcarve` (`src/hive_logs.rs`), which documents
  verification against Windows 11 `NTUSER.DAT.LOG1` / `.LOG2` entries.
  <https://crates.io/crates/blockcarve>

## Common hive

The primary hive is 8192 bytes: a 4096-byte base block and one 4096-byte
`hbin`. It contains:

* root key `ROOT` with subkeys `Alpha` and `Beta`;
* one value `RootV` (REG_BINARY, 16 bytes);
* a deliberately dirty base block: primary sequence `12`, secondary sequence
  `11`.

The dirty-page fixtures replace the 512-byte page containing the `RootV` data
cell. `GEN12`, `GEN13`, and `GEN14` identify which entry last wrote that page.
`manifest.json` records the exact layout offsets and SHA-256 of every file.

## Cases

| Case | Expected result |
| --- | --- |
| `minimal` | `LOG2` passed before `LOG1`, but entries are assembled by sequence: 12 (`LOG1`), 13 (`LOG2`), 14 (`LOG1`). Final value is `GEN14`. |
| `trailing` | Same chain as `minimal`, plus non-`HvLE` garbage after `LOG1`'s last entry. Recovery is `recovered_partial`; the corrupt tail is reported. |
| `truncated` | Entry 13 is cut short. Only sequence 12 is published; the incomplete entry is not partially applied. |
| `conflict` | Sequence 13 exists in both logs with different page bytes. Recovery fails and publishes no view. |
| `missing` | The earliest available entry is 13 while the dirty hive needs 12. Recovery fails with a missing-predecessor error. |
| `old` | Both logs use base-block file type 2. `LOG2` even contains an `HvLE`-shaped entry, but old-format logs are reported `unsupported`, never parsed as modern logs. |
| `cycle` | Recovery succeeds, but the recovered `lf` index points back to the root key node. The structural validator reports a cell-reference cycle and marks the recovered view untrustworthy. |

## Integrity checks

Tests assert that:

* every input's SHA-256 is identical before and after recovery;
* source streams are left open (including on exception paths);
* recovered bytes carry provenance spans naming the primary file, header
  repair, zero extension, or a specific log entry and sequence;
* overlapping dirty pages are applied in sequence order, with later entries
  overriding earlier bytes;
* log replay success is reported separately from structural trust and safe
  readable ranges.

Regenerate from the repository root with:

```bash
python tests/_data/recovery/build_fixtures.py
```
