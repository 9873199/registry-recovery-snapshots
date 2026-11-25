from __future__ import annotations

from dissect.regf.exceptions import (
    Error,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.regf.recovery import (
    Evidence,
    RecoveryResult,
    RecoveryStatus,
    RecoveredHive,
    provenance_for,
    recover_hive,
)
from dissect.regf.regf import RegistryHive
from dissect.regf.structure import ByteRange, StructureIssue, StructureReport, validate_hive_structure

__all__ = [
    "ByteRange",
    "Error",
    "Evidence",
    "RecoveredHive",
    "RecoveryResult",
    "RecoveryStatus",
    "RegistryHive",
    "RegistryKeyNotFoundError",
    "RegistryValueNotFoundError",
    "StructureIssue",
    "StructureReport",
    "provenance_for",
    "recover_hive",
    "validate_hive_structure",
]
