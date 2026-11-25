from __future__ import annotations

import argparse
import json
import sys
from contextlib import ExitStack
from pathlib import Path

from dissect.regf.recovery import Evidence, RecoveryStatus, recover_hive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recover a dirty registry hive from modern HvLE logs, read-only")
    parser.add_argument("hive", type=Path, help="Primary hive file (for example NTUSER.DAT)")
    parser.add_argument("logs", type=Path, nargs="+", help="Transaction log files (LOG1 / LOG2)")
    parser.add_argument("--output", type=Path, help="Write the recovered hive to this new file")
    parser.add_argument("--report", type=Path, help="Write the JSON report to this file")
    args = parser.parse_args(argv)

    inputs = [args.hive, *args.logs]
    if args.output is not None:
        output = args.output.resolve()
        if any(output == path.resolve() for path in inputs):
            parser.error("--output must not overwrite an evidence file")
        if output.exists():
            parser.error("--output already exists")

    with ExitStack() as stack:
        hive_fh = stack.enter_context(args.hive.open("rb"))
        log_fhs = [stack.enter_context(log.open("rb")) for log in args.logs]
        result = recover_hive(
            hive_fh,
            [Evidence(log.name, log_fh) for log, log_fh in zip(args.logs, log_fhs, strict=True)],
            hive_name=args.hive.name,
        )

    report = json.dumps(result.to_dict(), indent=2)
    if args.report:
        args.report.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)

    print(f"status: {result.status.value}", file=sys.stderr)
    if result.report.structure:
        print(
            f"structure trustworthy: {result.report.structure.trustworthy}",
            file=sys.stderr,
        )
    if result.recovered is not None and args.output is not None:
        args.output.write_bytes(result.recovered.data)
        print(f"recovered hive written to {args.output}", file=sys.stderr)
    if result.status is RecoveryStatus.RECOVERED_PARTIAL:
        return 2
    if result.report.structure is not None and result.report.structure.trustworthy is False:
        return 3
    return 0 if result.recovered is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
