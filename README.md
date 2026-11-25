# dissect.regf

A Dissect module implementing a parser for Windows registry file format, used to store application and OS configuration
on Windows operating systems. For more information, please see [the
documentation](https://docs.dissect.tools/en/latest/projects/dissect.regf/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.regf` is available on [PyPI](https://pypi.org/project/dissect.regf/).

```bash
pip install dissect.regf
```

This module is also automatically installed if you install the `dissect` package.

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Transaction log recovery

`recover_hive` applies modern `HvLE` transaction logs into an independent in-memory view. Caller-owned streams are
only read; they are never written to or closed. The recovery object is published only after the whole selected
sequence chain has been validated.

```python
from dissect.regf import Evidence, recover_hive

with open("NTUSER.DAT", "rb") as hive, open("NTUSER.DAT.LOG1", "rb") as log1, open("NTUSER.DAT.LOG2", "rb") as log2:
    result = recover_hive(
        hive,
        [Evidence("NTUSER.DAT.LOG1", log1), Evidence("NTUSER.DAT.LOG2", log2)],
        hive_name="NTUSER.DAT",
    )

print(result.status)
print(result.report.to_dict())
if result.recovered and result.recovered.hive:
    root = result.recovered.hive.root()
```

The report separates:

* recovery status (`clean`, `recovered`, `recovered_partial`, `failed`, `unsupported`);
* the selected sequence chain, log pairing checks, hashes, dirty-page ranges and overlaps;
* post-replay structural errors, cell-reference cycles and safe readable ranges;
* SHA-256 of every input before and after recovery;
* byte provenance for the recovered buffer, including the log entry and sequence that supplied each span.

Old-format `DIRT` logs are reported as `unsupported`; they are never fed through the modern `HvLE` parser.

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
