"""Report which decompiler backends this machine can *actually* run.

The provider layer in :mod:`codevanta.analysis.decompilers` never installs
anything: it probes each backend and either reports it available or explains what
is missing. This script surfaces that same probe as text, so a human -- or a CI
log -- can see the truth about an environment instead of a claim in a README:

* ``ghidra``  needs ``pyghidra`` *and* a Ghidra installation (``GHIDRA_INSTALL_DIR``)
* ``angr``    needs the ``angr`` package (``pip install -e ".[decompilers]"``)
* ``native``  is built into CODEVANTA and always runs

The exit status is always ``0``: this is a reporter, not a gate. The parity gate
is ``tests/test_decompiler_parity.py``, which *skips* without angr and *fails* if
angr is present but the provider layer does not use it.

Usage::

    python scripts/check_decompiler_backends.py
    python scripts/check_decompiler_backends.py --json

Text output is one line per backend, in probe order (``ghidra``, ``angr``,
``native``), with the name, the availability, the requirements and the reason.
``--json`` prints a single JSON object instead::

    {
      "backends": [{"name": ..., "available": ..., "reason": ..., "requires": [...]}, ...],
      "available": ["native"],
      "external_available": []
    }

``external_available`` lists the available backends that are third-party
(i.e. that declare a requirement); it is empty when only the native renderer can
run, which is exactly the situation the parity test exists to catch.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
#: Let ``python scripts/check_decompiler_backends.py`` run from a checkout without
#: an install. Appended, so an existing install wins and the script reports the
#: backends of the code the user actually imports.
_SRC_DIR = REPO_ROOT / "src"
if _SRC_DIR.is_dir():
    sys.path.append(str(_SRC_DIR))

#: Header used by the text output; wide enough for "unavailable".
_STATUS_AVAILABLE = "available"
_STATUS_UNAVAILABLE = "unavailable"


def probe_records() -> list[dict[str, Any]]:
    """Probe every backend and return the JSON-safe records of the results.

    Returns:
        One :meth:`~codevanta.analysis.decompilers.BackendAvailability.to_dict`
        record per backend, in probe order.

    Raises:
        Exception: Whatever the import or the probe raised; the caller turns that
            into a message and a ``0`` exit status.
    """
    from codevanta.analysis.decompilers import available_backends

    return [record.to_dict() for record in available_backends()]


def build_payload(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the ``--json`` payload from probed records.

    Args:
        records: The records returned by :func:`probe_records`.

    Returns:
        A JSON-safe mapping with every backend plus the names that are available
        and the subset of those that are third-party.
    """
    available = [record["name"] for record in records if record["available"]]
    external = [
        record["name"] for record in records if record["available"] and record["requires"]
    ]
    return {
        "backends": records,
        "available": available,
        "external_available": external,
    }


def format_report(records: list[dict[str, Any]]) -> list[str]:
    """Render the probe as one aligned line per backend.

    Args:
        records: The records returned by :func:`probe_records`.

    Returns:
        One line per record: ``name  status  requires=<...>  reason=<...>``. An
        empty list stays empty, so the caller prints nothing for no backends.
    """
    if not records:
        return []
    requires_text = [
        ",".join(record["requires"]) if record["requires"] else "-" for record in records
    ]
    name_width = max(len(record["name"]) for record in records)
    requires_width = max(len(text) for text in requires_text)
    status_width = len(_STATUS_UNAVAILABLE)
    lines: list[str] = []
    for record, requires in zip(records, requires_text, strict=True):
        status = _STATUS_AVAILABLE if record["available"] else _STATUS_UNAVAILABLE
        lines.append(
            f"{record['name']:<{name_width}}  {status:<{status_width}}  "
            f"requires={requires:<{requires_width}}  reason={record['reason']}"
        )
    return lines


def _parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="check_decompiler_backends",
        description=(
            "Report which decompiler backends CODEVANTA can run here "
            "(ghidra, angr, native). Always exits 0."
        ),
        epilog=(
            "Install a real backend with: python -m pip install -e '.[decompilers]' "
            "(angr) or pyghidra plus a Ghidra installation (ghidra)."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print one JSON object (backends, available, external_available) instead of lines.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Print the backend report and return ``0``, always.

    Args:
        argv: Command-line arguments; ``None`` uses :data:`sys.argv`.

    Returns:
        ``0``. A probe that raises is reported as a message, never as a failure,
        because this script is a diagnostic and must stay safe inside CI logs.
    """
    args = _parser().parse_args(argv)
    try:
        records = probe_records()
    except Exception as exc:  # a diagnostic must never fail the caller
        message = (
            f"could not probe the decompiler backends "
            f"({type(exc).__name__}: {exc}); is the package installed?"
        )
        if args.json:
            print(json.dumps({"error": message}, indent=2))
        else:
            print(message)
        return 0
    if args.json:
        print(json.dumps(build_payload(records), indent=2))
    else:
        for line in format_report(records):
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
