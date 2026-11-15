"""MCP tool exposing the YARA-subset rule engine (no MCP imports).

One tool: ``codevanta_yara`` (pure-Python parse + evaluate of a bounded
subset of real YARA rule syntax). The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrapper lives inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import yara_subset


def codevanta_yara(
    path: str,
    rules_text: str | None = None,
    rules_path: str | None = None,
    max_strings: int = 200_000,
    max_matches_per_string: int = 64,
) -> dict[str, Any]:
    """Match a bounded subset of real YARA rules against a file.

    Provide the rules as text or a .yar file path. Supported: text strings
    (nocase / wide), hex strings with ``??`` nibble wildcards and bounded
    ``[n-m]`` jumps, conditions from ``and/or/not``, ``$a``, ``#a OP N``,
    ``filesize OP N`` and ``all of / any of / N of``; anything else is a
    typed error naming the rule -- never silently ignored. String hits are
    certain evidence (offsets recorded); a satisfied rule is a
    medium-confidence conclusion. Nothing is executed.
    """
    return yara_subset.match_rules(
        Path(path),
        rules_text=rules_text,
        rules_path=Path(rules_path) if rules_path else None,
        max_strings=max_strings,
        max_matches_per_string=max_matches_per_string,
    ).to_dict()
