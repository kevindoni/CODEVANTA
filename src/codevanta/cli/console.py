"""Rich consoles for the CLI, safe on legacy Windows code pages.

PowerShell may hand CPython a legacy ANSI code page (cp1252) for ``stdout``
even though rich will print arrows and box-drawing characters. Rich's legacy
Windows renderer then writes through that encoder and raises
``UnicodeEncodeError``. Every console here is therefore built with
``legacy_windows=False`` and the standard streams are switched to UTF-8 with a
replacement fallback when they are reconfigurable.
"""

from __future__ import annotations

import codecs
import sys
from typing import IO, Any

from rich.console import Console


def _reconfigure(stream: IO[str] | None) -> None:
    """Switch ``stream`` to UTF-8 when it can be reconfigured.

    Streams installed by test runners or wrappers may not expose
    ``reconfigure``; those are left untouched and rely on rich's replacement
    behaviour instead.
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    encoding = getattr(stream, "encoding", None)
    if encoding:
        try:
            if codecs.lookup(encoding).name == "utf-8":
                return
        except LookupError:
            pass
    try:
        reconfigure(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        # A stream may be closed already, or a pipeline may disallow it.
        pass


def configure_stdio() -> None:
    """Make ``stdout``/``stderr`` safe for rich output on any code page."""
    _reconfigure(sys.stdout)
    _reconfigure(sys.stderr)


def make_console(*, stderr: bool = False, **kwargs: Any) -> Console:
    """Return a console that never uses the legacy Windows renderer."""
    kwargs.setdefault("legacy_windows", False)
    return Console(stderr=stderr, **kwargs)


configure_stdio()
