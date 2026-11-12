"""Local, dependency-free web dashboard for CODEVANTA.

The GUI is a standard-library-only HTTP server bound to loopback. It exposes the
existing analysis engines over a small JSON API and serves one self-contained
HTML page, so a single command is enough to try CODEVANTA in a browser::

    from codevanta.gui import serve

    serve()                      # http://127.0.0.1:8765/

Nothing here reimplements analysis: every route delegates to the CLI/MCP engine
of the same name, keeps its bounds and returns its evidence payload. The server
is read-only (it parses bytes, never executes or writes them) and refuses to bind
anything but a loopback address.

Public API:

* :func:`~codevanta.gui.layout.render_dashboard_html` -- the dashboard page.
* :func:`~codevanta.gui.server.create_server` -- a bound, unstarted server.
* :func:`~codevanta.gui.server.create_handler` -- the request-handler class.
* :func:`~codevanta.gui.server.serve` -- bind, print the URL, serve until Ctrl+C.
"""

from __future__ import annotations

from .layout import render_dashboard_html
from .server import (
    MAX_RESPONSE_BYTES,
    ROUTES,
    VERSION,
    create_handler,
    create_server,
    normalize_host,
    serve,
)

__all__ = [
    "MAX_RESPONSE_BYTES",
    "ROUTES",
    "VERSION",
    "create_handler",
    "create_server",
    "normalize_host",
    "render_dashboard_html",
    "serve",
]
