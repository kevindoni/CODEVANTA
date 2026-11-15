"""MCP tools exposing the depth bridges (no MCP imports).

Five tools: ``codevanta_apk_decode`` (apktool, skip-gated),
``codevanta_js_recover`` (Wakaru, skip-gated), ``codevanta_javascript``
(pure-Python static app inventory, always available offline),
``codevanta_electron_audit`` (pure-Python Electron security audit, always
available offline) and ``codevanta_certs`` (pure-Python PE certificate
table, always available offline). The registration import lives in
:mod:`codevanta.mcp_server.tools`; the ``@server.tool`` wrappers live inside
:func:`codevanta.mcp_server.server.build_server` -- imports alone do not
register anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codevanta.analysis import apktool_bridge, electron_audit, javascript, pe_certs, wakaru_bridge


def codevanta_apk_decode(apk_path: str, out_dir: str) -> dict[str, Any]:
    """Decode an APK with apktool (--no-src, bounded 120s).

    Runs ``apktool d --no-src -f`` into ``out_dir`` and shallow-walks the
    decoded tree: decoded ``AndroidManifest.xml``, ``apktool.yml``, a bounded
    ``res/`` file count, smali absence (expected with ``--no-src``) and the
    bounded top-level entry names. Requires apktool on PATH; its absence is a
    typed error with the install hint and the offline ``codevanta metadata``
    fallback pointer.
    """
    return apktool_bridge.apk_decode(apk_path, out_dir).to_dict()


def codevanta_javascript(path: str, max_files: int = javascript.DEFAULT_MAX_FILES) -> dict[str, Any]:
    """Statically inventory a JavaScript/Electron application (offline).

    Accepts an extracted application directory or an ``.asar`` archive and
    returns, bounded and read-only: the JavaScript files with their imports
    (CommonJS/ESM/dynamic, classified relative/bare/builtin and resolved
    against the scanned set when possible), the ``package.json`` facts, a
    heuristic Electron process role per file, and the ``ipcMain`` /
    ``ipcRenderer`` call sites with literal channels paired across sides by
    exact name. Literal text matches are certain; roles and channel pairs are
    medium confidence and say so in their evidence. Nothing is executed.
    """
    return javascript.analyze_javascript_app(Path(path), max_files=max_files).to_dict()


def codevanta_electron_audit(
    path: str, max_files: int = electron_audit.DEFAULT_MAX_FILES
) -> dict[str, Any]:
    """Audit a JavaScript/Electron application for security anti-patterns.

    Runs the static JavaScript inventory first (roles, package facts), then
    applies bounded regex rules over the JavaScript and HTML sources:
    ``nodeIntegration: true``, ``contextIsolation: false``, ``sandbox:
    false``, ``webSecurity: false``, missing or weak CSP, interpolated
    ``exec``/``spawn`` commands, caller-chosen IPC channels behind
    ``contextBridge``, ``shell.openExternal`` with non-literal arguments and
    remote ``loadURL`` literals. Each finding carries a rule id, severity,
    confidence, file, line, snippet, recommendation and evidence; literal
    misconfigurations are certain, shape-based findings are medium. Nothing
    is executed and no Node.js is required.
    """
    return electron_audit.audit_electron_app(Path(path), max_files=max_files).to_dict()


def codevanta_js_recover(
    bundle_path: str, out_dir: str, mode: str = wakaru_bridge.MODE_MINIFY
) -> dict[str, Any]:
    """Recover readable JavaScript from a bundle with Wakaru.

    ``mode='minify'`` runs wakaru's ``unminify`` verb (readable identifiers);
    ``mode='unpack'`` splits a webpack-style bundle into per-module files.
    Requires Node.js with ``npm i -g @wakaru/cli`` (or npx detection); its
    absence is a typed error naming that install hint. The recovered-entry
    list is bounded and the console transcript is preserved under ``out_dir``.
    """
    return wakaru_bridge.js_recover(bundle_path, out_dir, mode).to_dict()


def codevanta_certs(path: str) -> dict[str, Any]:
    """Parse a PE file's certificate table offline (pure Python).

    Walks the ``IMAGE_DIRECTORY_ENTRY_SECURITY`` table's ``WIN_CERTIFICATE``
    entries and, for ``PKCS_SIGNED_DATA`` payloads, a minimal hand-rolled DER
    reader over the PKCS#7 ``SignedData`` structure: signer count, serial
    numbers (hex), digest/signature OID names (common SHA RSA/ECDSA map) and
    ``signingTime`` when the authenticated attributes carry it. Structure
    only: no trust-chain verification; issuer names are honestly reported as
    an explicit gap.
    """
    return pe_certs.inspect_cert_table(path).to_dict()
