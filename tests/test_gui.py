"""Dashboard HTTP tests over tiny synthetic ELF64 samples.

The server is always started on port ``0`` (an OS-assigned free port) inside a
background thread and shut down in a ``finally`` block, so no test leaks a
listening socket. The ELF fixture is assembled byte-by-byte with :mod:`struct`
(the same self-contained helper ``tests/test_type_recovery.py`` uses), so these
tests need no compiler, linker or shared binary sample.
"""

from __future__ import annotations

import http.client
import json
import struct
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

import pytest

from codevanta.analysis.bridge import BridgeCapability
from codevanta.analysis.decompilers import available_backends
from codevanta.analysis.emulate import MAX_MAX_INSTRUCTIONS
from codevanta.analysis.nav import NavStore
from codevanta.analysis.symbolic import MAX_MAX_PATHS
from codevanta.core.report import AnalysisError
from codevanta.core.unknowns import (
    make_open_unknown,
    records_to_payload,
    resolve_record,
)
from codevanta.gui import (
    ROUTES,
    VERSION,
    create_handler,
    create_server,
    normalize_host,
    render_dashboard_html,
)
from codevanta.gui import server as gui_server_module
from codevanta.gui.server import MAX_RESPONSE_BYTES, _encode_payload, is_allowed_host
from codevanta.storage.session import MAX_LIMIT as MAX_SESSION_LIMIT
from codevanta.storage.session import MAX_NOTE_LENGTH as MAX_SESSION_NOTE_LENGTH

TEXT_VA = 0x401000
DATA_VA = 0x402000

#: ``mov rax, qword ptr [rdi + 0x10]`` -- read of field 0x10 (8 bytes wide).
MOV_RAX_RDI_10 = bytes.fromhex("488b4710")

#: ``mov qword ptr [rdi + 0x18], rbx`` -- write of field 0x18 (8 bytes wide).
MOV_RDI_18_RBX = bytes.fromhex("48895f18")

#: ``mov ecx, dword ptr [rdi + 0x20]`` -- read of field 0x20 (4 bytes wide).
MOV_ECX_RDI_20 = bytes.fromhex("8b4f20")

#: ``ret``
RET = bytes.fromhex("c3")

#: ``mov eax, 42`` (B8 imm32) -- the straight-line body both new routes run.
MOV_EAX_42 = bytes.fromhex("b82a000000")

#: Straight-line ``mov eax, 42; ret``: returns 42 along a single path.
RETURN_42 = MOV_EAX_42 + RET

#: Three distinct struct offsets: 0x10, 0x18 and 0x20.
THREE_FIELDS = MOV_RAX_RDI_10 + MOV_RDI_18_RBX + MOV_ECX_RDI_20 + RET

#: How many fields :data:`THREE_FIELDS` must yield.
EXPECTED_FIELDS = 3


def _make_elf64(path: Path, code: bytes, data: bytes = b"", entry: int = TEXT_VA) -> Path:
    """Write an ELF64 file with an executable ``.text`` and a ``.data`` section."""
    if not code:
        raise ValueError("code must not be empty")
    shstr = b"\x00.text\x00.data\x00.shstrtab\x00"
    off_text = 0x40
    off_data = off_text + len(code)
    off_shstr = off_data + len(data)
    shoff = off_shstr + len(shstr)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type = ET_EXEC
        62,  # e_machine = EM_X86_64
        1,  # e_version
        entry,  # e_entry
        0,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        0,  # e_phnum
        64,  # e_shentsize
        4,  # e_shnum: null, .text, .data, .shstrtab
        3,  # e_shstrndx
    )
    null_section = bytes(64)
    text_section = struct.pack("<IIQQQQIIQQ", 1, 1, 6, entry, off_text, len(code), 0, 0, 16, 0)
    data_section = struct.pack("<IIQQQQIIQQ", 7, 1, 3, DATA_VA, off_data, len(data), 0, 0, 8, 0)
    str_section = struct.pack("<IIQQQQIIQQ", 13, 3, 0, 0, off_shstr, len(shstr), 0, 0, 1, 0)
    blob = bytearray(shoff)
    blob[0:64] = header
    blob[off_text:off_text + len(code)] = code
    blob[off_data:off_data + len(data)] = data
    blob[off_shstr:off_shstr + len(shstr)] = shstr
    blob += null_section + text_section + data_section + str_section
    path.write_bytes(bytes(blob))
    return path


def _stop(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    """Shut a background server down and prove the thread is gone."""
    server.shutdown()
    server.server_close()
    thread.join(timeout=15)
    assert not thread.is_alive(), "server thread did not stop"


def _start(server: ThreadingHTTPServer) -> threading.Thread:
    """Run ``server`` in a daemon thread and return that thread."""
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.daemon = True
    thread.start()
    return thread


@pytest.fixture()
def sample_binary(tmp_path: Path) -> Path:
    """A tiny ELF64 with a three-offset struct access pattern at ``.text``."""
    return _make_elf64(tmp_path / "sample.bin", THREE_FIELDS)


@pytest.fixture()
def return_binary(tmp_path: Path) -> Path:
    """A tiny ELF64 whose ``.text`` is the straight-line ``mov eax, 42; ret``."""
    return _make_elf64(tmp_path / "return42.bin", RETURN_42)


@pytest.fixture()
def gui_server() -> Iterator[ThreadingHTTPServer]:
    """A loopback dashboard server on an ephemeral port, started and stopped."""
    server = create_server("127.0.0.1", 0)
    thread = _start(server)
    try:
        yield server
    finally:
        _stop(server, thread)


def _fetch(
    server: ThreadingHTTPServer, path: str, method: str = "GET"
) -> tuple[int, str, bytes]:
    """Issue ``method path`` against the in-process ``server`` via http.client.

    The server is addressed as a plain socket (like the Host-header tests
    below already do): no URL is built or fetched, and every status —
    including error statuses — comes back without raising.
    """
    host, port = server.server_address[0], server.server_address[1]
    connection = http.client.HTTPConnection(host or "127.0.0.1", port, timeout=30)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, response.headers.get("Content-Type", ""), response.read()
    finally:
        connection.close()


def _get(server: ThreadingHTTPServer, path: str) -> tuple[int, dict]:
    """GET ``path`` and return ``(status, payload)``, including error statuses."""
    status, _, body = _fetch(server, path)
    return status, json.loads(body.decode("utf-8"))


def _get_text(server: ThreadingHTTPServer, path: str) -> tuple[int, str, str]:
    """GET ``path`` and return ``(status, content_type, body)`` as text."""
    status, content_type, body = _fetch(server, path)
    return status, content_type, body.decode("utf-8")


def _raw_get(
    server: ThreadingHTTPServer, path: str, host: str | None
) -> tuple[int, dict[str, str], bytes]:
    """GET ``path`` with exactly the ``Host`` header asked for (or none at all).

    :mod:`urllib` always sends a matching ``Host``, so the allowlist tests drive
    :mod:`http.client` directly with ``skip_host=True``: that is the only way to
    reproduce the DNS-rebinding request shape.
    """
    connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
    try:
        connection.putrequest("GET", path, skip_host=True)
        if host is not None:
            connection.putheader("Host", host)
        connection.endheaders()
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()



def test_dashboard_page_contains_form_controls_and_no_external_url() -> None:
    page = render_dashboard_html()

    for element_id in ("path", "left", "right", "out", "tbl", "backend"):
        assert f'id="{element_id}"' in page
    for action in (
        "info",
        "functions",
        "strings",
        "xrefs",
        "cfg",
        "struct",
        "callgraph",
        "decompile",
        "emulate",
        "symbolic",
    ):
        assert f'data-action="{action}"' in page
    assert 'data-action="diff"' in page
    # Self-contained: no CDN, no font, no image, no absolute URL of any scheme.
    assert "http://" not in page
    assert "https://" not in page
    assert "<script src=" not in page
    assert "<link" not in page
    # Results are written with textContent only, never with innerHTML.
    assert "textContent" in page
    assert "innerHTML" not in page


def test_dashboard_page_has_a_decompile_control() -> None:
    page = render_dashboard_html()

    assert '<button type="button" data-action="decompile">Decompile</button>' in page
    assert 'id="backend"' in page
    # The control posts to the same-origin decompile route and renders the
    # answer with textContent, exactly like the other buttons.
    assert 'decompile: "/api/decompile"' in page
    assert 'addParam(parts, "backend", fieldValue("backend") || "auto")' in page
    assert "innerHTML" not in page


def test_dashboard_page_escapes_the_title() -> None:
    page = render_dashboard_html('<b>evil & "quoted"</b>')

    assert "<b>evil" not in page
    assert "&lt;b&gt;evil &amp; &quot;quoted&quot;&lt;/b&gt;" in page


def test_index_serves_the_dashboard_page(gui_server: ThreadingHTTPServer) -> None:
    status, content_type, body = _get_text(gui_server, "/")

    assert status == 200
    assert content_type.startswith("text/html")
    assert body == render_dashboard_html()


def test_health_returns_ok_and_version(gui_server: ThreadingHTTPServer) -> None:
    status, payload = _get(gui_server, "/api/health")

    assert status == 200
    assert payload["status"] == "ok"
    assert payload["version"] == VERSION
    assert set(payload["routes"]) == set(ROUTES)


def test_info_returns_binary_metadata(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    status, payload = _get(gui_server, f"/api/info?path={sample_binary.as_posix()}")

    assert status == 200
    assert payload["binary"]["format"] == "ELF"
    assert payload["binary"]["architecture"] == "x86_64"
    assert payload["binary"]["entry_point"] == "0x401000"
    assert payload["function_count"] == len(payload["functions"])
    assert "provenance" in payload


def test_missing_path_is_a_400(gui_server: ThreadingHTTPServer, tmp_path: Path) -> None:
    missing = (tmp_path / "does-not-exist.bin").as_posix()

    status, payload = _get(gui_server, f"/api/info?path={missing}")

    assert status == 400
    assert payload["error"]


def test_absent_path_parameter_is_a_400(gui_server: ThreadingHTTPServer) -> None:
    status, payload = _get(gui_server, "/api/functions")

    assert status == 400
    assert payload["error"] == "path is required"


def test_unknown_route_is_a_404(gui_server: ThreadingHTTPServer) -> None:
    status, payload = _get(gui_server, "/api/nope")

    assert status == 404
    assert "unknown route" in payload["error"]


def test_non_loopback_host_is_refused() -> None:
    for host in ("0.0.0.0", "10.0.0.5", "example.com", "::", ""):
        with pytest.raises(ValueError):
            create_server(host, 0)


def test_normalize_host_accepts_loopback_only() -> None:
    assert normalize_host("127.0.0.1") == "127.0.0.1"
    assert normalize_host("localhost") == "127.0.0.1"
    assert normalize_host("127.9.9.9") == "127.9.9.9"
    assert normalize_host("::1") == "::1"
    with pytest.raises(ValueError):
        normalize_host("192.168.1.10")


def test_is_allowed_host_accepts_only_the_dashboard_origin() -> None:
    assert is_allowed_host("127.0.0.1:8765", 8765) is True
    assert is_allowed_host("127.0.0.1", 8765) is True
    assert is_allowed_host("localhost:8765", 8765) is True
    assert is_allowed_host("LocalHost", 8765) is True
    assert is_allowed_host("[::1]:8765", 8765) is True
    assert is_allowed_host("[::1]", 8765) is True

    for header in (
        "attacker.example:8080",
        "attacker.example",
        "127.0.0.1.attacker.example:8765",
        "127.0.0.1:9999",  # the port must be the one we are bound to
        "[::1]:9999",
        "0.0.0.0:8765",
        "127.0.0.1:http",
        "",
        "   ",
        "[::1",
        None,
    ):
        assert is_allowed_host(header, 8765) is False, header


def test_foreign_host_header_is_rejected_with_421(gui_server: ThreadingHTTPServer) -> None:
    for host in ("attacker.example:8080", "attacker.example", "0.0.0.0:80", "127.0.0.1:1"):
        status, headers, body = _raw_get(gui_server, "/api/health", host)

        assert status == 421, host
        payload = json.loads(body.decode("utf-8"))
        assert "Host" in payload["error"]
        assert host in payload["error"]
        assert headers["Content-Type"].startswith("application/json")


def test_missing_host_header_is_rejected_with_421(gui_server: ThreadingHTTPServer) -> None:
    status, _, body = _raw_get(gui_server, "/api/health", None)

    assert status == 421
    payload = json.loads(body.decode("utf-8"))
    assert "Host" in payload["error"]
    assert "<missing>" in payload["error"]


def test_loopback_host_header_with_the_real_port_is_accepted(
    gui_server: ThreadingHTTPServer,
) -> None:
    port = gui_server.server_address[1]
    for host in ("127.0.0.1", f"127.0.0.1:{port}", "localhost", f"localhost:{port}",
                 "[::1]", f"[::1]:{port}"):
        status, _, body = _raw_get(gui_server, "/api/health", host)

        assert status == 200, host
        assert json.loads(body.decode("utf-8"))["status"] == "ok"


def test_foreign_host_is_rejected_before_the_route_runs(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    # A rebound page must not be able to read a local binary even though the
    # route itself would happily serve it.
    status, _, body = _raw_get(
        gui_server, f"/api/info?path={sample_binary.as_posix()}", "attacker.example:8080"
    )

    assert status == 421
    assert "ELF" not in body.decode("utf-8")
    assert json.loads(body.decode("utf-8"))["error"].startswith("refusing Host")


def test_every_response_carries_the_security_headers(
    gui_server: ThreadingHTTPServer,
) -> None:
    port = gui_server.server_address[1]
    good_host = f"127.0.0.1:{port}"
    expected = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": (
            "default-src 'none'; script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; connect-src 'self'"
        ),
    }
    cases = (
        ("/", good_host),  # the HTML page
        ("/api/health", good_host),  # a JSON route
        ("/api/nope", good_host),  # 404
        ("/api/health", "attacker.example:8080"),  # 421
    )
    for path, host in cases:
        _, headers, _ = _raw_get(gui_server, path, host)

        for name, value in expected.items():
            assert headers.get(name) == value, (path, host, name)


def test_security_headers_are_not_duplicated(gui_server: ThreadingHTTPServer) -> None:
    port = gui_server.server_address[1]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        connection.request("GET", "/api/health", headers={"Host": f"127.0.0.1:{port}"})
        response = connection.getresponse()
        response.read()
        names = [name.lower() for name, _ in response.getheaders()]
    finally:
        connection.close()

    assert names.count("x-frame-options") == 1
    assert names.count("x-content-type-options") == 1
    assert names.count("content-security-policy") == 1


def test_payload_cap_holds_for_one_huge_string() -> None:
    oversized = "a" * (MAX_RESPONSE_BYTES * 2)

    body = _encode_payload({"path": "/tmp/sample.bin", "blob": oversized})

    assert len(body) <= MAX_RESPONSE_BYTES
    payload = json.loads(body.decode("utf-8"))
    assert payload["response_truncated"] is True
    assert payload["path"] == "/tmp/sample.bin"
    assert payload["blob"] == f"<cut: {len(oversized)} chars>"


def test_payload_cap_holds_for_a_huge_string_nested_below_the_top_level() -> None:
    oversized = "b" * (MAX_RESPONSE_BYTES * 2)

    body = _encode_payload({"items": [{"label": "one", "blob": oversized}]})

    assert len(body) <= MAX_RESPONSE_BYTES
    payload = json.loads(body.decode("utf-8"))
    assert payload["response_truncated"] is True
    assert payload["items"][0]["blob"] == f"<cut: {len(oversized)} chars>"


def test_payload_cap_falls_back_to_a_minimal_error_document() -> None:
    # 30k distinct keys of 200 chars each: nothing to halve (no top-level list)
    # and nothing the string cut may shorten, so the cap can only be met by
    # giving up on the payload itself.
    payload = {f"key{index:05d}": "c" * 200 for index in range(30_000)}

    body = _encode_payload(payload)

    assert len(body) <= MAX_RESPONSE_BYTES
    assert json.loads(body.decode("utf-8")) == {
        "error": "response too large",
        "response_truncated": True,
        "limit": MAX_RESPONSE_BYTES,
    }



def test_functions_honours_the_limit(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    path = sample_binary.as_posix()

    status_all, payload_all = _get(gui_server, f"/api/functions?path={path}&limit=10")
    assert status_all == 200
    assert payload_all["count"] >= 1
    assert len(payload_all["functions"]) == min(payload_all["count"], 10)
    assert payload_all["returned"] == len(payload_all["functions"])

    status_one, payload_one = _get(gui_server, f"/api/functions?path={path}&limit=1")
    assert status_one == 200
    assert len(payload_one["functions"]) == 1
    assert payload_one["truncated"] is (payload_one["count"] > 1)

    status_none, payload_none = _get(gui_server, f"/api/functions?path={path}&limit=0")
    assert status_none == 200
    assert payload_none["functions"] == []
    assert payload_none["returned"] == 0


def test_struct_honours_the_field_limit(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    path = sample_binary.as_posix()

    status_full, payload_full = _get(
        gui_server, f"/api/struct?path={path}&address=0x401000&max_fields=64"
    )
    assert status_full == 200
    assert len(payload_full["fields"]) == EXPECTED_FIELDS
    assert payload_full["truncated"] is False

    status_capped, payload_capped = _get(
        gui_server, f"/api/struct?path={path}&address=0x401000&max_fields=1"
    )
    assert status_capped == 200
    assert len(payload_capped["fields"]) == 1
    assert payload_capped["truncated"] is True


def test_out_of_bounds_and_non_numeric_limits_are_400(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    path = sample_binary.as_posix()

    status_big, payload_big = _get(gui_server, f"/api/functions?path={path}&limit=99999999")
    assert status_big == 400
    assert "limit" in payload_big["error"]

    status_text, payload_text = _get(gui_server, f"/api/functions?path={path}&limit=abc")
    assert status_text == 400
    assert "limit" in payload_text["error"]

    status_fields, _ = _get(
        gui_server, f"/api/struct?path={path}&address=0x401000&max_fields=99999"
    )
    assert status_fields == 400


def test_every_analysis_route_answers(
    gui_server: ThreadingHTTPServer, sample_binary: Path, tmp_path: Path
) -> None:
    path = sample_binary.as_posix()
    twin = _make_elf64(tmp_path / "twin.bin", THREE_FIELDS).as_posix()

    for route in (
        f"/api/functions?path={path}&limit=5",
        f"/api/strings?path={path}&limit=3&min_length=4",
        f"/api/xrefs?path={path}&limit=5",
        f"/api/cfg?path={path}&address=0x401000&traversal=linear",
        f"/api/cfg?path={path}&address=0x401000&traversal=recursive",
        f"/api/struct?path={path}&address=0x401000&include_stack=0",
        f"/api/callgraph?path={path}&limit_functions=10&limit_edges=10",
        f"/api/diff?left={path}&right={twin}&semantic=0&threshold=0.5",
        f"/api/decompile?path={path}&address=0x401000&backend=auto",
    ):
        status, payload = _get(gui_server, route)
        assert status == 200, (route, payload)
        assert isinstance(payload, dict)

    _, strings = _get(gui_server, f"/api/strings?path={path}&limit=3")
    assert len(strings["strings"]) <= 3

    _, graph = _get(gui_server, f"/api/callgraph?path={path}&limit_functions=10")
    assert graph["limit_functions"] == 10
    assert graph["node_count"] >= 1

    _, diff = _get(gui_server, f"/api/diff?left={path}&right={twin}&semantic=0")
    assert diff["identical"] is True


def test_invalid_traversal_is_a_400(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    status, payload = _get(
        gui_server,
        f"/api/cfg?path={sample_binary.as_posix()}&address=0x401000&traversal=sideways",
    )

    assert status == 400
    assert "traversal" in payload["error"]


def test_non_get_methods_are_405(gui_server: ThreadingHTTPServer) -> None:
    for method in ("POST", "PUT", "DELETE", "HEAD"):
        status, _, body = _fetch(gui_server, "/api/health", method=method)
        assert status == 405
        if method != "HEAD":
            payload = json.loads(body.decode("utf-8"))
            assert payload["error"] == "only GET is supported"


def test_handler_can_refuse_path_parameters(sample_binary: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(paths_allowed=False))
    thread = _start(server)
    try:
        status, payload = _get(server, f"/api/functions?path={sample_binary.as_posix()}")
        assert status == 400
        assert "disabled" in payload["error"]
        health_status, health = _get(server, "/api/health")
        assert health_status == 200
        assert health["paths_allowed"] is False
    finally:
        _stop(server, thread)


# ---------------------------------------------------------------------------
# /api/decompile
# ---------------------------------------------------------------------------


def test_decompile_returns_a_text_body(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    status, payload = _get(
        gui_server, f"/api/decompile?path={sample_binary.as_posix()}&address=0x401000"
    )

    assert status == 200
    assert payload["backend"] == "native"
    assert payload["language"] == "c"
    assert Path(payload["path"]) == sample_binary
    assert payload["address"] == "0x401000"
    assert payload["blocks"] == 1
    assert isinstance(payload["text"], str)
    assert "sub_401000" in payload["text"]
    assert "blocks: 1" in payload["text"]
    # The fallback is reported, not silent.
    assert payload["warnings"]


def test_decompile_defaults_to_the_entry_point(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    status, payload = _get(
        gui_server, f"/api/decompile?path={sample_binary.as_posix()}&backend=native"
    )

    assert status == 200
    assert payload["address"] == "0x401000"
    assert payload["warnings"] == []


def test_decompile_unknown_backend_is_a_400(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    status, payload = _get(
        gui_server, f"/api/decompile?path={sample_binary.as_posix()}&backend=radare2"
    )

    assert status == 400
    assert "backend" in payload["error"]
    assert "radare2" in payload["error"]


def test_decompile_unavailable_backend_is_a_400_not_a_500(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    probes = {probe.name: probe for probe in available_backends()}
    if probes["angr"].available:
        pytest.skip("the angr backend is installed in this environment")

    status, payload = _get(
        gui_server, f"/api/decompile?path={sample_binary.as_posix()}&backend=angr"
    )

    assert status == 400
    assert "angr" in payload["error"]


def test_decompile_rejects_an_unusable_address(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    path = sample_binary.as_posix()

    status_text, payload_text = _get(gui_server, f"/api/decompile?path={path}&address=zzz")
    assert status_text == 400
    assert "address" in payload_text["error"]

    status_range, payload_range = _get(
        gui_server, f"/api/decompile?path={path}&address=0x401000&max_blocks=0"
    )
    assert status_range == 400
    assert "max_blocks" in payload_range["error"]


def test_foreign_host_is_rejected_before_the_decompile_route_runs(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    status, headers, body = _raw_get(
        gui_server,
        f"/api/decompile?path={sample_binary.as_posix()}&address=0x401000",
        "attacker.example:8080",
    )

    assert status == 421
    text = body.decode("utf-8")
    assert "sub_401000" not in text
    assert json.loads(text)["error"].startswith("refusing Host")
    assert headers["X-Frame-Options"] == "DENY"


def test_decompile_reply_carries_the_security_headers(
    gui_server: ThreadingHTTPServer, sample_binary: Path
) -> None:
    port = gui_server.server_address[1]

    status, headers, body = _raw_get(
        gui_server,
        f"/api/decompile?path={sample_binary.as_posix()}&address=0x401000",
        f"127.0.0.1:{port}",
    )

    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert json.loads(body.decode("utf-8"))["backend"] == "native"


def test_decompile_body_counts_toward_the_response_cap(
    gui_server: ThreadingHTTPServer,
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The rendering is text, but it is JSON-encoded like every other payload, so
    # the existing cap must shrink it rather than being bypassed. The fixture
    # payload is ~1.8 kB, the shrunk form ~1.1 kB: a 1.5 kB cap forces the
    # placeholder stage and leaves no doubt about which stage ran.
    cap = 1500
    monkeypatch.setattr(gui_server_module, "MAX_RESPONSE_BYTES", cap)
    port = gui_server.server_address[1]

    status, headers, body = _raw_get(
        gui_server,
        f"/api/decompile?path={sample_binary.as_posix()}&address=0x401000",
        f"127.0.0.1:{port}",
    )

    assert status == 200
    assert len(body) <= cap
    assert int(headers["Content-Length"]) == len(body)
    payload = json.loads(body.decode("utf-8"))
    assert payload["response_truncated"] is True
    assert payload["text"].startswith("<cut: ")
    assert payload["address"] == "0x401000"


def test_response_cap_shrinks_a_decompiled_text_field() -> None:
    oversized = "d" * (MAX_RESPONSE_BYTES * 2)

    body = _encode_payload(
        {"text": oversized, "path": "/tmp/sample.bin", "address": "0x401000"}
    )

    assert len(body) <= MAX_RESPONSE_BYTES
    payload = json.loads(body.decode("utf-8"))
    assert payload["response_truncated"] is True
    assert payload["text"] == f"<cut: {len(oversized)} chars>"
    assert payload["address"] == "0x401000"



# ---------------------------------------------------------------------------
# /api/emulate and /api/symbolic
# ---------------------------------------------------------------------------


def test_emulate_returns_the_function_return_value(
    gui_server: ThreadingHTTPServer, return_binary: Path
) -> None:
    status, payload = _get(
        gui_server,
        f"/api/emulate?path={return_binary.as_posix()}&address=0x401000"
        "&max_instructions=100",
    )

    assert status == 200
    assert payload["stopped_reason"] == "return"
    # mov eax, 42; ret -> the run returns 0x2a after completing both steps.
    assert payload["return_value"] == "0x2a"
    assert payload["instructions"] >= 1
    assert Path(payload["path"]) == return_binary
    assert payload["address"] == "0x401000"


def test_emulate_seeds_registers_from_repeatable_set_parameters(
    gui_server: ThreadingHTTPServer, return_binary: Path
) -> None:
    # rbx is untouched by ``mov eax, 42; ret``, so a non-zero final value proves
    # the seed reached the emulator. The second ``set`` parameter is the
    # repeatable case: both occurrences must arrive, not just the first.
    status, payload = _get(
        gui_server,
        f"/api/emulate?path={return_binary.as_posix()}&address=0x401000"
        "&set=eax=0&set=rbx=2",
    )

    assert status == 200
    assert payload["stopped_reason"] == "return"
    assert payload["registers"]["rbx"] == "0x2"


def test_emulate_refuses_when_the_emulator_is_unavailable(
    gui_server: ThreadingHTTPServer,
    return_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gui_server_module, "EMULATOR_AVAILABLE", False)
    monkeypatch.setattr(
        gui_server_module, "emulator_status", lambda: "unicorn is missing"
    )

    status, payload = _get(
        gui_server,
        f"/api/emulate?path={return_binary.as_posix()}&address=0x401000",
    )

    assert status == 400
    assert payload["error"] == "unicorn is missing"


def test_emulate_rejects_bad_parameters(
    gui_server: ThreadingHTTPServer, return_binary: Path
) -> None:
    path = return_binary.as_posix()

    status_missing, payload_missing = _get(gui_server, "/api/emulate?address=0x401000")
    assert status_missing == 400
    assert payload_missing["error"] == "path is required"

    status_text, payload_text = _get(
        gui_server, f"/api/emulate?path={path}&address=0x401000&max_instructions=abc"
    )
    assert status_text == 400
    assert "max_instructions" in payload_text["error"]

    status_range, _ = _get(
        gui_server,
        f"/api/emulate?path={path}&address=0x401000"
        f"&max_instructions={MAX_MAX_INSTRUCTIONS + 1}",
    )
    assert status_range == 400

    status_set, payload_set = _get(
        gui_server, f"/api/emulate?path={path}&address=0x401000&set=eax"
    )
    assert status_set == 400
    assert "set" in payload_set["error"]


def test_symbolic_returns_at_least_one_path_on_a_straight_line(
    gui_server: ThreadingHTTPServer, return_binary: Path
) -> None:
    status, payload = _get(
        gui_server,
        f"/api/symbolic?path={return_binary.as_posix()}&address=0x401000"
        "&max_paths=8&max_steps=200",
    )

    assert status == 200
    assert payload["explorer"] == "unicorn"
    assert payload["paths"] >= 1
    assert len(payload["entries"]) == payload["paths"]
    assert payload["entries"][0]["stopped_reason"] == "return"
    assert payload["entries"][0]["return_value"] == "0x2a"
    assert payload["return_values"] == ["0x2a"]
    assert Path(payload["path"]) == return_binary


def test_symbolic_rejects_bad_parameters(
    gui_server: ThreadingHTTPServer, return_binary: Path
) -> None:
    path = return_binary.as_posix()

    status_zero, payload_zero = _get(
        gui_server, f"/api/symbolic?path={path}&address=0x401000&max_paths=0"
    )
    assert status_zero == 400
    assert "max_paths" in payload_zero["error"]

    status_range, _ = _get(
        gui_server,
        f"/api/symbolic?path={path}&address=0x401000&max_paths={MAX_MAX_PATHS + 1}",
    )
    assert status_range == 400

    status_text, payload_text = _get(
        gui_server, f"/api/symbolic?path={path}&address=0x401000&max_steps=nope"
    )
    assert status_text == 400
    assert "max_steps" in payload_text["error"]


def test_foreign_host_is_rejected_before_the_new_routes_run(
    gui_server: ThreadingHTTPServer, return_binary: Path
) -> None:
    path = return_binary.as_posix()
    for route in (
        f"/api/emulate?path={path}&address=0x401000",
        f"/api/symbolic?path={path}&address=0x401000",
    ):
        status, headers, body = _raw_get(gui_server, route, "attacker.example:8080")

        assert status == 421, route
        assert headers["X-Frame-Options"] == "DENY"
        text = body.decode("utf-8")
        assert json.loads(text)["error"].startswith("refusing Host")
        # The 421 is answered before any route runs: no analysis payload leaks.
        assert "stopped_reason" not in text


def test_new_route_replies_carry_the_security_headers(
    gui_server: ThreadingHTTPServer, return_binary: Path
) -> None:
    port = gui_server.server_address[1]
    path = return_binary.as_posix()
    for route in (
        f"/api/emulate?path={path}&address=0x401000",
        f"/api/symbolic?path={path}&address=0x401000",
    ):
        status, headers, body = _raw_get(gui_server, route, f"127.0.0.1:{port}")

        assert status == 200, route
        assert headers["Content-Type"].startswith("application/json")
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "connect-src 'self'" in headers["Content-Security-Policy"]


def test_emulate_body_counts_toward_the_response_cap(
    gui_server: ThreadingHTTPServer,
    return_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The natural payload is comfortably above this cap, so hitting the limit
    # proves the new route goes through the same bounded renderer as the rest.
    cap = 400
    monkeypatch.setattr(gui_server_module, "MAX_RESPONSE_BYTES", cap)
    port = gui_server.server_address[1]

    status, headers, body = _raw_get(
        gui_server,
        f"/api/emulate?path={return_binary.as_posix()}&address=0x401000",
        f"127.0.0.1:{port}",
    )

    assert status == 200
    assert len(body) <= cap
    assert int(headers["Content-Length"]) == len(body)
    payload = json.loads(body.decode("utf-8"))
    assert payload["response_truncated"] is True


def test_dashboard_page_has_emulate_and_symbolic_controls() -> None:
    page = render_dashboard_html()

    for element_id in (
        "emu-address",
        "emu-max",
        "sym-address",
        "sym-max-paths",
        "sym-max-steps",
    ):
        assert f'id="{element_id}"' in page
    assert (
        '<button type="button" id="emu-run" data-action="emulate">'
        "Emulate function</button>" in page
    )
    assert (
        '<button type="button" id="sym-run" data-action="symbolic">'
        "Explore paths</button>" in page
    )
    # Both controls talk to the same-origin emulation routes only.
    assert 'emulate: "/api/emulate"' in page
    assert 'symbolic: "/api/symbolic"' in page
    assert 'addParam(parts, "max_instructions", fieldValue("emu-max"))' in page
    assert 'addParam(parts, "max_paths", fieldValue("sym-max-paths"))' in page
    assert 'addParam(parts, "max_steps", fieldValue("sym-max-steps"))' in page
    assert "innerHTML" not in page


# ---------------------------------------------------------------------------
# /api/session_save and /api/session_list
# ---------------------------------------------------------------------------

#: Note used by the session tests: it carries the two characters (``&`` and a
#: space) that a query string mangles unless the value is encoded on the way out
#: and decoded on the way in.
SESSION_NOTES = "reviewed by hand & filed"


def _session_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the dashboard at a throw-away session database and return its path.

    ``$CODEVANTA_DB`` is the override the CLI and the MCP tools already read
    (``tests/test_cli_phase2.py`` uses it the same way), so the routes resolve the
    temporary file through the production mechanism rather than a test-only hook.
    """
    db = tmp_path / "sessions.db"
    monkeypatch.setenv("CODEVANTA_DB", str(db))
    return db


def _save(
    server: ThreadingHTTPServer, binary: Path, notes: str | None = None
) -> tuple[int, dict]:
    """GET ``/api/session_save`` for ``binary``, optionally with ``notes``."""
    query = f"path={quote(binary.as_posix())}"
    if notes is not None:
        query = f"{query}&notes={quote(notes)}"
    return _get(server, f"/api/session_save?{query}")


def test_session_save_stores_a_record_that_session_list_returns(
    gui_server: ThreadingHTTPServer,
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = _session_db(monkeypatch, tmp_path)

    status, saved = _save(gui_server, sample_binary, SESSION_NOTES)

    assert status == 200, saved
    # Exactly the two identifiers the page needs to confirm the save.
    assert set(saved) == {"session_id", "created_at"}
    assert saved["session_id"]
    assert db.exists()

    list_status, listing = _get(gui_server, "/api/session_list")

    assert list_status == 200
    assert listing["count"] == 1
    assert len(listing["sessions"]) == 1
    record = listing["sessions"][0]
    assert record["session_id"] == saved["session_id"]
    assert record["created_at"] == saved["created_at"]
    assert Path(record["path"]) == sample_binary
    assert record["format"] == "ELF"
    assert record["architecture"]
    assert record["notes"] == SESSION_NOTES




def test_a_saved_session_survives_a_restart(
    sample_binary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The point of the panel: a reload (or a restarted dashboard) still sees the
    # record, because it lives in the database file and not in a browser tab.
    _session_db(monkeypatch, tmp_path)
    first = create_server("127.0.0.1", 0)
    first_thread = _start(first)
    try:
        status, saved = _save(first, sample_binary)
        assert status == 200, saved
    finally:
        _stop(first, first_thread)

    second = create_server("127.0.0.1", 0)
    second_thread = _start(second)
    try:
        status, listing = _get(second, "/api/session_list")
    finally:
        _stop(second, second_thread)

    assert status == 200
    assert [row["session_id"] for row in listing["sessions"]] == [saved["session_id"]]


def test_session_list_respects_the_limit(
    gui_server: ThreadingHTTPServer,
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _session_db(monkeypatch, tmp_path)
    for _ in range(3):
        status, saved = _save(gui_server, sample_binary)
        assert status == 200, saved

    status, listing = _get(gui_server, "/api/session_list?limit=2")

    assert status == 200
    assert listing["limit"] == 2
    assert listing["count"] == 2
    assert len(listing["sessions"]) == 2

    wide_status, wide = _get(gui_server, f"/api/session_list?limit={MAX_SESSION_LIMIT}")

    assert wide_status == 200
    assert wide["count"] == 3


@pytest.mark.parametrize("limit", ["0", "-1", str(MAX_SESSION_LIMIT + 1), "many", "1.5"])
def test_session_list_rejects_limits_outside_the_storage_bounds(
    gui_server: ThreadingHTTPServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
) -> None:
    _session_db(monkeypatch, tmp_path)

    status, payload = _get(gui_server, f"/api/session_list?limit={limit}")

    assert status == 400
    assert "limit" in payload["error"]


def test_session_routes_reject_unknown_query_parameters(
    gui_server: ThreadingHTTPServer,
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _session_db(monkeypatch, tmp_path)

    # No "db" parameter: the database comes from the server's environment, so a
    # request cannot aim the dashboard at an arbitrary file.
    list_status, list_payload = _get(gui_server, "/api/session_list?db=elsewhere.db")
    assert list_status == 400
    assert "unknown query parameter" in list_payload["error"]
    assert "db" in list_payload["error"]

    save_status, save_payload = _get(
        gui_server,
        f"/api/session_save?path={quote(sample_binary.as_posix())}&notse=typo",
    )
    assert save_status == 400
    assert "notse" in save_payload["error"]

    # A rejected save writes nothing, so the list is still empty.
    _, listing = _get(gui_server, "/api/session_list")
    assert listing["count"] == 0


def test_foreign_host_is_rejected_before_the_session_routes_run(
    gui_server: ThreadingHTTPServer,
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = _session_db(monkeypatch, tmp_path)

    for route in (
        "/api/session_list",
        f"/api/session_save?path={quote(sample_binary.as_posix())}",
    ):
        status, headers, body = _raw_get(gui_server, route, "attacker.example:8080")

        assert status == 421, route
        assert headers["X-Frame-Options"] == "DENY"
        assert json.loads(body.decode("utf-8"))["error"].startswith("refusing Host")

    # 421 is answered before any route runs, so not even the database was made.
    assert not db.exists()


def test_session_list_reply_carries_the_security_headers(
    gui_server: ThreadingHTTPServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _session_db(monkeypatch, tmp_path)
    port = gui_server.server_address[1]

    status, headers, body = _raw_get(gui_server, "/api/session_list", f"127.0.0.1:{port}")

    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "connect-src 'self'" in headers["Content-Security-Policy"]
    assert json.loads(body.decode("utf-8"))["count"] == 0




def test_session_list_body_counts_toward_the_response_cap(
    gui_server: ThreadingHTTPServer,
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _session_db(monkeypatch, tmp_path)
    for _ in range(3):
        status, saved = _save(gui_server, sample_binary, "n" * 400)
        assert status == 200, saved

    cap = 700
    monkeypatch.setattr(gui_server_module, "MAX_RESPONSE_BYTES", cap)
    port = gui_server.server_address[1]

    status, headers, body = _raw_get(gui_server, "/api/session_list", f"127.0.0.1:{port}")

    assert status == 200
    assert len(body) <= cap
    assert int(headers["Content-Length"]) == len(body)
    payload = json.loads(body.decode("utf-8"))
    assert payload["response_truncated"] is True
    assert len(payload["sessions"]) < 3


def test_session_save_requires_a_path(
    gui_server: ThreadingHTTPServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _session_db(monkeypatch, tmp_path)

    status, payload = _get(gui_server, "/api/session_save")

    assert status == 400
    assert "path" in payload["error"]


def test_session_save_rejects_an_oversized_note(
    gui_server: ThreadingHTTPServer,
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _session_db(monkeypatch, tmp_path)

    status, payload = _save(gui_server, sample_binary, "n" * (MAX_SESSION_NOTE_LENGTH + 1))

    assert status == 400
    assert "notes" in payload["error"]
    _, listing = _get(gui_server, "/api/session_list")
    assert listing["count"] == 0


def test_dashboard_page_has_a_sessions_panel() -> None:
    page = render_dashboard_html()

    for element_id in ("session-notes", "session-limit", "session-tbl", "session-wrap"):
        assert f'id="{element_id}"' in page
    assert (
        '<button type="button" id="session-save" class="primary" '
        'data-action="session_save">Save session</button>' in page
    )
    assert 'data-action="session_list">Refresh list</button>' in page
    # Both controls talk to the same-origin session routes only.
    assert 'session_save: "/api/session_save"' in page
    assert 'session_list: "/api/session_list"' in page
    # The table shows the fields the list route returns, in that order, and every
    # cell goes through textContent -- a path or a note is never markup.
    for column in ("session_id", "created_at", "path", "format", "architecture", "notes"):
        assert f'"{column}"' in page
    assert "SESSION_COLUMNS" in page
    assert "innerHTML" not in page


# ---------------------------------------------------------------------------
# lane routes: /bridges, /unknowns, /obligations, /compare, /nav, /metadata
# ---------------------------------------------------------------------------

#: Committed JSON artifacts the /compare happy paths compare offline.
SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"

#: The six routes this block adds to the dashboard.
LANE_ROUTES = (
    "/bridges",
    "/unknowns",
    "/obligations",
    "/compare",
    "/nav",
    "/metadata",
)


@pytest.fixture()
def unknowns_ledger(tmp_path: Path) -> Path:
    """A ledger file holding two open records and one resolved record."""
    records = [
        make_open_unknown(domain="functions", summary="unreached block at the tail"),
        make_open_unknown(domain="strings", summary="unlabeled blob in .data", severity="high"),
        resolve_record(
            make_open_unknown(domain="cfg", summary="loop exit unknown"),
            note="checked by hand",
        ),
    ]
    ledger = tmp_path / "unknowns.json"
    ledger.write_text(json.dumps(records_to_payload(records)), encoding="utf-8")
    return ledger


def test_lane_routes_are_registered_and_listed_by_health(
    gui_server: ThreadingHTTPServer,
) -> None:
    status, payload = _get(gui_server, "/api/health")

    assert status == 200
    assert set(payload["routes"]) == set(ROUTES)
    for route in LANE_ROUTES:
        assert route in payload["routes"]
    # Fourteen established routes plus the six lane routes.
    assert len(ROUTES) == 20
    # A near-miss spelling stays an unknown route: 404, never a silent match.
    miss_status, miss_payload = _get(gui_server, "/bridge")
    assert miss_status == 404
    assert "unknown route" in miss_payload["error"]


def test_bridges_reports_capability_records(
    gui_server: ThreadingHTTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The real probe walks PATH with per-tool subprocess budgets; the report is
    # served from canned records so the assertion is deterministic and offline.
    monkeypatch.setattr(
        gui_server_module,
        "bridges_report",
        lambda: [
            BridgeCapability(
                tool="binwalk", available=False, reason="binwalk is not installed"
            ),
            BridgeCapability(tool="z3", available=True, version="4.13.0"),
        ],
    )

    status, payload = _get(gui_server, "/bridges")

    assert status == 200
    assert payload["count"] == 2
    assert payload["available"] == 1
    assert payload["tools"][0]["tool"] == "binwalk"
    assert payload["tools"][0]["available"] is False
    assert payload["tools"][1]["version"] == "4.13.0"


def test_bridges_engine_failure_is_a_typed_400(
    gui_server: ThreadingHTTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom() -> list[BridgeCapability]:
        raise AnalysisError("probe runner exploded")

    monkeypatch.setattr(gui_server_module, "bridges_report", boom)

    status, payload = _get(gui_server, "/bridges")

    assert status == 400
    assert payload["error"] == "probe runner exploded"


def test_unknowns_lists_the_ledger(
    gui_server: ThreadingHTTPServer, unknowns_ledger: Path
) -> None:
    ledger = quote(unknowns_ledger.as_posix())

    status, payload = _get(gui_server, f"/unknowns?ledger={ledger}")

    assert status == 200
    assert payload["count"] == 3
    assert payload["returned"] == 3
    assert payload["truncated"] is False
    assert {item["domain"] for item in payload["items"]} == {"functions", "strings", "cfg"}
    assert {item["status"] for item in payload["items"]} == {"open", "resolved"}
    assert Path(payload["path"]) == unknowns_ledger

    status_two, two = _get(gui_server, f"/unknowns?ledger={ledger}&limit=2")

    assert status_two == 200
    assert two["count"] == 3
    assert two["returned"] == 2
    assert two["truncated"] is True


def test_unknowns_bad_inputs_are_typed_400s(
    gui_server: ThreadingHTTPServer, unknowns_ledger: Path, tmp_path: Path
) -> None:
    # Missing parameter.
    status, payload = _get(gui_server, "/unknowns")
    assert status == 400
    assert payload["error"] == "ledger is required"

    # Named file does not exist.
    missing = (tmp_path / "absent.json").as_posix()
    status, payload = _get(gui_server, f"/unknowns?ledger={quote(missing)}")
    assert status == 400
    assert "ledger does not exist" in payload["error"]

    # Out-of-bounds limit.
    status, payload = _get(
        gui_server, f"/unknowns?ledger={quote(unknowns_ledger.as_posix())}&limit=-1"
    )
    assert status == 400
    assert "limit" in payload["error"]

    # Malformed JSON.
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    status, payload = _get(gui_server, f"/unknowns?ledger={quote(bad.as_posix())}")
    assert status == 400
    assert "not valid JSON" in payload["error"]

    # Well-formed JSON that is not a valid ledger shape (engine validation).
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"items": "nope"}), encoding="utf-8")
    status, payload = _get(gui_server, f"/unknowns?ledger={quote(wrong.as_posix())}")
    assert status == 400
    assert "items" in payload["error"]


def test_unknowns_ledger_documents_are_read_bounded(
    gui_server: ThreadingHTTPServer, unknowns_ledger: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A ledger larger than the read budget is refused before it is parsed.
    monkeypatch.setattr(gui_server_module, "MAX_LEDGER_BYTES", 8)
    status, payload = _get(
        gui_server, f"/unknowns?ledger={quote(unknowns_ledger.as_posix())}"
    )
    assert status == 400
    assert "read budget" in payload["error"]

    # A JSON document that is not an object.
    monkeypatch.setattr(gui_server_module, "MAX_LEDGER_BYTES", 4 * 1024 * 1024)
    array_doc = tmp_path / "array.json"
    array_doc.write_text("[1, 2]", encoding="utf-8")
    status, payload = _get(gui_server, f"/unknowns?ledger={quote(array_doc.as_posix())}")
    assert status == 400
    assert "not a JSON object" in payload["error"]

    # A file that is not UTF-8 text at all.
    binary = tmp_path / "binary.json"
    binary.write_bytes(b"\xff\xfe\x00bad")
    status, payload = _get(gui_server, f"/unknowns?ledger={quote(binary.as_posix())}")
    assert status == 400
    assert "not UTF-8 text" in payload["error"]


def test_obligations_lists_the_ledger(
    gui_server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    obligations = pytest.importorskip("codevanta.core.obligations")
    record = obligations.make_open_obligation(
        question="verify the string table offset",
        evidence_refs=("report:sections",),
    )
    ledger = tmp_path / "obligations.json"
    ledger.write_text(
        json.dumps(obligations.obligations_to_payload([record])), encoding="utf-8"
    )

    status, payload = _get(gui_server, f"/obligations?ledger={quote(ledger.as_posix())}")

    assert status == 200
    assert payload["count"] == 1
    assert payload["returned"] == 1
    assert payload["items"][0]["question"] == "verify the string table offset"
    assert payload["items"][0]["status"] == "open"


def test_obligations_bad_inputs_are_typed_400s(
    gui_server: ThreadingHTTPServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Missing parameter (the module is present on this build, so the route
    # reaches the parameter validation).
    status, payload = _get(gui_server, "/obligations")
    assert status == 400
    assert payload["error"] == "ledger is required"

    # Named file does not exist.
    missing = (tmp_path / "absent.json").as_posix()
    status, payload = _get(gui_server, f"/obligations?ledger={quote(missing)}")
    assert status == 400
    assert "ledger does not exist" in payload["error"]

    # On a build without the ledger module the route answers the typed
    # "not available" payload instead of an import-time crash.
    monkeypatch.setattr(gui_server_module, "_obligations_module", None)
    any_file = tmp_path / "whatever.json"
    any_file.write_text("{}", encoding="utf-8")
    status, payload = _get(gui_server, f"/obligations?ledger={quote(any_file.as_posix())}")
    assert status == 400
    assert "not available" in payload["error"]
    assert "codevanta.core.obligations" in payload["error"]


def test_compare_dispatches_each_kind(gui_server: ThreadingHTTPServer) -> None:
    report = quote((SAMPLES_DIR / "report_elf64.json").as_posix())
    other = quote((SAMPLES_DIR / "report_notepad.json").as_posix())
    bundle = quote((SAMPLES_DIR / "report_bundle.json").as_posix())

    status_f, functions = _get(
        gui_server, f"/compare?left={report}&right={other}&what=functions"
    )
    assert status_f == 200
    assert functions["what"] == "functions"
    assert isinstance(functions["added"], list)

    # The default kind is "functions", like the CLI's --what default.
    status_d, default_kind = _get(gui_server, f"/compare?left={report}&right={other}")
    assert status_d == 200
    assert default_kind["what"] == "functions"

    status_s, strings = _get(
        gui_server, f"/compare?left={report}&right={other}&what=strings&max_strings=5"
    )
    assert status_s == 200
    assert strings["what"] == "strings"
    assert strings["max_strings"] == 5
    assert isinstance(strings["added"], list)

    status_b, bundles = _get(
        gui_server, f"/compare?left={bundle}&right={bundle}&what=bundles"
    )
    assert status_b == 200
    assert bundles["what"] == "bundles"
    assert bundles["added_count"] == 0
    assert bundles["changed_count"] == 0
    assert bundles["unchanged_count"] >= 1


def test_compare_bad_inputs_are_typed_400s(
    gui_server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    report = quote((SAMPLES_DIR / "report_elf64.json").as_posix())
    missing = quote((tmp_path / "absent.json").as_posix())

    # Unknown kind, with the supported kinds named in the error.
    status, payload = _get(gui_server, f"/compare?left={report}&right={report}&what=sounds")
    assert status == 400
    assert "what" in payload["error"]
    assert "bundles" in payload["error"]

    # Missing right parameter.
    status, payload = _get(gui_server, f"/compare?left={report}")
    assert status == 400
    assert payload["error"] == "right is required"

    # Left path does not exist.
    status, payload = _get(gui_server, f"/compare?left={missing}&right={report}")
    assert status == 400
    assert "left does not exist" in payload["error"]


def test_nav_returns_bookmarks_comments_and_cursor(
    gui_server: ThreadingHTTPServer,
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = _session_db(monkeypatch, tmp_path)
    status, saved = _save(gui_server, sample_binary)
    assert status == 200, saved
    session_id = saved["session_id"]

    # Seed the navigation state the read APIs serve, on the same database the
    # dashboard session routes wrote (same helper, same production path).
    with NavStore(db) as store:
        store.bookmark(session_id, 0x401000, "entry")
        store.comment(session_id, 0x402000, "string table here")
        store.goto(session_id, 0x401400)

    status, payload = _get(
        gui_server, f"/nav?db={quote(db.as_posix())}&session={quote(session_id)}"
    )

    assert status == 200
    assert payload["session_id"] == session_id
    assert [row["name"] for row in payload["bookmarks"]] == ["entry"]
    assert payload["bookmarks"][0]["address"] == "0x401000"
    assert [row["text"] for row in payload["comments"]] == ["string table here"]
    assert payload["cursor"] is not None
    assert payload["cursor"]["address"] == "0x401400"


def test_nav_bad_inputs_are_typed_400s(
    gui_server: ThreadingHTTPServer,
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = _session_db(monkeypatch, tmp_path)
    status, saved = _save(gui_server, sample_binary)
    assert status == 200, saved
    session_id = saved["session_id"]

    # Missing session parameter.
    status, payload = _get(gui_server, f"/nav?db={quote(db.as_posix())}")
    assert status == 400
    assert payload["error"] == "session is required"

    # A database that does not exist is refused (never created) by the route.
    missing_db = tmp_path / "absent.db"
    status, payload = _get(
        gui_server, f"/nav?db={quote(missing_db.as_posix())}&session={quote(session_id)}"
    )
    assert status == 400
    assert "db does not exist" in payload["error"]
    assert not missing_db.exists()

    # A session the database does not know: the engine's typed error, hint in.
    status, payload = _get(gui_server, f"/nav?db={quote(db.as_posix())}&session=zz-other")
    assert status == 400
    assert "zz-other" in payload["error"]


def test_metadata_detects_a_pyc_file(gui_server: ThreadingHTTPServer, tmp_path: Path) -> None:
    # A PEP 552 timestamp-based .pyc header (16 bytes): magic 3439, "\r\n",
    # flags 0, timestamp, source size. Bytecode is never read by the detector.
    pyc = tmp_path / "stripped.pyc"
    pyc.write_bytes(struct.pack("<H", 3439) + b"\r\n" + struct.pack("<III", 0, 0x5F000000, 16))

    status, payload = _get(gui_server, f"/metadata?path={quote(pyc.as_posix())}")

    assert status == 200
    assert payload["kind"] == "python-pyc"
    assert Path(payload["path"]) == pyc
    assert payload["details"]["pyc"]["magic"] == 3439
    assert isinstance(payload["evidence"], list)


def test_metadata_bad_inputs_are_typed_400s(
    gui_server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    # Missing parameter.
    status, payload = _get(gui_server, "/metadata")
    assert status == 400
    assert payload["error"] == "path is required"

    # Named path does not exist (the engine's typed error).
    missing = (tmp_path / "absent.bin").as_posix()
    status, payload = _get(gui_server, f"/metadata?path={quote(missing)}")
    assert status == 400
    assert "path does not exist" in payload["error"]

    # An existing file no detector claims.
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"\x00" * 64)
    status, payload = _get(gui_server, f"/metadata?path={quote(plain.as_posix())}")
    assert status == 400
    assert "unrecognized file format" in payload["error"]


def test_dashboard_page_has_the_lane_controls() -> None:
    page = render_dashboard_html()

    for element_id in (
        "uk-ledger",
        "uk-limit",
        "ob-ledger",
        "cmp-what",
        "nv-db",
        "nv-session",
        "md-path",
    ):
        assert f'id="{element_id}"' in page
    for action in LANE_ROUTES:
        assert f'data-action="{action.lstrip("/")}"' in page
    for endpoint in (
        'bridges: "/bridges"',
        'unknowns: "/unknowns"',
        'obligations: "/obligations"',
        'compare: "/compare"',
        'nav: "/nav"',
        'metadata: "/metadata"',
    ):
        assert endpoint in page
    # The lane controls build their own query strings and never fall through to
    # the generic "path" line, so the main binary input cannot leak into them.
    for line in (
        'addParam(parts, "ledger", fieldValue("uk-ledger"));',
        'addParam(parts, "what", fieldValue("cmp-what") || "functions");',
        'addParam(parts, "session", fieldValue("nv-session"));',
        'addParam(parts, "path", fieldValue("md-path"));',
    ):
        assert line in page
    assert "innerHTML" not in page
