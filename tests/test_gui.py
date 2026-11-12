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
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from codevanta.analysis.decompilers import available_backends
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
def gui_server() -> Iterator[ThreadingHTTPServer]:
    """A loopback dashboard server on an ephemeral port, started and stopped."""
    server = create_server("127.0.0.1", 0)
    thread = _start(server)
    try:
        yield server
    finally:
        _stop(server, thread)


def _url(server: ThreadingHTTPServer, path: str) -> str:
    """Return the absolute URL of ``path`` on ``server``."""
    host, port = server.server_address[0], server.server_address[1]
    return f"http://{host}:{port}{path}"


def _get(server: ThreadingHTTPServer, path: str) -> tuple[int, dict]:
    """GET ``path`` and return ``(status, payload)``, including error statuses."""
    try:
        with urllib.request.urlopen(_url(server, path), timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _get_text(server: ThreadingHTTPServer, path: str) -> tuple[int, str, str]:
    """GET ``path`` and return ``(status, content_type, body)`` as text."""
    with urllib.request.urlopen(_url(server, path), timeout=30) as response:
        return (
            response.status,
            response.headers.get("Content-Type", ""),
            response.read().decode("utf-8"),
        )


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
        request = urllib.request.Request(_url(gui_server, "/api/health"), method=method)
        if method == "POST":
            request.data = b""
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(request, timeout=30)
        assert excinfo.value.code == 405
        if method != "HEAD":
            payload = json.loads(excinfo.value.read().decode("utf-8"))
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


