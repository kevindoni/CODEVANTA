"""Plugin SDK tests: discovery without imports, bounded runs, built-ins.

The interesting properties are all negative ones: discovery must not import
anything, a broken distribution must not raise, an oversized or wrongly shaped
payload must not escape, and a plugin that overruns its budget must be reported
rather than silently accepted.  Entry point metadata is faked here instead of
installing a real distribution, so the tests pin *our* handling of the data
rather than the state of the machine.
"""

from __future__ import annotations

import json
import threading
import time
from importlib import metadata as importlib_metadata
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

import codevanta.plugins as plugins_module
from codevanta.core.report import AnalysisError
from codevanta.plugins import (
    DEFAULT_ENTRY_POINT_GROUP,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_SECONDS,
    METRICS_PLUGIN,
    AnalysisContext,
    AnalyzerPlugin,
    PluginInfo,
    build_context,
    builtin_plugins,
    canonical_json,
    discover,
    discovery_warnings,
    load,
    register,
    registry_snapshot,
    run_plugin,
    unregister,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "samples" / "elf64_text.bin"
GROUP = DEFAULT_ENTRY_POINT_GROUP


class FakePlugin:
    """An analyser that satisfies the protocol structurally, without inheriting."""

    name = "fake"
    version = "0.2"
    description = "Fake analyser used by the tests."

    def __init__(self, payload: Any = None) -> None:
        self.payload: Any = {"answer": 42} if payload is None else payload

    def analyze(self, context: AnalysisContext) -> Any:
        return self.payload


class SlowPlugin(FakePlugin):
    """Sleeps so the post-return time check has something to catch."""

    name = "slow"

    def analyze(self, context: AnalysisContext) -> Any:
        time.sleep(0.05)
        return {"slept": True}


class _FakeDist:
    """Stand-in for ``importlib.metadata.Distribution``."""

    def __init__(self, version: str = "1.2.3", summary: str | None = "Fake distribution") -> None:
        self._version = version
        self.metadata = {} if summary is None else {"Summary": summary}

    @property
    def version(self) -> str:
        if self._version == "broken":
            raise RuntimeError("metadata is corrupt")
        return self._version


class _FakeEntryPoint:
    """Stand-in for ``importlib.metadata.EntryPoint`` that records ``load()``."""

    def __init__(
        self,
        name: str,
        value: str = "fake_module:plugin",
        *,
        version: str = "1.2.3",
        summary: str | None = "Fake distribution",
        loads: Any = None,
    ) -> None:
        self.name = name
        self.value = value
        self.load_calls = 0
        self._dist = _FakeDist(version, summary)
        self._loads = loads

    @property
    def dist(self) -> _FakeDist:
        return self._dist

    def load(self) -> Any:
        self.load_calls += 1
        if self._loads is None:
            raise AssertionError("discover() must not import plugins")
        if isinstance(self._loads, BaseException):
            raise self._loads
        return self._loads


def _fake_entry_points(monkeypatch: pytest.MonkeyPatch, entry_points: list[_FakeEntryPoint]) -> None:
    """Replace the metadata module used by ``codevanta.plugins`` with a stub."""

    def entry_points_for(group: str) -> list[_FakeEntryPoint]:
        assert group, "the group must never be empty"
        return list(entry_points)

    monkeypatch.setattr(plugins_module, "metadata", SimpleNamespace(entry_points=entry_points_for))


@pytest.fixture()
def context() -> AnalysisContext:
    """A real context over the committed ELF sample."""
    return build_context(SAMPLE)


@pytest.fixture()
def restore_registry() -> Any:
    """Leave the built-in registry exactly as it was found."""
    before = registry_snapshot()
    try:
        yield
    finally:
        for name in registry_snapshot():
            if name not in before:
                unregister(name)
        for plugin in before.values():
            register(plugin)


# ---- PluginInfo -------------------------------------------------------------


def test_plugin_info_normalises_and_is_json_safe() -> None:
    info = PluginInfo(name="  spaced  ", version="", kind="Analyzer", entry_point=" mod:obj ")
    assert info.name == "spaced"
    assert info.version == "unknown"
    assert info.kind == "analyzer"
    assert info.entry_point == "mod:obj"
    assert json.loads(json.dumps(info.to_dict()))["name"] == "spaced"


def test_plugin_info_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="unknown kind"):
        PluginInfo(name="x", version="1", kind="transformer", entry_point="m:o")


def test_protocol_is_structural_and_runtime_checkable() -> None:
    assert isinstance(FakePlugin(), AnalyzerPlugin), "no inheritance required"
    assert not isinstance(object(), AnalyzerPlugin)


# ---- discovery --------------------------------------------------------------


def test_discover_returns_empty_tuple_without_registered_plugins() -> None:
    declared = list(importlib_metadata.entry_points(group=GROUP))
    if declared:  # pragma: no cover - only if a plugin is installed on this machine
        pytest.skip("this environment declares codevanta.analyzers entry points")
    assert discover() == ()
    assert isinstance(discover(), tuple)


def test_discover_never_imports_a_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    entry_point = _FakeEntryPoint("never-imported")
    _fake_entry_points(monkeypatch, [entry_point])

    found = discover(GROUP)

    assert [info.name for info in found] == ["never-imported"]
    assert found[0].version == "1.2.3"
    assert found[0].kind == "analyzer"
    assert entry_point.load_calls == 0, "discover() must read metadata only"


def test_discover_sorts_by_name_and_infers_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_entry_points(monkeypatch, [_FakeEntryPoint("zeta"), _FakeEntryPoint("alpha")])
    assert [info.name for info in discover(GROUP)] == ["alpha", "zeta"]

    _fake_entry_points(monkeypatch, [_FakeEntryPoint("export")])
    assert discover("example.exporters")[0].kind == "exporter"
    _fake_entry_points(monkeypatch, [_FakeEntryPoint("provider")])
    assert discover("example.providers")[0].kind == "provider"


def test_discover_tolerates_broken_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_entry_points(
        monkeypatch,
        [
            _FakeEntryPoint(""),  # no name at all
            _FakeEntryPoint("no-target", value=""),
            _FakeEntryPoint("bad-version", version="broken"),
            _FakeEntryPoint("duplicate"),
            _FakeEntryPoint("duplicate", value="other:thing"),
        ],
    )

    found = discover(GROUP)
    warnings = discovery_warnings()

    assert [info.name for info in found] == ["bad-version", "duplicate"]
    assert next(i for i in found if i.name == "bad-version").version == "unknown"
    assert next(i for i in found if i.name == "duplicate").entry_point == "fake_module:plugin"
    joined = " | ".join(warnings)
    assert "declares no name" in joined
    assert "declares no importable target" in joined
    assert "unreadable version metadata" in joined
    assert "duplicate entry point" in joined


def test_discover_survives_unreadable_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(group: str) -> list[Any]:
        raise RuntimeError("distribution database is corrupt")

    monkeypatch.setattr(
        plugins_module, "metadata", SimpleNamespace(entry_points=explode)
    )

    assert discover(GROUP) == ()
    assert "cannot read entry points" in " ".join(discovery_warnings())


def test_discover_rejects_empty_group() -> None:
    with pytest.raises(AnalysisError, match="group must not be empty"):
        discover("  ")


# ---- loading ----------------------------------------------------------------


def test_load_unknown_plugin_raises_analysis_error() -> None:
    with pytest.raises(AnalysisError) as raised:
        load(GROUP, "definitely-not-installed")
    message = str(raised.value)
    assert "definitely-not-installed" in message
    assert GROUP in message


def test_load_rejects_empty_name() -> None:
    with pytest.raises(AnalysisError, match="name must not be empty"):
        load(GROUP, "   ")


def test_load_returns_registered_builtin(restore_registry: Any) -> None:
    fake = FakePlugin()
    register(fake)

    assert load(GROUP, "fake") is fake
    assert registry_snapshot()["fake"] is fake


def test_load_imports_the_entry_point_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakePlugin()
    entry_point = _FakeEntryPoint("lazy", loads=fake)
    _fake_entry_points(monkeypatch, [entry_point])

    assert load(GROUP, "lazy") is fake
    assert entry_point.load_calls == 1


def test_load_reports_import_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_entry_points(monkeypatch, [_FakeEntryPoint("broken", loads=ImportError("no such module"))])

    with pytest.raises(AnalysisError) as raised:
        load(GROUP, "broken")
    assert "broken" in str(raised.value)
    assert "failed to import" in str(raised.value)


def test_load_rejects_duplicate_declarations(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_entry_points(
        monkeypatch,
        [_FakeEntryPoint("twice", loads=FakePlugin()), _FakeEntryPoint("twice", loads=FakePlugin())],
    )

    with pytest.raises(AnalysisError, match="declared 2 times"):
        load(GROUP, "twice")


def test_load_rejects_object_without_analyze(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_entry_points(monkeypatch, [_FakeEntryPoint("hollow", loads=SimpleNamespace(name="hollow"))])

    with pytest.raises(AnalysisError) as raised:
        load(GROUP, "hollow")
    assert "analyze" in str(raised.value)


# ---- running ----------------------------------------------------------------


def test_run_plugin_returns_a_bounded_result(context: AnalysisContext) -> None:
    result = run_plugin(FakePlugin({"answer": 42, "warnings": ["a note", 7]}), context)

    assert result.payload == {"answer": 42, "warnings": ["a note", 7]}
    assert result.warnings == ("a note",), "non-string warnings are dropped"
    assert result.plugin.name == "fake"
    assert result.plugin.kind == "analyzer"
    assert result.elapsed_ms >= 0.0
    assert result.evidence is not None
    assert result.evidence.extra["payload_bytes"] > 0


def test_run_plugin_accepts_any_mapping_implementation(context: AnalysisContext) -> None:
    payload = MappingProxyType({"mapping": "proxy"})
    assert run_plugin(FakePlugin(payload), context).payload == {"mapping": "proxy"}


def test_run_plugin_rejects_oversized_payload(context: AnalysisContext) -> None:
    oversized = FakePlugin({"blob": "x" * 4096})

    with pytest.raises(AnalysisError) as raised:
        run_plugin(oversized, context, max_bytes=256)
    assert "over the 256-byte limit" in str(raised.value)
    assert "'fake'" in str(raised.value)


def test_run_plugin_rejects_non_mapping_payload(context: AnalysisContext) -> None:
    with pytest.raises(AnalysisError) as raised:
        run_plugin(FakePlugin(["not", "a", "mapping"]), context)
    assert "returned list" in str(raised.value)
    assert "expected a mapping" in str(raised.value)


def test_run_plugin_rejects_non_json_payload(context: AnalysisContext) -> None:
    with pytest.raises(AnalysisError, match="not JSON-serialisable"):
        run_plugin(FakePlugin({"value": object()}), context)


def test_run_plugin_rejects_plugin_without_analyze(context: AnalysisContext) -> None:
    class Hollow:
        name = "hollow"

    with pytest.raises(AnalysisError) as raised:
        run_plugin(Hollow(), context)  # type: ignore[arg-type]
    assert "hollow" in str(raised.value)
    assert "analyze" in str(raised.value)


def test_run_plugin_rejects_a_string_instead_of_a_plugin(context: AnalysisContext) -> None:
    with pytest.raises(AnalysisError, match="call load\\(\\) first"):
        run_plugin("fake", context)  # type: ignore[arg-type]


def test_run_plugin_rejects_a_context_of_the_wrong_type() -> None:
    with pytest.raises(AnalysisError, match="needs an AnalysisContext"):
        run_plugin(FakePlugin(), "not a context")  # type: ignore[arg-type]


def test_run_plugin_reports_timeout_after_return(context: AnalysisContext) -> None:
    with pytest.raises(AnalysisError) as raised:
        run_plugin(SlowPlugin(), context, max_seconds=0.01)
    message = str(raised.value)
    assert "'slow'" in message
    assert "budget" in message
    assert "cannot be interrupted" in message


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"max_seconds": 0}, "max_seconds must be finite and > 0"),
        ({"max_seconds": float("inf")}, "max_seconds must be finite and > 0"),
        ({"max_seconds": "30"}, "max_seconds must be a number"),
        ({"max_bytes": 0}, "max_bytes must be >= 1"),
        ({"max_bytes": True}, "max_bytes must be an integer"),
    ],
)
def test_run_plugin_rejects_invalid_budgets(
    context: AnalysisContext, kwargs: dict[str, Any], match: str
) -> None:
    with pytest.raises(AnalysisError, match=match):
        run_plugin(FakePlugin(), context, **kwargs)


def test_default_budgets_are_the_documented_ones() -> None:
    assert DEFAULT_MAX_SECONDS == 30.0
    assert DEFAULT_MAX_BYTES == 4 * 1024 * 1024


# ---- canonical JSON and result serialisation --------------------------------


def test_canonical_json_is_stable_and_ascii_escaped() -> None:
    payload = {"b": 1, "a": "caf\u00e9"}
    first = canonical_json(payload)
    second = canonical_json({"a": "caf\u00e9", "b": 1})

    assert first == second == b'{"a":"caf\\u00e9","b":1}'


def test_canonical_json_rejects_nan() -> None:
    with pytest.raises(AnalysisError, match="not JSON-serialisable"):
        canonical_json({"value": float("nan")})


def test_result_to_dict_is_json_safe(context: AnalysisContext) -> None:
    result = run_plugin(METRICS_PLUGIN, context)
    document = json.loads(json.dumps(result.to_dict(), allow_nan=False))

    assert document["plugin"]["name"] == "metrics"
    assert document["payload"]["function_count"] == result.payload["function_count"]
    assert document["evidence"]["source"] == "plugin.metrics"


# ---- built-in registry ------------------------------------------------------


def test_register_describes_the_plugin(restore_registry: Any) -> None:
    info = register(FakePlugin())

    assert info == PluginInfo(
        name="fake",
        version="0.2",
        kind="analyzer",
        entry_point=f"{FakePlugin.__module__}:{FakePlugin.__qualname__}",
        description="Fake analyser used by the tests.",
    )
    assert [plugin.name for plugin in builtin_plugins()] == ["fake", "metrics"]


def test_unregister_is_idempotent(restore_registry: Any) -> None:
    register(FakePlugin())

    assert unregister("fake") is True
    assert unregister("fake") is False
    assert "fake" not in registry_snapshot()


def test_registry_snapshot_is_a_copy() -> None:
    snapshot = registry_snapshot()
    snapshot.clear()
    assert "metrics" in registry_snapshot()


def test_registry_is_thread_safe(restore_registry: Any) -> None:
    def worker(index: int) -> None:
        plugin = FakePlugin()
        plugin.name = f"thread-{index}"
        register(plugin)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    names = {name for name in registry_snapshot() if name.startswith("thread-")}
    assert names == {f"thread-{index}" for index in range(8)}


def test_register_rejects_object_without_name() -> None:
    class Anonymous:
        def analyze(self, context: AnalysisContext) -> dict[str, Any]:
            return {}

    with pytest.raises(AnalysisError, match="no usable 'name'"):
        register(Anonymous())  # type: ignore[arg-type]


# ---- built-in metrics analyser ----------------------------------------------


def test_metrics_plugin_is_wired_and_loadable() -> None:
    names = [info.name for info in builtin_plugins()]

    assert names == sorted(names)
    assert "metrics" in names
    assert load(GROUP, "metrics") is METRICS_PLUGIN
    assert load(name="metrics") is METRICS_PLUGIN


def test_metrics_plugin_runs_on_the_elf_sample(context: AnalysisContext) -> None:
    result = run_plugin(METRICS_PLUGIN, context)
    payload = result.payload

    assert context.path == SAMPLE
    assert payload["format"] == "ELF"
    assert payload["architecture"] == "x86_64"
    assert payload["bitness"] == 64
    assert payload["entry_point"] == "0x401000"
    assert payload["function_count"] >= 1
    assert payload["string_count"] >= 1
    assert payload["distinct_string_count"] <= payload["string_count"]
    assert payload["budget"] == {"max_strings": 5000}
    assert result.warnings == (), "the sample is far below the string budget"


def test_metrics_plugin_honours_its_budget() -> None:
    context = build_context(SAMPLE, budget={"max_strings": 1})
    result = run_plugin(METRICS_PLUGIN, context)

    assert result.payload["budget"] == {"max_strings": 1}
    assert result.payload["string_count"] == 1
    assert len(result.warnings) == 1
    assert "lower bound" in result.warnings[0]


def test_metrics_plugin_clamps_an_absurd_budget() -> None:
    context = build_context(SAMPLE, budget={"max_strings": 10**9})
    assert run_plugin(METRICS_PLUGIN, context).payload["budget"]["max_strings"] == 200_000


# ---- context ----------------------------------------------------------------


def test_build_context_defaults_address_and_freezes_budget() -> None:
    context = build_context(SAMPLE, budget={"max_strings": 10})

    assert context.address == 0x401000
    assert context.path == SAMPLE
    assert context.info.bitness == 64
    assert len(context.functions) >= 1
    with pytest.raises(TypeError):
        context.budget["max_strings"] = 5  # type: ignore[index]


def test_build_context_accepts_precomputed_functions() -> None:
    context = build_context(SAMPLE, functions=[])

    assert context.functions == ()
    assert context.address == 0x401000
