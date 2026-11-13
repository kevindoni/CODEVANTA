"""Plugin SDK: discover, load and run analysers without touching the core.

An analyser that ships outside the package must not require an edit inside it.
Three functions make that possible:

* :func:`discover` reads the ``codevanta.analyzers`` entry point group through
  :mod:`importlib.metadata` and returns :class:`PluginInfo` records.  It
  **never imports** a plugin: discovery only touches distribution metadata, so
  listing what is installed cannot execute third-party code.
* :func:`load` imports one plugin lazily, by name, and validates the object
  before handing it back.  A broken import or a wrong interface becomes an
  :class:`~codevanta.core.report.AnalysisError` that names the plugin, so one
  bad plugin cannot take the caller down with an arbitrary traceback.
* :func:`run_plugin` is the only place a plugin actually runs, and it is the
  chokepoint for the two limits that matter: wall-clock time and payload size.

The contract is deliberately tiny -- one dataclass in, one mapping out::

    class MyAnalyzer:
        name = "my-analyzer"
        version = "1.0"
        description = "Counts something interesting."

        def analyze(self, context: AnalysisContext) -> Mapping[str, Any]:
            return {"count": len(context.functions)}

That object satisfies :class:`AnalyzerPlugin` structurally; it does not have to
import this module or subclass anything.

Safety limits
-------------

* **Time.** ``run_plugin`` measures the call with ``perf_counter`` and rejects
  a run over ``max_seconds`` (default :data:`DEFAULT_MAX_SECONDS`, 30 s).
  Python cannot kill a thread that is stuck inside third-party code, so the
  budget is **checked on return, not enforced during the call**: a plugin that
  never returns still hangs the caller.  Run untrusted plugins in a subprocess
  if that matters; for the pure-Python, read-only analysers this SDK targets,
  a post-return check still stops a merely slow plugin from bloating a sweep.
* **Size.** The payload is reduced to canonical JSON and rejected above
  ``max_bytes`` (default :data:`DEFAULT_MAX_BYTES`, 4 MiB).  The cap is checked
  *before* the time budget, so an oversized payload is always reported as
  oversized rather than as a timeout.  Serialising first also rejects payloads
  that are not JSON-safe (``NaN``, arbitrary objects), which keeps every
  :class:`PluginResult` exportable.
* **Shape.** Only a ``Mapping`` is accepted as a payload; anything else is an
  :class:`AnalysisError` naming the plugin and the type it returned.

Built-in registry
-----------------

Analysers wired inside the package live in a process-local, lock-guarded dict
(:func:`register` / :func:`unregister`).  :func:`load` consults it before entry
points, so an internal analyser is reachable by name without being installable,
and tests can register a throw-away analyser and drive it through the same code
path as an installed plugin.  :func:`builtin_plugins` describes whatever is
registered; no plugin code runs at import time.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast, runtime_checkable

from codevanta.core.functions import FunctionCandidate, discover_functions
from codevanta.core.loader import BinaryInfo
from codevanta.core.report import MAX_STRING_LIMIT, AnalysisError, load_binary
from codevanta.core.strings import StringExtractor
from codevanta.evidence.confidence import Confidence
from codevanta.evidence.models import Evidence

#: Entry point group scanned for analysers unless the caller says otherwise.
DEFAULT_ENTRY_POINT_GROUP = "codevanta.analyzers"

KIND_ANALYZER = "analyzer"
KIND_EXPORTER = "exporter"
KIND_PROVIDER = "provider"
#: The three plugin kinds this SDK knows how to describe.
PLUGIN_KINDS = frozenset({KIND_ANALYZER, KIND_EXPORTER, KIND_PROVIDER})

#: Wall-clock budget for one plugin run, in seconds.
DEFAULT_MAX_SECONDS = 30.0
#: Ceiling on the canonical-JSON size of one plugin payload (4 MiB).
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
#: Strings the built-in metrics analyser reads per run.
DEFAULT_MAX_STRINGS = 5000

#: Version reported when a distribution does not declare one.
UNKNOWN_VERSION = "unknown"

#: Plugin kinds keyed by entry point group suffix.
_KIND_BY_GROUP_SUFFIX: dict[str, str] = {
    "analyzer": KIND_ANALYZER,
    "analyzers": KIND_ANALYZER,
    "exporter": KIND_EXPORTER,
    "exporters": KIND_EXPORTER,
    "provider": KIND_PROVIDER,
    "providers": KIND_PROVIDER,
}

@dataclass(frozen=True)
class PluginInfo:
    """What is known about a plugin without importing it.

    Attributes:
        name: Entry point name / registry key; unique per group.
        version: Declaring distribution's version, or ``"unknown"``.
        kind: One of :data:`PLUGIN_KINDS`.
        entry_point: The ``module:attribute`` reference as declared.
        description: One-line summary from the distribution metadata, if any.

    Raises:
        ValueError: When the name is blank or the kind is not a known kind.
    """

    name: str
    version: str
    kind: str
    entry_point: str
    description: str = ""

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("plugin name must not be empty")
        kind = self.kind.strip().lower()
        if kind not in PLUGIN_KINDS:
            raise ValueError(
                f"plugin {name!r} has unknown kind {self.kind!r}; "
                f"expected one of {sorted(PLUGIN_KINDS)}"
            )
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "version", self.version.strip() or UNKNOWN_VERSION)
        object.__setattr__(self, "entry_point", self.entry_point.strip())
        object.__setattr__(self, "description", self.description.strip())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe description of the plugin."""
        return {
            "name": self.name,
            "version": self.version,
            "kind": self.kind,
            "entry_point": self.entry_point,
            "description": self.description,
        }


@dataclass(frozen=True)
class AnalysisContext:
    """Everything an analyser is given: the subject, and a budget.

    Attributes:
        path: The file under analysis (bytes, not a parsed copy).
        info: Normalized binary metadata from the loader.
        address: Focus address for address-scoped analysers; :func:`build_context`
            defaults it to the entry point.
        functions: Pre-discovered function candidates, so a plugin does not
            repeat work the core already did.
        budget: Plugin-specific integer limits (e.g. ``{"max_strings": 5000}``),
            read-only for the plugin.
    """

    path: Path
    info: BinaryInfo
    address: int | None = None
    functions: tuple[FunctionCandidate, ...] = ()
    budget: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path))
        object.__setattr__(self, "functions", tuple(self.functions))
        object.__setattr__(self, "budget", MappingProxyType(dict(self.budget)))


@runtime_checkable
class AnalyzerPlugin(Protocol):
    """Structural contract for an analyser plugin.

    No base class is required: any object with these three attributes and an
    ``analyze`` method works, which keeps plugins independent of CODEVANTA's
    release cadence.
    """

    name: str
    version: str
    description: str

    def analyze(self, context: AnalysisContext) -> Mapping[str, Any]:
        """Analyse ``context`` and return a JSON-serialisable mapping."""
        ...


@dataclass(frozen=True)
class PluginResult:
    """The bounded outcome of one :func:`run_plugin` call.

    Attributes:
        plugin: Description of the plugin that produced the payload.
        payload: The mapping the plugin returned (a shallow copy).
        elapsed_ms: Measured run time in milliseconds.
        warnings: Warnings lifted out of ``payload["warnings"]``.
        evidence: Provenance for the run, including the payload size.
    """

    plugin: PluginInfo
    payload: Mapping[str, Any]
    elapsed_ms: float
    warnings: tuple[str, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation, ready for a report or a bundle."""
        data: dict[str, Any] = {
            "plugin": self.plugin.to_dict(),
            "payload": dict(self.payload),
            "elapsed_ms": round(float(self.elapsed_ms), 3),
            "warnings": list(self.warnings),
        }
        if self.evidence is not None:
            data["evidence"] = self.evidence.to_dict()
        return data


# ---- built-in registry ------------------------------------------------------

#: Process-local registry of plugins wired inside the package (and, in tests,
#: registered by hand).  Guarded by ``_REGISTRY_LOCK``: built-ins are registered
#: once at import and read from any thread thereafter.
_REGISTRY: dict[str, AnalyzerPlugin] = {}
_REGISTRY_LOCK = threading.RLock()

#: Warnings produced by the most recent :func:`discover` call.
_DISCOVERY_WARNINGS: tuple[str, ...] = ()


def register(plugin: AnalyzerPlugin) -> PluginInfo:
    """Register ``plugin`` under its own name and return its description.

    Registering the same name twice replaces the previous object, which is how
    an internal analyser gets swapped out during development.

    Raises:
        AnalysisError: When the object does not satisfy :class:`AnalyzerPlugin`
            (no usable ``name``, no callable ``analyze``).
    """
    validated = _validate_plugin(plugin, source="plugin")
    info = _plugin_info(validated)
    with _REGISTRY_LOCK:
        _REGISTRY[info.name] = validated
    return info


def unregister(name: str) -> bool:
    """Remove ``name`` from the registry; return whether it was there.

    Idempotent on purpose, so a test can clean up in a ``finally`` block
    without first checking what it managed to register.
    """
    key = (name or "").strip()
    with _REGISTRY_LOCK:
        return _REGISTRY.pop(key, None) is not None


def registry_snapshot() -> dict[str, AnalyzerPlugin]:
    """Return a shallow copy of the registry, safe to iterate while mutating."""
    with _REGISTRY_LOCK:
        return dict(_REGISTRY)


def builtin_plugins() -> tuple[PluginInfo, ...]:
    """Describe the plugins currently wired into this process, sorted by name.

    This is the live registry, not a static list: a plugin registered by a
    caller (a test, say) shows up here too, which is what makes the built-in
    path testable end to end.
    """
    with _REGISTRY_LOCK:
        plugins = list(_REGISTRY.values())
    return tuple(sorted((_plugin_info(plugin) for plugin in plugins), key=lambda i: i.name))


def discovery_warnings() -> tuple[str, ...]:
    """Return the warnings collected by the last :func:`discover` call."""
    with _REGISTRY_LOCK:
        return _DISCOVERY_WARNINGS


# ---- discovery and loading --------------------------------------------------


def discover(entry_point_group: str = DEFAULT_ENTRY_POINT_GROUP) -> tuple[PluginInfo, ...]:
    """List the plugins declared in ``entry_point_group``, sorted by name.

    Only distribution metadata is read -- no entry point is loaded -- so
    enumerating what is installed never executes plugin code.  Broken metadata
    degrades the result instead of raising it: an entry point without a name or
    without a target is skipped, an unreadable version falls back to
    ``"unknown"``, a name declared twice is kept once, and each of those
    records a warning retrievable through :func:`discovery_warnings`.

    Args:
        entry_point_group: Entry point group to scan.

    Returns:
        One :class:`PluginInfo` per declared plugin, sorted by name.  An empty
        tuple when nothing is installed for the group -- never an exception.
    """
    group = _group_name(entry_point_group)
    warnings: list[str] = []
    try:
        declared = list(metadata.entry_points(group=group))
    except Exception as exc:  # noqa: BLE001 - distribution metadata is external data
        _store_discovery_warnings(
            (f"{group}: cannot read entry points ({exc}); no plugins discovered",)
        )
        return ()

    found: dict[str, PluginInfo] = {}
    for entry_point in sorted(declared, key=_ep_name):
        label = _ep_name(entry_point) or "?"
        try:
            info, warning = _info_from_entry_point(entry_point, group)
        except Exception as exc:  # noqa: BLE001 - one bad entry point must not win
            warnings.append(f"{group}: skipped entry point {label!r} ({exc})")
            continue
        if warning is not None:
            warnings.append(warning)
        if info.name in found:
            warnings.append(
                f"{group}: duplicate entry point {info.name!r} ignored "
                f"({found[info.name].entry_point!r} already declared)"
            )
            continue
        found[info.name] = info

    _store_discovery_warnings(tuple(warnings))
    return tuple(found[name] for name in sorted(found))


def load(
    entry_point_group: str = DEFAULT_ENTRY_POINT_GROUP,
    name: str = "",
) -> AnalyzerPlugin:
    """Import and return the plugin called ``name``, validating its interface.

    The built-in registry is consulted first, so an internal analyser is
    reachable by name whether or not anything is installed.  Otherwise the
    entry point is imported now -- lazily, and only for the one plugin asked
    for.

    Args:
        entry_point_group: Entry point group to search.
        name: Plugin name, as declared by the entry point or the registry.

    Returns:
        The plugin object, validated against :class:`AnalyzerPlugin`.

    Raises:
        AnalysisError: When the name is empty or unknown, when the import
            fails, or when the imported object does not implement the
            interface.  The message always names the plugin.
    """
    key = (name or "").strip()
    if not key:
        raise AnalysisError("plugin name must not be empty")
    group = _group_name(entry_point_group)

    with _REGISTRY_LOCK:
        builtin = _REGISTRY.get(key)
    if builtin is not None:
        return _validate_plugin(builtin, source=f"plugin {key!r} (built-in)")

    try:
        declared = [ep for ep in metadata.entry_points(group=group) if _ep_name(ep) == key]
    except Exception as exc:  # noqa: BLE001 - distribution metadata is external data
        raise AnalysisError(f"cannot read entry points for {group!r}: {exc}") from exc

    if not declared:
        raise AnalysisError(f"no plugin {key!r} in entry point group {group!r}")
    if len(declared) > 1:
        raise AnalysisError(
            f"plugin {key!r} is declared {len(declared)} times in {group!r}; "
            "refusing to guess which one to load"
        )

    try:
        loaded = declared[0].load()
    except Exception as exc:  # noqa: BLE001 - arbitrary import-time failure
        raise AnalysisError(f"plugin {key!r} failed to import: {exc}") from exc
    if isinstance(loaded, type) and not callable(getattr(loaded, "analyze", None)):
        # An entry point can point at a class rather than an instance; say so
        # instead of reporting a bare "no analyze()".
        raise AnalysisError(
            f"plugin {key!r} resolves to the class {loaded.__name__}; "
            "point the entry point at an instance instead"
        )
    return _validate_plugin(loaded, source=f"plugin {key!r}")


# ---- running ----------------------------------------------------------------


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """Serialise ``payload`` as canonical JSON bytes.

    Canonical means ``sort_keys``, ``separators=(",", ":")``, ASCII-escaped and
    NaN-free, matching the rest of the project, so two runs of the same plugin
    on the same input serialise to identical bytes.

    Raises:
        AnalysisError: When the payload is not JSON-serialisable.
    """
    try:
        text = json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise AnalysisError(f"payload is not JSON-serialisable: {exc}") from exc
    return text.encode("utf-8")


def run_plugin(
    plugin: AnalyzerPlugin,
    context: AnalysisContext,
    *,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> PluginResult:
    """Run ``plugin`` against ``context`` under a time and size budget.

    Checks are applied in this order: the plugin interface, the payload shape,
    the canonical-JSON byte cap, then the time budget.  The time budget is
    measured with ``perf_counter`` and therefore checked *after* the call
    returned -- the call is not interruptible (see the module docstring), so a
    hung plugin still hangs the caller, and the byte cap is deliberately
    enforced first so an oversized payload is never masked by a slow run.

    Args:
        plugin: The plugin object, not its name (:func:`load` resolves names).
        context: Subject and budget handed to ``analyze``.
        max_seconds: Wall-clock budget for the call, in seconds.
        max_bytes: Ceiling on the canonical-JSON size of the payload.

    Returns:
        A :class:`PluginResult` carrying the payload, the measured time, any
        warnings lifted out of ``payload["warnings"]`` and the run's evidence.

    Raises:
        AnalysisError: When the plugin is malformed, returns a non-mapping,
        exceeds either budget, or when a budget argument is invalid.
    """
    if isinstance(plugin, str):
        raise AnalysisError("run_plugin takes a plugin object, not a name; call load() first")
    validated = _validate_plugin(plugin, source="plugin")
    if not isinstance(context, AnalysisContext):
        raise AnalysisError(f"run_plugin needs an AnalysisContext, got {type(context).__name__}")
    seconds = _budget_seconds(max_seconds)
    limit = _budget_bytes(max_bytes)

    label = _plugin_label(validated)
    started = time.perf_counter()
    payload = validated.analyze(context)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    if not isinstance(payload, Mapping):
        raise AnalysisError(
            f"plugin {label} returned {type(payload).__name__}, expected a mapping"
        )
    try:
        data = canonical_json(payload)
    except AnalysisError as exc:
        raise AnalysisError(f"plugin {label}: {exc}") from exc
    if len(data) > limit:
        raise AnalysisError(
            f"plugin {label} produced {len(data)} bytes of JSON, over the {limit}-byte limit"
        )
    if elapsed_ms > seconds * 1000.0:
        raise AnalysisError(
            f"plugin {label} took {elapsed_ms:.1f} ms, over its {seconds:.3f} s budget "
            "(measured after return; the call cannot be interrupted)"
        )

    info = _plugin_info(validated)
    return PluginResult(
        plugin=info,
        payload=dict(payload),
        elapsed_ms=round(elapsed_ms, 3),
        warnings=_payload_warnings(payload),
        evidence=Evidence(
            source=f"plugin.{info.name}",
            method="plugin.analyze",
            confidence=Confidence.MEDIUM,
            detail=(
                f"ran to completion, {len(data)} bytes of JSON in {elapsed_ms:.1f} ms; "
                "the harness vouches for the run, not for the plugin's method"
            ),
            extra={
                "plugin": info.name,
                "version": info.version,
                "payload_bytes": len(data),
                "elapsed_ms": round(elapsed_ms, 3),
            },
        ),
    )


def build_context(
    path: str | Path,
    *,
    address: int | None = None,
    functions: Iterable[FunctionCandidate] | None = None,
    budget: Mapping[str, int] | None = None,
) -> AnalysisContext:
    """Load ``path`` and assemble the :class:`AnalysisContext` for a run.

    Convenience for callers (and tests) that want one obvious way from a file
    to a runnable context: the binary is loaded, functions are discovered
    unless supplied, and ``address`` falls back to the entry point.

    Args:
        path: Binary to analyse.
        address: Focus address; defaults to the entry point (may stay ``None``).
        functions: Pre-computed candidates, skipping discovery when given.
        budget: Plugin-specific integer limits.

    Raises:
        BinaryLoadError: When the file cannot be loaded (propagated from the
            loader, which already names the offending path).
    """
    binary_path = Path(path)
    info = load_binary(binary_path)
    discovered: tuple[FunctionCandidate, ...]
    if functions is None:
        discovered = tuple(discover_functions(info))
    else:
        discovered = tuple(functions)
    return AnalysisContext(
        path=binary_path,
        info=info,
        address=info.entry_point if address is None else address,
        functions=discovered,
        budget=dict(budget or {}),
    )


class MetricsAnalyzer:
    """Built-in analyser: counts functions and strings via the public API.

    Deliberately unambitious.  It exists to prove the plugin path end to end
    (registry -> :func:`load` -> :func:`run_plugin` -> bounded JSON) with an
    analyser whose numbers the core can independently check, and to show how a
    plugin honours a budget from :class:`AnalysisContext`.
    """

    name = "metrics"
    version = "1.0"
    description = "Function and string counts from the public CODEVANTA analysis API."

    def analyze(self, context: AnalysisContext) -> dict[str, Any]:
        """Return counts plus the shape of the subject, bounded by the budget."""
        max_strings = _budget_within(context.budget.get("max_strings", DEFAULT_MAX_STRINGS))
        strings = StringExtractor().extract(context.path, context.info, limit=max_strings)
        functions = context.functions
        named = sum(1 for candidate in functions if candidate.name)
        warnings: list[str] = []
        if len(strings) >= max_strings:
            warnings.append(
                f"string scan stopped at the {max_strings}-string budget; "
                "string_count is a lower bound"
            )
        entry_point = context.info.entry_point
        return {
            "format": context.info.format,
            "architecture": context.info.architecture,
            "bitness": context.info.bitness,
            "endianness": context.info.endianness,
            "entry_point": f"0x{entry_point:x}" if entry_point is not None else None,
            "function_count": len(functions),
            "named_function_count": named,
            "string_count": len(strings),
            "distinct_string_count": len({result.text for result in strings}),
            "budget": {"max_strings": max_strings},
            "warnings": warnings,
        }


#: The built-in analyser instance, registered by ``_wire_builtins`` below.
METRICS_PLUGIN = MetricsAnalyzer()


# ---- internals --------------------------------------------------------------


def _group_name(entry_point_group: str) -> str:
    """Return a validated entry point group name."""
    group = (entry_point_group or "").strip()
    if not group:
        raise AnalysisError("entry point group must not be empty")
    return group


def _kind_for_group(entry_point_group: str) -> str:
    """Map an entry point group (``...analyzers``) to a plugin kind."""
    suffix = _group_name(entry_point_group).rpartition(".")[2].lower()
    return _KIND_BY_GROUP_SUFFIX.get(suffix, KIND_ANALYZER)


def _ep_name(entry_point: Any) -> str:
    """Return an entry point's name, stripped, or ``""`` when it has none."""
    return str(getattr(entry_point, "name", "") or "").strip()


def _plugin_label(plugin: object) -> str:
    """A message-safe identifier for ``plugin``, using its name when it has one."""
    name = getattr(plugin, "name", None)
    if isinstance(name, str) and name.strip():
        return repr(name.strip())
    return f"<{type(plugin).__name__} at 0x{id(plugin):x}>"


def _validate_plugin(plugin: object, *, source: str) -> AnalyzerPlugin:
    """Check the plugin contract, raising :class:`AnalysisError` naming it."""
    label = _plugin_label(plugin)
    name = getattr(plugin, "name", None)
    if not isinstance(name, str) or not name.strip():
        raise AnalysisError(f"{source} has no usable 'name' attribute (got {name!r})")
    if not callable(getattr(plugin, "analyze", None)):
        raise AnalysisError(f"{source} has no callable 'analyze' method (plugin {label})")
    return cast(AnalyzerPlugin, plugin)


def _plugin_info(plugin: AnalyzerPlugin) -> PluginInfo:
    """Describe a plugin object that already passed validation."""
    version = getattr(plugin, "version", "") or ""
    description = getattr(plugin, "description", "") or ""
    return PluginInfo(
        name=str(plugin.name),
        version=str(version),
        kind=KIND_ANALYZER,
        entry_point=f"{type(plugin).__module__}:{type(plugin).__qualname__}",
        description=str(description),
    )


def _info_from_entry_point(entry_point: Any, group: str) -> tuple[PluginInfo, str | None]:
    """Build :class:`PluginInfo` from one entry point without importing it.

    Returns the description and, when the metadata was partially broken but
    recoverable, a warning string instead of raising.
    """
    name = _ep_name(entry_point)
    if not name:
        raise ValueError("entry point declares no name")
    value = str(getattr(entry_point, "value", "") or "").strip()
    if not value:
        raise ValueError(f"entry point {name!r} declares no importable target")

    version, description, warning = UNKNOWN_VERSION, "", None
    dist = getattr(entry_point, "dist", None)
    if dist is not None:
        try:
            version = str(dist.version or UNKNOWN_VERSION)
        except Exception as exc:  # noqa: BLE001 - broken distribution metadata
            warning = (
                f"{group}: {name!r} has unreadable version metadata ({exc}); "
                f"reporting {UNKNOWN_VERSION!r}"
            )
        try:
            summary = dist.metadata["Summary"]
        except Exception:  # noqa: BLE001 - the summary is optional metadata
            summary = None
        if isinstance(summary, str):
            description = summary

    info = PluginInfo(
        name=name,
        version=version,
        kind=_kind_for_group(group),
        entry_point=value,
        description=description,
    )
    return info, warning


def _store_discovery_warnings(warnings: tuple[str, ...]) -> None:
    """Record the warnings from one discovery pass."""
    global _DISCOVERY_WARNINGS
    with _REGISTRY_LOCK:
        _DISCOVERY_WARNINGS = warnings


def _payload_warnings(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Lift string warnings out of ``payload["warnings"]``, ignoring the rest."""
    raw = payload.get("warnings")
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Iterable):
        return ()
    return tuple(item for item in raw if isinstance(item, str))


def _budget_seconds(value: float) -> float:
    """Validate ``max_seconds``: a positive, finite number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalysisError(f"max_seconds must be a number, got {value!r}")
    seconds = float(value)
    if not seconds > 0.0 or seconds == float("inf") or seconds != seconds:
        raise AnalysisError(f"max_seconds must be finite and > 0, got {value!r}")
    return seconds


def _budget_bytes(value: int) -> int:
    """Validate ``max_bytes``: a positive integer."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"max_bytes must be an integer, got {value!r}")
    if value < 1:
        raise AnalysisError(f"max_bytes must be >= 1, got {value}")
    return value


def _budget_within(value: Any) -> int:
    """Clamp a plugin-side integer budget into ``1 .. MAX_STRING_LIMIT``.

    A plugin budget comes from a caller, so it is treated as untrusted input:
    a bad value falls back to the default rather than failing the analysis, and
    a huge one is capped by the core's string limit.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return DEFAULT_MAX_STRINGS
    return max(1, min(value, MAX_STRING_LIMIT))


def _wire_builtins() -> None:
    """Register the analysers that ship inside the package."""
    register(METRICS_PLUGIN)


_wire_builtins()
