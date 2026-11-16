"""Guided investigations exposed as MCP prompts.

Six playbooks, one per question an analyst actually asks: what is this binary,
how does this feature work, what changed between builds, is this Electron app
safe, why did it crash, and is my reconstruction faithful. Each prompt returns
a step-by-step script that names the CODEVANTA tool for every step, the bound
to pass it, and what the result does and does not prove -- the same
observation/inference discipline the tool payloads carry.

Register with :func:`register_prompts`; ``build_server`` and the gateway both
call it, so a client sees the same investigations either way.
"""

from __future__ import annotations

from typing import Any

_REGISTERED: set[int] = set()


def register_prompts(server: Any) -> None:
    """Attach the six guided investigations to ``server`` (idempotent)."""

    if id(server) in _REGISTERED:
        return

    @server.prompt()
    def triage_binary(path: str) -> str:
        """First contact with an unknown binary: identify, bound, and risk-rank it.

        Args:
            path: The binary to triage.
        """
        return _TRIAGE.format(path=path)

    @server.prompt()
    def investigate_feature(feature: str, path: str) -> str:
        """Trace one feature of a binary to the functions that implement it.

        Args:
            feature: The behaviour to explain (a name, a string, a constant).
            path: The binary under analysis.
        """
        return _FEATURE.format(feature=feature, path=path)

    @server.prompt()
    def diff_versions(left: str, right: str) -> str:
        """Compare two builds and report what structurally changed.

        Args:
            left: The older binary or app directory.
            right: The newer binary or app directory.
        """
        return _DIFF.format(left=left, right=right)

    @server.prompt()
    def audit_electron_app(path: str) -> str:
        """Review a JavaScript/Electron application for security anti-patterns.

        Args:
            path: Extracted app directory or .asar archive.
        """
        return _ELECTRON.format(path=path)

    @server.prompt()
    def trace_crash(path: str) -> str:
        """Correlate a crash dump with static structure to name the fault.

        Args:
            path: The core dump, .ips report, or the crashed binary.
        """
        return _CRASH.format(path=path)

    @server.prompt()
    def prepare_rebuild(path: str) -> str:
        """Plan a faithful reconstruction and the evidence that will verify it.

        Args:
            path: The binary or app to rebuild.
        """
        return _REBUILD.format(path=path)

    _REGISTERED.add(id(server))


_TRIAGE = """\
Triage the binary at {path} with CODEVANTA, in this order. Separate what was
observed from what you inferred, and say when a step proves nothing.

1. codevanta_info on {path} -- format, architecture, entry point, sections,
   imports/exports. This is certain evidence; it says what the file IS.
2. codevanta_entropy -- per-section Shannon entropy. A packed/encrypted
   section is a hypothesis (medium confidence), never a verdict.
3. codevanta_strings (min_length 8) and codevanta_stackstrings -- readable
   and stack-built text. Strings prove presence, not use.
4. codevanta_functions -- candidates with source (export/symbol/entry_point)
   and confidence. A missing symbol table is a finding, report it.
5. codevanta_capabilities -- rule-based capability domains; matched rules are
   indicators, not behaviour.
6. codevanta_triage -- imphash + fuzzy hash for clustering against known sets.

Close with: format summary, packing hypothesis with confidence, the three
most interesting strings or capabilities, and the single next analysis step
you would take. Do not speculate beyond the evidence fields.
"""

_FEATURE = """\
Explain how "{feature}" works in {path}. Work from the outside in, and keep
observation and inference apart at every step.

1. Locate the anchor: codevanta_strings for a literal match; codevanta_export
   equivalents via codevanta_info if it is an exported name. Record the
   address, not just the fact.
2. codevanta_functions -- is there a candidate whose name or neighbourhood
   matches? Names from symbols are strong; entry-point-only candidates are
   weak.
3. codevanta_xrefs around the anchor -- who calls/jumps here. Direct branch
   targets are certain; indirect slots name the slot, not the callee.
4. codevanta_callgraph (limit small first) -- the feature's neighbourhood.
   Caller attribution is heuristic: medium confidence.
5. codevanta_decompile the two or three central functions (backend auto).
   If Ghidra is installed you get provider-grade C; otherwise the native
   renderer is low confidence -- say which one answered.
6. codevanta_struct on the data-touching function -- field hypotheses from
   memory operands. Offsets prove access, not types.

Finish with: the call chain in addresses, the decompiled core, and an
explicit residual-unknowns list (what you could NOT establish). Use
codevanta_evidence_bundle to freeze the payloads you relied on.
"""

_DIFF = """\
Compare {left} (older) with {right} (newer) and report the structural delta.

1. codevanta_diff on the two binaries -- functions matched by address then
   name, sections/exports by name, imports by (library, name). Structural
   only: medium confidence, bytes are not compared.
2. Add --deep: address-matched functions whose normalized fingerprints
   differ are marked changed -- a shape signal, not a semantic one.
3. Add --semantic --threshold 0.9: leftovers paired by token-multiset
   similarity. Cross-architecture pairs are skipped by design.
4. For the functions that changed, codevanta_decompile both sides and diff
   the renderings by eye; say which backend answered.
5. If these are JavaScript/Electron apps instead: codevanta_js_diff {left}
   {right} -- modules, import sets, dependency version pins, IPC boundary
   changes.

Report: added/removed/changed counts, the three most significant changes,
and what the diff method cannot see (byte-level edits inside unchanged
shapes, runtime behaviour).
"""

_ELECTRON = """\
Audit the Electron application at {path} (static, offline, nothing executed).

1. codevanta_asar if {path} is an archive -- list first, extract only what
   the next steps need.
2. codevanta_javascript -- bounded module inventory, imports classified,
   per-file process roles, IPC pairs with literal channels. Roles and pairs
   are medium confidence.
3. codevanta_electron_audit -- the 11 EA rules with severity and file:line.
   Each finding is a pattern match, not an exploit proof.
4. codevanta_sbom -- CycloneDX 1.6 inventory from package.json pins, then
   codevanta_js_diff against the previous release if you have it: new
   dependencies and version jumps deserve the first look.
5. For every high/critical finding, quote the rule text, the code site, and
   the recommended fix from the payload.

Close with a findings table, the IPC boundary map, and the residual unknowns
(minified code, dynamic requires, native modules).
"""

_CRASH = """\
Name the fault behind the crash artefact at {path}.

1. codevanta_crash -- ELF core dump or Apple .ips: signal, faulting frame,
   register set, module map. These observations are the ground truth.
2. Identify the faulting module and address, then load that binary:
   codevanta_info, codevanta_functions, and codevanta_xrefs around the
   faulting address -- what calls into this code, on which paths.
3. codevanta_decompile the faulting function (backend auto; name the backend
   that answered). Registers from the dump constrain which branch ran.
4. codevanta_struct if the fault is a memory access -- a null or wild
   displacement in the operands is often visible in the field hypotheses.
5. codevanta_evidence_bundle with the crash payload and the decompilation,
   so the conclusion is auditable.

Answer with: the faulting instruction and its address, the most probable
cause labelled as inference with confidence, and which alternatives the
registers rule out.
"""

_REBUILD = """\
Plan the reconstruction of {path} and the evidence that will verify it.

1. Inventory what exists: codevanta_info / codevanta_javascript, then
   codevanta_capabilities to fix the behavioural scope you must cover.
2. Extract the contract: codevanta_functions + codevanta_callgraph for the
   module map; codevanta_decompile for the algorithms you must reproduce;
   codevanta_dwarf / codevanta_pdb / codevanta_gosymbols when debug info
   survived -- symbol-grade evidence beats inference.
3. Record obligations, not vibes: every behaviour you owe the rebuild is an
   entry (input -> observed effect -> evidence id). Use the unknowns ledger
   for what you could not establish; an unknown is a scope boundary, not a
   TODO to hide.
4. Build, then verify differentially: run your reconstruction's outputs
   against the payloads captured in step 2-3, and codevanta_diff the
   artefacts where a structural comparison exists.
5. Freeze the audit trail: codevanta_evidence_bundle over the payloads, so
   the chain of digests -- not a claim -- backs the verification.

The rebuild is faithful to the recorded evidence and to nothing else; say
so in the final report.
"""
