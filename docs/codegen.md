# Starter-code generation from a rebuild project

`codevanta_rebuild_generate` turns a studied rebuild project — the
`craft.json` + `capture/` layout written by `codevanta_rebuild` — into
deterministic starter implementation files. It writes code, but it
invents nothing: every block it emits cites the capture evidence that
justifies it, and identical inputs produce byte-identical files (no
timestamps anywhere). Nothing is executed and nothing touches the
network.

## What it writes

Into `output_directory`:

* **`app/main.py`** — a header citing the target and the sha256
  evidence digest; one import-surface block per observed API group
  (`kernel32`, `ws2_32`, `user32`, … grouped from the capture's
  imports evidence); one `raise NotImplementedError` stub per group,
  citing the reference count and an example symbol.
* **`app/pseudo_c/*.c`** — the deep-mode pseudo-C evidence files, when
  deep-mode decompiles were recorded in the capture.
* **`ui_layout.json` + `ui.html`** — the dialog-decode capture rendered
  as data plus a deterministic HTML preview, when a dialog decode was
  captured.
* **`checks/behavior_checklist.md`** — one checklist item per recorded
  behavior check.

Evidence on the generated set is `high` confidence in the generator's
own sense: the files are faithful transcriptions of stored capture
records, not reconstructions.

## Usage

```json
{"project_dir": "C:\\rebuild\\target-app", "output_directory": "C:\\rebuild\\gen", "language": "python"}
```

`language` currently accepts `python` (the default and only emitter);
the parameter exists so the manifest records the choice. Python
surface:

```python
from codevanta.analysis.rebuild_codegen import generate_starter

manifest = generate_starter("rebuild/target-app", "rebuild/gen", language="python")
print(manifest.files, manifest.warnings)
payload = manifest.to_dict()   # JSON-safe
```

A directory without a readable `craft.json` is a typed error — the
generator refuses to invent a project layout.

## Bounds and confidence

Every bound that fires is reported as an honest truncation warning —
never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| Files written | 32 | further groups/evidence are named in warnings |
| Stubs | 256 | overflow stays in the honest counts |
| Lines per file | 2000 | larger emissions are clipped with a warning |

| Finding | Confidence | Why |
|---------|------------|-----|
| A generated file | `high` | deterministic transcription of stored capture records; byte-identical across runs |
| The import-surface groups | `high` | grouped from the capture's own imports evidence |

## Limitations

* Stubs are **stubs**: every function body is
  `raise NotImplementedError` plus its evidence citation. The generator
  produces the skeleton and the checklist, not a working clone.
* Only projects already studied by `codevanta_rebuild` are valid
  inputs — there is no capture inside the generator.
* The HTML UI preview is deterministic and minimal; it mirrors
  `ui_layout.json`, it is not a pixel-accurate replica (compare with
  [win-shot](win-gui.md) captures for the real pixels).
* `language` beyond `python` is reserved, not implemented.
