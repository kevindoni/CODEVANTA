# Filesystem snapshot and diff

Two MCP tools, `codevanta_fs_snapshot` and `codevanta_fs_diff`, record a
directory tree as a deterministic manifest and compare two manifests
into created/deleted/modified lists. The pair exists for a single
question — *what did this program change on disk?* — answered by
snapshotting before and after a run. Both are pure Python standard
library, fully offline, and nothing is executed.

## What it reports

**`codevanta_fs_snapshot(root, output_directory)`** walks the tree at
`root` recursively with `os.walk` (symlinks are never followed) and
records:

* every regular file: relative POSIX path, size and sha256 — files
  above **8 MiB** are recorded size-only with `hashed=false`;
* every directory; and
* every symlink with its target text (clipped to the name cap).

**No timestamps are recorded**, so the same tree snapshots to a
byte-identical manifest. The manifest is written as `fs_snapshot.json`
into `output_directory`, and the result carries the written file's
`path`, `bytes` and `sha256` under `written`.

**`codevanta_fs_diff(before, after)`** loads two snapshot files and
classifies every relative path:

* `created` — present after only;
* `deleted` — present before only;
* `modified` — present on both sides with a differing fingerprint:
  content sha256 when both sides hashed the file, otherwise the size
  fallback, flagged `size_only`;
* `unchanged` — counted only, not listed.

The verdict is `identical` when nothing changed, otherwise `changed`.
Every list is bounded with its own truncation flag while the counts
report the true totals.

## Usage

```json
{"root": "C:\\sandbox\\run-before", "output_directory": "C:\\sandbox"}
{"before": "C:\\sandbox\\fs_snapshot.json", "after": "C:\\sandbox\\fs_snapshot_after.json"}
```

Python surface:

```python
from pathlib import Path
from codevanta.analysis.fs_diff import snapshot_tree, diff_snapshots, load_snapshot

before = snapshot_tree(Path("sandbox/before"))
after = snapshot_tree(Path("sandbox/after"))
diff = diff_snapshots(before, after)
print(diff.verdict, diff.created, diff.modified)
```

Missing or non-directory roots, uncreatable output directories, and
missing, unreadable or malformed snapshot files are typed
`AnalysisError`s — the diff never guesses across a broken manifest.

## Bounds and confidence

Every bound that fires is reported through `truncated` flags or
warnings — never silently.

| Bound | Default | Effect |
|-------|---------|--------|
| Snapshot entries kept | 2048 | counting continues; `truncated: true` |
| Hashed bytes per snapshot | 256 MiB | further files recorded size-only; warning |
| Per-file hashing threshold | 8 MiB | larger files: `hashed=false`, size-only row |
| Diff list entries (each list) | 512 | `truncated: true` on that list; counts stay true |
| Symlink target text | clipped | long targets recorded clipped |

| Finding | Confidence | Why |
|---------|------------|-----|
| Snapshot rows | `high` | read straight from the filesystem walk (`fs.snapshot`, `walk-sha256`) |
| A `modified` verdict on hashed files | `high` | content sha256 differs (`fs.diff`, `hash-set-compare`) |
| A `modified` verdict from the size fallback | reported, not inflated | the row is flagged `size_only` — size can match while content differs |

## Limitations

* Files above the 8 MiB threshold are hashed nowhere: a same-size
  content change inside one of them will not surface as `modified`.
  The `size_only` flag on the row states this.
* Timestamps are deliberately absent — that is what makes manifests
  deterministic — so time-only changes (touch) are invisible by design.
* Symlinks are recorded as text and never followed; a symlink pointing
  outside the tree is reported, its target's contents are not walked.
* The diff only sees paths both snapshots recorded. A tree that grew
  past the 2048-entry bound in one snapshot only compares the entries
  that exist, and the truncation flags make that honest.
