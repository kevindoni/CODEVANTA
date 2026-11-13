# Release checklist (maintainers)

The publishing pipeline in `.github/workflows/release.yml` is wired but has
never run: no `v*` tag exists yet. Branch protection on `main` is applied (see
[repository-settings.md](repository-settings.md)); the steps below are the ones
that still need repository and PyPI admin access, in the order they should be
done.

## 1. Claim the project on PyPI (pending publisher)

PyPI → Your projects → Publishing → **Add a new pending publisher**:

| Field | Value |
|-------|-------|
| PyPI project name | `codevanta` |
| Owner | `kevindoni` |
| Repository name | `CODEVANTA` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

These five values must match `.github/workflows/release.yml` exactly — the
publish job (`publish-pypi`) declares `environment: name: pypi, url:
https://pypi.org/p/codevanta` and publishes through OIDC trusted publishing
(`permissions: id-token: write`), so **no API token is created or stored**. A
pending publisher only *reserves* the name: the first successful publish claims
the project.

## 2. Create the GitHub environment `pypi`

Settings → Environments → New environment → `pypi`:

- [ ] Required reviewers: at least one maintainer (the publish job then waits
      for that approval on every real release)
- [ ] Deployment branches and tags: `main`, `v*`

Until both are configured, the release workflow's publish step cannot satisfy
the environment the pending publisher names.

## 3. Pre-tag checks

- [ ] `CHANGELOG.md` `[Unreleased]` renamed to the version being cut (and a
      fresh empty `[Unreleased]` above it)
- [ ] `pyproject.toml` `version` matches the tag (currently `0.1.0`)
- [ ] Full suite green: `python -m pytest` (CI enforces lint + tests + wheel
      smoke test on every PR)
- [ ] Dry run passed (section 4)

## 4. Dry run first: `workflow_dispatch` with `dry_run=true`

`release.yml` accepts a manual run whose `dry_run` input **defaults to
`true`** — build the distributions, skip the PyPI publish and the GitHub
release. Run it before cutting a tag:

```powershell
gh workflow run release.yml --ref main      # dry_run defaults to true
gh run watch                                # or: gh run list --workflow release.yml
```

Then download the artifact and inspect it locally:

```powershell
gh run download <run-id> -n dist -D _release_dry_run
Get-ChildItem _release_dry_run     # expect codevanta-0.1.0.tar.gz + .whl
```

The publish job's guard is `if: ${{ github.event_name == 'push' ||
inputs.dry_run == false }}` — a dry run never touches PyPI, and the
`github-release` job is skipped with it (`needs.publish-pypi.result ==
'success'` is not met when publish never ran).

## 5. Tag and release

```powershell
cd D:\PALIKASIKU\CODEVANTA
git tag v0.1.0
git push origin v0.1.0
```

The `v*` tag push triggers the real pipeline: `build` → `publish-pypi`
(trusted publishing, environment `pypi`) → `github-release` (attaches the sdist
and wheel with generated release notes).

Verify each stage:

```powershell
gh run list --workflow release.yml --limit 1
gh run watch <run-id>
# PyPI
python -m pip index versions codevanta        # or open https://pypi.org/p/codevanta
# GitHub release + assets
gh release view v0.1.0
```

If the environment has required reviewers, approve the deployment when the
`publish-pypi` job waits on it.

## 6. When CI must be re-triggered by hand

`ci.yml` runs on push to `main`, on pull requests, and on
`workflow_dispatch`. GitHub occasionally drops a `pull_request` event (flaky
webhook delivery), which leaves a branch without checks and blocks an
up-to-date merge. Re-run CI for the branch manually — the workflow name is
`CI`:

```powershell
gh workflow run CI --ref feat/my-change
gh run list --workflow CI --limit 1
```

The manual run executes the same jobs against the branch head, so required
status checks resolve the same way.

## 7. After the first release

- [ ] Pending publisher on PyPI now shows the project as claimed
- [ ] `pip install codevanta` works from a clean venv
- [ ] Docs that mention "never released" (this file,
      `docs/repository-settings.md` §6, README roadmap) are updated
- [ ] Next release: repeat sections 3–5 with the new version
