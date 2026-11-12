# Repository settings checklist (maintainers)

These steps need repository admin rights and are performed once in the GitHub
UI. They cannot be applied from the codebase.

## 1. Branch protection for `main`

Settings → Branches → Add branch ruleset (or classic protection) for `main`:

- [ ] Require a pull request before merging (1 approval)
- [ ] Dismiss stale approvals when new commits are pushed
- [ ] Require status checks to pass:
  - `test (py3.11)`
  - `test (py3.13)`
  - `build and smoke-test wheel`
- [ ] Require branches to be up to date before merging
- [ ] Require linear history
- [ ] Block force pushes and deletions
- [ ] (Optional) Require signed commits

## 2. Environment `pypi`

Settings → Environments → New environment → `pypi`:

- [ ] Required reviewers: at least one maintainer
- [ ] Deployment branches and tags: `main`, `v*`

## 3. PyPI trusted publishing

PyPI → Your projects → Publishing → **Add a new pending publisher**:

| Field | Value |
|-------|-------|
| PyPI project name | `codevanta` |
| Owner | `kevindoni` |
| Repository name | `CODEVANTA` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

No API token is needed: `.github/workflows/release.yml` publishes through OIDC
(`id-token: write`).

## 4. First release

```powershell
cd D:\PALIKASIKU\CODEVANTA
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds the sdist and wheel, publishes to PyPI, and attaches
both files to the GitHub release. Update `CHANGELOG.md` before tagging.

## 5. Optional hardening

- [ ] Secret scanning and push protection (Settings → Code security)
- [ ] Dependabot alerts and security updates (enabled by `.github/dependabot.yml`)
- [ ] Private vulnerability reporting (Settings → Security → Advisories)
- [ ] Squash-only merges and `main` as the default branch
- [ ] Require conventional PR titles (optional, helps release notes)

## 6. CI expectations

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | push to `main`, pull requests, manual | lint + tests on 3.11/3.13, wheel build and clean-venv smoke test |
| `release.yml` | tag `v*` | build, PyPI trusted publish, GitHub release assets |

Python 3.14 is intentionally not in the CI matrix yet: it depends on published
`lief` wheels for 3.14. Add it to `ci.yml` once those are available.
