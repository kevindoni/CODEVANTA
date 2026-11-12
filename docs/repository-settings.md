# Repository settings checklist (maintainers)

Branch protection for `main` is applied. The PyPI publishing steps still require
repository and PyPI admin access.

## 1. Branch protection for `main` — applied

Applied through the GitHub API (`PUT /repos/kevindoni/CODEVANTA/branches/main/protection`):

| Rule | Value |
|------|-------|
| Require a pull request before merging | yes (0 approvals, so a maintainer can self-merge) |
| Dismiss stale approvals on new commits | yes |
| Require status checks | `test (py3.11)`, `test (py3.13)`, `build and smoke-test wheel` |
| Require branches to be up to date | yes (strict) |
| Require linear history | yes (squash or rebase merges only) |
| Block force pushes | yes |
| Block deletions | yes |
| Enforce for administrators | yes |

Direct pushes to `main` are rejected, including for maintainers. Work on a branch:

```powershell
git checkout -b feat/my-change
# ... commit ...
git push -u origin feat/my-change
gh pr create --fill --base main
gh pr checks --watch
gh pr merge --squash --delete-branch
```

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

Python 3.11, 3.13, and 3.14 are in the CI matrix. Older interpreters are
supported by `requires-python = ">=3.10"` but not exercised by CI.
