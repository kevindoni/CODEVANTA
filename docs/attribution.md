# Commit attribution for AI agents

GitHub's contributor graph is built from one field only: **the author email of
each commit, mapped to a GitHub account whose verified address matches**. A
`Co-authored-by:` trailer, a `.mailmap` entry, or a distinctive author *name* are
all ignored. That is why an agent can write most of a repository and still not
appear next to the human maintainer — and why `dependabot[bot]` does appear: a bot
account exists for it.

CODEVANTA keeps two records that do not depend on the graph:

* [`CONTRIBUTORS.md`](../CONTRIBUTORS.md) — the authoritative list of agents and
  what each delivered.
* The `Co-authored-by:` trailer on agent commits — readable in `git log`.

This page describes the optional third step: giving the agent a real account so
the graph credits it too.

## 1. Create the account

1. Sign up for a GitHub account for the agent, for example `codevanta-cline`.
   Use an address you control; GitHub verifies it before it can be used.
2. Open **Settings → Emails** and copy the address shown under
   *Keep my email addresses private*, in the form
   `<user-id>+<login>@users.noreply.github.com`.
3. Grant the account read access to the repository (or add it as a collaborator
   with **read** only). Commits authored by an account do not need write access,
   but a collaborator record makes the intent explicit.

## 2. Point the commit helper at it

The helper lives in [`scripts/agent_commit.py`](../scripts/agent_commit.py) and
refuses an address GitHub cannot link, so a typo cannot silently drop the agent
out of the graph again.

```powershell
$env:CODEVANTA_AGENT_NAME  = "codevanta-cline"
$env:CODEVANTA_AGENT_EMAIL = "123456789+codevanta-cline@users.noreply.github.com"

python scripts/agent_commit.py --print-identity   # shows what will be recorded
```

Commit through it instead of `git commit`:

```powershell
python scripts/agent_commit.py -m "feat: add entropy column" -- -a
python scripts/agent_commit.py -m "docs: fix link" -- README.md docs/api.md
python scripts/agent_commit.py -m "test: cover the loader" --dry-run   # print only
```

Everything after `--` is forwarded to `git commit`, so pathspecs, `-a`, `--amend`
and message files keep working. The helper adds
`Co-authored-by: Cline (AI coding agent) <noreply@cline.bot>` unless
`--no-co-author` is passed.

On macOS or Linux the same script runs with `python3`; a shell alias is enough:

```bash
export CODEVANTA_AGENT_NAME=codevanta-cline
export CODEVANTA_AGENT_EMAIL=123456789+codevanta-cline@users.noreply.github.com
alias agent-commit='python3 scripts/agent_commit.py'
```

## 3. Verify

```powershell
git log -1 --format="%an <%ae>%n%b"
git shortlog -sne HEAD
```

The author must be the agent account and the trailer must be present. After the
next push to `main`, the account appears on
`https://github.com/<owner>/<repo>/graphs/contributors`; GitHub refreshes that
page from a cache, so allow up to about 24 hours.

## What cannot be retroactive

* Commits already in `main` keep their recorded author. Re-authoring them would
  rewrite every SHA, break pull-request references, and require a force-push that
  the protected branch rejects — so history is left alone.
* A commit whose author email belongs to no account never appears in the graph,
  whatever its author name says. `git log --format='%ae'` shows which of your
  commits are in that state.
* Squash merges attribute the squashed commit to the account that clicked merge.
  If the goal is for the agent to appear, the agent's commits must land through a
  merge that preserves authorship (a merge commit) rather than a squash — or the
  maintainer accepts that the graph shows the merge actor while
  `CONTRIBUTORS.md` carries the credit.
