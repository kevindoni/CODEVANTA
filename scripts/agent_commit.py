"""Commit as an AI agent so GitHub's contributor graph credits it.

GitHub builds the contributors graph from each commit's **author email**, mapped
to a GitHub account whose verified address matches. A ``Co-authored-by:`` trailer,
a ``.mailmap`` entry and a fancy author *name* are all ignored, which is why agent
work stays invisible while the agent has no account (``dependabot[bot]`` appears
only because a bot account exists for it).

This wrapper makes the honest path easy: once the agent has its own GitHub
account, every commit it produces is authored with that account's noreply address
and keeps the ``Co-authored-by`` trailer as a human-readable record.

Typical use, after creating the account and copying its noreply address from
GitHub's email settings::

    $env:CODEVANTA_AGENT_NAME  = "codevanta-cline"
    $env:CODEVANTA_AGENT_EMAIL = "123456789+codevanta-cline@users.noreply.github.com"
    python scripts/agent_commit.py --print-identity
    python scripts/agent_commit.py -m "feat: ..." -- -a

Everything after ``--`` is forwarded to ``git commit``, so pathspecs, flags and
message files keep working. ``--dry-run`` prints the command instead of running
it.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Sequence

#: Human-readable record kept in every agent commit.
CO_AUTHOR = "Cline (AI coding agent) <noreply@cline.bot>"

#: Env vars that carry the agent identity, so no secret has to be committed.
NAME_ENV = "CODEVANTA_AGENT_NAME"
EMAIL_ENV = "CODEVANTA_AGENT_EMAIL"

#: GitHub's modern noreply form: ``<user-id>+<login>@users.noreply.github.com``.
_NOREPLY = re.compile(r"^\d+\+[A-Za-z0-9-]+@users\.noreply\.github\.com$")

#: Generic noreply form without an id; still linkable when the account owns it.
_PLAIN_NOREPLY = re.compile(r"^[A-Za-z0-9-]+@users\.noreply\.github\.com$")


class IdentityError(ValueError):
    """Raised when the agent identity is missing or cannot be linked to GitHub."""


def resolve_identity(name: str | None, email: str | None) -> tuple[str, str]:
    """Return the agent ``(name, email)``, preferring explicit arguments.

    Args:
        name: Account login to record as the author name; ``None`` falls back to
            ``CODEVANTA_AGENT_NAME``.
        email: Account noreply address; ``None`` falls back to
            ``CODEVANTA_AGENT_EMAIL``.

    Returns:
        The resolved pair, with surrounding whitespace stripped.

    Raises:
        IdentityError: When either value is missing or blank.
    """
    resolved_name = (name or os.environ.get(NAME_ENV) or "").strip()
    resolved_email = (email or os.environ.get(EMAIL_ENV) or "").strip()
    if not resolved_name:
        raise IdentityError(
            f"no agent name: pass --name or set {NAME_ENV} to the GitHub login"
        )
    if not resolved_email:
        raise IdentityError(
            f"no agent email: pass --email or set {EMAIL_ENV} to the account's "
            "noreply address (GitHub > Settings > Emails)"
        )
    return resolved_name, resolved_email


def validate_email(email: str, *, allow_any: bool = False) -> str:
    """Return ``email`` when GitHub can link it to an account.

    A commit is credited only if its author email is verified on some account, so
    a made-up address silently keeps the agent out of the graph. The noreply forms
    are accepted because GitHub links them; ``allow_any`` exists for maintainers
    who verified a different address on the agent account.

    Args:
        email: Candidate author address.
        allow_any: Skip the noreply-shape check.

    Returns:
        The address unchanged.

    Raises:
        IdentityError: When ``email`` cannot be linked to a GitHub account.
    """
    candidate = email.strip()
    if allow_any:
        if "@" not in candidate:
            raise IdentityError(f"not an email address: {candidate!r}")
        return candidate
    if _NOREPLY.match(candidate) or _PLAIN_NOREPLY.match(candidate):
        return candidate
    raise IdentityError(
        f"{candidate!r} cannot be linked to a GitHub account: use the account's "
        "noreply address (<id>+<login>@users.noreply.github.com) or pass "
        "--allow-any-email when that address is verified on the agent account"
    )


def build_command(
    name: str,
    email: str,
    message: str | None,
    passthrough: Sequence[str],
    *,
    co_author: bool = True,
) -> list[str]:
    """Return the ``git commit`` argument list for one agent commit.

    Args:
        name: Author name.
        email: Author email.
        message: ``-m`` value, or ``None`` when the caller forwards its own
            message flags through ``passthrough``.
        passthrough: Arguments forwarded verbatim after the identity flags.
        co_author: Append the ``Co-authored-by`` trailer as a second paragraph.

    Returns:
        The command, starting with ``git``.
    """
    command = ["git", "-c", f"user.name={name}", "-c", f"user.email={email}", "commit"]
    if message is not None:
        command += ["-m", message]
    if co_author:
        command += ["-m", f"Co-authored-by: {CO_AUTHOR}"]
    return command + list(passthrough)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and run the agent commit.

    Returns:
        ``0`` on success (or a dry run), the ``git`` exit code otherwise, and
        ``2`` for a rejected identity.
    """
    parser = argparse.ArgumentParser(
        description="Commit with an AI agent as the author so GitHub credits it.",
    )
    parser.add_argument("--name", help=f"author name (default: ${NAME_ENV})")
    parser.add_argument("--email", help=f"author email (default: ${EMAIL_ENV})")
    parser.add_argument("-m", "--message", help="commit message")
    parser.add_argument(
        "--allow-any-email",
        action="store_true",
        help="accept an email that is not a GitHub noreply address",
    )
    parser.add_argument(
        "--no-co-author",
        action="store_true",
        help="omit the Co-authored-by trailer",
    )
    parser.add_argument(
        "--print-identity",
        action="store_true",
        help="print the resolved identity and exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the git command instead of running it",
    )
    parser.add_argument(
        "passthrough",
        nargs=argparse.REMAINDER,
        help="arguments after -- are forwarded to git commit",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        name, email = resolve_identity(args.name, args.email)
        email = validate_email(email, allow_any=args.allow_any_email)
    except IdentityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.print_identity:
        print(f"{name} <{email}>")
        return 0

    passthrough = [item for item in args.passthrough if item != "--"]
    command = build_command(
        name,
        email,
        args.message,
        passthrough,
        co_author=not args.no_co_author,
    )
    if args.dry_run:
        print(" ".join(command))
        return 0
    try:
        return subprocess.run(command, check=False).returncode
    except OSError as exc:  # pragma: no cover - git missing entirely
        print(f"error: cannot run git: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
