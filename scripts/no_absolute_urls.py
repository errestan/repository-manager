#!/usr/bin/env python3
"""Fail on root-relative URLs in templates.

The application must work when mounted at a sub-path (specification.md 13.5, AD-14).
A literal ``href="/repositories"`` silently breaks that, and breaks it in a way that
only shows up in the sub-path CI run -- or in production.  Every URL must be built
with ``request.url_for()`` (or ``url_for()`` in a template) so the mount prefix is
always applied.

Escape hatch: put ``{# allow-absolute-url #}`` on the offending line when the URL is
genuinely external to the application's mount, e.g. a link to an unrelated host.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# href="/...", action="/...", hx-get="/...", src="/..." and friends -- single or
# double quoted.  Protocol-relative "//host" is matched too: it is not a mount-relative
# URL, but it is nearly always a mistake in this codebase.
PATTERN = re.compile(
    r"""(?P<attr>\b(?:href|action|src|hx-(?:get|post|put|patch|delete)))\s*=\s*(?P<q>["'])/""",
)

ALLOW_MARKER = "allow-absolute-url"


def check(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:  # pragma: no cover - defensive
        return [f"{path}: could not read ({exc})"]

    for lineno, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        match = PATTERN.search(line)
        if match:
            problems.append(
                f"{path}:{lineno}: root-relative URL in {match.group('attr')}="
                f"{match.group('q')}/... -- use url_for() so the sub-path mount is applied"
            )
    return problems


def main(argv: list[str]) -> int:
    problems: list[str] = []
    for name in argv:
        problems.extend(check(Path(name)))

    if problems:
        print("Root-relative URLs found (see specification.md 13.5):\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nBuild URLs with url_for(). If the link really is external, add "
            f"{{# {ALLOW_MARKER} #}} to that line.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
