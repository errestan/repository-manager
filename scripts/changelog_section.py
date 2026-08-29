"""Extract one version's notes from CHANGELOG.md, for the release workflow.

The changelog is the source of truth for what a release says, so the GitHub
Release should quote it rather than paraphrase it with a second, differently
worded, automatically generated list.  Written as a script rather than a shell
one-liner because "find the heading, stop at the next one" is exactly the kind
of thing that quietly returns the whole file when the format shifts -- and a
release whose notes are the entire changelog is a release nobody reads.

Usage: ``python scripts/changelog_section.py 0.1.0``
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"

#: `## [0.1.0] — 2026-08-29`, `## [0.1.0]`, `## 0.1.0` all count.
HEADING = re.compile(r"^##\s+\[?(?P<version>[^\]\s]+)\]?")


def section(text: str, version: str) -> str:
    """The body under ``version``'s heading, up to the next ``##``."""
    wanted = version.lstrip("v")
    lines = text.splitlines()
    collected: list[str] = []
    inside = False
    for line in lines:
        match = HEADING.match(line)
        if match:
            if inside:
                break
            inside = match.group("version").lstrip("v") == wanted
            continue
        if inside:
            collected.append(line)
    body = "\n".join(collected).strip()
    if not body:
        raise SystemExit(f"No changelog section for {version!r} in {CHANGELOG}")
    return body


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <version>", file=sys.stderr)
        return 2
    print(section(CHANGELOG.read_text(encoding="utf-8"), argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
