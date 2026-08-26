#!/usr/bin/env python3
"""Fail if any installed dependency's licence is incompatible with GPL-3.0-or-later.

This project is GPL-3-or-later (specification.md 14.1, AD-17).  Inbound, that is a
permissive posture: MIT, BSD, ISC, Apache-2.0, LGPL and GPL-3 are all fine.  The
trap this guards against is a **GPL-2-only** dependency arriving via a transitive
upgrade -- GPL-2-only cannot be combined with GPL-3, and nothing else in the
toolchain would notice.

Usage:  python3 scripts/check_licences.py
"""

from __future__ import annotations

import json
import subprocess
import sys

# Substrings matched case-insensitively against the declared licence string.
ALLOWED = (
    "mit",
    "bsd",
    "isc",
    "apache",
    "python software foundation",
    "psf",
    "zope public",
    "mozilla public license 2",
    "mpl-2",
    "unlicense",
    "public domain",
    "cc0",
    "lgpl",
    "gpl-3",
    "gplv3",
    "general public license v3",
    "gpl-2.0-or-later",
    "gplv2+",
    "general public license v2 or later",
    "artistic",
    "historical permission notice",
)

# Matched first: these are rejected even if an ALLOWED substring also matches.
# "GPLv2" without "+"/"or later" is the incompatible case.
DENIED_EXACT = (
    "gpl-2.0-only",
    "gplv2",
    "gnu general public license v2 (gplv2)",
    "agpl",
)

# Dependencies whose declared metadata is missing or misleading, with the licence
# verified by hand.  Keep this list short and justified.
KNOWN: dict[str, str] = {
    "repository-manager": "GPL-3.0-or-later",
}


def declared_licences() -> list[dict[str, str]]:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "piplicenses",
            "--format=json",
            "--with-system",
            "--from=mixed",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print("pip-licenses failed:", result.stderr.strip(), file=sys.stderr)
        raise SystemExit(1)
    licences: list[dict[str, str]] = json.loads(result.stdout)
    return licences


def classify(name: str, licence: str) -> str | None:
    """Return a rejection reason, or None when the licence is acceptable."""
    text = KNOWN.get(name.lower(), licence).strip().lower()

    if not text or text in {"unknown", "unknown license"}:
        return "licence not declared -- verify by hand and add to KNOWN"

    for denied in DENIED_EXACT:
        # Reject GPLv2-only, but not "GPLv2+" / "GPL-2.0-or-later".
        if denied in text and "or later" not in text and "+" not in text:
            return f"'{licence}' is not compatible with GPL-3.0-or-later"

    if any(allowed in text for allowed in ALLOWED):
        return None

    return f"'{licence}' is not on the GPL-3-compatible allow-list"


def main() -> int:
    problems: list[str] = []
    for entry in declared_licences():
        name = entry.get("Name", "?")
        licence = entry.get("License", "")
        reason = classify(name, licence)
        if reason:
            problems.append(f"{name} ({entry.get('Version', '?')}): {reason}")

    if problems:
        print("Incompatible or unverified dependency licences:\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nThis project is GPL-3.0-or-later (specification.md 14.1). A GPL-2-only "
            "dependency cannot be combined with it. Replace the dependency, or -- if the "
            "metadata is simply wrong -- record the verified licence in KNOWN.",
            file=sys.stderr,
        )
        return 1

    print("All dependency licences are compatible with GPL-3.0-or-later.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
