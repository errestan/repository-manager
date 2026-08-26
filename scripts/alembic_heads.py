#!/usr/bin/env python3
"""Fail when the migration history has more than one head.

Two branches each adding a migration merge cleanly in git and then refuse to apply,
usually discovered at deploy time.  Catching it at commit time is much cheaper.

Skips silently until Alembic is actually set up, so it is safe to enable from the
first commit.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CONFIG = Path("alembic.ini")


def main() -> int:
    if not CONFIG.exists():
        return 0

    try:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "heads"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"Could not run 'alembic heads': {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        print("'alembic heads' failed:", file=sys.stderr)
        print(result.stderr.strip(), file=sys.stderr)
        return 1

    heads = [line for line in result.stdout.splitlines() if line.strip()]
    if len(heads) > 1:
        print(
            f"Migration history has {len(heads)} heads; it must have exactly one:",
            file=sys.stderr,
        )
        for head in heads:
            print(f"  {head}", file=sys.stderr)
        print("\nResolve with: alembic merge -m 'merge heads' <rev1> <rev2>", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
