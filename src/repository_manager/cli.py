"""Command-line entry point.

Subcommands are declared here so the console script, the container image, and the
documentation agree from the first commit.  Implementations land with their
milestones (see specification.md 13.6); until then they exit non-zero rather than
pretending to succeed.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from repository_manager.__about__ import __version__


def _not_yet(name: str) -> int:
    print(f"'{name}' is not implemented yet.", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repository-manager",
        description="Manage the contents of APT and RPM package repositories.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the web application")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    db = sub.add_parser("db", help="database migrations")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    db_sub.add_parser("upgrade", help="apply pending migrations")
    revision = db_sub.add_parser("revision", help="create a new migration")
    revision.add_argument("-m", "--message", required=True)

    sub.add_parser("check-config", help="validate configuration and exit")

    rescan = sub.add_parser("rescan", help="reconcile the database against on-disk state")
    rescan.add_argument("slug", help="repository slug")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _not_yet(args.command)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
