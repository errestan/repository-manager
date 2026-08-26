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
from repository_manager.config import ConfigError, Settings, load_settings


def _not_yet(name: str) -> int:
    print(f"'{name}' is not implemented yet.", file=sys.stderr)
    return 2


def _load(**overrides: object) -> Settings:
    """Load settings or exit with the validation message, never a traceback."""
    try:
        return load_settings(**overrides)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc


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
    serve.add_argument(
        "--reload", action="store_true", help="reload on code changes (development only)"
    )

    db = sub.add_parser("db", help="database migrations")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    db_sub.add_parser("upgrade", help="apply pending migrations")
    revision = db_sub.add_parser("revision", help="create a new migration")
    revision.add_argument("-m", "--message", required=True)

    sub.add_parser("check-config", help="validate configuration and exit")

    rescan = sub.add_parser("rescan", help="reconcile the database against on-disk state")
    rescan.add_argument("slug", help="repository slug")

    return parser


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    # Validate before binding a port.  The worker builds its own Settings via
    # the app factory; doing it here too means a bad environment variable fails
    # immediately with a readable message instead of inside a reload loop.
    settings = _load()
    print(
        f"Serving at http://{args.host}:{args.port}"
        f"{settings.effective_root_path or ''} (public: {settings.public_url})",
        file=sys.stderr,
    )
    # Migrations are never applied implicitly: a process that silently rewrites
    # the schema on start is a bad surprise in production. Run `db upgrade`.
    uvicorn.run(
        "repository_manager.web.app:app_from_environment",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_config=None,
        access_log=False,
        # Forwarded headers are handled by our own middleware, which applies the
        # trusted-proxy allow-list (10.6); uvicorn's version has no such check.
        proxy_headers=False,
        forwarded_allow_ips=None,
    )
    return 0


def cmd_db_upgrade(_args: argparse.Namespace) -> int:
    from repository_manager import migrate

    settings = _load()
    migrate.upgrade(settings.database_url)
    print(f"Database is up to date: {settings.database_url}")
    return 0


def cmd_db_revision(args: argparse.Namespace) -> int:
    from repository_manager import migrate

    settings = _load()
    migrate.revision(settings.database_url, args.message)
    return 0


def cmd_check_config(_args: argparse.Namespace) -> int:
    settings = _load()
    print("Configuration is valid.\n")
    print(f"  environment      : {settings.env}")
    print(f"  public URL       : {settings.public_url}")
    print(f"  mounted at       : {settings.effective_root_path or '/'}")
    print(f"  database         : {settings.database_url}")
    print(f"  allowed roots    : {', '.join(str(p) for p in settings.allowed_roots)}")
    print(f"  GnuPG home       : {settings.gnupghome}")
    print(f"  secure cookies   : {settings.cookie_secure}")
    print(f"  cookie path      : {settings.cookie_path}")
    trusted = ", ".join(settings.trusted_proxies) or "(none — forwarded headers ignored)"
    print(f"  trusted proxies  : {trusted}")
    print(f"  log format       : {settings.log_format}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        return cmd_serve(args)
    if args.command == "db":
        if args.db_command == "upgrade":
            return cmd_db_upgrade(args)
        if args.db_command == "revision":
            return cmd_db_revision(args)
    if args.command == "check-config":
        return cmd_check_config(args)

    return _not_yet(args.command)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
