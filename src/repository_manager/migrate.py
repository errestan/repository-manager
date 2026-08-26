"""Programmatic access to Alembic (specification.md 9).

The migration tree ships inside the installed package, so `repository-manager
db upgrade` works from a pip install or the container image where there is no
checkout and no `alembic.ini` on disk.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from alembic import command
from alembic.config import Config

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

T = TypeVar("T")


def _run_isolated(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run an Alembic command on a thread of its own when a loop is already running.

    ``env.py`` drives the async engine with ``asyncio.run``, which refuses to
    start inside a thread that already has a running loop.  Callers should not
    have to know that, so give the command a private thread -- and therefore a
    private loop -- whenever the current thread is busy.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return func(*args, **kwargs)

    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["value"] = func(*args, **kwargs)
        except BaseException as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=target, name="alembic")
    thread.start()
    thread.join()

    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]  # type: ignore[no-any-return]


def build_config(database_url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    # env.py reads the URL from here first, so the caller's choice always wins
    # over the environment.
    config.set_main_option("repoman_url", database_url)
    return config


def upgrade(database_url: str, revision: str = "head") -> None:
    _run_isolated(command.upgrade, build_config(database_url), revision)


def downgrade(database_url: str, revision: str) -> None:
    _run_isolated(command.downgrade, build_config(database_url), revision)


def revision(database_url: str, message: str, *, autogenerate: bool = True) -> None:
    _run_isolated(
        command.revision,
        build_config(database_url),
        message=message,
        autogenerate=autogenerate,
    )


def current_heads(database_url: str) -> None:
    _run_isolated(command.heads, build_config(database_url))
