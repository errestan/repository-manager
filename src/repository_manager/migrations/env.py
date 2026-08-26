"""Alembic environment (specification.md 9).

The database URL comes from ``REPOMAN_DATABASE_URL`` or ``alembic -x url=...``
rather than from ``alembic.ini``.  Migrations deliberately do *not* require the
full application configuration -- running `db upgrade` should not need an LDAP
server or a public URL to be configured.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import Connection, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from repository_manager.config import Settings
from repository_manager.models import Base
from repository_manager.models.base import UtcDateTime

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def database_url() -> str:
    """Resolve the URL, most explicit source first.

    `alembic -x url=...` > a URL set by the CLI > REPOMAN_DATABASE_URL > the
    packaged default.
    """
    override = context.get_x_argument(as_dictionary=True).get("url")
    if override:
        return override
    from_cli = config.get_main_option("repoman_url", None)
    if from_cli:
        return from_cli
    from_env = os.environ.get("REPOMAN_DATABASE_URL")
    if from_env:
        return from_env
    default = Settings.model_fields["database_url"].default
    return str(default)


def render_item(type_: str, obj: Any, autogen_context: Any) -> Any:
    """Render UtcDateTime as its underlying SQL type.

    A migration must keep working years after it was written, so it should not
    import application models -- those move and get renamed.  UtcDateTime adds
    no DDL of its own beyond ``DateTime(timezone=True)``; the UTC normalisation
    is Python-side behaviour.  Emitting the plain SQLAlchemy type keeps every
    migration self-contained.
    """
    if type_ == "type" and isinstance(obj, UtcDateTime):
        autogen_context.imports.add("import sqlalchemy as sa")
        return "sa.DateTime(timezone=True)"
    return False


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite cannot ALTER most things in place; batch mode rebuilds the
        # table instead, so the same migration works on SQLite and PostgreSQL.
        render_as_batch=True,
        compare_type=True,
        compare_server_default=True,
        render_item=render_item,
    )


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        compare_type=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    section: dict[str, Any] = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = database_url()

    connectable = async_engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(_run)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
