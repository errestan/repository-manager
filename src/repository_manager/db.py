"""Async engine and session management (specification.md 9, AD-6).

SQLite is the default and PostgreSQL is supported; the differences that matter
are handled here so no other module has to branch on dialect.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from repository_manager.config import Settings


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def _is_memory_sqlite(url: str) -> bool:
    return _is_sqlite(url) and (":memory:" in url or "mode=memory" in url)


def create_engine(settings: Settings, **kwargs: Any) -> AsyncEngine:
    """Build the async engine, applying the SQLite settings the app relies on."""
    options: dict[str, Any] = {"echo": False, "future": True, **kwargs}

    if _is_memory_sqlite(settings.database_url):
        # An in-memory database lives inside its connection, so every session
        # must share one.  Without this, tests see an empty schema.
        options["poolclass"] = StaticPool
        options["connect_args"] = {"check_same_thread": False}

    engine = create_async_engine(settings.database_url, **options)

    if _is_sqlite(settings.database_url):

        @event.listens_for(engine.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            # SQLite disables foreign keys per connection by default, so the
            # ON DELETE CASCADE declared on the models would silently not fire.
            cursor.execute("PRAGMA foreign_keys=ON")
            # WAL lets readers proceed during a metadata regeneration write.
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return engine


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


@asynccontextmanager
async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """A session that commits on success and rolls back on any exception."""
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_connection(engine: AsyncEngine) -> None:
    """Raise if the database is unreachable; used by the readiness probe (13.3)."""
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
