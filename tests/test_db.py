"""Engine construction and session lifecycle (specification.md 9)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from repository_manager.config import Settings
from repository_manager.db import (
    check_connection,
    create_engine,
    create_sessionmaker,
    session_scope,
)
from repository_manager.models import Repository, RepositoryType


async def test_check_connection_succeeds(settings: Settings) -> None:
    engine = create_engine(settings)
    try:
        await check_connection(engine)
    finally:
        await engine.dispose()


async def test_session_scope_commits_on_success(settings: Settings) -> None:
    engine = create_engine(settings)
    factory = create_sessionmaker(engine)
    try:
        async with session_scope(factory) as session:
            session.add(
                Repository(
                    slug="committed",
                    name="Committed",
                    type=RepositoryType.APT,
                    root_path="/tmp/c",
                )
            )
        async with session_scope(factory) as session:
            found = (await session.execute(select(Repository))).scalars().all()
        assert [r.slug for r in found] == ["committed"]
    finally:
        await engine.dispose()


async def test_session_scope_rolls_back_on_error(settings: Settings) -> None:
    """A half-applied change must never survive an exception."""
    engine = create_engine(settings)
    factory = create_sessionmaker(engine)
    try:

        async def insert_then_fail() -> None:
            async with session_scope(factory) as session:
                session.add(
                    Repository(
                        slug="rolled-back",
                        name="Rolled back",
                        type=RepositoryType.APT,
                        root_path="/tmp/r",
                    )
                )
                await session.flush()
                raise RuntimeError("deliberate")

        with pytest.raises(RuntimeError, match="deliberate"):
            await insert_then_fail()

        async with session_scope(factory) as session:
            found = (await session.execute(select(Repository))).scalars().all()
        assert found == []
    finally:
        await engine.dispose()


async def test_sqlite_enforces_foreign_keys(settings: Settings) -> None:
    """The pragma is per-connection; without it ON DELETE CASCADE silently does nothing."""
    engine = create_engine(settings)
    try:
        async with engine.connect() as connection:
            from sqlalchemy import text

            result = await connection.execute(text("PRAGMA foreign_keys"))
            assert result.scalar() == 1
    finally:
        await engine.dispose()
