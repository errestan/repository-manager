"""Declarative base and shared column types (specification.md 9)."""

from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import DateTime, MetaData, TypeDecorator
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase

# Explicit constraint naming.  Without this, SQLite produces anonymous
# constraints that Alembic cannot later drop or alter by name -- which only
# becomes apparent at the first migration that needs to, by which time the
# database already exists.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class UtcDateTime(TypeDecorator[dt.datetime]):
    """A timezone-aware ``DateTime`` that is always UTC.

    SQLite has no native timezone support and hands back naive datetimes, which
    then compare incorrectly against aware ones.  Normalising in both directions
    here means the rest of the codebase can assume every datetime is aware --
    the DTZ lint rules enforce the other half of that bargain.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: dt.datetime | None, dialect: Dialect) -> dt.datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime passed to a UtcDateTime column")
        return value.astimezone(dt.UTC)

    def process_result_value(
        self, value: dt.datetime | None, dialect: Dialect
    ) -> dt.datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.UTC)
        return value.astimezone(dt.UTC)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class RepositoryType(enum.StrEnum):
    """Repository format.  Values are stored as strings, not integers."""

    APT = "apt"
    RPM = "rpm"


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
