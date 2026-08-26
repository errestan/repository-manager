"""Model validation and persistence (specification.md 9)."""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import sqlite
from sqlalchemy.orm import Session

from repository_manager.models import (
    AptComponent,
    AptDistribution,
    Repository,
    RepositoryType,
    RpmVariant,
)
from repository_manager.models.base import UtcDateTime, utcnow


@pytest.mark.parametrize("slug", ["a", "repo", "internal-apt", "el9", "a1-b2-c3"])
def test_valid_slugs_are_accepted(slug: str) -> None:
    assert Repository(slug=slug).slug == slug


@pytest.mark.parametrize(
    "slug",
    ["", "A", "Repo", "-leading", "trailing-", "has space", "has/slash", "has.dot", "a" * 65],
)
def test_invalid_slugs_are_rejected(slug: str) -> None:
    # The slug is the only user string that reaches a URL path (10.2, 10.4).
    with pytest.raises(ValueError, match="slug"):
        Repository(slug=slug)


@pytest.mark.parametrize("name", ["", "bad name", "bad/name", "../escape"])
def test_distribution_codenames_are_validated(name: str) -> None:
    with pytest.raises(ValueError, match="codename"):
        AptDistribution(codename=name)


@pytest.mark.parametrize("arch", ["../..", "x 86", ""])
def test_variant_arch_is_validated(arch: str) -> None:
    with pytest.raises(ValueError, match="arch"):
        RpmVariant(name="el9", arch=arch)


def test_repository_round_trips(sync_session: Session, apt_repository: Repository) -> None:
    stored = sync_session.execute(
        select(Repository).where(Repository.slug == "internal")
    ).scalar_one()
    assert stored.type is RepositoryType.APT
    assert stored.retention_count == 3
    assert stored.is_active is True
    assert [d.codename for d in stored.distributions] == ["bookworm"]
    assert sorted(c.name for c in stored.distributions[0].components) == ["contrib", "main"]


def test_created_at_is_timezone_aware(sync_session: Session, apt_repository: Repository) -> None:
    stored = sync_session.execute(select(Repository)).scalar_one()
    assert stored.created_at.tzinfo is not None
    assert stored.created_at.utcoffset() == dt.timedelta(0)


def test_deleting_a_repository_removes_its_children(
    sync_session: Session, apt_repository: Repository
) -> None:
    # ON DELETE CASCADE only fires because the SQLite foreign_keys pragma is on.
    sync_session.delete(apt_repository)
    sync_session.commit()
    assert sync_session.execute(select(AptDistribution)).scalars().all() == []
    assert sync_session.execute(select(AptComponent)).scalars().all() == []


def test_slug_is_unique(sync_session: Session, apt_repository: Repository) -> None:
    from sqlalchemy.exc import IntegrityError

    sync_session.add(
        Repository(
            slug="internal", name="Duplicate", type=RepositoryType.RPM, root_path="/tmp/dupe"
        )
    )
    with pytest.raises(IntegrityError):
        sync_session.commit()
    sync_session.rollback()


def test_retention_count_cannot_be_negative(sync_session: Session) -> None:
    from sqlalchemy.exc import IntegrityError

    sync_session.add(
        Repository(
            slug="negative",
            name="Negative",
            type=RepositoryType.APT,
            root_path="/tmp/n",
            retention_count=-1,
        )
    )
    with pytest.raises(IntegrityError):
        sync_session.commit()
    sync_session.rollback()


def test_deregistered_repository_is_not_active() -> None:
    repository = Repository(slug="gone", deregistered_at=utcnow())
    assert repository.is_active is False


def test_utc_datetime_rejects_naive_values() -> None:
    column = UtcDateTime()
    with pytest.raises(ValueError, match="naive datetime"):
        column.process_bind_param(dt.datetime(2026, 1, 1), sqlite.dialect())  # noqa: DTZ001


def test_utc_datetime_normalises_to_utc() -> None:
    column = UtcDateTime()
    eastern = dt.timezone(dt.timedelta(hours=-5))
    value = dt.datetime(2026, 1, 1, 12, 0, tzinfo=eastern)
    assert column.process_bind_param(value, sqlite.dialect()) == value.astimezone(dt.UTC)
