"""Repository shape: the repository itself and its publication targets.

Only the tables M1 actually needs are defined here.  Packages, keys, jobs,
sessions, tokens and the audit log arrive with their own milestones
(specification.md 13.6) so that every migration corresponds to working code.
"""

from __future__ import annotations

import datetime as dt
import re

from sqlalchemy import (
    CheckConstraint,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from repository_manager.models.base import Base, RepositoryType, UtcDateTime, utcnow

# Lowercase, digits and hyphens; must start and end alphanumeric.  This is the
# only user-supplied string that ever appears in a URL path, so it is kept
# deliberately narrow (10.2, 10.4).
SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
SLUG_MAX_LENGTH = 64

# APT codenames and component names follow the same shape as Debian's own.
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _validate(pattern: re.Pattern[str], value: str, *, field: str, max_length: int) -> str:
    if not value:
        raise ValueError(f"{field} must not be empty")
    if len(value) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    if not pattern.match(value):
        raise ValueError(f"{field} {value!r} contains characters that are not permitted")
    return value


class Repository(Base):
    __tablename__ = "repository"
    __table_args__ = (CheckConstraint("retention_count >= 0", name="retention_count_non_negative"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(SLUG_MAX_LENGTH), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    type: Mapped[RepositoryType] = mapped_column(
        Enum(RepositoryType, native_enum=False, length=8, validate_strings=True)
    )
    root_path: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text, default=None)

    # 0 means "keep every version"; retention is version-based, not time-based
    # (AD-16, 5.3).  NOT NULL so the policy is always an explicit choice.
    retention_count: Mapped[int] = mapped_column(Integer, default=0)

    # APT Release fields; harmless and unused for RPM repositories.
    origin: Mapped[str | None] = mapped_column(String(200), default=None)
    label: Mapped[str | None] = mapped_column(String(200), default=None)

    created_at: Mapped[dt.datetime] = mapped_column(UtcDateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(Text, default=None)

    # Deregistration is soft: the row survives so the audit trail keeps meaning
    # even when the on-disk tree has been purged (8.1).
    deregistered_at: Mapped[dt.datetime | None] = mapped_column(UtcDateTime, default=None)

    distributions: Mapped[list[AptDistribution]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
        order_by="AptDistribution.codename",
    )
    variants: Mapped[list[RpmVariant]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
        order_by="RpmVariant.name, RpmVariant.arch",
    )

    @validates("slug")
    def _check_slug(self, _key: str, value: str) -> str:
        return _validate(SLUG_PATTERN, value, field="slug", max_length=SLUG_MAX_LENGTH)

    @property
    def is_active(self) -> bool:
        return self.deregistered_at is None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Repository {self.slug!r} type={self.type.value}>"


class AptDistribution(Base):
    """One `dists/<codename>` tree (4.1)."""

    __tablename__ = "apt_distribution"
    __table_args__ = (UniqueConstraint("repository_id", "codename"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repository.id", ondelete="CASCADE"), index=True
    )
    codename: Mapped[str] = mapped_column(String(100))
    suite: Mapped[str | None] = mapped_column(String(100), default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)

    repository: Mapped[Repository] = relationship(back_populates="distributions")
    components: Mapped[list[AptComponent]] = relationship(
        back_populates="distribution",
        cascade="all, delete-orphan",
        order_by="AptComponent.name",
    )
    architectures: Mapped[list[AptArchitecture]] = relationship(
        back_populates="distribution",
        cascade="all, delete-orphan",
        order_by="AptArchitecture.name",
    )

    @validates("codename", "suite")
    def _check_name(self, key: str, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate(NAME_PATTERN, value, field=key, max_length=100)


class AptComponent(Base):
    __tablename__ = "apt_component"
    __table_args__ = (UniqueConstraint("distribution_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    distribution_id: Mapped[int] = mapped_column(
        ForeignKey("apt_distribution.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))

    distribution: Mapped[AptDistribution] = relationship(back_populates="components")

    @validates("name")
    def _check_name(self, key: str, value: str) -> str:
        return _validate(NAME_PATTERN, value, field=key, max_length=100)


class AptArchitecture(Base):
    __tablename__ = "apt_architecture"
    __table_args__ = (UniqueConstraint("distribution_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    distribution_id: Mapped[int] = mapped_column(
        ForeignKey("apt_distribution.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(32))

    distribution: Mapped[AptDistribution] = relationship(back_populates="architectures")

    @validates("name")
    def _check_name(self, key: str, value: str) -> str:
        return _validate(NAME_PATTERN, value, field=key, max_length=32)


class RpmVariant(Base):
    """One `<name>/<arch>` tree, e.g. `el9/x86_64` (4.2, AD-15)."""

    __tablename__ = "rpm_variant"
    __table_args__ = (UniqueConstraint("repository_id", "name", "arch"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repository.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    arch: Mapped[str] = mapped_column(String(32))

    repository: Mapped[Repository] = relationship(back_populates="variants")

    @validates("name")
    def _check_name(self, key: str, value: str) -> str:
        return _validate(NAME_PATTERN, value, field=key, max_length=100)

    @validates("arch")
    def _check_arch(self, key: str, value: str) -> str:
        return _validate(NAME_PATTERN, value, field=key, max_length=32)
