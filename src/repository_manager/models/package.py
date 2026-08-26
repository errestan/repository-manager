"""Uploaded packages and where they are published (specification.md 9, 5.1).

A package is a single file in the pool.  Publishing it is a separate row, so
one pool file can appear under several distributions or components without
being stored twice -- which is how `Architecture: all` packages and shared
components stay cheap.
"""

from __future__ import annotations

import datetime as dt
import enum
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from repository_manager.models.base import Base, UtcDateTime, utcnow

if TYPE_CHECKING:  # pragma: no cover - resolved by SQLAlchemy at mapper configuration
    from repository_manager.models.repository import AptComponent, Repository, RpmVariant

# SQLite has no JSONB; PostgreSQL wants it for indexability.  One column type
# that resolves per dialect keeps the models free of `if dialect ==` branches.
ControlJSON = JSON().with_variant(JSONB(), "postgresql")


class UploadSource(enum.StrEnum):
    """How a package arrived, for the audit trail (9)."""

    WEB = "web"
    TOKEN = "token"  # noqa: S105 - an upload channel, not a credential
    IMPORT = "import"


class Package(Base):
    """One file in the pool, with its parsed metadata."""

    __tablename__ = "package"
    __table_args__ = (
        # The pool path is derived from parsed metadata, so two rows sharing one
        # path would mean two different packages claiming the same bytes.
        UniqueConstraint("repository_id", "relative_path", name="uq_package_repository_path"),
        CheckConstraint("size >= 0", name="size_non_negative"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repository.id", ondelete="CASCADE"), index=True
    )

    name: Mapped[str] = mapped_column(String(200), index=True)
    # The source package, used to compute the Debian pool prefix (4.1).  Falls
    # back to `name` when the control file omits `Source`.
    source_name: Mapped[str] = mapped_column(String(200))

    # RPM splits a version into epoch/version/release; Debian keeps one string.
    # Both formats store what they have and leave the rest NULL.
    epoch: Mapped[int | None] = mapped_column(Integer, default=None)
    version: Mapped[str] = mapped_column(String(200))
    release: Mapped[str | None] = mapped_column(String(200), default=None)
    architecture: Mapped[str] = mapped_column(String(32), index=True)

    # Relative to the repository root, always forward-slashed, never taken from
    # the uploaded filename (10.2).
    relative_path: Mapped[str] = mapped_column(Text)
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64), index=True)

    # Every control field the format gave us, so indices can be regenerated
    # without re-reading (and re-trusting) the file on disk.
    control_json: Mapped[dict[str, str]] = mapped_column(ControlJSON, default=dict)

    uploaded_at: Mapped[dt.datetime] = mapped_column(UtcDateTime, default=utcnow)
    uploaded_by: Mapped[str | None] = mapped_column(Text, default=None)
    uploaded_via: Mapped[UploadSource] = mapped_column(
        Enum(UploadSource, native_enum=False, length=8, validate_strings=True),
        default=UploadSource.WEB,
    )

    repository: Mapped[Repository] = relationship(back_populates="packages")
    publications: Mapped[list[PackagePublication]] = relationship(
        back_populates="package", cascade="all, delete-orphan"
    )

    @property
    def full_version(self) -> str:
        """Version as a human reads it, including epoch and release when present."""
        rendered = self.version
        if self.release:
            rendered = f"{rendered}-{self.release}"
        if self.epoch:
            rendered = f"{self.epoch}:{rendered}"
        return rendered

    @property
    def filename(self) -> str:
        return self.relative_path.rsplit("/", 1)[-1]

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Package {self.name}_{self.full_version}_{self.architecture}>"


class PackagePublication(Base):
    """A package's presence in one publication target.

    Exactly one of ``component_id`` (APT) and ``variant_id`` (RPM) is set.  The
    check constraint is what stops a half-written service call from producing a
    publication that belongs nowhere and is therefore invisible to every index.
    """

    __tablename__ = "package_publication"
    __table_args__ = (
        # Named explicitly: the naming convention keys on the first column, so
        # both of these would otherwise be called uq_package_publication_package_id
        # and the second CREATE would collide with the first on PostgreSQL.
        UniqueConstraint("package_id", "component_id", name="uq_publication_component"),
        UniqueConstraint("package_id", "variant_id", name="uq_publication_variant"),
        CheckConstraint(
            "(component_id IS NOT NULL) <> (variant_id IS NOT NULL)",
            name="exactly_one_target",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    package_id: Mapped[int] = mapped_column(
        ForeignKey("package.id", ondelete="CASCADE"), index=True
    )
    component_id: Mapped[int | None] = mapped_column(
        ForeignKey("apt_component.id", ondelete="CASCADE"), index=True, default=None
    )
    variant_id: Mapped[int | None] = mapped_column(
        ForeignKey("rpm_variant.id", ondelete="CASCADE"), index=True, default=None
    )

    published_at: Mapped[dt.datetime] = mapped_column(UtcDateTime, default=utcnow)

    package: Mapped[Package] = relationship(back_populates="publications")
    component: Mapped[AptComponent | None] = relationship(back_populates="publications")
    variant: Mapped[RpmVariant | None] = relationship(back_populates="publications")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        target = (
            f"component={self.component_id}" if self.component_id else f"variant={self.variant_id}"
        )
        return f"<PackagePublication package={self.package_id} {target}>"
