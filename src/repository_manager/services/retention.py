"""Pruning old versions (specification.md 5.3).

Retention is version-based and never time-based.  A package that is simply
stable rather than abandoned would be deleted by an age rule despite being the
only version clients can install, so nothing here looks at a date.

Three decisions shape this module.

**Ordering is the format's own.**  Debian's ``~`` and rpm's ``~`` and ``^`` do
not sort like strings, and "newest" decided by string comparison would prune
``1.10`` in favour of ``1.9``.  Both comparators already exist in
:mod:`repository_manager.metadata`; this module chooses between them and does
no arithmetic of its own.

**The group is (name, architecture, target).**  5.3 says "per package name per
publication target" and does not mention architecture, but grouping without it
is wrong in a way that loses data: a repository publishing ``amd64`` and
``arm64`` with N=3 would keep three *files* between them -- the newest three
across both -- and silently delete the current arm64 build because three amd64
builds happened to be newer.  Architecture is already part of what this
application calls the same package (an upload of the same name and version for
a different architecture is a new row, not a conflict), so it is part of the
group here too.

**Pruning goes through the ordinary removal path.**  A pruned publication is
deleted by :func:`repository_manager.services.packages.remove_publication`, the
same function the delete button calls, so the rule that a pool file survives
until no target references it holds without being restated.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from repository_manager.config import Settings
from repository_manager.logging import get_logger
from repository_manager.metadata import deb, rpm
from repository_manager.models import (
    ActorType,
    AptComponent,
    AuditAction,
    Package,
    PackagePublication,
    Repository,
    RepositoryType,
)
from repository_manager.services import audit
from repository_manager.services import packages as package_service

log = get_logger(__name__)

#: ``retention_count`` of zero means keep everything (5.3, AD-11).
KEEP_ALL = 0


@dataclass(frozen=True)
class Pruned:
    """One publication retention removed, for the audit trail and the UI."""

    name: str
    version: str
    architecture: str
    target: str
    relative_path: str
    #: False when the pool file survives because another target still lists it.
    file_deleted: bool = False

    @property
    def summary(self) -> str:
        return f"{self.name} {self.version} ({self.architecture}) from {self.target}"


@dataclass(frozen=True)
class Candidate:
    """A publication that retention would remove, before anything is removed."""

    publication: PackagePublication
    name: str
    version: str
    architecture: str
    target: str


def _sort_key(repository_type: RepositoryType, package: Package) -> Any:
    """Newest-last ordering for one package, in its own format's terms."""
    if repository_type is RepositoryType.APT:
        return deb.version_sort_key(package.version)
    return rpm.version_sort_key(package.epoch, package.version, package.release or "")


def target_label(publication: PackagePublication) -> str:
    """How a publication names its target, in the words the interface uses."""
    if publication.component is not None:
        return f"{publication.component.distribution.codename}/{publication.component.name}"
    variant = publication.variant
    return "" if variant is None else f"{variant.name}/{variant.arch}"


def _target_id(publication: PackagePublication) -> tuple[str, int]:
    """A key that cannot confuse a component id with a variant id."""
    if publication.component_id is not None:
        return ("component", publication.component_id)
    return ("variant", publication.variant_id or 0)


async def _publications(
    session: AsyncSession, repository: Repository, *, names: Sequence[str] | None = None
) -> list[PackagePublication]:
    """Every publication in this repository, with what the grouping needs loaded."""
    statement = (
        select(PackagePublication)
        .join(Package, Package.id == PackagePublication.package_id)
        .where(Package.repository_id == repository.id)
        .options(
            # `package.publications` as well as the package: removal reads that
            # collection to decide whether the pool file is still referenced,
            # and a lazy load there is MissingGreenlet on an async session
            # rather than merely a second query.
            selectinload(PackagePublication.package).selectinload(Package.publications),
            selectinload(PackagePublication.component).selectinload(AptComponent.distribution),
            selectinload(PackagePublication.variant),
        )
    )
    if names is not None:
        statement = statement.where(Package.name.in_(list(names)))
    return list((await session.execute(statement)).scalars().all())


def _surplus(repository: Repository, publications: Iterable[PackagePublication]) -> list[Candidate]:
    """The publications beyond the newest ``retention_count`` in each group."""
    keep = repository.retention_count
    if keep <= KEEP_ALL:
        return []

    groups: dict[tuple[str, str, tuple[str, int]], list[PackagePublication]] = {}
    for publication in publications:
        package = publication.package
        key = (package.name, package.architecture, _target_id(publication))
        groups.setdefault(key, []).append(publication)

    surplus: list[Candidate] = []
    for members in groups.values():
        if len(members) <= keep:
            continue
        # Newest first, so everything after the first `keep` is surplus.  The
        # publication id breaks ties: two rows can share a version only if the
        # same bytes were published twice, and a stable order matters more than
        # which of an identical pair goes.
        members.sort(
            key=lambda entry: (_sort_key(repository.type, entry.package), entry.id),
            reverse=True,
        )
        for publication in members[keep:]:
            package = publication.package
            surplus.append(
                Candidate(
                    publication=publication,
                    name=package.name,
                    version=package.full_version,
                    architecture=package.architecture,
                    target=target_label(publication),
                )
            )
    return surplus


async def preview(session: AsyncSession, repository: Repository) -> list[Candidate]:
    """What "apply retention now" would remove, for the settings page (5.3).

    Read-only.  Lowering N does not prune retroactively, so the number this
    returns is the backlog an admin may choose to clear, not something that is
    about to happen on its own.
    """
    return _surplus(repository, await _publications(session, repository))


async def _remove(
    session: AsyncSession,
    settings: Settings,
    repository: Repository,
    candidates: Sequence[Candidate],
) -> list[Pruned]:
    removed: list[Pruned] = []
    for candidate in candidates:
        relative_path = candidate.publication.package.relative_path
        file_deleted = await package_service.remove_publication(
            session, settings, repository, candidate.publication
        )
        removed.append(
            Pruned(
                name=candidate.name,
                version=candidate.version,
                architecture=candidate.architecture,
                target=candidate.target,
                relative_path=relative_path,
                file_deleted=file_deleted,
            )
        )
    return removed


async def enforce_for(
    session: AsyncSession,
    settings: Settings,
    repository: Repository,
    *,
    name: str,
) -> list[Pruned]:
    """Prune one package name after a successful publish (5.3).

    Scoped to the name just published rather than sweeping the repository: a
    publish should cost work proportional to itself, and pruning something a
    different upload left behind would make one person's action delete another
    person's package with no explanation.  Clearing that backlog is the
    settings page's explicit action.
    """
    if repository.retention_count <= KEEP_ALL:
        return []
    candidates = _surplus(repository, await _publications(session, repository, names=[name]))
    removed = await _remove(session, settings, repository, candidates)
    if removed:
        log.info(
            "retention pruned",
            repository=repository.slug,
            package=name,
            keep=repository.retention_count,
            removed=len(removed),
        )
    return removed


async def enforce_all(
    session: AsyncSession, settings: Settings, repository: Repository
) -> list[Pruned]:
    """The "apply retention now" action: prune the whole repository (5.3)."""
    candidates = await preview(session, repository)
    removed = await _remove(session, settings, repository, candidates)
    if removed:
        log.info(
            "retention applied",
            repository=repository.slug,
            keep=repository.retention_count,
            removed=len(removed),
        )
    return removed


async def record(
    session: AsyncSession,
    repository: Repository,
    pruned: Sequence[Pruned],
    *,
    actor: str,
    actor_type: ActorType = ActorType.USER,
    source_ip: str | None = None,
) -> None:
    """Write one audit entry per pruned publication (5.3).

    One entry each rather than a single summary: the audit log's job is to
    answer "what happened to this package?", and a row naming a count answers
    that for nobody.
    """
    for entry in pruned:
        await audit.record(
            session,
            action=AuditAction.PACKAGE_PRUNE,
            actor=actor,
            actor_type=actor_type,
            repository_id=repository.id,
            target=entry.relative_path,
            source_ip=source_ip,
            details={
                "name": entry.name,
                "version": entry.version,
                "architecture": entry.architecture,
                "pruned_from": entry.target,
                "file_deleted": entry.file_deleted,
                "retention_count": repository.retention_count,
            },
        )
