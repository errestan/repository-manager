"""Turning database state into signed on-disk metadata (specification.md 5.4).

Regeneration is always a job, never inline (AD-8).  An upload returns as soon
as the file is safely in the pool; the index rebuild that follows is bounded by
the repository's size, not the request's patience.

The plan handed to the generator is built entirely from the database.  Nothing
in this module reads a ``.deb`` -- the stanza was computed once, at upload, and
stored on the row.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from collections import defaultdict
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from repository_manager.config import Settings
from repository_manager.jobs.lock import repository_lock
from repository_manager.jobs.queue import JobContext, JobQueue
from repository_manager.logging import get_logger
from repository_manager.metadata import apt
from repository_manager.models import (
    AptComponent,
    AptDistribution,
    JobType,
    Package,
    PackagePublication,
    Repository,
    RepositoryType,
)
from repository_manager.security.paths import atomic_write_text, resolve_within_roots

log = get_logger(__name__)

# Regeneration holds the on-disk lock for the whole rebuild.  Longer than a
# rebuild should ever take, short enough that a wedged peer is reported rather
# than waited on forever.
LOCK_TIMEOUT_SECONDS = 120.0


class PublishError(Exception):
    """Metadata could not be regenerated; the message reaches the job log."""


def public_key_filename(key_name: str) -> str:
    """Where the armoured public key sits in the repository root (4.1)."""
    return f"{key_name}.asc"


async def load_for_publish(session: AsyncSession, repository_id: int) -> Repository:
    """Load a repository with everything the generator needs, eagerly.

    Every relationship touched below is loaded here: a lazy load inside the
    worker would raise ``MissingGreenlet`` rather than simply being slow.
    """
    repository = await session.scalar(
        select(Repository)
        .where(Repository.id == repository_id)
        .options(
            selectinload(Repository.signing_key),
            selectinload(Repository.distributions).selectinload(AptDistribution.components),
            selectinload(Repository.distributions).selectinload(AptDistribution.architectures),
            selectinload(Repository.variants),
        )
    )
    if repository is None:
        raise PublishError(f"Repository {repository_id} no longer exists.")
    return repository


async def stanzas_by_target(
    session: AsyncSession, repository: Repository
) -> dict[tuple[str, str], list[dict[str, str]]]:
    """Published package stanzas, keyed by (codename, component)."""
    rows = await session.execute(
        select(AptDistribution.codename, AptComponent.name, Package.control_json)
        .join(AptComponent, AptComponent.distribution_id == AptDistribution.id)
        .join(PackagePublication, PackagePublication.component_id == AptComponent.id)
        .join(Package, Package.id == PackagePublication.package_id)
        .where(AptDistribution.repository_id == repository.id)
    )
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for codename, component, control in rows:
        grouped[(codename, component)].append(dict(control))
    return grouped


async def build_apt_plan(session: AsyncSession, repository: Repository) -> apt.RepositoryPlan:
    grouped = await stanzas_by_target(session, repository)
    distributions = tuple(
        apt.DistributionPlan(
            codename=distribution.codename,
            suite=distribution.suite or distribution.codename,
            description=distribution.description,
            architectures=tuple(a.name for a in distribution.architectures),
            components=tuple(c.name for c in distribution.components),
            stanzas={
                component.name: grouped.get((distribution.codename, component.name), [])
                for component in distribution.components
            },
        )
        for distribution in repository.distributions
    )
    return apt.RepositoryPlan(
        # Origin and Label end up in every client's apt cache; falling back to
        # the repository's own name keeps them meaningful without extra input.
        origin=repository.origin or repository.name,
        label=repository.label or repository.name,
        distributions=distributions,
    )


def write_apt_metadata(
    root: Path,
    plan: apt.RepositoryPlan,
    *,
    signer: apt.Signer,
    key_name: str,
    public_key: str,
    moment: dt.datetime | None = None,
) -> int:
    """Blocking half of a regeneration: signing and filesystem work.

    Called through ``asyncio.to_thread``; gpg is a subprocess and the index
    write is synchronous IO, so running it on the loop would stall every other
    request for the duration.
    """
    with repository_lock(root, timeout=LOCK_TIMEOUT_SECONDS):
        apt.create_skeleton(root, plan)
        generated = apt.generate(root, plan, signer=signer, moment=moment)
        # Re-exported on every publish: it is cheap, and it repairs a root whose
        # key file was deleted out of band without needing a separate action.
        atomic_write_text(root / public_key_filename(key_name), public_key)
    return sum(len(files) for files in generated.values())


async def regenerate_metadata(context: JobContext) -> None:
    """Job handler for :data:`JobType.REGENERATE_METADATA`."""
    from repository_manager.services.keys import build_signer

    if context.repository_id is None:
        raise PublishError("A metadata regeneration job must name a repository.")

    settings = context.settings
    async with context.sessionmaker() as session:
        repository = await load_for_publish(session, context.repository_id)
        if repository.type is not RepositoryType.APT:
            raise PublishError(
                f"{repository.slug!r} is an RPM repository; createrepo_c integration "
                "arrives in M4 (specification.md 13.6)."
            )
        if repository.signing_key is None:
            raise PublishError(
                f"{repository.slug!r} has no signing key, so its metadata cannot be signed."
            )
        plan = await build_apt_plan(session, repository)
        key = repository.signing_key
        key_name, public_key = key.name, key.public_key_armored
        root_path = repository.root_path
        slug = repository.slug

    await context.log(f"Regenerating metadata for {slug}.")
    await context.set_progress(10)

    # Re-checked here, not merely at creation: the allowed roots may have been
    # narrowed since, and this is a write (10.4).
    root = resolve_within_roots(Path(root_path), settings.allowed_roots)
    signer = build_signer(settings, key)

    await context.set_progress(30)
    written = await asyncio.to_thread(
        write_apt_metadata,
        root,
        plan,
        signer=signer,
        key_name=key_name,
        public_key=public_key,
    )

    await context.set_progress(100)
    distributions = ", ".join(d.codename for d in plan.distributions) or "(none)"
    await context.log(f"Wrote {written} index files across: {distributions}.")
    log.info("metadata regenerated", repository=slug, files=written)


def register_handlers(queue: JobQueue) -> None:
    queue.register(JobType.REGENERATE_METADATA, regenerate_metadata)


async def request_regeneration(
    session: AsyncSession,
    queue: JobQueue,
    repository: Repository,
    *,
    actor: str | None = None,
) -> int:
    """Queue a rebuild in the caller's transaction.

    The caller must commit and then call :meth:`JobQueue.wake`; see
    :meth:`JobQueue.enqueue` for why the two steps are separate.
    """
    return await queue.enqueue(
        session, JobType.REGENERATE_METADATA, repository_id=repository.id, actor=actor
    )


def initial_metadata(
    settings: Settings,
    root: Path,
    plan: apt.RepositoryPlan,
    *,
    signer: apt.Signer,
    key_name: str,
    public_key: str,
) -> int:
    """Write the empty-but-valid metadata a brand new repository needs (4.3).

    Doing this at creation rather than at first upload means a client can add
    the repository and run ``apt update`` straight away, which is when people
    actually try it.
    """
    resolve_within_roots(root, settings.allowed_roots)
    return write_apt_metadata(root, plan, signer=signer, key_name=key_name, public_key=public_key)
