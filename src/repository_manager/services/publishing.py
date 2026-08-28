"""Turning database state into signed on-disk metadata (specification.md 5.4).

Regeneration is always a job, never inline (AD-8).  An upload returns as soon
as the file is safely in the pool; the index rebuild that follows is bounded by
the repository's size, not the request's patience.

For APT the plan handed to the generator is built entirely from the database.
Nothing in this module reads a ``.deb`` -- the stanza was computed once, at
upload, and stored on the row.

RPM is the other way round, and deliberately so (AD-2): ``createrepo_c`` reads
the packages on disk itself, so the plan is only the *shape* of the tree -- which
variants exist -- and the database is never asked what is inside them.  The two
formats therefore fail differently, and it is worth knowing which you are
looking at: a wrong APT index means the row was wrong, a wrong RPM index means
the filesystem was.
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
from repository_manager.metadata import apt, repodata
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


async def build_rpm_plan(session: AsyncSession, repository: Repository) -> repodata.RepositoryPlan:
    """The variants to reindex.

    Takes no package data at all: ``createrepo_c`` walks each variant's
    ``Packages`` directory and builds the indices from the files themselves
    (4.2).  ``session`` is unused for that reason and kept only so both plan
    builders have the same signature -- an asymmetry here would be read as an
    oversight rather than as the design.
    """
    del session
    return repodata.RepositoryPlan(
        variants=tuple(
            repodata.VariantPlan(name=variant.name, arch=variant.arch)
            for variant in repository.variants
        )
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


def write_rpm_metadata(
    root: Path,
    plan: repodata.RepositoryPlan,
    *,
    signer: repodata.Signer,
    key_name: str,
    public_key: str,
) -> dict[str, repodata.VariantResult]:
    """Blocking half of an RPM regeneration: createrepo_c, signing, filesystem.

    Called through ``asyncio.to_thread`` for the same reason as its APT
    counterpart, and more urgently: ``createrepo_c`` is a subprocess that can
    run for minutes on a large variant, and running it on the event loop would
    stop the application answering anything at all until it finished.
    """
    with repository_lock(root, timeout=LOCK_TIMEOUT_SECONDS):
        repodata.create_skeleton(root, plan)
        generated = repodata.generate(root, plan, signer=signer)
        atomic_write_text(root / repodata.public_key_filename(key_name), public_key)
    return generated


async def regenerate_metadata(context: JobContext) -> None:
    """Job handler for :data:`JobType.REGENERATE_METADATA`."""
    from repository_manager.services.keys import build_signer

    if context.repository_id is None:
        raise PublishError("A metadata regeneration job must name a repository.")

    settings = context.settings
    async with context.sessionmaker() as session:
        repository = await load_for_publish(session, context.repository_id)
        if repository.signing_key is None:
            raise PublishError(
                f"{repository.slug!r} has no signing key, so its metadata cannot be signed."
            )
        is_apt = repository.type is RepositoryType.APT
        plan: apt.RepositoryPlan | repodata.RepositoryPlan = (
            await build_apt_plan(session, repository)
            if is_apt
            else await build_rpm_plan(session, repository)
        )
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
    if isinstance(plan, apt.RepositoryPlan):
        written = await asyncio.to_thread(
            write_apt_metadata,
            root,
            plan,
            signer=signer,
            key_name=key_name,
            public_key=public_key,
        )
        targets = ", ".join(d.codename for d in plan.distributions) or "(none)"
        summary = f"Wrote {written} index files across: {targets}."
        count = written
    else:
        try:
            results = await asyncio.to_thread(
                write_rpm_metadata,
                root,
                plan,
                signer=signer,
                key_name=key_name,
                public_key=public_key,
            )
        except repodata.RepodataError as exc:
            # Surfaced as a job failure with the tool's own words rather than a
            # traceback: "createrepo_c is not installed" is something an
            # operator can act on, and a stack trace is not (6).
            raise PublishError(str(exc)) from exc
        indexed = sum(result.packages for result in results.values())
        targets = ", ".join(sorted(results)) or "(none)"
        summary = f"Indexed and signed {indexed} package(s) across: {targets}."
        count = len(results)

    await context.set_progress(100)
    await context.log(summary)
    log.info("metadata regenerated", repository=slug, type=repository.type.value, written=count)


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


def initial_apt_metadata(
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


def initial_rpm_metadata(
    settings: Settings,
    root: Path,
    plan: repodata.RepositoryPlan,
    *,
    signer: repodata.Signer,
    key_name: str,
    public_key: str,
) -> dict[str, repodata.VariantResult]:
    """The RPM equivalent: an empty but signed ``repodata`` per variant (4.3).

    ``createrepo_c`` is perfectly happy to index a directory with no packages
    in it, and the result is a repository ``dnf`` can be pointed at and will
    refresh without complaint -- which is the whole point of doing this now
    rather than at first upload.
    """
    resolve_within_roots(root, settings.allowed_roots)
    return write_rpm_metadata(root, plan, signer=signer, key_name=key_name, public_key=public_key)
