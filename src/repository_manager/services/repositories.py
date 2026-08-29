"""Creating and configuring repositories (specification.md 4.3)."""

from __future__ import annotations

import asyncio
import contextlib
import re
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from repository_manager.config import Settings
from repository_manager.logging import get_logger
from repository_manager.metadata import apt, repodata
from repository_manager.models import (
    AptArchitecture,
    AptComponent,
    AptDistribution,
    PackagePublication,
    Repository,
    RepositoryType,
    RpmVariant,
    SigningKey,
)
from repository_manager.models.base import utcnow
from repository_manager.models.repository import SLUG_MAX_LENGTH
from repository_manager.security.paths import (
    PathError,
    force_remove_tree,
    is_empty_directory,
    remove_tree,
    resolve_within_roots,
)
from repository_manager.services import keys as key_service
from repository_manager.services import publishing

log = get_logger(__name__)

_NON_SLUG = re.compile(r"[^a-z0-9]+")


class RepositoryServiceError(Exception):
    """A repository could not be created; the message is shown to the user."""


@dataclass(frozen=True)
class DistributionSpec:
    """One requested ``dists/<codename>`` tree."""

    codename: str
    components: tuple[str, ...]
    architectures: tuple[str, ...]
    suite: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class VariantSpec:
    """One requested ``<name>/<arch>`` tree, e.g. ``el9/x86_64`` (4.2)."""

    name: str
    arch: str

    @property
    def path(self) -> str:
        return f"{self.name}/{self.arch}"


def slugify(name: str) -> str:
    """Derive a URL-safe identifier from a display name.

    The slug is generated rather than asked for: it is the only user-controlled
    string that appears in a URL path, and one fewer free-text field is one
    fewer place for a name that fails validation for reasons nobody expected.
    """
    slug = _NON_SLUG.sub("-", name.strip().lower()).strip("-")[:SLUG_MAX_LENGTH].rstrip("-")
    return slug or "repository"


async def unique_slug(session: AsyncSession, base: str) -> str:
    """``base``, or ``base-2``, ``base-3``... until it is free."""
    candidate = base
    suffix = 1
    while await session.scalar(select(Repository.id).where(Repository.slug == candidate)):
        suffix += 1
        tail = f"-{suffix}"
        candidate = f"{base[: SLUG_MAX_LENGTH - len(tail)].rstrip('-')}{tail}"
    return candidate


def validate_root(raw: str, settings: Settings) -> Path:
    """Check a proposed repository root against every rule in 4.3 step 1."""
    if not raw.strip():
        raise RepositoryServiceError("A repository root path is required.")
    try:
        root = resolve_within_roots(Path(raw.strip()), settings.allowed_roots)
    except PathError as exc:
        raise RepositoryServiceError(str(exc)) from exc

    if root.exists():
        if not root.is_dir():
            raise RepositoryServiceError(f"{root} exists and is not a directory.")
        if not is_empty_directory(root):
            raise RepositoryServiceError(
                f"{root} already contains files. Choose an empty or non-existent directory "
                "so an existing repository is never partially overwritten."
            )
    return root


async def _resolve_key(session: AsyncSession, key_id: int) -> SigningKey:
    key = await session.get(SigningKey, key_id)
    if key is None:
        raise RepositoryServiceError("The selected signing key no longer exists.")
    return key


def _plan_from_specs(
    name: str, origin: str | None, label: str | None, specs: tuple[DistributionSpec, ...]
) -> apt.RepositoryPlan:
    return apt.RepositoryPlan(
        origin=origin or name,
        label=label or name,
        distributions=tuple(
            apt.DistributionPlan(
                codename=spec.codename,
                suite=spec.suite or spec.codename,
                description=spec.description,
                architectures=spec.architectures,
                components=spec.components,
            )
            for spec in specs
        ),
    )


def _check_specs(specs: tuple[DistributionSpec, ...]) -> None:
    if not specs:
        raise RepositoryServiceError(
            "An APT repository needs at least one distribution with a component and "
            "an architecture, or clients have nothing to point at."
        )
    for spec in specs:
        if not spec.components:
            raise RepositoryServiceError(
                f"Distribution {spec.codename!r} needs at least one component (for example 'main')."
            )
        if not spec.architectures:
            raise RepositoryServiceError(
                f"Distribution {spec.codename!r} needs at least one architecture "
                "(for example 'amd64')."
            )


async def create_apt_repository(
    session: AsyncSession,
    settings: Settings,
    *,
    name: str,
    root_path: str,
    signing_key_id: int,
    retention_count: int,
    distributions: tuple[DistributionSpec, ...],
    description: str | None = None,
    origin: str | None = None,
    label: str | None = None,
    actor: str | None = None,
) -> Repository:
    """Create an APT repository, on disk and in the database (4.3).

    The database rows are written first and the filesystem second, so a failure
    while writing metadata rolls the transaction back rather than leaving a row
    pointing at a tree that was never finished.  The reverse order would leave
    an orphaned directory that only a rescan could explain.
    """
    if not name.strip():
        raise RepositoryServiceError("A repository name is required.")
    if retention_count < 0:
        raise RepositoryServiceError("Retention must be 'keep all' or a positive number.")
    _check_specs(distributions)

    root = validate_root(root_path, settings)
    key = await _resolve_key(session, signing_key_id)
    await key_service.verify_usable(settings, key)

    repository = Repository(
        slug=await unique_slug(session, slugify(name)),
        name=name.strip(),
        type=RepositoryType.APT,
        root_path=str(root),
        description=(description or "").strip() or None,
        retention_count=retention_count,
        origin=(origin or "").strip() or None,
        label=(label or "").strip() or None,
        signing_key_id=key.id,
        created_by=actor,
    )
    for spec in distributions:
        repository.distributions.append(
            AptDistribution(
                codename=spec.codename,
                suite=spec.suite,
                description=spec.description,
                components=[AptComponent(name=component) for component in spec.components],
                architectures=[
                    AptArchitecture(name=architecture) for architecture in spec.architectures
                ],
            )
        )
    session.add(repository)
    await session.flush()

    plan = _plan_from_specs(repository.name, repository.origin, repository.label, distributions)
    signer = key_service.build_signer(settings, key)
    await asyncio.to_thread(
        publishing.initial_apt_metadata,
        settings,
        root,
        plan,
        signer=signer,
        key_name=key.name,
        public_key=key.public_key_armored,
    )

    log.info(
        "repository created",
        slug=repository.slug,
        root=str(root),
        key=key.name,
        distributions=[spec.codename for spec in distributions],
    )
    return repository


def _check_variants(specs: tuple[VariantSpec, ...]) -> None:
    if not specs:
        raise RepositoryServiceError(
            "An RPM repository needs at least one variant, or clients have nothing to "
            "point at. A variant is a name and an architecture, for example 'el9' and "
            "'x86_64'."
        )
    seen: set[str] = set()
    for spec in specs:
        # Validated by the generator's own rules rather than by a second copy of
        # them here: these names become directory names, and the module that
        # creates the directories is the one that should decide what is safe
        # (4.2, 10.4).
        try:
            repodata.VariantPlan(name=spec.name, arch=spec.arch)
        except repodata.RepodataError as exc:
            raise RepositoryServiceError(str(exc)) from exc
        if spec.path in seen:
            raise RepositoryServiceError(f"Variant {spec.path!r} is listed twice.")
        seen.add(spec.path)


def _variant_plan(specs: tuple[VariantSpec, ...]) -> repodata.RepositoryPlan:
    return repodata.RepositoryPlan(
        variants=tuple(repodata.VariantPlan(name=spec.name, arch=spec.arch) for spec in specs)
    )


async def create_rpm_repository(
    session: AsyncSession,
    settings: Settings,
    *,
    name: str,
    root_path: str,
    signing_key_id: int,
    retention_count: int,
    variants: tuple[VariantSpec, ...],
    description: str | None = None,
    actor: str | None = None,
) -> Repository:
    """Create an RPM repository, on disk and in the database (4.3).

    Rows first, filesystem second, for the same reason as
    :func:`create_apt_repository`: a failure part-way through rolls the
    transaction back rather than leaving a row pointing at a half-built tree.

    This is the first point at which ``createrepo_c`` has to be present.  It is
    a better place to discover it is missing than the first upload, which is
    both later and further from the person who can install it.
    """
    if not name.strip():
        raise RepositoryServiceError("A repository name is required.")
    if retention_count < 0:
        raise RepositoryServiceError("Retention must be 'keep all' or a positive number.")
    _check_variants(variants)

    root = validate_root(root_path, settings)
    key = await _resolve_key(session, signing_key_id)
    await key_service.verify_usable(settings, key)

    repository = Repository(
        slug=await unique_slug(session, slugify(name)),
        name=name.strip(),
        type=RepositoryType.RPM,
        root_path=str(root),
        description=(description or "").strip() or None,
        retention_count=retention_count,
        signing_key_id=key.id,
        created_by=actor,
    )
    for spec in variants:
        repository.variants.append(RpmVariant(name=spec.name, arch=spec.arch))
    session.add(repository)
    await session.flush()

    signer = key_service.build_signer(settings, key)
    try:
        await asyncio.to_thread(
            publishing.initial_rpm_metadata,
            settings,
            root,
            _variant_plan(variants),
            signer=signer,
            key_name=key.name,
            public_key=key.public_key_armored,
        )
    except repodata.RepodataError as exc:
        raise RepositoryServiceError(str(exc)) from exc

    log.info(
        "repository created",
        slug=repository.slug,
        root=str(root),
        key=key.name,
        variants=[spec.path for spec in variants],
    )
    return repository


async def add_variant(
    session: AsyncSession, repository: Repository, spec: VariantSpec
) -> RpmVariant:
    """Add a variant to an existing RPM repository (4.3).

    The new tree is empty until the regeneration job the caller queues runs,
    which is what writes and signs its first ``repodata``.
    """
    if repository.type is not RepositoryType.RPM:
        raise RepositoryServiceError("Only RPM repositories have variants.")
    _check_variants((spec,))

    clash = await session.scalar(
        select(RpmVariant).where(
            RpmVariant.repository_id == repository.id,
            RpmVariant.name == spec.name,
            RpmVariant.arch == spec.arch,
        )
    )
    if clash is not None:
        raise RepositoryServiceError(
            f"{repository.name} already has a variant called {spec.path!r}."
        )

    variant = RpmVariant(repository_id=repository.id, name=spec.name, arch=spec.arch)
    session.add(variant)
    await session.flush()
    log.info("variant added", slug=repository.slug, variant=spec.path)
    return variant


async def add_distribution(
    session: AsyncSession, repository: Repository, spec: DistributionSpec
) -> AptDistribution:
    """Add a distribution to an existing APT repository (4.3)."""
    if repository.type is not RepositoryType.APT:
        raise RepositoryServiceError("Only APT repositories have distributions.")
    _check_specs((spec,))

    clash = await session.scalar(
        select(AptDistribution).where(
            AptDistribution.repository_id == repository.id,
            AptDistribution.codename == spec.codename,
        )
    )
    if clash is not None:
        raise RepositoryServiceError(
            f"{repository.name} already has a distribution called {spec.codename!r}."
        )

    distribution = AptDistribution(
        repository_id=repository.id,
        codename=spec.codename,
        suite=spec.suite,
        description=spec.description,
        components=[AptComponent(name=component) for component in spec.components],
        architectures=[AptArchitecture(name=architecture) for architecture in spec.architectures],
    )
    session.add(distribution)
    await session.flush()
    log.info("distribution added", slug=repository.slug, codename=spec.codename)
    return distribution


def parse_name_list(raw: str) -> tuple[str, ...]:
    """Split a comma- or space-separated form field into a sorted, unique tuple.

    Sorted rather than kept in the order typed, because the relationships load
    ordered by name: leaving the typed order here would make the Release written
    at creation list `Components: main contrib` and every later regeneration
    list `contrib main`.  Identical content, different bytes -- which would
    quietly break the guarantee that regenerating an unchanged repository
    produces an unchanged index (4.1).
    """
    parts = [part.strip() for part in re.split(r"[,\s]+", raw) if part.strip()]
    return tuple(sorted(set(parts)))


@dataclass(frozen=True)
class SettingsUpdate:
    """What an admin may change about a repository after it exists (8.1).

    Four things are deliberately absent.

    The **slug** is immutable: it is in every client's ``sources.list`` and
    ``.repo`` file, and an interface that silently broke those would be worse
    than one that never offered to.

    The **root path** is immutable for the same class of reason — moving a
    published tree is a filesystem operation with clients reading from it, not
    a form field.

    The **format** is immutable because the on-disk layout is the format.

    Distributions and variants have their own routes; they are lists, not
    settings, and editing them inline would put "delete everything published to
    bookworm" behind a Save button next to a description field.
    """

    name: str
    description: str | None
    retention_count: int
    signing_key_id: int
    origin: str | None = None
    label: str | None = None


async def update_settings(
    session: AsyncSession, settings: Settings, repository: Repository, update: SettingsUpdate
) -> set[str]:
    """Apply a settings change, returning the names of the fields that moved.

    Returning what changed rather than nothing is what lets the caller decide
    whether a regeneration is needed and what to write in the audit log: a
    description edit does not touch a single byte on disk, and queueing a
    rebuild for it would be noise in the job list.
    """
    if not update.name.strip():
        raise RepositoryServiceError("A repository name is required.")
    if update.retention_count < 0:
        raise RepositoryServiceError("Retention must be 'keep all' or a positive number.")

    key = await _resolve_key(session, update.signing_key_id)
    changed: set[str] = set()
    previous_key = repository.signing_key

    if key.id != repository.signing_key_id:
        # Rotation (3): checked before anything is written, because a key that
        # cannot sign would leave the repository unable to regenerate and the
        # only evidence in a job that fails later.
        await key_service.verify_usable(settings, key)
        changed.add("signing_key")

    for field_name, value in (
        ("name", update.name.strip()),
        ("description", (update.description or "").strip() or None),
        ("origin", (update.origin or "").strip() or None),
        ("label", (update.label or "").strip() or None),
        ("retention_count", update.retention_count),
    ):
        if getattr(repository, field_name) != value:
            setattr(repository, field_name, value)
            changed.add(field_name)

    if "signing_key" in changed:
        repository.signing_key_id = key.id
        if previous_key is not None:
            await asyncio.to_thread(
                _discard_public_key, Path(repository.root_path), repository.type, previous_key.name
            )
    await session.flush()

    if changed:
        log.info("repository settings changed", slug=repository.slug, fields=sorted(changed))
    return changed


def _discard_public_key(root: Path, repository_type: RepositoryType, key_name: str) -> None:
    """Remove a superseded key's exported public half.

    Left behind, it is a file clients may already be pinned to that no longer
    signs anything -- which reads as "this repository is signed by two keys"
    when it is signed by one.  The replacement is written by the regeneration
    the caller queues.
    """
    filename = (
        publishing.public_key_filename(key_name)
        if repository_type is RepositoryType.APT
        else repodata.public_key_filename(key_name)
    )
    (root / filename).unlink(missing_ok=True)


async def _publication_count(session: AsyncSession, **filters: int) -> int:
    statement = select(func.count(PackagePublication.id))
    for column, value in filters.items():
        statement = statement.where(getattr(PackagePublication, column) == value)
    return int(await session.scalar(statement) or 0)


async def remove_distribution(
    session: AsyncSession, settings: Settings, repository: Repository, distribution: AptDistribution
) -> None:
    """Delete a distribution and its ``dists/<codename>`` tree (8.1).

    Refused while anything is still published in it.  The cascade would happily
    delete those publications, and their pool files with them -- so the check is
    not politeness, it is the difference between removing an empty tree and
    silently deleting packages somebody is installing.
    """
    if repository.type is not RepositoryType.APT:
        raise RepositoryServiceError("Only APT repositories have distributions.")

    published = 0
    for component in distribution.components:
        published += await _publication_count(session, component_id=component.id)
    if published:
        raise RepositoryServiceError(
            f"{distribution.codename} still publishes {published} package(s). Remove them "
            "first; deleting the distribution would delete them without a record of which."
        )

    codename = distribution.codename
    root = resolve_within_roots(Path(repository.root_path), settings.allowed_roots)
    await session.delete(distribution)
    await session.flush()
    await asyncio.to_thread(force_remove_tree, root / "dists" / codename)
    log.info("distribution removed", slug=repository.slug, codename=codename)


async def remove_variant(
    session: AsyncSession, settings: Settings, repository: Repository, variant: RpmVariant
) -> None:
    """Delete a variant and its ``<name>/<arch>`` tree (8.1)."""
    if repository.type is not RepositoryType.RPM:
        raise RepositoryServiceError("Only RPM repositories have variants.")

    published = await _publication_count(session, variant_id=variant.id)
    if published:
        raise RepositoryServiceError(
            f"{variant.name}/{variant.arch} still publishes {published} package(s). Remove "
            "them first; deleting the variant would delete them without a record of which."
        )

    path = f"{variant.name}/{variant.arch}"
    root = resolve_within_roots(Path(repository.root_path), settings.allowed_roots)
    await session.delete(variant)
    await session.flush()
    await asyncio.to_thread(force_remove_tree, root / variant.name / variant.arch)
    # The name directory is shared by every architecture of that variant, so it
    # goes only once nothing is left in it.
    with contextlib.suppress(OSError):
        (root / variant.name).rmdir()
    log.info("variant removed", slug=repository.slug, variant=path)


async def deregister(
    session: AsyncSession,
    settings: Settings,
    repository: Repository,
    *,
    purge: bool = False,
) -> bool:
    """Stop managing a repository, optionally deleting its files (8.1).

    Deregistration is **soft**: the row keeps its slug, its creation record and
    its foreign keys, so the audit trail still names something real long after
    the tree is gone (9).  What goes away is the repository's presence in every
    listing, and its ability to accept an upload.

    Purging is the destructive half and is separate for that reason.  It is
    re-checked against the allowed roots on the way in -- the check that matters
    is the one made at the moment of the ``rm``, not the one made when the path
    was first accepted (10.4).

    Returns whether files were actually removed.
    """
    repository.deregistered_at = utcnow()
    await session.flush()

    if not purge:
        log.info("repository deregistered", slug=repository.slug, purged=False)
        return False

    root = resolve_within_roots(Path(repository.root_path), settings.allowed_roots)
    await asyncio.to_thread(remove_tree, root, settings.allowed_roots)
    log.info("repository purged", slug=repository.slug, root=str(root))
    return True
