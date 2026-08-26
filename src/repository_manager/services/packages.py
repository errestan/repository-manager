"""Package upload and removal (specification.md 5.1, 5.2).

The upload path is the one place an unauthenticated byte stream reaches the
filesystem, so the order of operations is deliberate:

1. stream to a temporary file **inside the repository root**, capped by size;
2. check the magic bytes before handing anything to a parser;
3. derive the stored path from the parsed metadata, never from the uploaded
   filename;
4. rename into the pool atomically, so a partial file is never visible;
5. write the row, then enqueue the index rebuild.

A failure at any step leaves the pool exactly as it was.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from repository_manager.config import Settings
from repository_manager.logging import get_logger
from repository_manager.metadata.deb import (
    DebMetadata,
    PackageFormatError,
    read_deb,
)
from repository_manager.models import (
    AptComponent,
    AptDistribution,
    Package,
    PackagePublication,
    Repository,
    UploadSource,
)
from repository_manager.security.paths import (
    DIR_MODE,
    FILE_MODE,
    ensure_directory,
    relative_within,
    resolve_within_roots,
)

log = get_logger(__name__)

# Uploads land here first.  Inside the repository root so the final move is a
# rename on the same filesystem rather than a copy; dot-prefixed so a web server
# generating directory indexes does not advertise half-received files.
INCOMING_DIRNAME = ".incoming"

# Architecture-independent packages are accepted for any target (5.1).
ARCH_ALL = "all"

STREAM_CHUNK_BYTES = 1024 * 1024


class UploadError(Exception):
    """An upload was refused.  ``status_code`` is what the HTTP layer returns."""

    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class UploadOutcome:
    package: Package
    #: False when the exact package was already published here -- a no-op success (5.1).
    created: bool
    job_id: int | None = None

    @property
    def summary(self) -> str:
        verb = "published" if self.created else "was already published"
        return f"{self.package.name} {self.package.full_version} {verb}"


async def stage_upload(root: Path, chunks: AsyncIterator[bytes], *, max_bytes: int) -> Path:
    """Stream an upload to a temporary file, refusing to exceed ``max_bytes``.

    The cap is enforced while writing rather than from ``Content-Length``: the
    header is supplied by the client and a chunked upload has none at all.
    """
    incoming = ensure_directory(root / INCOMING_DIRNAME, mode=DIR_MODE)
    handle, name = tempfile.mkstemp(dir=str(incoming), prefix="upload-", suffix=".part")
    staged = Path(name)
    written = 0
    try:
        with open(handle, "wb") as sink:  # noqa: PTH123 - adopting mkstemp's descriptor
            async for chunk in chunks:
                written += len(chunk)
                if written > max_bytes:
                    raise UploadError(
                        f"The upload exceeds the {max_bytes:,}-byte limit "
                        "(REPOMAN_MAX_UPLOAD_BYTES).",
                        status_code=413,
                    )
                sink.write(chunk)
        if written == 0:
            raise UploadError("The uploaded file is empty.")
        staged.chmod(FILE_MODE)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return staged


def _check_architecture(metadata: DebMetadata, distribution: AptDistribution) -> None:
    configured = {architecture.name for architecture in distribution.architectures}
    if metadata.architecture == ARCH_ALL or metadata.architecture in configured:
        return
    offered = ", ".join(sorted(configured)) or "(none configured)"
    raise UploadError(
        f"{metadata.name} is built for {metadata.architecture}, which {distribution.codename} "
        f"does not publish. Configured architectures: {offered}."
    )


async def _existing_package(
    session: AsyncSession, repository: Repository, metadata: DebMetadata
) -> Package | None:
    found: Package | None = await session.scalar(
        select(Package)
        .where(
            Package.repository_id == repository.id,
            Package.name == metadata.name,
            Package.version == metadata.version,
            Package.architecture == metadata.architecture,
        )
        .options(selectinload(Package.publications))
    )
    return found


def _install_into_pool(root: Path, staged: Path, relative_path: str) -> None:
    """Move a validated upload into the pool with an atomic rename."""
    destination = relative_within(root, relative_path)
    ensure_directory(destination.parent, mode=DIR_MODE)
    # Same filesystem by construction (the staging directory is inside the
    # root), so this is a rename rather than a copy: the file is either wholly
    # absent or wholly present, never partially readable by a client.
    staged.replace(destination)
    destination.chmod(FILE_MODE)


async def publish_deb(
    session: AsyncSession,
    settings: Settings,
    *,
    repository: Repository,
    distribution: AptDistribution,
    component: AptComponent,
    staged: Path,
    actor: str | None = None,
    source: UploadSource = UploadSource.WEB,
) -> UploadOutcome:
    """Validate a staged ``.deb`` and publish it to one component (5.1).

    Takes ownership of ``staged``: on success it is moved into the pool, and on
    any failure it is removed.
    """
    root = resolve_within_roots(Path(repository.root_path), settings.allowed_roots)
    try:
        try:
            metadata = await asyncio.to_thread(read_deb, staged)
        except PackageFormatError as exc:
            raise UploadError(str(exc)) from exc

        _check_architecture(metadata, distribution)

        existing = await _existing_package(session, repository, metadata)
        if existing is not None:
            return await _republish(session, existing, metadata, component)

        relative_path = metadata.pool_path(component.name)
        await asyncio.to_thread(_install_into_pool, root, staged, relative_path)

        package = Package(
            repository_id=repository.id,
            name=metadata.name,
            source_name=metadata.source_name,
            epoch=metadata.epoch,
            version=metadata.version,
            architecture=metadata.architecture,
            relative_path=relative_path,
            size=metadata.digests.size,
            sha256=metadata.digests.sha256,
            control_json=metadata.stanza(relative_path),
            uploaded_by=actor,
            uploaded_via=source,
        )
        package.publications.append(PackagePublication(component_id=component.id))
        session.add(package)
        await session.flush()
    finally:
        staged.unlink(missing_ok=True)

    log.info(
        "package published",
        repository=repository.slug,
        package=package.name,
        version=package.full_version,
        architecture=package.architecture,
        component=component.name,
    )
    return UploadOutcome(package=package, created=True)


async def _republish(
    session: AsyncSession,
    existing: Package,
    metadata: DebMetadata,
    component: AptComponent,
) -> UploadOutcome:
    """Handle an upload of a name/version/architecture that is already present (5.1).

    Identical bytes are a no-op success, because a CI job that retries an upload
    should not fail.  Different bytes under the same version are always refused:
    a client that already installed the old file would never be told.
    """
    if existing.sha256 != metadata.digests.sha256:
        raise UploadError(
            f"{metadata.name} {metadata.version} ({metadata.architecture}) is already published "
            "with different contents. Publish a new version rather than replacing one clients "
            "may already have installed.",
            status_code=409,
        )

    already = any(publication.component_id == component.id for publication in existing.publications)
    if already:
        return UploadOutcome(package=existing, created=False)

    # Same bytes, new target: one pool file, a second publication (9).
    session.add(PackagePublication(package_id=existing.id, component_id=component.id))
    await session.flush()
    return UploadOutcome(package=existing, created=True)


async def load_publication(
    session: AsyncSession, repository: Repository, publication_id: int
) -> PackagePublication:
    publication = await session.scalar(
        select(PackagePublication)
        .where(PackagePublication.id == publication_id)
        .options(
            selectinload(PackagePublication.package).selectinload(Package.publications),
            selectinload(PackagePublication.component),
        )
    )
    if publication is None or publication.package.repository_id != repository.id:
        raise UploadError("That package is not published in this repository.", status_code=404)
    return publication


async def remove_publication(
    session: AsyncSession,
    settings: Settings,
    repository: Repository,
    publication: PackagePublication,
) -> bool:
    """Unpublish from one target, deleting the pool file when it is the last (5.2).

    Returns whether the file itself was removed.
    """
    package = publication.package
    remaining = [entry for entry in package.publications if entry.id != publication.id]
    await session.delete(publication)

    if remaining:
        await session.flush()
        log.info(
            "package unpublished",
            repository=repository.slug,
            package=package.name,
            remaining_targets=len(remaining),
        )
        return False

    root = resolve_within_roots(Path(repository.root_path), settings.allowed_roots)
    pool_file = relative_within(root, package.relative_path)
    await session.delete(package)
    await session.flush()
    await asyncio.to_thread(_unlink_and_prune, root, pool_file)
    log.info(
        "package removed",
        repository=repository.slug,
        package=package.name,
        version=package.full_version,
    )
    return True


def _unlink_and_prune(root: Path, pool_file: Path) -> None:
    """Delete a pool file and any directories it leaves empty behind it."""
    pool_file.unlink(missing_ok=True)
    directory = pool_file.parent
    pool_root = root / "pool"
    while directory != pool_root and directory.is_relative_to(pool_root):
        try:
            directory.rmdir()
        except OSError:
            return  # not empty, or gone already: nothing more to prune
        directory = directory.parent


def discard_incoming(root: Path) -> None:
    """Remove leftover staging files, e.g. after an unclean shutdown."""
    incoming = root / INCOMING_DIRNAME
    if incoming.is_dir():
        shutil.rmtree(incoming, ignore_errors=True)
