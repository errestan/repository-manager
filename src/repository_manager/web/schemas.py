"""JSON shapes for the REST API (specification.md 8.2).

Declared as Pydantic models rather than assembled as dictionaries, because the
OpenAPI schema is generated from exactly these classes: a response built by
hand would document itself only by accident, and would drift the first time a
field was added to one endpoint and not the other.

Two conventions run through all of them.

Timestamps are timezone-aware and serialise as RFC 3339 in UTC, because the
consumer is a script comparing them, not a person reading them.

Nothing here exposes a filesystem path outside the repository.  A package
reports ``path`` relative to the repository root -- which is what a client
appends to the repository URL to fetch it -- and never ``root_path``, which is
a server-side detail and a small disclosure for no benefit.
"""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, Field

from repository_manager.models import (
    Job,
    Package,
    PackagePublication,
    Repository,
    RepositoryType,
    UploadSource,
)


class SigningKeyOut(BaseModel):
    """The public half of a repository's signing key.

    The fingerprint is here so a client can pin it; the armoured key itself is
    a separate download, because it is bytes rather than metadata.
    """

    name: str
    fingerprint: str
    public_key_url: str


class DistributionOut(BaseModel):
    codename: str
    suite: str | None = None
    components: list[str] = Field(default_factory=list)
    architectures: list[str] = Field(default_factory=list)


class VariantOut(BaseModel):
    name: str
    arch: str


class RepositorySummary(BaseModel):
    """One repository, as it appears in a listing."""

    slug: str
    name: str
    type: RepositoryType
    description: str | None = None
    #: 0 means every version is kept (5.3).
    retention_count: int
    url: str
    created_at: dt.datetime

    @classmethod
    def of(cls, repository: Repository, *, url: str) -> RepositorySummary:
        return cls(
            slug=repository.slug,
            name=repository.name,
            type=repository.type,
            description=repository.description,
            retention_count=repository.retention_count,
            url=url,
            created_at=repository.created_at,
        )


class RepositoryDetail(RepositorySummary):
    """One repository, with everything a client needs to publish into it.

    The publication targets are the point: an upload names its target by the
    strings in here, so this endpoint is what a CI job reads to find out what
    it may say.
    """

    distributions: list[DistributionOut] = Field(default_factory=list)
    variants: list[VariantOut] = Field(default_factory=list)
    signing_key: SigningKeyOut | None = None


class PackageOut(BaseModel):
    """One package as published to one target.

    ``id`` is the *publication*, not the package: a single pool file may be
    published to several distributions or variants, and removing it from one
    must not remove it from the others (5.2).  It is the id ``DELETE`` takes.
    """

    id: int
    package_id: int
    name: str
    epoch: int | None = None
    version: str
    release: str | None = None
    #: Version as a person writes it, epoch and release included.
    full_version: str
    architecture: str
    #: The publication target: ``bookworm/main`` for APT, ``el9/x86_64`` for RPM.
    target: str
    #: Relative to the repository URL, so ``{repository.url}/{path}`` fetches it.
    path: str
    size: int
    sha256: str
    uploaded_at: dt.datetime
    uploaded_by: str | None = None
    uploaded_via: UploadSource

    @classmethod
    def of(cls, publication: PackagePublication, *, target: str) -> PackageOut:
        package: Package = publication.package
        return cls(
            id=publication.id,
            package_id=package.id,
            name=package.name,
            epoch=package.epoch,
            version=package.version,
            release=package.release,
            full_version=package.full_version,
            architecture=package.architecture,
            target=target,
            path=package.relative_path,
            size=package.size,
            sha256=package.sha256,
            uploaded_at=package.uploaded_at,
            uploaded_by=package.uploaded_by,
            uploaded_via=package.uploaded_via,
        )


class PackageListOut(BaseModel):
    total: int
    page: int
    pages: int
    per_page: int
    packages: list[PackageOut] = Field(default_factory=list)


class UploadOut(BaseModel):
    """The result of a publish (5.1, 8.2).

    ``created`` is false when the identical file was already published to this
    target -- a no-op success, so a retried CI step does not fail.  ``job_id``
    is the enqueued regeneration, which is what makes the answer to "is it
    live yet?" a poll rather than a guess; it is null when nothing changed and
    so nothing needed rebuilding.
    """

    package: PackageOut
    created: bool
    job_id: int | None = None
    #: Older versions retention removed to make room for this one (5.3).  Named
    #: rather than counted: a pipeline that publishes nightly should be able to
    #: see in its own log which builds stopped being available and when.
    pruned: list[str] = Field(default_factory=list)


class RemovalOut(BaseModel):
    removed: str
    #: Whether the pool file went too, or is still referenced by another target.
    file_deleted: bool
    job_id: int


class JobOut(BaseModel):
    id: int
    type: str
    state: str
    #: True once the job has reached a state it will not leave, so a poller
    #: knows to stop without keeping its own list of terminal states.
    finished: bool
    progress: int
    repository: str | None = None
    error: str | None = None
    log: str = ""
    created_at: dt.datetime
    started_at: dt.datetime | None = None
    finished_at: dt.datetime | None = None

    @classmethod
    def of(cls, job: Job) -> JobOut:
        return cls(
            id=job.id,
            type=job.type.value,
            state=job.state.value,
            finished=job.state.is_terminal,
            progress=job.progress,
            repository=job.repository.slug if job.repository else None,
            error=job.error,
            log=job.log,
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
        )
