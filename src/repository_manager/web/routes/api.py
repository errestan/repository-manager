"""The REST API (specification.md 8.2).

This is the same application as the web interface with a different front on it:
every write goes through the identical service call the HTML form uses, writes
the identical audit entry, and enqueues the identical regeneration job.  That
is worth stating because the alternative -- an API that reimplements publishing
"more simply" -- is how the two halves of a system end up disagreeing about
what a duplicate upload means.

Three things differ, and only three.

*Identity* comes from a bearer token rather than a session cookie, and is
established in :func:`repository_manager.web.deps._api_gate` before any handler
here runs.

*Targets are named, not numbered.*  The upload form posts an opaque integer
because a ``<select>`` has to; a CI job says ``distribution=bookworm`` and
``component=main``, which is what its author wrote in the pipeline file and
what they can read back in a diff.

*Failures are documents.*  Every refusal is RFC 9457 ``application/problem+json``
with a stable ``type``, so a pipeline can branch on the kind of failure -- a 409
for "that version already exists with different bytes" is a different thing to
do about than a 403.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.datastructures import UploadFile

from repository_manager.config import Settings
from repository_manager.jobs.queue import JobQueue
from repository_manager.models import (
    ActorType,
    AptComponent,
    AptDistribution,
    AuditAction,
    Job,
    Package,
    PackagePublication,
    Repository,
    RepositoryType,
    RpmVariant,
    TokenScope,
    UploadSource,
)
from repository_manager.security.paths import resolve_within_roots
from repository_manager.services import audit, publishing, retention
from repository_manager.services import packages as package_service
from repository_manager.services.packages import UploadError
from repository_manager.web.deps import (
    MAX_FORM_FIELDS,
    MAX_FORM_FILES,
    TokenIdentity,
    db_session,
    get_limits,
    get_queue,
    get_settings,
    record_upload,
    require_scope,
)
from repository_manager.web.middleware import client_ip
from repository_manager.web.problems import HTTP_413_TOO_LARGE, ApiError, openapi_responses
from repository_manager.web.schemas import (
    DistributionOut,
    JobOut,
    PackageListOut,
    PackageOut,
    RemovalOut,
    RepositoryDetail,
    RepositorySummary,
    SigningKeyOut,
    UploadOut,
    VariantOut,
)

#: Versioned, per 8.2.  A second version would be a second router mounted
#: alongside this one rather than a branch inside it.  Repeated as
#: :data:`repository_manager.web.deps.API_ROOT`, which is what decides that a
#: request is token-authenticated; the two must agree.
API_PREFIX = "/api/v1"

#: OpenAPI security requirement, attached to the operations that need a token.
#: FastAPI infers this from its own security dependencies, and the token gate
#: here is not one of them -- it runs application-wide -- so the operations say
#: so themselves and :func:`repository_manager.web.app.build_openapi` supplies
#: the matching scheme.
BEARER_SECURITY: dict[str, Any] = {"security": [{"bearerAuth": []}]}

#: The upload body is parsed by hand so the size and field limits are this
#: application's rather than Starlette's defaults, which means FastAPI cannot
#: infer its shape.  Described here instead, so the schema still documents it.
UPLOAD_BODY: dict[str, Any] = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "file": {
                            "type": "string",
                            "format": "binary",
                            "description": "The .deb or .rpm to publish.",
                        },
                        "distribution": {
                            "type": "string",
                            "description": "APT only: the codename to publish into, e.g. bookworm.",
                        },
                        "component": {
                            "type": "string",
                            "description": "APT only: the component, e.g. main.",
                        },
                        "variant": {
                            "type": "string",
                            "description": "RPM only: the variant as name/arch, e.g. el9/x86_64.",
                        },
                    },
                    "required": ["file"],
                }
            }
        },
    }
}

router = APIRouter(prefix=API_PREFIX, tags=["api"])

UPLOAD_CHUNK_BYTES = 1024 * 1024

#: Page size for package listings.  The specification does not ask for
#: pagination, but a repository with fifty thousand packages would otherwise
#: answer a single ``GET`` with a response no client wants and this server
#: should not build.
DEFAULT_PER_PAGE = 100
MAX_PER_PAGE = 500

#: The multipart field carrying the package.  ``file`` rather than the web
#: form's ``package`` because it is what ``curl -F file=@...`` reads as, and
#: this endpoint's audience is a shell script.
UPLOAD_FIELD = "file"

_LOADS = (
    selectinload(Repository.distributions).selectinload(AptDistribution.components),
    selectinload(Repository.distributions).selectinload(AptDistribution.architectures),
    selectinload(Repository.variants),
    selectinload(Repository.signing_key),
)

#: Injected as an annotated parameter rather than listed in ``dependencies``,
#: so the handler receives the token it was admitted by.  A route that asks for
#: ``Write`` cannot then forget which token is acting, and cannot reach for one
#: that might be absent.
Read = Annotated[TokenIdentity, Depends(require_scope(TokenScope.PACKAGE_READ))]
Write = Annotated[TokenIdentity, Depends(require_scope(TokenScope.PACKAGE_WRITE))]


# --------------------------------------------------------------------------- helpers


async def _load(session: AsyncSession, slug: str) -> Repository:
    repository = await session.scalar(
        select(Repository)
        .where(Repository.slug == slug, Repository.deregistered_at.is_(None))
        .options(*_LOADS)
    )
    if repository is None:
        raise ApiError(
            status.HTTP_404_NOT_FOUND,
            f"No repository with the slug {slug!r} is published here.",
        )
    return repository


def _summary(settings: Settings, repository: Repository) -> RepositorySummary:
    return RepositorySummary.of(repository, url=settings.repository_url(repository.slug))


def _detail(request: Request, settings: Settings, repository: Repository) -> RepositoryDetail:
    key = repository.signing_key
    return RepositoryDetail(
        **_summary(settings, repository).model_dump(),
        distributions=[
            DistributionOut(
                codename=distribution.codename,
                suite=distribution.suite,
                components=[component.name for component in distribution.components],
                architectures=[architecture.name for architecture in distribution.architectures],
            )
            for distribution in repository.distributions
        ],
        variants=[
            VariantOut(name=variant.name, arch=variant.arch) for variant in repository.variants
        ],
        signing_key=None
        if key is None
        else SigningKeyOut(
            name=key.name,
            fingerprint=key.fingerprint,
            public_key_url=str(request.url_for("key_public", name=key.name)),
        ),
    )


def _target_label(publication: PackagePublication) -> str:
    """How a publication names its target, in the same words an upload uses."""
    if publication.component is not None:
        return f"{publication.component.distribution.codename}/{publication.component.name}"
    variant = publication.variant
    return "" if variant is None else f"{variant.name}/{variant.arch}"


def _root_of(repository: Repository, settings: Settings) -> Path:
    return resolve_within_roots(Path(repository.root_path), settings.allowed_roots)


# --------------------------------------------------------------------------- reads


@router.get(
    "/repositories",
    name="api_repository_list",
    summary="List repositories",
    response_model=list[RepositorySummary],
    response_description="Every repository published by this instance.",
)
# Anonymous, and never narrowed by who is asking: read access is unconditional
# (AD-16), so a token holder and a stranger see the same list.
async def repository_list(
    request: Request, session: Annotated[AsyncSession, Depends(db_session)]
) -> list[RepositorySummary]:
    """Every repository this instance publishes.

    No token is needed. Repository and package listings are public, exactly as
    they are in the web interface.
    """
    settings = get_settings(request)
    statement = (
        select(Repository).where(Repository.deregistered_at.is_(None)).order_by(Repository.slug)
    )
    found = (await session.execute(statement)).scalars().all()
    return [_summary(settings, repository) for repository in found]


@router.get(
    "/repositories/{slug}",
    name="api_repository_detail",
    summary="Read one repository",
    response_model=RepositoryDetail,
    response_description="The repository, its publication targets and its signing key.",
    responses=openapi_responses(status.HTTP_404_NOT_FOUND),
)
async def repository_detail(
    request: Request, slug: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> RepositoryDetail:
    """One repository, including the targets an upload may name.

    Read this to find out what to put in `distribution` and `component` (APT)
    or `variant` (RPM), rather than hard-coding them in a pipeline.
    """
    repository = await _load(session, slug)
    return _detail(request, get_settings(request), repository)


def _filtered(
    repository: Repository,
    *,
    name: str,
    architecture: str,
    distribution: str,
    component: str,
    variant: str,
) -> Select[Any]:
    """The package query, joined through the target table.

    Joining through the target rather than filtering on ``Package`` alone is
    what stops a publication belonging to another repository appearing here
    even if the two share a pool file.

    ``name`` is an exact match, unlike the web interface's substring search.
    The caller here is a script asking "is this package published?", and a
    substring match would answer yes for ``libfoo-dev`` when it asked about
    ``libfoo``.
    """
    statement = select(PackagePublication).join(
        Package, Package.id == PackagePublication.package_id
    )
    if repository.type is RepositoryType.APT:
        statement = statement.join(
            AptComponent, AptComponent.id == PackagePublication.component_id
        ).join(AptDistribution, AptDistribution.id == AptComponent.distribution_id)
        if distribution:
            statement = statement.where(AptDistribution.codename == distribution)
        if component:
            statement = statement.where(AptComponent.name == component)
    else:
        statement = statement.join(RpmVariant, RpmVariant.id == PackagePublication.variant_id)
        if variant:
            name_part, _, arch_part = variant.partition("/")
            statement = statement.where(RpmVariant.name == name_part)
            if arch_part:
                statement = statement.where(RpmVariant.arch == arch_part)

    statement = statement.where(Package.repository_id == repository.id)
    if name:
        statement = statement.where(Package.name == name)
    if architecture:
        statement = statement.where(Package.architecture == architecture)
    return statement


@router.get(
    "/repositories/{slug}/packages",
    name="api_package_list",
    summary="List published packages",
    response_model=PackageListOut,
    response_description="One page of published packages, newest page size first.",
    responses=openapi_responses(status.HTTP_404_NOT_FOUND),
)
async def package_list(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    name: str = "",
    arch: str = "",
    distribution: str = "",
    component: str = "",
    variant: str = "",
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
) -> PackageListOut:
    """Packages published in this repository.

    `name` is an exact match, unlike the search box in the web interface: a
    script asking about `libfoo` does not want `libfoo-dev` back.

    Filters that do not apply to this repository's format are ignored rather
    than rejected, so a script that filters generically does not have to know
    which format it is talking to.
    """
    repository = await _load(session, slug)
    page = max(1, page)
    size = max(1, min(per_page, MAX_PER_PAGE))

    base = _filtered(
        repository,
        name=name.strip(),
        architecture=arch.strip(),
        distribution=distribution.strip(),
        component=component.strip(),
        variant=variant.strip(),
    )
    total = int(await session.scalar(select(func.count()).select_from(base.subquery())) or 0)
    listing = (
        base.options(
            selectinload(PackagePublication.package),
            selectinload(PackagePublication.component).selectinload(AptComponent.distribution),
            selectinload(PackagePublication.variant),
        )
        .order_by(Package.name, Package.version, Package.architecture, PackagePublication.id)
        .offset((page - 1) * size)
        .limit(size)
    )
    publications = list((await session.execute(listing)).scalars().all())
    return PackageListOut(
        total=total,
        page=page,
        pages=max(1, -(-total // size)),
        per_page=size,
        packages=[
            PackageOut.of(publication, target=_target_label(publication))
            for publication in publications
        ],
    )


@router.get(
    "/jobs/{job_id}",
    name="api_job_detail",
    summary="Read a job",
    response_model=JobOut,
    response_description="The job's current state, its log excerpt and any error.",
    openapi_extra=BEARER_SECURITY,
    responses=openapi_responses(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
    ),
)
# Job state, per 6.  Authenticated for the same reason the web interface's own
# job pages are (8.1): the log excerpt is more than the anonymous surface shows.
async def job_detail(
    job_id: int,
    identity: Read,
    session: Annotated[AsyncSession, Depends(db_session)],
) -> JobOut:
    """The state of one background job, for polling after an upload.

    Poll until `finished` is true, then check `state`. A failed job explains
    itself in `error` and `log`.

    This is the one read that needs a token: a job record carries the log of
    whatever ran, including the tail of a failed subprocess, which is more than
    the anonymous browsing surface exposes.
    """
    job = await session.scalar(
        select(Job).where(Job.id == job_id).options(selectinload(Job.repository))
    )
    if job is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, f"There is no job with the id {job_id}.")

    if job.repository is not None and not identity.covers(job.repository.slug):
        # 404 rather than 403: a token restricted to other repositories should
        # not be able to confirm which job ids belong to the ones it cannot see.
        raise ApiError(status.HTTP_404_NOT_FOUND, f"There is no job with the id {job_id}.")
    return JobOut.of(job)


# --------------------------------------------------------------------------- writes


def _apt_target(
    repository: Repository, distribution: str, component: str
) -> tuple[AptDistribution, AptComponent]:
    if not distribution or not component:
        offered = ", ".join(
            f"{dist.codename}/{comp.name}"
            for dist in repository.distributions
            for comp in dist.components
        )
        raise ApiError(
            status.HTTP_400_BAD_REQUEST,
            "An APT upload needs 'distribution' and 'component' fields. This repository "
            f"publishes: {offered or '(no components configured)'}.",
        )
    for candidate in repository.distributions:
        if candidate.codename != distribution:
            continue
        for entry in candidate.components:
            if entry.name == component:
                return candidate, entry
    raise ApiError(
        status.HTTP_404_NOT_FOUND,
        f"{repository.slug} does not publish {distribution}/{component}.",
    )


def _rpm_target(repository: Repository, variant: str) -> RpmVariant:
    offered = ", ".join(f"{entry.name}/{entry.arch}" for entry in repository.variants)
    if not variant:
        raise ApiError(
            status.HTTP_400_BAD_REQUEST,
            "An RPM upload needs a 'variant' field, written as name/arch. This repository "
            f"publishes: {offered or '(no variants configured)'}.",
        )
    name, separator, arch = variant.partition("/")
    if not separator:
        raise ApiError(
            status.HTTP_400_BAD_REQUEST,
            f"Write the variant as name/arch, for example {offered.split(', ')[0] or 'el9/x86_64'}"
            f", rather than {variant!r}: a variant is a name and an architecture together.",
        )
    for candidate in repository.variants:
        if candidate.name == name and candidate.arch == arch:
            return candidate
    raise ApiError(
        status.HTTP_404_NOT_FOUND,
        f"{repository.slug} does not publish the variant {variant}. It publishes: "
        f"{offered or '(none configured)'}.",
    )


async def _chunks(upload: UploadFile) -> AsyncIterator[bytes]:
    while chunk := await upload.read(UPLOAD_CHUNK_BYTES):
        yield chunk


@router.post(
    "/repositories/{slug}/packages",
    name="api_package_upload",
    summary="Publish a package",
    response_model=UploadOut,
    status_code=status.HTTP_201_CREATED,
    response_description=(
        "201 when the package was published, 200 when the identical file was already there."
    ),
    openapi_extra={**BEARER_SECURITY, **UPLOAD_BODY},
    responses=openapi_responses(
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
        status.HTTP_409_CONFLICT,
        HTTP_413_TOO_LARGE,
        status.HTTP_429_TOO_MANY_REQUESTS,
    ),
)
# Publishing, per 5.1: the same service call the upload form makes, with the
# target named rather than numbered.
async def package_upload(
    request: Request,
    slug: str,
    response: Response,
    identity: Write,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
) -> UploadOut:
    """Upload one package and publish it to one target.

    Send `multipart/form-data` with a `file` part, plus `distribution` and
    `component` for APT or `variant` (written `name/arch`) for RPM.

    Answers 201 when something was published and 200 when the identical file
    was already there — a retried pipeline step is a success, not a conflict. A
    *different* file under a version that already exists is a 409: overwriting a
    version clients may have installed is never allowed.

    The architecture is read from the package, and the stored path is derived
    from its metadata — the filename you send is never used.

    The response carries `job_id`. Publication is not complete until that job
    succeeds, so a pipeline that needs the package to be installable should poll
    `GET /api/v1/jobs/{id}` rather than assume.
    """
    repository = await _load(session, slug)
    settings = get_settings(request)

    # Before the body is read: a pipeline over its allowance is turned away
    # without this process spooling the package to disk first (10.3).
    allowance = get_limits(request).upload_allowed(
        client=client_ip(request.scope), actor=identity.owner_dn
    )
    if not allowance.allowed:
        raise ApiError(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many uploads. Retry in {allowance.retry_after_seconds} seconds.",
            slug="rate-limited",
            headers={"retry-after": str(allowance.retry_after_seconds)},
            retry_after=allowance.retry_after_seconds,
        )

    try:
        async with request.form(
            max_files=MAX_FORM_FILES,
            max_fields=MAX_FORM_FIELDS,
            max_part_size=settings.max_upload_bytes,
        ) as submitted:
            upload = submitted.get(UPLOAD_FIELD)
            if not isinstance(upload, UploadFile):
                suffix = ".deb" if repository.type is RepositoryType.APT else ".rpm"
                raise ApiError(
                    status.HTTP_400_BAD_REQUEST,
                    f"Attach the {suffix} as a multipart part named {UPLOAD_FIELD!r}, "
                    f"for example: curl -F {UPLOAD_FIELD}=@package{suffix}",
                )
            if repository.type is RepositoryType.APT:
                apt_target = _apt_target(
                    repository,
                    str(submitted.get("distribution") or ""),
                    str(submitted.get("component") or ""),
                )
            else:
                rpm_target = _rpm_target(repository, str(submitted.get("variant") or ""))

            # Staged inside the form context: closing it discards the spooled
            # upload, so the copy has to happen before then.
            staged = await package_service.stage_upload(
                _root_of(repository, settings),
                _chunks(upload),
                max_bytes=settings.max_upload_bytes,
            )
    except UploadError as exc:
        raise ApiError(exc.status_code, str(exc)) from exc

    try:
        if repository.type is RepositoryType.APT:
            outcome = await package_service.publish_deb(
                session,
                settings,
                repository=repository,
                distribution=apt_target[0],
                component=apt_target[1],
                staged=staged,
                actor=identity.owner_dn,
                source=UploadSource.TOKEN,
            )
            label = f"{apt_target[0].codename}/{apt_target[1].name}"
        else:
            outcome = await package_service.publish_rpm(
                session,
                settings,
                repository=repository,
                variant=rpm_target,
                staged=staged,
                actor=identity.owner_dn,
                source=UploadSource.TOKEN,
            )
            label = f"{rpm_target.name}/{rpm_target.arch}"
    except UploadError as exc:
        raise ApiError(exc.status_code, str(exc)) from exc

    record_upload(request, outcome.package.size)
    await audit.record(
        session,
        action=AuditAction.PACKAGE_UPLOAD,
        actor=identity.owner_dn,
        actor_type=ActorType.TOKEN,
        repository_id=repository.id,
        target=outcome.package.relative_path,
        source_ip=client_ip(request.scope),
        details={
            "name": outcome.package.name,
            "version": outcome.package.full_version,
            "architecture": outcome.package.architecture,
            "published_in": label,
            "created": outcome.created,
            **identity.audit_details,
        },
    )

    job_id: int | None = None
    pruned: list[retention.Pruned] = []
    if outcome.created:
        # Pruned before the rebuild is queued, so one regeneration publishes the
        # addition and the removals together (5.3).
        pruned = await retention.enforce_for(
            session, settings, repository, name=outcome.package.name
        )
        await retention.record(
            session,
            repository,
            pruned,
            actor=identity.owner_dn,
            actor_type=ActorType.TOKEN,
            source_ip=client_ip(request.scope),
        )
        job_id = await publishing.request_regeneration(session, queue, repository)
    else:
        # Nothing changed on disk, so there is nothing to rebuild.  Reported as
        # 200 rather than 201 for the same reason.
        response.status_code = status.HTTP_200_OK

    payload = UploadOut(
        package=PackageOut.of(outcome.package.publications[-1], target=label),
        created=outcome.created,
        job_id=job_id,
        pruned=[entry.summary for entry in pruned],
    )
    # Commit before waking a worker: the job row has to be visible to the other
    # connection that will claim it.
    await session.commit()
    queue.wake()
    return payload


@router.delete(
    "/repositories/{slug}/packages/{publication_id}",
    name="api_package_delete",
    summary="Unpublish a package",
    response_model=RemovalOut,
    response_description="What was removed, and whether the pool file went with it.",
    openapi_extra=BEARER_SECURITY,
    responses=openapi_responses(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
    ),
)
# Removal, per 5.2: per publication target, not per pool file.
async def package_delete(
    request: Request,
    slug: str,
    publication_id: int,
    identity: Write,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
) -> RemovalOut:
    """Remove one publication.

    The id is the `id` from a package listing, which identifies a package *in
    one target*. A pool file published to two distributions is removed from one
    of them and stays in the other; `file_deleted` says which happened.
    """
    repository = await _load(session, slug)
    settings = get_settings(request)

    try:
        publication = await package_service.load_publication(session, repository, publication_id)
        name = publication.package.name
        version = publication.package.full_version
        label = _target_label(publication)
        deleted = await package_service.remove_publication(
            session, settings, repository, publication
        )
    except UploadError as exc:
        raise ApiError(exc.status_code, str(exc)) from exc

    await audit.record(
        session,
        action=AuditAction.PACKAGE_REMOVE,
        actor=identity.owner_dn,
        actor_type=ActorType.TOKEN,
        repository_id=repository.id,
        target=name,
        source_ip=client_ip(request.scope),
        details={
            "name": name,
            "version": version,
            "removed_from": label,
            "file_deleted": deleted,
            **identity.audit_details,
        },
    )
    job_id = await publishing.request_regeneration(session, queue, repository)
    await session.commit()
    queue.wake()
    return RemovalOut(removed=f"{name} {version}", file_deleted=deleted, job_id=job_id)


@router.post(
    "/repositories/{slug}/regenerate",
    name="api_regenerate",
    summary="Rebuild repository metadata",
    response_model=JobOut,
    status_code=status.HTTP_202_ACCEPTED,
    response_description="The queued job. Poll it to find out when the rebuild finished.",
    openapi_extra=BEARER_SECURITY,
    responses=openapi_responses(
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
        status.HTTP_404_NOT_FOUND,
    ),
)
# Regeneration, per 5.4: always a job, locked and coalescing.
async def regenerate(
    request: Request,
    slug: str,
    identity: Write,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
) -> JobOut:
    """Queue a rebuild of this repository's metadata.

    Always a job, never inline, and coalescing: asking twice while one is
    pending returns the same job rather than queueing a second. Uploads already
    do this for themselves — this endpoint is for recovering after something
    changed the tree out of band.
    """
    repository = await _load(session, slug)
    job_id = await publishing.request_regeneration(
        session, queue, repository, actor=identity.owner_dn
    )
    await audit.record(
        session,
        action=AuditAction.REGENERATE,
        actor=identity.owner_dn,
        actor_type=ActorType.TOKEN,
        repository_id=repository.id,
        target=repository.slug,
        source_ip=client_ip(request.scope),
        details={"job_id": job_id, **identity.audit_details},
    )
    await session.commit()
    queue.wake()

    job = await session.scalar(
        select(Job).where(Job.id == job_id).options(selectinload(Job.repository))
    )
    if job is None:  # pragma: no cover - just enqueued in this transaction
        raise ApiError(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "The job was queued but could not be read back."
        )
    return JobOut.of(job)
