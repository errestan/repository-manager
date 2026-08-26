"""Repository browsing and management (specification.md 8.1).

Reads are anonymous (AD-11).  Writes go through ``require_write_access``, which
stands in for the role check until LDAP login lands in M3.

Route order matters: ``/repositories/new`` is declared before
``/repositories/{slug}``, or the literal would be swallowed by the parameter.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException
from starlette.responses import RedirectResponse, Response

from repository_manager.config import Settings
from repository_manager.jobs.queue import JobQueue
from repository_manager.models import (
    AptComponent,
    AptDistribution,
    Job,
    Package,
    PackagePublication,
    Repository,
    RepositoryType,
    SigningKey,
)
from repository_manager.security.paths import resolve_within_roots
from repository_manager.services import packages as package_service
from repository_manager.services import publishing
from repository_manager.services import repositories as repository_service
from repository_manager.services.packages import UploadError
from repository_manager.services.repositories import (
    DistributionSpec,
    RepositoryServiceError,
    parse_name_list,
)
from repository_manager.web.deps import (
    db_session,
    get_queue,
    get_settings,
    get_templates,
    require_write_access,
    writes_enabled,
)
from repository_manager.web.forms import FormState, required
from repository_manager.web.templating import render

router = APIRouter(tags=["repositories"])

PACKAGES_PER_PAGE = 50
UPLOAD_CHUNK_BYTES = 1024 * 1024

# Enough parts for the upload field plus the target select, with headroom; a
# request with more than this is not a form this application serves.
MAX_FORM_FILES = 2
MAX_FORM_FIELDS = 12

_PUBLICATION_LOADS = (
    selectinload(Repository.distributions).selectinload(AptDistribution.components),
    selectinload(Repository.distributions).selectinload(AptDistribution.architectures),
    selectinload(Repository.variants),
    selectinload(Repository.signing_key),
)


# --------------------------------------------------------------------------- helpers


async def _load_active(session: AsyncSession) -> list[Repository]:
    """Active repositories with their publication targets eagerly loaded.

    Async SQLAlchemy cannot lazy-load during template rendering -- the implicit
    IO raises MissingGreenlet -- so every relationship a template touches is
    loaded up front.
    """
    statement = (
        select(Repository)
        .where(Repository.deregistered_at.is_(None))
        .options(*_PUBLICATION_LOADS)
        .order_by(Repository.name)
    )
    return list((await session.execute(statement)).scalars().all())


async def _load(session: AsyncSession, slug: str) -> Repository:
    repository = await session.scalar(
        select(Repository)
        .where(Repository.slug == slug, Repository.deregistered_at.is_(None))
        .options(*_PUBLICATION_LOADS)
    )
    if repository is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such repository")
    return repository


def _root_of(repository: Repository, settings: Settings) -> Path:
    """The repository's root, re-proved to be inside the sandbox (10.4)."""
    return resolve_within_roots(Path(repository.root_path), settings.allowed_roots)


async def _package_count(session: AsyncSession, repository: Repository) -> int:
    total = await session.scalar(
        select(func.count(Package.id)).where(Package.repository_id == repository.id)
    )
    return int(total or 0)


def _client_snippet(settings: Settings, repository: Repository) -> str | None:
    """The `sources.list` line for this repository (4.4).

    Returns nothing without a signing key: apt refuses an unverifiable
    repository, so a snippet naming a keyring file that will never exist would
    only send someone down a dead end.
    """
    if repository.type is not RepositoryType.APT or not repository.distributions:
        return None
    if repository.signing_key is None:
        return None
    key_name = repository.signing_key.name
    lines = []
    for distribution in repository.distributions:
        components = " ".join(component.name for component in distribution.components)
        lines.append(
            f"deb [signed-by=/usr/share/keyrings/{key_name}.asc] "
            f"{settings.repository_url(repository.slug)} {distribution.codename} {components}"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------- browsing


@router.get("/", include_in_schema=False, name="repository_list")
async def repository_list(
    request: Request, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    repositories = await _load_active(session)
    return render(
        get_templates(request),
        request,
        "repositories/list.html.j2",
        {"repositories": repositories, "writes_enabled": writes_enabled(request)},
    )


# --------------------------------------------------------------------------- creation


def _creation_context(request: Request, keys: list[SigningKey], form: FormState) -> dict[str, Any]:
    return {
        "form": form,
        "keys": keys,
        # Pre-paired for the select macro: Jinja has no zip, and building the
        # pairs in the template would need the `do` extension.
        "key_options": [(key.id, f"{key.name} ({key.algorithm.label})") for key in keys],
        "writes_enabled": writes_enabled(request),
    }


async def _signing_keys(session: AsyncSession) -> list[SigningKey]:
    return list(
        (await session.execute(select(SigningKey).order_by(SigningKey.name))).scalars().all()
    )


@router.get(
    "/repositories/new",
    include_in_schema=False,
    name="repository_new",
    dependencies=[Depends(require_write_access)],
)
async def repository_new(
    request: Request, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    form = FormState(values={"retention": "all", "components": "main", "architectures": "amd64"})
    return render(
        get_templates(request),
        request,
        "repositories/new.html.j2",
        _creation_context(request, await _signing_keys(session), form),
    )


def _retention(form: FormState, choice: str, count: str) -> int:
    """Retention is a required, explicit choice -- there is no default (5.3)."""
    if choice == "all":
        return 0
    if choice != "count":
        form.add("retention", "Choose whether to keep every version or a fixed number.")
        return 0
    try:
        value = int(count)
    except ValueError:
        form.add("retention_count", "Enter a whole number of versions to keep.")
        return 0
    if value < 1:
        form.add("retention_count", "Keep at least one version, or choose 'keep all'.")
    return value


@router.post(
    "/repositories/new",
    include_in_schema=False,
    name="repository_create",
    dependencies=[Depends(require_write_access)],
)
async def repository_create(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
    name: Annotated[str, Form()] = "",
    root_path: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
    signing_key_id: Annotated[str, Form()] = "",
    retention: Annotated[str, Form()] = "",
    retention_count: Annotated[str, Form()] = "",
    codename: Annotated[str, Form()] = "",
    suite: Annotated[str, Form()] = "",
    components: Annotated[str, Form()] = "",
    architectures: Annotated[str, Form()] = "",
    origin: Annotated[str, Form()] = "",
    label: Annotated[str, Form()] = "",
) -> Response:
    settings = get_settings(request)
    form = FormState(
        values={
            "name": name,
            "root_path": root_path,
            "description": description,
            "signing_key_id": signing_key_id,
            "retention": retention,
            "retention_count": retention_count,
            "codename": codename,
            "suite": suite,
            "components": components,
            "architectures": architectures,
            "origin": origin,
            "label": label,
        }
    )

    clean_name = required(form, "name", name, "Repository name")
    clean_root = required(form, "root_path", root_path, "Root path")
    clean_codename = required(form, "codename", codename, "Distribution codename")
    component_names = parse_name_list(components)
    architecture_names = parse_name_list(architectures)
    if not component_names:
        form.add("components", "Name at least one component, for example 'main'.")
    if not architecture_names:
        form.add("architectures", "Name at least one architecture, for example 'amd64'.")

    keep = _retention(form, retention, retention_count)

    key_id = 0
    if not signing_key_id:
        form.add("signing_key_id", "Choose the key this repository's metadata is signed with.")
    else:
        try:
            key_id = int(signing_key_id)
        except ValueError:
            form.add("signing_key_id", "That signing key is not valid.")

    if not form.ok:
        return render(
            get_templates(request),
            request,
            "repositories/new.html.j2",
            _creation_context(request, await _signing_keys(session), form),
            status_code=400,
        )

    try:
        repository = await repository_service.create_apt_repository(
            session,
            settings,
            name=clean_name,
            root_path=clean_root,
            description=description,
            signing_key_id=key_id,
            retention_count=keep,
            origin=origin,
            label=label,
            distributions=(
                DistributionSpec(
                    codename=clean_codename,
                    suite=suite.strip() or None,
                    components=component_names,
                    architectures=architecture_names,
                ),
            ),
        )
    except (RepositoryServiceError, ValueError) as exc:
        form.add("root_path", str(exc))
        return render(
            get_templates(request),
            request,
            "repositories/new.html.j2",
            _creation_context(request, await _signing_keys(session), form),
            status_code=400,
        )

    return RedirectResponse(
        request.url_for("repository_detail", slug=repository.slug),
        status_code=status.HTTP_303_SEE_OTHER,
    )


# --------------------------------------------------------------------------- detail


@router.get("/repositories/{slug}", include_in_schema=False, name="repository_detail")
async def repository_detail(
    request: Request, slug: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    repository = await _load(session, slug)
    settings = get_settings(request)
    recent = list(
        (
            await session.execute(
                select(Job)
                .where(Job.repository_id == repository.id)
                .order_by(Job.created_at.desc(), Job.id.desc())
                .limit(5)
            )
        )
        .scalars()
        .all()
    )
    return render(
        get_templates(request),
        request,
        "repositories/detail.html.j2",
        {
            "repository": repository,
            "package_count": await _package_count(session, repository),
            "recent_jobs": recent,
            # Client setup snippets are copied into sources.list files, so they
            # must be absolute and built from the external URL (13.5, 4.4).
            "base_url": settings.repository_url(repository.slug),
            "client_snippet": _client_snippet(settings, repository),
            "writes_enabled": writes_enabled(request),
        },
    )


# --------------------------------------------------------------------------- packages


def _filtered(repository: Repository, query: str, architecture: str) -> Select[Any]:
    statement = (
        select(PackagePublication)
        .join(Package, Package.id == PackagePublication.package_id)
        .join(AptComponent, AptComponent.id == PackagePublication.component_id)
        .join(AptDistribution, AptDistribution.id == AptComponent.distribution_id)
        .where(Package.repository_id == repository.id)
    )
    if query:
        # Escaped so a user searching for "lib_" does not get every three-letter
        # package name back.  Built by concatenation because an f-string may not
        # contain a backslash until Python 3.12, and this runs on 3.11.
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        statement = statement.where(Package.name.ilike("%" + escaped + "%", escape="\\"))
    if architecture:
        statement = statement.where(Package.architecture == architecture)
    return statement


@router.get("/repositories/{slug}/packages", include_in_schema=False, name="repository_packages")
async def repository_packages(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    q: str = "",
    arch: str = "",
    page: int = 1,
) -> Response:
    repository = await _load(session, slug)
    query = q.strip()[:200]
    architecture = arch.strip()[:32]
    page = max(1, page)

    base = _filtered(repository, query, architecture)
    total = int(await session.scalar(select(func.count()).select_from(base.subquery())) or 0)
    listing = (
        base.options(
            selectinload(PackagePublication.package),
            selectinload(PackagePublication.component).selectinload(AptComponent.distribution),
        )
        .order_by(Package.name, Package.version, Package.architecture)
        .offset((page - 1) * PACKAGES_PER_PAGE)
        .limit(PACKAGES_PER_PAGE)
    )
    publications = list((await session.execute(listing)).scalars().all())

    architectures = sorted(
        {
            architecture.name
            for distribution in repository.distributions
            for architecture in distribution.architectures
        }
    )
    pages = max(1, -(-total // PACKAGES_PER_PAGE))
    return render(
        get_templates(request),
        request,
        "repositories/packages.html.j2",
        {
            "repository": repository,
            "publications": publications,
            "total": total,
            "page": page,
            "pages": pages,
            "query": query,
            "architecture": architecture,
            "architectures": architectures,
            "writes_enabled": writes_enabled(request),
        },
    )


def _targets(repository: Repository) -> list[tuple[int, str]]:
    """Selectable (component id, label) pairs, flattened across distributions.

    One flat select rather than two dependent ones: a distribution/component
    pair of selects only works if JavaScript repopulates the second, and every
    flow has to work without it (11).
    """
    return [
        (component.id, f"{distribution.codename} / {component.name}")
        for distribution in repository.distributions
        for component in distribution.components
    ]


def _find_component(
    repository: Repository, component_id: int
) -> tuple[AptDistribution, AptComponent]:
    for distribution in repository.distributions:
        for component in distribution.components:
            if component.id == component_id:
                return distribution, component
    raise UploadError("Choose a distribution and component to publish into.", status_code=400)


def _upload_context(request: Request, repository: Repository, form: FormState) -> dict[str, Any]:
    return {
        "repository": repository,
        "form": form,
        "targets": _targets(repository),
        "writes_enabled": writes_enabled(request),
    }


@router.get(
    "/repositories/{slug}/packages/upload",
    include_in_schema=False,
    name="repository_upload_form",
    dependencies=[Depends(require_write_access)],
)
async def repository_upload_form(
    request: Request, slug: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    repository = await _load(session, slug)
    return render(
        get_templates(request),
        request,
        "repositories/upload.html.j2",
        _upload_context(request, repository, FormState()),
    )


async def _chunks(upload: UploadFile) -> AsyncIterator[bytes]:
    while chunk := await upload.read(UPLOAD_CHUNK_BYTES):
        yield chunk


@router.post(
    "/repositories/{slug}/packages/upload",
    include_in_schema=False,
    name="repository_upload",
    dependencies=[Depends(require_write_access)],
)
async def repository_upload(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
) -> Response:
    repository = await _load(session, slug)
    settings = get_settings(request)
    form = FormState()

    def reject(message: str, field: str = "package", code: int = 400) -> Response:
        form.add(field, message)
        return render(
            get_templates(request),
            request,
            "repositories/upload.html.j2",
            _upload_context(request, repository, form),
            status_code=code,
        )

    try:
        # The form is parsed here rather than through `File(...)` so the size cap
        # is the configured one.  Starlette's default max_part_size is 1 MiB,
        # which would reject essentially every real package (5.1).
        async with request.form(
            max_files=MAX_FORM_FILES,
            max_fields=MAX_FORM_FIELDS,
            max_part_size=settings.max_upload_bytes,
        ) as submitted:
            raw_target = str(submitted.get("target") or "")
            form.values["target"] = raw_target
            upload = submitted.get("package")

            if not isinstance(upload, UploadFile) or not upload.filename:
                return reject("Choose a .deb file to upload.")
            try:
                distribution, component = _find_component(repository, int(raw_target or 0))
            except ValueError:
                return reject("Choose a distribution and component.", "target")
            except UploadError as exc:
                return reject(str(exc), "target")

            # Staged while the form context is still open: closing it discards
            # the spooled upload, so the copy has to happen before then.
            staged = await package_service.stage_upload(
                _root_of(repository, settings),
                _chunks(upload),
                max_bytes=settings.max_upload_bytes,
            )
    except MultiPartException as exc:
        return reject(
            f"The upload was rejected before it finished: {exc.message} "
            f"The limit is {settings.max_upload_bytes:,} bytes.",
            code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
    except UploadError as exc:
        return reject(str(exc), code=exc.status_code)

    try:
        outcome = await package_service.publish_deb(
            session,
            settings,
            repository=repository,
            distribution=distribution,
            component=component,
            staged=staged,
        )
    except UploadError as exc:
        return reject(str(exc), code=exc.status_code)

    if outcome.created:
        await publishing.request_regeneration(session, queue, repository)
    # Commit before waking a worker: the job row has to be visible to the other
    # connection that will claim it.
    await session.commit()
    queue.wake()

    return RedirectResponse(
        request.url_for("repository_packages", slug=repository.slug).include_query_params(
            published=outcome.package.id
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/repositories/{slug}/packages/{publication_id}/delete",
    include_in_schema=False,
    name="repository_package_delete",
    dependencies=[Depends(require_write_access)],
)
async def repository_package_delete(
    request: Request,
    slug: str,
    publication_id: int,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
) -> Response:
    repository = await _load(session, slug)
    settings = get_settings(request)
    try:
        publication = await package_service.load_publication(session, repository, publication_id)
        name = publication.package.name
        await package_service.remove_publication(session, settings, repository, publication)
    except UploadError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    await publishing.request_regeneration(session, queue, repository)
    await session.commit()
    queue.wake()
    return RedirectResponse(
        request.url_for("repository_packages", slug=repository.slug).include_query_params(
            removed=name
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


# --------------------------------------------------------------------------- operations


@router.post(
    "/repositories/{slug}/regenerate",
    include_in_schema=False,
    name="repository_regenerate",
    dependencies=[Depends(require_write_access)],
)
async def repository_regenerate(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
) -> Response:
    repository = await _load(session, slug)
    job_id = await publishing.request_regeneration(session, queue, repository, actor="web")
    await session.commit()
    queue.wake()
    return RedirectResponse(
        request.url_for("job_detail", job_id=job_id), status_code=status.HTTP_303_SEE_OTHER
    )


@router.get(
    "/repositories/{slug}/distributions",
    include_in_schema=False,
    name="repository_distributions",
    dependencies=[Depends(require_write_access)],
)
async def repository_distributions(
    request: Request, slug: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    repository = await _load(session, slug)
    return render(
        get_templates(request),
        request,
        "repositories/distributions.html.j2",
        {
            "repository": repository,
            "form": FormState(values={"components": "main", "architectures": "amd64"}),
            "writes_enabled": writes_enabled(request),
        },
    )


@router.post(
    "/repositories/{slug}/distributions",
    include_in_schema=False,
    name="repository_distribution_add",
    dependencies=[Depends(require_write_access)],
)
async def repository_distribution_add(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    codename: Annotated[str, Form()] = "",
    suite: Annotated[str, Form()] = "",
    components: Annotated[str, Form()] = "",
    architectures: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
) -> Response:
    repository = await _load(session, slug)
    form = FormState(
        values={
            "codename": codename,
            "suite": suite,
            "components": components,
            "architectures": architectures,
            "description": description,
        }
    )
    clean_codename = required(form, "codename", codename, "Codename")
    component_names = parse_name_list(components)
    architecture_names = parse_name_list(architectures)
    if not component_names:
        form.add("components", "Name at least one component, for example 'main'.")
    if not architecture_names:
        form.add("architectures", "Name at least one architecture, for example 'amd64'.")

    if form.ok:
        try:
            await repository_service.add_distribution(
                session,
                repository,
                DistributionSpec(
                    codename=clean_codename,
                    suite=suite.strip() or None,
                    description=description.strip() or None,
                    components=component_names,
                    architectures=architecture_names,
                ),
            )
        except (RepositoryServiceError, ValueError) as exc:
            form.add("codename", str(exc))

    if not form.ok:
        return render(
            get_templates(request),
            request,
            "repositories/distributions.html.j2",
            {"repository": repository, "form": form, "writes_enabled": True},
            status_code=400,
        )

    await publishing.request_regeneration(session, queue, repository, actor="web")
    await session.commit()
    queue.wake()
    return RedirectResponse(
        request.url_for("repository_distributions", slug=repository.slug),
        status_code=status.HTTP_303_SEE_OTHER,
    )
