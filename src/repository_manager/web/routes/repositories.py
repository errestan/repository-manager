"""Repository browsing and management (specification.md 8.1).

Reads are anonymous and unfiltered (AD-16): there is no hidden repository
state, so no listing here is ever narrowed by who is asking.  Writes carry the
role the permission matrix in specification.md 3 gives them -- maintainer for
package operations, admin for the shape of the repository itself.

Route order matters: ``/repositories/new`` is declared before
``/repositories/{slug}``, or the literal would be swallowed by the parameter.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.datastructures import UploadFile
from starlette.responses import RedirectResponse, Response

from repository_manager.config import Settings
from repository_manager.jobs.queue import JobQueue
from repository_manager.metadata.repodata import public_key_filename
from repository_manager.metadata.rpm import ARCH_NOARCH
from repository_manager.models import (
    AptComponent,
    AptDistribution,
    AuditAction,
    Job,
    Package,
    PackagePublication,
    Repository,
    RepositoryType,
    RpmVariant,
    SigningKey,
)
from repository_manager.security.paths import resolve_within_roots
from repository_manager.services import audit, publishing, retention
from repository_manager.services import packages as package_service
from repository_manager.services import repositories as repository_service
from repository_manager.services.packages import ARCH_ALL, UploadError
from repository_manager.services.repositories import (
    DistributionSpec,
    RepositoryServiceError,
    VariantSpec,
    parse_name_list,
)
from repository_manager.web.deps import (
    MAX_FORM_FIELDS,
    MAX_FORM_FILES,
    Identity,
    db_session,
    get_limits,
    get_queue,
    get_settings,
    get_templates,
    record_upload,
    require_admin,
    require_maintainer,
)
from repository_manager.web.forms import FormState, required
from repository_manager.web.middleware import client_ip
from repository_manager.web.templating import render

router = APIRouter(tags=["repositories"])

PACKAGES_PER_PAGE = 50
UPLOAD_CHUNK_BYTES = 1024 * 1024

#: What the upload form accepts, and how the package file is described, per
#: format.  Kept here rather than in the template so the two never disagree.
#: Where each ecosystem expects a repository's public key to be installed.
APT_KEYRING_DIR = "/usr/share/keyrings"
RPM_KEYRING_DIR = "/etc/pki/rpm-gpg"

UPLOAD_HINTS: dict[RepositoryType, tuple[str, str]] = {
    RepositoryType.APT: (
        ".deb,application/vnd.debian.binary-package",
        "A .deb file. Its architecture must be one this distribution publishes, or 'all'.",
    ),
    RepositoryType.RPM: (
        ".rpm,application/x-rpm",
        "A binary .rpm file. Its architecture must match the variant, or be 'noarch'. "
        "Source packages (.src.rpm) are not accepted.",
    ),
}

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


async def load_repository(session: AsyncSession, slug: str) -> Repository:
    """One active repository by slug, with its publication targets loaded.

    Public rather than private because the administration routes need exactly
    this and duplicating the eager loads is how two modules end up disagreeing
    about which relationships are safe to touch in a template.
    """
    repository = await session.scalar(
        select(Repository)
        .where(Repository.slug == slug, Repository.deregistered_at.is_(None))
        .options(*_PUBLICATION_LOADS)
    )
    if repository is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such repository")
    return repository


def root_of(repository: Repository, settings: Settings) -> Path:
    """The repository's root, re-proved to be inside the sandbox (10.4)."""
    return resolve_within_roots(Path(repository.root_path), settings.allowed_roots)


async def _package_count(session: AsyncSession, repository: Repository) -> int:
    total = await session.scalar(
        select(func.count(Package.id)).where(Package.repository_id == repository.id)
    )
    return int(total or 0)


def _apt_snippet(settings: Settings, repository: Repository, key_name: str) -> str:
    base = settings.repository_url(repository.slug)
    return "\n".join(
        f"deb [signed-by={APT_KEYRING_DIR}/{key_name}.asc] "
        f"{base} {distribution.codename} "
        + " ".join(component.name for component in distribution.components)
        for distribution in repository.distributions
    )


def _rpm_snippet(settings: Settings, repository: Repository, key_name: str) -> str:
    """One ``.repo`` section per variant (4.4).

    ``gpgcheck`` and ``repo_gpgcheck`` are both on.  They are different checks:
    the first verifies each package's own signature, the second verifies
    ``repomd.xml``, and only the second is one this application can promise --
    so the snippet turning both on is a statement about how the repository
    should be *consumed*, not about what has already been guaranteed.
    """
    base = settings.repository_url(repository.slug)
    sections = []
    for variant in repository.variants:
        path = f"{variant.name}/{variant.arch}"
        sections.append(
            "\n".join(
                [
                    f"[{repository.slug}-{variant.name}-{variant.arch}]",
                    f"name={repository.name} — {path}",
                    f"baseurl={base}/{path}",
                    "enabled=1",
                    "gpgcheck=1",
                    "repo_gpgcheck=1",
                    f"gpgkey=file://{RPM_KEYRING_DIR}/{public_key_filename(key_name)}",
                ]
            )
        )
    return "\n\n".join(sections)


def _client_snippet(settings: Settings, repository: Repository) -> str | None:
    """The client setup snippet for this repository (4.4).

    Returns nothing without a signing key: both apt and dnf refuse an
    unverifiable repository, so a snippet naming a key file that will never
    exist would only send someone down a dead end.
    """
    if repository.signing_key is None:
        return None
    key_name = repository.signing_key.name
    if repository.type is RepositoryType.APT:
        if not repository.distributions:
            return None
        return _apt_snippet(settings, repository, key_name)
    if not repository.variants:
        return None
    return _rpm_snippet(settings, repository, key_name)


def _key_install(repository: Repository) -> dict[str, str] | None:
    """Where a client is told to put the public key, and what to call it.

    The two ecosystems disagree on both, and getting either wrong produces a
    repository that looks configured and refuses to refresh.
    """
    if repository.signing_key is None:
        return None
    name = repository.signing_key.name
    if repository.type is RepositoryType.APT:
        return {"directory": APT_KEYRING_DIR, "filename": f"{name}.asc"}
    return {"directory": RPM_KEYRING_DIR, "filename": public_key_filename(name)}


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
        {"repositories": repositories},
    )


# --------------------------------------------------------------------------- creation


def _creation_context(request: Request, keys: list[SigningKey], form: FormState) -> dict[str, Any]:
    return {
        "form": form,
        "keys": keys,
        # Pre-paired for the select macro: Jinja has no zip, and building the
        # pairs in the template would need the `do` extension.
        "key_options": [(key.id, f"{key.name} ({key.algorithm.label})") for key in keys],
    }


async def _signing_keys(session: AsyncSession) -> list[SigningKey]:
    return list(
        (await session.execute(select(SigningKey).order_by(SigningKey.name))).scalars().all()
    )


@router.get(
    "/repositories/new",
    include_in_schema=False,
    name="repository_new",
    dependencies=[Depends(require_admin)],
)
async def repository_new(
    request: Request, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    form = FormState(
        values={
            "retention": "all",
            "components": "main",
            "architectures": "amd64",
            "variant_arch": "x86_64",
        }
    )
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


def _repository_format(form: FormState, raw: str) -> RepositoryType | None:
    """The format is a required choice, like retention (4.3).

    No default is applied.  The two formats produce entirely different trees
    and cannot be converted into one another afterwards, so guessing on the
    user's behalf would be guessing about the one decision that cannot be
    undone.
    """
    try:
        return RepositoryType(raw)
    except ValueError:
        form.add("format", "Choose whether this repository serves APT or RPM packages.")
        return None


@router.post(
    "/repositories/new",
    include_in_schema=False,
    name="repository_create",
)
async def repository_create(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
    identity: Annotated[Identity, Depends(require_admin)],
    name: Annotated[str, Form()] = "",
    root_path: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
    signing_key_id: Annotated[str, Form()] = "",
    retention: Annotated[str, Form()] = "",
    retention_count: Annotated[str, Form()] = "",
    repository_format: Annotated[str, Form(alias="format")] = "",
    codename: Annotated[str, Form()] = "",
    suite: Annotated[str, Form()] = "",
    components: Annotated[str, Form()] = "",
    architectures: Annotated[str, Form()] = "",
    variant_name: Annotated[str, Form()] = "",
    variant_arch: Annotated[str, Form()] = "",
    origin: Annotated[str, Form()] = "",
    label: Annotated[str, Form()] = "",
) -> Response:
    settings = get_settings(request)
    available_keys = await _signing_keys(session)
    form = FormState(
        values={
            "name": name,
            "root_path": root_path,
            "description": description,
            "signing_key_id": signing_key_id,
            "retention": retention,
            "retention_count": retention_count,
            "format": repository_format,
            "codename": codename,
            "suite": suite,
            "components": components,
            "architectures": architectures,
            "variant_name": variant_name,
            "variant_arch": variant_arch,
            "origin": origin,
            "label": label,
        }
    )

    def rejected() -> Response:
        return render(
            get_templates(request),
            request,
            "repositories/new.html.j2",
            _creation_context(request, available_keys, form),
            status_code=400,
        )

    clean_name = required(form, "name", name, "Repository name")
    clean_root = required(form, "root_path", root_path, "Root path")
    keep = _retention(form, retention, retention_count)
    chosen = _repository_format(form, repository_format)

    # Only the chosen format's fields are validated.  The form shows both
    # subdivisions because it has to work without JavaScript (11), so whatever
    # sits in the other one is not an error -- it is a field the user correctly
    # ignored.
    component_names: tuple[str, ...] = ()
    architecture_names: tuple[str, ...] = ()
    clean_codename = ""
    if chosen is RepositoryType.APT:
        clean_codename = required(form, "codename", codename, "Distribution codename")
        component_names = parse_name_list(components)
        architecture_names = parse_name_list(architectures)
        if not component_names:
            form.add("components", "Name at least one component, for example 'main'.")
        if not architecture_names:
            form.add("architectures", "Name at least one architecture, for example 'amd64'.")
    elif chosen is RepositoryType.RPM:
        required(form, "variant_name", variant_name, "Variant name")
        required(form, "variant_arch", variant_arch, "Variant architecture")

    key_id = 0
    if not signing_key_id:
        form.add("signing_key_id", "Choose the key this repository's metadata is signed with.")
    else:
        try:
            key_id = int(signing_key_id)
        except ValueError:
            form.add("signing_key_id", "That signing key is not valid.")

    if not form.ok:
        return rejected()

    try:
        if chosen is RepositoryType.APT:
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
                actor=identity.user_dn,
                distributions=(
                    DistributionSpec(
                        codename=clean_codename,
                        suite=suite.strip() or None,
                        components=component_names,
                        architectures=architecture_names,
                    ),
                ),
            )
        else:
            repository = await repository_service.create_rpm_repository(
                session,
                settings,
                name=clean_name,
                root_path=clean_root,
                description=description,
                signing_key_id=key_id,
                retention_count=keep,
                actor=identity.user_dn,
                variants=(VariantSpec(name=variant_name.strip(), arch=variant_arch.strip()),),
            )
    except (RepositoryServiceError, ValueError) as exc:
        form.add("root_path", str(exc))
        return rejected()

    await audit.record(
        session,
        action=AuditAction.REPOSITORY_CREATE,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=repository.slug,
        source_ip=client_ip(request.scope),
        details={
            "name": repository.name,
            "type": repository.type.value,
            "root_path": repository.root_path,
        },
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
    repository = await load_repository(session, slug)
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
            "key_install": _key_install(repository),
        },
    )


# --------------------------------------------------------------------------- packages


def _filtered(repository: Repository, query: str, architecture: str) -> Select[Any]:
    statement = select(PackagePublication).join(
        Package, Package.id == PackagePublication.package_id
    )
    # Joined through the target table rather than filtered on `Package` alone,
    # so a publication whose target belongs to another repository can never
    # appear here even if the two share a package row.
    if repository.type is RepositoryType.APT:
        statement = statement.join(
            AptComponent, AptComponent.id == PackagePublication.component_id
        ).join(AptDistribution, AptDistribution.id == AptComponent.distribution_id)
    else:
        statement = statement.join(RpmVariant, RpmVariant.id == PackagePublication.variant_id)
    statement = statement.where(Package.repository_id == repository.id)
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
    repository = await load_repository(session, slug)
    query = q.strip()[:200]
    architecture = arch.strip()[:32]
    page = max(1, page)

    base = _filtered(repository, query, architecture)
    total = int(await session.scalar(select(func.count()).select_from(base.subquery())) or 0)
    listing = (
        base.options(
            selectinload(PackagePublication.package),
            selectinload(PackagePublication.component).selectinload(AptComponent.distribution),
            selectinload(PackagePublication.variant),
        )
        .order_by(Package.name, Package.version, Package.architecture)
        .offset((page - 1) * PACKAGES_PER_PAGE)
        .limit(PACKAGES_PER_PAGE)
    )
    publications = list((await session.execute(listing)).scalars().all())
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
            "architectures": _architecture_options(repository),
            # The spelling of "runs anywhere" differs by format, and the filter
            # offers it explicitly because no package's own header ever names
            # the other one.
            "any_architecture": ARCH_ALL if repository.type is RepositoryType.APT else ARCH_NOARCH,
        },
    )


def _architecture_options(repository: Repository) -> list[str]:
    """The architectures this repository publishes, for the filter.

    The format's own "runs anywhere" name is left out and offered separately by
    the template: an APT distribution may well list ``all`` among its
    architectures, and it would otherwise appear in the list twice.
    """
    if repository.type is RepositoryType.APT:
        found = {
            architecture.name
            for distribution in repository.distributions
            for architecture in distribution.architectures
        }
        return sorted(found - {ARCH_ALL})
    return sorted({variant.arch for variant in repository.variants} - {ARCH_NOARCH})


@dataclass(frozen=True)
class AptTarget:
    """A resolved ``distribution/component`` to publish a ``.deb`` into."""

    distribution: AptDistribution
    component: AptComponent

    @property
    def label(self) -> str:
        return f"{self.distribution.codename}/{self.component.name}"


@dataclass(frozen=True)
class RpmTarget:
    """A resolved variant to publish an ``.rpm`` into."""

    variant: RpmVariant

    @property
    def label(self) -> str:
        return f"{self.variant.name}/{self.variant.arch}"


#: Two shapes rather than one with optional halves, so the upload route branches
#: on a type the checker can narrow instead of on a field that might be unset.
UploadTarget = AptTarget | RpmTarget


def _targets(repository: Repository) -> list[tuple[int, str]]:
    """Selectable (id, label) pairs for the publication targets.

    One flat select rather than two dependent ones: a distribution/component
    pair of selects only works if JavaScript repopulates the second, and every
    flow has to work without it (11).

    The ids come from different tables for the two formats and are only ever
    resolved against the repository they were rendered for, which is what stops
    a component id from being read as a variant id.
    """
    if repository.type is RepositoryType.APT:
        return [
            (component.id, f"{distribution.codename} / {component.name}")
            for distribution in repository.distributions
            for component in distribution.components
        ]
    return [(variant.id, f"{variant.name}/{variant.arch}") for variant in repository.variants]


def _find_target(repository: Repository, target_id: int) -> UploadTarget:
    if repository.type is RepositoryType.APT:
        for distribution in repository.distributions:
            for component in distribution.components:
                if component.id == target_id:
                    return AptTarget(distribution=distribution, component=component)
        raise UploadError("Choose a distribution and component to publish into.", status_code=400)

    for variant in repository.variants:
        if variant.id == target_id:
            return RpmTarget(variant=variant)
    raise UploadError("Choose a variant to publish into.", status_code=400)


def _upload_context(request: Request, repository: Repository, form: FormState) -> dict[str, Any]:
    accept, hint = UPLOAD_HINTS[repository.type]
    return {
        "repository": repository,
        "form": form,
        "targets": _targets(repository),
        "accept": accept,
        "package_hint": hint,
    }


@router.get(
    "/repositories/{slug}/packages/upload",
    include_in_schema=False,
    name="repository_upload_form",
    dependencies=[Depends(require_maintainer)],
)
async def repository_upload_form(
    request: Request, slug: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    repository = await load_repository(session, slug)
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
)
async def repository_upload(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_maintainer)],
) -> Response:
    repository = await load_repository(session, slug)
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

    # Checked before the body is read, so a caller over the limit is turned away
    # without this process spooling their upload to disk first (10.3).
    allowance = get_limits(request).upload_allowed(
        client=client_ip(request.scope), actor=identity.user_dn
    )
    if not allowance.allowed:
        return reject(
            "Too many uploads from here just now. Wait "
            f"{allowance.retry_after_seconds} seconds and try again.",
            code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    try:
        # Parsed here rather than through `File(...)` so the limits are this
        # application's rather than Starlette's defaults.  There is deliberately
        # no `except MultiPartException` around this: Starlette converts that
        # into `HTTPException(400)` itself whenever a request is in scope, so
        # such a handler would be unreachable, and the 400 renders through the
        # application's own HTML error page.  `max_part_size`
        # bounds non-file fields only -- an uploaded file streams to a spooled
        # temporary file and is capped by `stage_upload` instead (5.1) -- but it
        # is set from the configured limit so the two cannot disagree.
        #
        # If the CSRF check already read the body (the no-JavaScript path, where
        # the token is a form field), this returns that same parsed form; the
        # limits are identical by construction, since both come from deps.
        async with request.form(
            max_files=MAX_FORM_FILES,
            max_fields=MAX_FORM_FIELDS,
            max_part_size=settings.max_upload_bytes,
        ) as submitted:
            raw_target = str(submitted.get("target") or "")
            form.values["target"] = raw_target
            upload = submitted.get("package")

            if not isinstance(upload, UploadFile) or not upload.filename:
                suffix = ".deb" if repository.type is RepositoryType.APT else ".rpm"
                return reject(f"Choose a {suffix} file to upload.")
            try:
                target = _find_target(repository, int(raw_target or 0))
            except ValueError:
                return reject("Choose somewhere to publish this package.", "target")
            except UploadError as exc:
                return reject(str(exc), "target")

            # Staged while the form context is still open: closing it discards
            # the spooled upload, so the copy has to happen before then.
            staged = await package_service.stage_upload(
                root_of(repository, settings),
                _chunks(upload),
                max_bytes=settings.max_upload_bytes,
            )
    except UploadError as exc:
        return reject(str(exc), code=exc.status_code)

    try:
        if isinstance(target, AptTarget):
            outcome = await package_service.publish_deb(
                session,
                settings,
                repository=repository,
                distribution=target.distribution,
                component=target.component,
                staged=staged,
                actor=identity.user_dn,
            )
        else:
            outcome = await package_service.publish_rpm(
                session,
                settings,
                repository=repository,
                variant=target.variant,
                staged=staged,
                actor=identity.user_dn,
            )
    except UploadError as exc:
        return reject(str(exc), code=exc.status_code)

    record_upload(request, outcome.package.size)
    await audit.record(
        session,
        action=AuditAction.PACKAGE_UPLOAD,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=outcome.package.relative_path,
        source_ip=client_ip(request.scope),
        details={
            "name": outcome.package.name,
            "version": outcome.package.full_version,
            "architecture": outcome.package.architecture,
            "published_in": target.label,
            # False means the identical file was already published here, which
            # is a successful no-op rather than a new package (5.1).
            "created": outcome.created,
        },
    )
    pruned: list[retention.Pruned] = []
    if outcome.created:
        # Pruned before the rebuild is queued, so one regeneration publishes the
        # addition and the removals together rather than briefly offering an
        # index that lists a package already deleted from the pool (5.3).
        pruned = await retention.enforce_for(
            session, settings, repository, name=outcome.package.name
        )
        await retention.record(
            session,
            repository,
            pruned,
            actor=identity.user_dn,
            source_ip=client_ip(request.scope),
        )
        await publishing.request_regeneration(session, queue, repository)
    # Commit before waking a worker: the job row has to be visible to the other
    # connection that will claim it.
    await session.commit()
    queue.wake()

    return RedirectResponse(
        request.url_for("repository_packages", slug=repository.slug).include_query_params(
            published=outcome.package.id, pruned=len(pruned)
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/repositories/{slug}/packages/{publication_id}/delete",
    include_in_schema=False,
    name="repository_package_delete",
)
async def repository_package_delete(
    request: Request,
    slug: str,
    publication_id: int,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_maintainer)],
) -> Response:
    repository = await load_repository(session, slug)
    settings = get_settings(request)
    try:
        publication = await package_service.load_publication(session, repository, publication_id)
        name = publication.package.name
        version = publication.package.version
        await package_service.remove_publication(session, settings, repository, publication)
    except UploadError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    await audit.record(
        session,
        action=AuditAction.PACKAGE_REMOVE,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=name,
        source_ip=client_ip(request.scope),
        details={"name": name, "version": version},
    )
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
)
async def repository_regenerate(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_maintainer)],
) -> Response:
    repository = await load_repository(session, slug)
    job_id = await publishing.request_regeneration(
        session, queue, repository, actor=identity.user_dn
    )
    await audit.record(
        session,
        action=AuditAction.REGENERATE,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=repository.slug,
        source_ip=client_ip(request.scope),
        details={"job_id": job_id},
    )
    await session.commit()
    queue.wake()
    return RedirectResponse(
        request.url_for("job_detail", job_id=job_id), status_code=status.HTTP_303_SEE_OTHER
    )


@router.get(
    "/repositories/{slug}/distributions",
    include_in_schema=False,
    name="repository_distributions",
    dependencies=[Depends(require_admin)],
)
async def repository_distributions(
    request: Request, slug: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    repository = await load_repository(session, slug)
    if repository.type is not RepositoryType.APT:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="That repository has no distributions"
        )
    return render(
        get_templates(request),
        request,
        "repositories/distributions.html.j2",
        {
            "repository": repository,
            "form": FormState(values={"components": "main", "architectures": "amd64"}),
        },
    )


@router.post(
    "/repositories/{slug}/distributions",
    include_in_schema=False,
    name="repository_distribution_add",
)
async def repository_distribution_add(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_admin)],
    codename: Annotated[str, Form()] = "",
    suite: Annotated[str, Form()] = "",
    components: Annotated[str, Form()] = "",
    architectures: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
) -> Response:
    repository = await load_repository(session, slug)
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
            {"repository": repository, "form": form},
            status_code=400,
        )

    await audit.record(
        session,
        action=AuditAction.DISTRIBUTION_ADD,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=clean_codename,
        source_ip=client_ip(request.scope),
        details={"components": component_names, "architectures": architecture_names},
    )
    await publishing.request_regeneration(session, queue, repository, actor=identity.user_dn)
    await session.commit()
    queue.wake()
    return RedirectResponse(
        request.url_for("repository_distributions", slug=repository.slug),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/repositories/{slug}/variants",
    include_in_schema=False,
    name="repository_variants",
    dependencies=[Depends(require_admin)],
)
async def repository_variants(
    request: Request, slug: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    repository = await load_repository(session, slug)
    if repository.type is not RepositoryType.RPM:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="That repository has no variants"
        )
    return render(
        get_templates(request),
        request,
        "repositories/variants.html.j2",
        {"repository": repository, "form": FormState(values={"variant_arch": "x86_64"})},
    )


@router.post(
    "/repositories/{slug}/variants",
    include_in_schema=False,
    name="repository_variant_add",
)
async def repository_variant_add(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_admin)],
    variant_name: Annotated[str, Form()] = "",
    variant_arch: Annotated[str, Form()] = "",
) -> Response:
    repository = await load_repository(session, slug)
    if repository.type is not RepositoryType.RPM:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="That repository has no variants"
        )

    form = FormState(values={"variant_name": variant_name, "variant_arch": variant_arch})
    clean_name = required(form, "variant_name", variant_name, "Variant name")
    clean_arch = required(form, "variant_arch", variant_arch, "Variant architecture")

    if form.ok:
        try:
            await repository_service.add_variant(
                session, repository, VariantSpec(name=clean_name, arch=clean_arch)
            )
        except (RepositoryServiceError, ValueError) as exc:
            form.add("variant_name", str(exc))

    if not form.ok:
        return render(
            get_templates(request),
            request,
            "repositories/variants.html.j2",
            {"repository": repository, "form": form},
            status_code=400,
        )

    await audit.record(
        session,
        action=AuditAction.VARIANT_ADD,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=f"{clean_name}/{clean_arch}",
        source_ip=client_ip(request.scope),
        details={"variant": clean_name, "architecture": clean_arch},
    )
    # Queued rather than written here: the new tree has no repodata at all
    # until it runs, and a variant clients cannot refresh is worse than one
    # that appears a few seconds late (5.4).
    await publishing.request_regeneration(session, queue, repository, actor=identity.user_dn)
    await session.commit()
    queue.wake()
    return RedirectResponse(
        request.url_for("repository_variants", slug=repository.slug),
        status_code=status.HTTP_303_SEE_OTHER,
    )
