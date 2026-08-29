"""Repository settings, retention, rescan and removal (specification.md 8.1).

The consequential half of the interface.  Everything here either changes what
clients are offered or deletes something, so three habits run through it.

**Destructive actions are confirmed on their own page**, not behind a button in
a row of others.  Deregistering asks; purging asks separately and by name,
because "remove this from the interface" and "delete the packages from disk"
are different decisions and only one of them can be undone.

**Refusals explain what to do instead.**  A distribution that still publishes
packages is not deleted with its contents; it is refused, with a count, because
the cascade would have deleted packages nobody named.

**Nothing that changes on-disk metadata forgets to rebuild it.**  Every handler
that alters what an index should contain queues a regeneration, and the audit
entry records which fields moved.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse, Response

from repository_manager.jobs.queue import JobQueue
from repository_manager.models import (
    AptDistribution,
    AuditAction,
    JobType,
    Package,
    Repository,
    RpmVariant,
    SigningKey,
)
from repository_manager.services import audit, publishing, retention
from repository_manager.services import repositories as repository_service
from repository_manager.services.repositories import (
    RepositoryServiceError,
    SettingsUpdate,
)
from repository_manager.web.deps import (
    Identity,
    db_session,
    get_queue,
    get_settings,
    get_templates,
    require_admin,
    require_maintainer,
)
from repository_manager.web.forms import FormState
from repository_manager.web.middleware import client_ip
from repository_manager.web.routes.repositories import load_repository
from repository_manager.web.templating import render

router = APIRouter(tags=["repositories"])

#: Typed by an admin to confirm a purge.  The slug rather than a generic word:
#: it cannot be typed by muscle memory on the wrong repository.
PURGE_CONFIRMATION_FIELD = "confirm"

#: Fields whose change means the published metadata no longer matches the
#: database.  A description edit is not one of them.
REBUILD_ON = frozenset({"name", "origin", "label", "signing_key"})


async def _signing_keys(session: AsyncSession) -> list[SigningKey]:
    return list((await session.execute(select(SigningKey).order_by(SigningKey.name))).scalars())


async def _package_count(session: AsyncSession, repository: Repository) -> int:
    """How much is at stake, for the confirmation page to say out loud."""
    return int(
        await session.scalar(
            select(func.count(Package.id)).where(Package.repository_id == repository.id)
        )
        or 0
    )


def _retention_fields(repository: Repository) -> dict[str, str]:
    return {
        "retention": "all" if repository.retention_count == 0 else "count",
        "retention_count": str(repository.retention_count or 5),
    }


async def _settings_context(
    request: Request, session: AsyncSession, repository: Repository, form: FormState
) -> dict[str, Any]:
    return {
        "repository": repository,
        "form": form,
        # (id, name) pairs rather than the rows: the select macro takes option
        # tuples, and building them in the template would need a zip filter
        # Jinja does not have.
        "key_options": [(key.id, key.name) for key in await _signing_keys(session)],
        # Recomputed on every render rather than cached: it is the answer to
        # "what would Apply remove?", and a stale answer to that is worse than
        # none (5.3).
        "prunable": await retention.preview(session, repository),
        "distributions": repository.distributions,
        "variants": repository.variants,
    }


async def _settings_page(
    request: Request,
    session: AsyncSession,
    repository: Repository,
    form: FormState,
    status_code: int = 200,
) -> Response:
    return render(
        get_templates(request),
        request,
        "repositories/settings.html.j2",
        await _settings_context(request, session, repository, form),
        status_code=status_code,
    )


@router.get(
    "/repositories/{slug}/settings",
    include_in_schema=False,
    name="repository_settings",
    dependencies=[Depends(require_admin)],
)
async def repository_settings(
    request: Request, slug: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    repository = await load_repository(session, slug)
    form = FormState(
        values={
            "name": repository.name,
            "description": repository.description or "",
            "origin": repository.origin or "",
            "label": repository.label or "",
            "signing_key_id": str(repository.signing_key_id or ""),
            **_retention_fields(repository),
        }
    )
    return await _settings_page(request, session, repository, form)


def _retention_choice(form: FormState, choice: str, count: str) -> int:
    """Read the retention pair back into a single number (5.3)."""
    if choice == "all":
        return 0
    if choice != "count":
        form.add("retention", "Choose whether to keep all versions or a fixed number.")
        return 0
    try:
        number = int(count)
    except ValueError:
        form.add("retention_count", "Give the number of versions to keep as a whole number.")
        return 0
    if number < 1:
        form.add("retention_count", "Keep at least one version, or choose 'keep all'.")
        return 0
    return number


@router.post(
    "/repositories/{slug}/settings",
    include_in_schema=False,
    name="repository_settings_save",
)
async def repository_settings_save(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_admin)],
    name: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
    origin: Annotated[str, Form()] = "",
    label: Annotated[str, Form()] = "",
    signing_key_id: Annotated[str, Form()] = "",
    retention: Annotated[str, Form()] = "",
    retention_count: Annotated[str, Form()] = "",
) -> Response:
    repository = await load_repository(session, slug)
    settings = get_settings(request)
    form = FormState(
        values={
            "name": name,
            "description": description,
            "origin": origin,
            "label": label,
            "signing_key_id": signing_key_id,
            "retention": retention,
            "retention_count": retention_count,
        }
    )

    keep = _retention_choice(form, retention, retention_count)
    try:
        key_id = int(signing_key_id)
    except ValueError:
        form.add("signing_key_id", "Choose the key this repository's metadata is signed with.")
        key_id = 0

    if not form.ok:
        return await _settings_page(request, session, repository, form, status_code=400)

    try:
        changed = await repository_service.update_settings(
            session,
            settings,
            repository,
            SettingsUpdate(
                name=name,
                description=description,
                origin=origin,
                label=label,
                retention_count=keep,
                signing_key_id=key_id,
            ),
        )
    except RepositoryServiceError as exc:
        form.add("name", str(exc))
        return await _settings_page(request, session, repository, form, status_code=400)

    if not changed:
        return RedirectResponse(
            request.url_for("repository_settings", slug=repository.slug).include_query_params(
                unchanged=1
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    await audit.record(
        session,
        action=AuditAction.SETTINGS_UPDATE,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=repository.slug,
        source_ip=client_ip(request.scope),
        # The field names, never the values: a settings row in the audit log is
        # a record of what somebody touched, and copying every value into it
        # would duplicate the repository into an append-only table.
        details={"fields": sorted(changed)},
    )
    if changed & REBUILD_ON:
        await publishing.request_regeneration(session, queue, repository, actor=identity.user_dn)
    await session.commit()
    queue.wake()

    return RedirectResponse(
        request.url_for("repository_settings", slug=repository.slug).include_query_params(
            saved=",".join(sorted(changed))
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/repositories/{slug}/retention",
    include_in_schema=False,
    name="repository_retention_apply",
)
async def repository_retention_apply(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    """The explicit "apply retention now" action (5.3).

    Explicit because lowering N does not prune retroactively: a repository can
    carry a backlog of versions that the current policy would not have kept,
    and clearing it deletes packages that clients can currently install. That
    is a decision, so it gets a button rather than a background sweep.
    """
    repository = await load_repository(session, slug)
    settings = get_settings(request)
    pruned = await retention.enforce_all(session, settings, repository)

    await audit.record(
        session,
        action=AuditAction.RETENTION_APPLY,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=repository.slug,
        source_ip=client_ip(request.scope),
        details={"removed": len(pruned), "retention_count": repository.retention_count},
    )
    await retention.record(
        session, repository, pruned, actor=identity.user_dn, source_ip=client_ip(request.scope)
    )
    if pruned:
        await publishing.request_regeneration(session, queue, repository, actor=identity.user_dn)
    await session.commit()
    queue.wake()

    return RedirectResponse(
        request.url_for("repository_settings", slug=repository.slug).include_query_params(
            pruned=len(pruned)
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/repositories/{slug}/rescan",
    include_in_schema=False,
    name="repository_rescan",
)
async def repository_rescan(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_maintainer)],
) -> Response:
    """Queue a reconciliation of the database against the disk (5.4).

    Maintainer rather than admin: it changes nothing, and the person who
    notices that a package is missing is the person who publishes packages.
    """
    repository = await load_repository(session, slug)
    job_id = await queue.enqueue(
        session, JobType.RESCAN, repository_id=repository.id, actor=identity.user_dn
    )
    await audit.record(
        session,
        action=AuditAction.RESCAN,
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


# --------------------------------------------------------------- removing targets


def _find_distribution(repository: Repository, distribution_id: int) -> AptDistribution:
    for candidate in repository.distributions:
        if candidate.id == distribution_id:
            return candidate
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such distribution")


def _find_variant(repository: Repository, variant_id: int) -> RpmVariant:
    for candidate in repository.variants:
        if candidate.id == variant_id:
            return candidate
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such variant")


@router.post(
    "/repositories/{slug}/distributions/{distribution_id}/delete",
    include_in_schema=False,
    name="repository_distribution_delete",
)
async def repository_distribution_delete(
    request: Request,
    slug: str,
    distribution_id: int,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    repository = await load_repository(session, slug)
    distribution = _find_distribution(repository, distribution_id)
    codename = distribution.codename
    try:
        await repository_service.remove_distribution(
            session, get_settings(request), repository, distribution
        )
    except RepositoryServiceError as exc:
        form = FormState()
        form.add("distributions", str(exc))
        return await _settings_page(request, session, repository, form, status_code=409)

    await audit.record(
        session,
        action=AuditAction.DISTRIBUTION_REMOVE,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=codename,
        source_ip=client_ip(request.scope),
        details={"codename": codename},
    )
    await publishing.request_regeneration(session, queue, repository, actor=identity.user_dn)
    await session.commit()
    queue.wake()
    return RedirectResponse(
        request.url_for("repository_settings", slug=repository.slug).include_query_params(
            removed=codename
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/repositories/{slug}/variants/{variant_id}/delete",
    include_in_schema=False,
    name="repository_variant_delete",
)
async def repository_variant_delete(
    request: Request,
    slug: str,
    variant_id: int,
    session: Annotated[AsyncSession, Depends(db_session)],
    queue: Annotated[JobQueue, Depends(get_queue)],
    identity: Annotated[Identity, Depends(require_admin)],
) -> Response:
    repository = await load_repository(session, slug)
    variant = _find_variant(repository, variant_id)
    path = f"{variant.name}/{variant.arch}"
    try:
        await repository_service.remove_variant(session, get_settings(request), repository, variant)
    except RepositoryServiceError as exc:
        form = FormState()
        form.add("variants", str(exc))
        return await _settings_page(request, session, repository, form, status_code=409)

    await audit.record(
        session,
        action=AuditAction.VARIANT_REMOVE,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=path,
        source_ip=client_ip(request.scope),
        details={"variant": path},
    )
    await publishing.request_regeneration(session, queue, repository, actor=identity.user_dn)
    await session.commit()
    queue.wake()
    return RedirectResponse(
        request.url_for("repository_settings", slug=repository.slug).include_query_params(
            removed=path
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


# --------------------------------------------------------------- deregistration


@router.get(
    "/repositories/{slug}/delete",
    include_in_schema=False,
    name="repository_delete_form",
    dependencies=[Depends(require_admin)],
)
async def repository_delete_form(
    request: Request, slug: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    """The confirmation page: what is about to happen, before it happens (8.1)."""
    repository = await load_repository(session, slug)
    return render(
        get_templates(request),
        request,
        "repositories/delete.html.j2",
        {
            "repository": repository,
            "form": FormState(),
            "packages": await _package_count(session, repository),
            "confirmation_field": PURGE_CONFIRMATION_FIELD,
        },
    )


@router.post(
    "/repositories/{slug}/delete",
    include_in_schema=False,
    name="repository_delete",
)
async def repository_delete(
    request: Request,
    slug: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    identity: Annotated[Identity, Depends(require_admin)],
    purge: Annotated[str, Form()] = "",
    confirm: Annotated[str, Form()] = "",
) -> Response:
    """Deregister, and optionally delete the files (8.1).

    Purging asks for the slug to be typed.  That is not ceremony: the two
    actions are one form apart, one of them is irreversible, and a checkbox is
    a single misplaced click.
    """
    repository = await load_repository(session, slug)
    wants_purge = purge in {"1", "true", "on", "yes"}

    if wants_purge and confirm.strip() != repository.slug:
        form = FormState(values={"purge": purge})
        form.add(
            PURGE_CONFIRMATION_FIELD,
            f"Type {repository.slug} exactly to confirm that the files should be deleted.",
        )
        return render(
            get_templates(request),
            request,
            "repositories/delete.html.j2",
            {
                "repository": repository,
                "form": form,
                "packages": await _package_count(session, repository),
                "confirmation_field": PURGE_CONFIRMATION_FIELD,
            },
            status_code=400,
        )

    root_path = repository.root_path
    purged = await repository_service.deregister(
        session, get_settings(request), repository, purge=wants_purge
    )
    await audit.record(
        session,
        action=AuditAction.REPOSITORY_PURGE if purged else AuditAction.REPOSITORY_DEREGISTER,
        actor=identity.user_dn,
        repository_id=repository.id,
        target=repository.slug,
        source_ip=client_ip(request.scope),
        details={"root_path": root_path, "purged": purged, "type": repository.type.value},
    )
    await session.commit()
    return RedirectResponse(
        request.url_for("repository_list").include_query_params(
            deregistered=repository.slug, purged=int(purged)
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )
