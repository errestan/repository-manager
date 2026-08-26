"""Anonymous repository browsing (specification.md 8.1).

All repositories are readable by everyone (AD-11), so these routes take no
authentication.  Write operations arrive with M2 and M3.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.responses import Response
from starlette.templating import Jinja2Templates

from repository_manager.models import AptDistribution, Repository
from repository_manager.web.templating import render

router = APIRouter(tags=["repositories"])


def _templates(request: Request) -> Jinja2Templates:
    templates: Jinja2Templates = request.app.state.templates
    return templates


async def _load_active(session: AsyncSession) -> list[Repository]:
    """Active repositories with their publication targets eagerly loaded.

    Async SQLAlchemy cannot lazy-load during template rendering -- the implicit
    IO raises MissingGreenlet -- so every relationship a template touches is
    loaded up front.
    """
    statement = (
        select(Repository)
        .where(Repository.deregistered_at.is_(None))
        .options(
            selectinload(Repository.distributions).selectinload(AptDistribution.components),
            selectinload(Repository.distributions).selectinload(AptDistribution.architectures),
            selectinload(Repository.variants),
        )
        .order_by(Repository.name)
    )
    return list((await session.execute(statement)).scalars().all())


@router.get("/", include_in_schema=False, name="repository_list")
async def repository_list(request: Request) -> Response:
    async with request.app.state.sessionmaker() as session:
        repositories = await _load_active(session)
    return render(
        _templates(request),
        request,
        "repositories/list.html.j2",
        {"repositories": repositories},
    )


@router.get("/repositories/{slug}", include_in_schema=False, name="repository_detail")
async def repository_detail(request: Request, slug: str) -> Response:
    async with request.app.state.sessionmaker() as session:
        statement = (
            select(Repository)
            .where(Repository.slug == slug, Repository.deregistered_at.is_(None))
            .options(
                selectinload(Repository.distributions).selectinload(AptDistribution.components),
                selectinload(Repository.distributions).selectinload(AptDistribution.architectures),
                selectinload(Repository.variants),
            )
        )
        repository = (await session.execute(statement)).scalar_one_or_none()

    if repository is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such repository")

    settings = request.app.state.settings
    return render(
        _templates(request),
        request,
        "repositories/detail.html.j2",
        {
            "repository": repository,
            # Client setup snippets are copied into sources.list and .repo files,
            # so they must be absolute and built from the external URL (13.5).
            "public_base": f"{settings.public_url}/repositories/{repository.slug}",
        },
    )
