"""Job status pages (specification.md 6, 8.1).

Rendered as complete pages with a manual refresh control.  HTMX polling is an
enhancement layered on top in a later milestone; the page has to be useful with
JavaScript disabled first, not as an afterthought (11).

Visible to any signed-in user, of either role (8.1).  A job log names the
repositories and packages being worked on and can carry the tail of a failed
subprocess, which is more than the anonymous browsing surface exposes.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.responses import Response

from repository_manager.models import Job, JobState
from repository_manager.web.deps import db_session, get_templates, require_authenticated
from repository_manager.web.templating import render

router = APIRouter(tags=["jobs"])

# Enough to cover a busy afternoon without turning the page into a report.
RECENT_JOB_LIMIT = 50


@router.get(
    "/jobs",
    include_in_schema=False,
    name="job_list",
    dependencies=[Depends(require_authenticated)],
)
async def job_list(
    request: Request, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    statement = (
        select(Job)
        .options(selectinload(Job.repository))
        .order_by(Job.created_at.desc(), Job.id.desc())
        .limit(RECENT_JOB_LIMIT)
    )
    jobs = list((await session.execute(statement)).scalars().all())
    active = sum(1 for job in jobs if not job.state.is_terminal)
    return render(
        get_templates(request),
        request,
        "jobs/list.html.j2",
        {"jobs": jobs, "active": active, "limit": RECENT_JOB_LIMIT},
    )


@router.get(
    "/jobs/{job_id}",
    include_in_schema=False,
    name="job_detail",
    dependencies=[Depends(require_authenticated)],
)
async def job_detail(
    request: Request, job_id: int, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    job = await session.scalar(
        select(Job).where(Job.id == job_id).options(selectinload(Job.repository))
    )
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such job")
    return render(
        get_templates(request),
        request,
        "jobs/detail.html.j2",
        {"job": job, "finished": job.state.is_terminal, "states": list(JobState)},
    )
