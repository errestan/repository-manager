"""The audit log page (specification.md 3, 8.1, 9).

Scope is decided here and applied to the query, not to the rendering: a
maintainer's own entries are the only rows the database is ever asked for, so
there is no filtered-out data sitting in the response waiting for a template
mistake to reveal it.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.responses import Response

from repository_manager.models import AuditAction, AuditLog, Role
from repository_manager.web.deps import Identity, db_session, get_templates, require_maintainer
from repository_manager.web.templating import render

router = APIRouter(tags=["audit"])

ENTRIES_PER_PAGE = 50


def _scoped(identity: Identity) -> Select[tuple[AuditLog]]:
    """Everything for an admin, only their own entries for a maintainer (3)."""
    statement = select(AuditLog).options(selectinload(AuditLog.repository))
    if identity.role is Role.ADMIN:
        return statement
    return statement.where(AuditLog.actor == identity.user_dn)


@router.get("/audit", include_in_schema=False, name="audit_log")
async def audit_log(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
    identity: Annotated[Identity, Depends(require_maintainer)],
    action: str = "",
    page: int = 1,
) -> Response:
    page = max(1, page)
    base = _scoped(identity)

    chosen = action if action in {member.value for member in AuditAction} else ""
    if chosen:
        base = base.where(AuditLog.action == AuditAction(chosen))

    total = int(await session.scalar(select(func.count()).select_from(base.subquery())) or 0)
    listing = (
        base.order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
        .offset((page - 1) * ENTRIES_PER_PAGE)
        .limit(ENTRIES_PER_PAGE)
    )
    entries = list((await session.execute(listing)).scalars().all())

    return render(
        get_templates(request),
        request,
        "audit/list.html.j2",
        {
            "entries": entries,
            "total": total,
            "page": page,
            "pages": max(1, -(-total // ENTRIES_PER_PAGE)),
            "action": chosen,
            "actions": [(member.value, member.label) for member in AuditAction],
            "scope_is_own": identity.role is not Role.ADMIN,
        },
    )
