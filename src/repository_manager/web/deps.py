"""Shared route dependencies.

Kept separate from the routes so the write gate (below) is defined in exactly
one place and cannot be forgotten on a new endpoint.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.templating import Jinja2Templates

from repository_manager.config import Settings
from repository_manager.jobs.queue import JobQueue

# Explains the M2 interim state to whoever hits a write endpoint (12).
WRITE_DISABLED_DETAIL = (
    "Repository changes are disabled on this instance. Uploads, repository creation and "
    "key management are guarded by LDAP login, which arrives in M3; until then they are "
    "only available when an operator sets REPOMAN_ALLOW_UNAUTHENTICATED_WRITES=true on a "
    "non-production deployment."
)


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_queue(request: Request) -> JobQueue:
    queue: JobQueue = request.app.state.queue
    return queue


def get_templates(request: Request) -> Jinja2Templates:
    templates: Jinja2Templates = request.app.state.templates
    return templates


def get_sessionmaker(request: Request) -> async_sessionmaker[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    return factory


async def db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """One transaction per request, committed only if the handler returns.

    A handler that raises -- including a deliberate ``HTTPException`` for a
    rejected upload -- leaves the database untouched.
    """
    async with get_sessionmaker(request)() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def writes_enabled(request: Request) -> bool:
    return bool(get_settings(request).allow_unauthenticated_writes)


async def require_write_access(request: Request) -> None:
    """Refuse state-changing requests until authentication exists (M3).

    This is a stand-in for the role check that replaces it, not a security
    model in its own right: it is a single global switch, off by default, that
    configuration refuses to turn on in production.
    """
    if writes_enabled(request):
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=WRITE_DISABLED_DETAIL)
