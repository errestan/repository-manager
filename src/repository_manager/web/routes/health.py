"""Liveness and readiness probes (specification.md 13.3)."""

from __future__ import annotations

import shutil
from typing import Any

from fastapi import APIRouter, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.__about__ import __version__
from repository_manager.db import check_connection
from repository_manager.logging import get_logger
from repository_manager.metadata.repodata import CREATEREPO_BINARY
from repository_manager.models import Repository, RepositoryType

log = get_logger(__name__)
router = APIRouter(tags=["health"])


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    """Liveness: the process is running and can serve a request.

    Deliberately checks nothing external -- a liveness probe that fails when the
    database blips gets the container killed just when it is least helpful.
    """
    return {"status": "ok", "version": __version__}


@router.get("/readyz", include_in_schema=False)
async def readyz(request: Request, response: Response) -> dict[str, Any]:
    """Readiness: the dependencies needed to serve real traffic are usable.

    The database and the allowed roots have been checked since M1.  GnuPG and
    ``createrepo_c`` join them here, because by M4 both are load-bearing: an
    instance that cannot sign, or cannot index an RPM variant, can still serve
    every read but will fail the first write it is given.
    """
    checks: dict[str, str] = {}
    healthy = True

    try:
        await check_connection(request.app.state.engine)
        checks["database"] = "ok"
    except Exception as exc:
        healthy = False
        checks["database"] = f"error: {type(exc).__name__}"
        log.warning("readiness check failed", check="database", error=str(exc))

    settings = request.app.state.settings
    missing = [str(root) for root in settings.allowed_roots if not root.is_dir()]
    if missing:
        healthy = False
        checks["allowed_roots"] = f"missing: {', '.join(missing)}"
    else:
        checks["allowed_roots"] = "ok"

    # Metadata cannot be signed without it, whatever the format (10.5).
    if shutil.which("gpg") is None:
        healthy = False
        checks["gnupg"] = "missing: gpg is not on PATH"
    else:
        checks["gnupg"] = "ok"

    # Only asked about when it would actually be used.  An APT-only deployment
    # has no reason to install createrepo_c, and reporting it as degraded would
    # train whoever reads this endpoint to ignore it (13.3).
    checks["createrepo_c"] = await _createrepo_state(request)
    if checks["createrepo_c"].startswith("missing"):
        healthy = False

    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if healthy else "degraded", "checks": checks}


async def _createrepo_state(request: Request) -> str:
    sessionmaker: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    try:
        async with sessionmaker() as session:
            rpm_repositories = await session.scalar(
                select(Repository.id)
                .where(
                    Repository.type == RepositoryType.RPM,
                    Repository.deregistered_at.is_(None),
                )
                .limit(1)
            )
    except Exception as exc:
        # The database check above already reported this; saying so twice would
        # make one outage look like two.
        log.warning("readiness check skipped", check="createrepo_c", error=str(exc))
        return "unknown: the database could not be queried"

    if rpm_repositories is None:
        return "not required: no RPM repositories"
    if shutil.which(CREATEREPO_BINARY) is None:
        return f"missing: {CREATEREPO_BINARY} is not on PATH"
    return "ok"
