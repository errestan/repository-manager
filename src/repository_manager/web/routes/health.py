"""Liveness and readiness probes (specification.md 13.3)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request, Response, status

from repository_manager.__about__ import __version__
from repository_manager.db import check_connection
from repository_manager.logging import get_logger

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

    M1 checks the database and the allowed roots.  GnuPG and createrepo_c join
    this list when M2 and M4 make them load-bearing.
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

    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if healthy else "degraded", "checks": checks}
