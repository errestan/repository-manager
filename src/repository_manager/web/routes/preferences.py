"""Display preferences.

The theme switch is a plain form POST, not a script.  Every flow in this
application has to work with JavaScript disabled (specification.md 11), and
starting with the smallest one keeps that honest from the first page.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from starlette import status

from repository_manager.auth import is_local_path
from repository_manager.config import Settings
from repository_manager.web.templating import (
    DEFAULT_THEME,
    THEME_COOKIE,
    THEME_COOKIE_MAX_AGE,
    THEMES,
)

router = APIRouter(tags=["preferences"])


def _safe_redirect_target(request: Request, candidate: str | None) -> str:
    """Resolve a post-submit redirect that cannot leave this application.

    Only a path is ever accepted, and it must sit under our own mount prefix,
    so a crafted `next` value cannot bounce a visitor to another origin.
    """
    root_path = request.scope.get("root_path", "")
    fallback = str(request.url_for("repository_list"))
    if not candidate or not is_local_path(candidate):
        return fallback
    if root_path and not (candidate == root_path or candidate.startswith(root_path + "/")):
        return fallback
    return candidate


@router.post("/preferences/theme", include_in_schema=False)
async def set_theme(
    request: Request,
    theme: Annotated[str, Form()] = DEFAULT_THEME,
    next_url: Annotated[str | None, Form(alias="next")] = None,
) -> RedirectResponse:
    chosen = theme if theme in THEMES else DEFAULT_THEME
    settings: Settings = request.app.state.settings

    response = RedirectResponse(
        _safe_redirect_target(request, next_url),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.set_cookie(
        THEME_COOKIE,
        chosen,
        max_age=THEME_COOKIE_MAX_AGE,
        path=settings.cookie_path,
        secure=settings.cookie_secure,
        httponly=False,
        samesite="lax",
    )
    return response
