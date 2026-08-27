"""Sign in and sign out (specification.md 7.1, 7.2, 8.1).

A plain form POST, like everything else here: the login page has to work with
JavaScript disabled (11), and it is the one page where that matters most --
somebody locked out of the interface cannot be told to enable a script first.
"""

from __future__ import annotations

from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from starlette.concurrency import run_in_threadpool
from starlette.responses import RedirectResponse, Response

from repository_manager.auth import is_local_path, sessions
from repository_manager.auth.ldap import (
    Authenticator,
    LdapError,
    LdapIdentity,
    NoRoleAssignedError,
)
from repository_manager.config import Settings
from repository_manager.logging import get_logger
from repository_manager.models import ActorType, AuditAction, AuditOutcome
from repository_manager.services import audit
from repository_manager.web.deps import (
    Identity,
    db_session,
    get_authenticator,
    get_settings,
    get_templates,
    identity_of,
)
from repository_manager.web.forms import FormState
from repository_manager.web.middleware import client_ip
from repository_manager.web.templating import render

log = get_logger(__name__)

router = APIRouter(tags=["auth"])


def safe_next(request: Request, candidate: str | None) -> str | None:
    """A post-login destination that cannot leave this application.

    An open redirect on a login page is worth more to an attacker than on any
    other page, because the victim has just been asked to type a password and
    is primed to type it again on whatever they land on.  Only a path under our
    own mount prefix is ever accepted; anything else is discarded rather than
    corrected, so a crafted value simply lands on the repository list.
    """
    if not candidate:
        return None
    # An absolute URL is accepted only if it is genuinely ours, and is then
    # reduced to its path so the redirect stays relative to this deployment.
    parts = urlsplit(candidate)
    if parts.scheme or parts.netloc:
        settings = get_settings(request)
        if f"{parts.scheme}://{parts.netloc}" != settings.public_origin:
            return None
        candidate = parts.path or "/"
    if not is_local_path(candidate):
        return None
    root_path = request.scope.get("root_path", "")
    if root_path and not (candidate == root_path or candidate.startswith(root_path + "/")):
        return None
    return candidate


def _login_page(
    request: Request, form: FormState, status_code: int = 200, message: str | None = None
) -> Response:
    return render(
        get_templates(request),
        request,
        "auth/login.html.j2",
        {"form": form, "message": message},
        status_code=status_code,
    )


@router.get("/login", include_in_schema=False, name="login_form")
async def login_form(
    request: Request, next_url: Annotated[str, Query(alias="next")] = ""
) -> Response:
    identity = identity_of(request)
    if identity.authenticated:
        # Already signed in: sending them back to the form invites them to type
        # a password they do not need to type.
        return RedirectResponse(
            safe_next(request, next_url) or str(request.url_for("repository_list")),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return _login_page(request, FormState(values={"next": safe_next(request, next_url) or ""}))


def _set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        sessions.SESSION_COOKIE,
        token,
        max_age=settings.session_absolute_lifetime_minutes * 60,
        path=settings.cookie_path,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )


@router.post("/login", include_in_schema=False, name="login")
async def login(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
    authenticator: Annotated[Authenticator, Depends(get_authenticator)],
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    next_url: Annotated[str, Form(alias="next")] = "",
) -> Response:
    settings = get_settings(request)
    destination = safe_next(request, next_url)
    # The password is never put back into the form; the username is, because
    # retyping it after a slip is pure friction.
    form = FormState(values={"username": username, "next": destination or ""})
    source = client_ip(request.scope)

    try:
        # ldap3 is synchronous, and a directory that has gone away will sit on
        # the connection until its timeout; doing that on the event loop would
        # stall every other request in the process.
        identity: LdapIdentity = await run_in_threadpool(
            authenticator.authenticate, username, password
        )
    except LdapError as exc:
        # Both failure kinds are recorded, and both are shown the same message
        # (7.1); the log is where the difference lives.
        log.info(
            "login failed",
            username=username.strip()[:255],
            reason=type(exc).__name__,
            client_ip=source,
        )
        await audit.record(
            session,
            action=AuditAction.LOGIN,
            actor=audit.ANONYMOUS_ACTOR,
            actor_type=ActorType.USER,
            outcome=(
                AuditOutcome.DENIED
                if isinstance(exc, NoRoleAssignedError)
                else AuditOutcome.FAILURE
            ),
            source_ip=source,
            details={"username": username.strip()[:255], "reason": type(exc).__name__},
        )
        form.add("username", exc.user_message)
        return _login_page(request, form, status_code=status.HTTP_401_UNAUTHORIZED)

    # Session fixation: whatever session this browser arrived with is destroyed
    # before a new one is issued, so a token planted before login is worthless
    # after it (7.2).
    existing = await sessions.load(session, settings, request.cookies.get(sessions.SESSION_COOKIE))
    if existing is not None:
        await sessions.destroy(session, existing)

    _, token = await sessions.issue(
        session,
        settings,
        user_dn=identity.dn,
        username=identity.username,
        display_name=identity.display_name,
        role=identity.role,
    )
    await audit.record(
        session,
        action=AuditAction.LOGIN,
        actor=identity.dn,
        actor_type=ActorType.USER,
        source_ip=source,
        details={"username": identity.username, "role": identity.role.value},
    )
    log.info("login", user_dn=identity.dn, role=identity.role.value, client_ip=source)

    response = RedirectResponse(
        destination or str(request.url_for("repository_list")),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _set_session_cookie(response, settings, token)
    return response


@router.post("/logout", include_in_schema=False, name="logout")
async def logout(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
) -> Response:
    settings = get_settings(request)
    identity: Identity = identity_of(request)
    record = await sessions.load(session, settings, request.cookies.get(sessions.SESSION_COOKIE))
    if record is not None:
        await audit.record(
            session,
            action=AuditAction.LOGOUT,
            actor=identity.user_dn,
            actor_type=ActorType.USER,
            source_ip=client_ip(request.scope),
            details={"username": identity.username},
        )
        await sessions.destroy(session, record)
        # The identity is stale from here on: anything rendered after this point
        # -- an error page, most likely -- must not claim the user is still in.
        request.state.identity = Identity()

    response = RedirectResponse(
        request.url_for("repository_list").include_query_params(signed_out=1),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.delete_cookie(sessions.SESSION_COOKIE, path=settings.cookie_path)
    return response
