"""Request identity, CSRF enforcement and the role gate (specification.md 3, 7).

:func:`security_gate` is registered as an application-wide dependency, so it
runs before every handler in the application whether or not that handler asked
for it.  That is the point: a permission layer that has to be remembered on each
new route is a permission layer that will eventually be forgotten on one.  The
gate itself only *establishes* identity and rejects forged requests; deciding
what a given role may do is :func:`require_role`'s job, and a route with no
``require_role`` is anonymous by design (AD-16).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator, Callable, Coroutine
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.concurrency import run_in_threadpool
from starlette.templating import Jinja2Templates

from repository_manager.auth import csrf, sessions
from repository_manager.auth.ldap import Authenticator, LdapError, NoRoleAssignedError
from repository_manager.config import Settings
from repository_manager.jobs.queue import JobQueue
from repository_manager.logging import get_logger
from repository_manager.models import Role, UserSession
from repository_manager.models.base import utcnow
from repository_manager.web.middleware import client_ip

log = get_logger(__name__)

#: How stale ``last_seen_at`` may get before a request writes it back.  Without
#: this every page view -- including an anonymous one that follows a login --
#: would be a write transaction, and on SQLite writes serialise against the job
#: workers.  The idle timeout is measured in hours, so a minute of imprecision
#: costs nothing.
TOUCH_INTERVAL = dt.timedelta(seconds=60)

FORBIDDEN_DETAIL = "You do not have permission to do that."

# Form-parsing limits, defined here rather than at the upload route because the
# CSRF check below may have to read the body first -- and whichever read happens
# first fixes the limits for the whole request, since Starlette caches the parsed
# form.  Two files and a dozen fields is more than any form this application
# serves; a request with more is not one of ours.
MAX_FORM_FILES = 2
MAX_FORM_FIELDS = 12


@dataclass(frozen=True)
class Identity:
    """Who is making this request.

    Plain values, deliberately: this is a *snapshot* of the session row, not the
    row itself.  Holding the ORM instance would make every template that shows a
    user's name depend on the database session still being open, and it is not:
    a handler that raises has already had its transaction rolled back by the
    time the error page renders.  Copying five strings avoids a whole class of
    detached-instance and lazy-load failures on exactly the paths -- errors and
    permission refusals -- where they would be least welcome.

    An anonymous request gets an ``Identity`` with nothing filled in rather than
    ``None``, so templates and handlers can ask the same questions of every
    request instead of guarding each one.
    """

    session_id: int | None = None
    user_dn: str = ""
    username: str = ""
    display_name: str = ""
    role: Role | None = None
    csrf_token: str = ""

    @classmethod
    def of(cls, record: UserSession | None) -> Identity:
        if record is None:
            return ANONYMOUS
        return cls(
            session_id=record.id,
            user_dn=record.user_dn,
            username=record.username,
            display_name=record.display_name,
            role=record.role,
            csrf_token=record.csrf_secret,
        )

    @property
    def authenticated(self) -> bool:
        return self.role is not None

    def permits(self, required: Role) -> bool:
        return self.role is not None and self.role.permits(required)

    @property
    def can_maintain(self) -> bool:
        """Upload, remove, regenerate -- the maintainer capabilities (3)."""
        return self.permits(Role.MAINTAINER)

    @property
    def can_admin(self) -> bool:
        """Repository, distribution and key administration (3)."""
        return self.permits(Role.ADMIN)


ANONYMOUS = Identity()


class LoginRequired(Exception):  # noqa: N818 - not an error condition; a redirect
    """A page needed a signed-in user, so send them to sign in.

    Not an ``HTTPException`` because the response is a redirect that has to
    carry the page they were heading for, and because the distinction between
    "log in" and "you may not" should be a different response, not a different
    message on the same one.
    """

    def __init__(self, next_url: str) -> None:
        super().__init__("authentication required")
        self.next_url = next_url


# --------------------------------------------------------------------- plumbing


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_queue(request: Request) -> JobQueue:
    queue: JobQueue = request.app.state.queue
    return queue


def get_templates(request: Request) -> Jinja2Templates:
    templates: Jinja2Templates = request.app.state.templates
    return templates


def get_authenticator(request: Request) -> Authenticator:
    authenticator: Authenticator = request.app.state.authenticator
    return authenticator


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


# --------------------------------------------------------------------- the gate


async def _revalidate(
    request: Request, session: AsyncSession, record: UserSession, now: dt.datetime
) -> UserSession | None:
    """Re-check group membership, ending the session if access was revoked (7.2).

    A directory that is merely unreachable must not sign everybody out -- an
    outage would otherwise lock the whole team out of a system whose data is on
    local disk -- so only a definite "no mapped group" answer ends the session.
    The deadline is left alone on an error, so the next request tries again.
    """
    settings = get_settings(request)
    authenticator = get_authenticator(request)
    try:
        role = await run_in_threadpool(authenticator.resolve_role, record.user_dn)
    except NoRoleAssignedError:
        log.info("session ended: access revoked", user_dn=record.user_dn)
        await sessions.destroy_for_user(session, record.user_dn)
        return None
    except LdapError as exc:
        log.warning("session revalidation deferred", user_dn=record.user_dn, error=str(exc))
        return record

    if role is not record.role:
        log.info(
            "session role changed",
            user_dn=record.user_dn,
            was=record.role.value,
            now=role.value,
        )
    sessions.mark_revalidated(record, settings, role, now=now)
    return record


async def security_gate(
    request: Request, session: Annotated[AsyncSession, Depends(db_session)]
) -> None:
    """Establish identity and reject forged state-changing requests (7.2, 7.3).

    Runs for every route in the application.  For an anonymous ``GET`` -- which
    is most traffic, since reads are unconditional (AD-16) -- it does no
    database work at all: the session lookup is skipped when there is no cookie
    to look up.
    """
    settings = get_settings(request)
    now = utcnow()
    token = request.cookies.get(sessions.SESSION_COOKIE)
    record = await sessions.load(session, settings, token, now=now)

    if record is not None and record.needs_revalidation(now=now):
        record = await _revalidate(request, session, record, now)

    if request.method not in csrf.SAFE_METHODS:
        _enforce_csrf(request, settings, record, presented_cookie=bool(token))
        # Awaited here rather than in the branch above so a rejected request
        # never gets as far as parsing its own form body.
        await _verify_token(request, record)

    if record is not None and now - record.last_seen_at >= TOUCH_INTERVAL:
        sessions.touch(record, now=now)

    request.state.identity = Identity.of(record)


def _enforce_csrf(
    request: Request, settings: Settings, record: UserSession | None, *, presented_cookie: bool
) -> None:
    allowed = csrf.origin_is_allowed(
        origin=request.headers.get("origin"),
        referer=request.headers.get("referer"),
        expected=settings.public_origin,
        ambient_credentials=presented_cookie,
    )
    if allowed:
        return
    log.warning(
        "cross-origin state change refused",
        path=request.url.path,
        origin=request.headers.get("origin"),
        client_ip=client_ip(request.scope),
        authenticated=record is not None,
    )
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=csrf.REJECTION_DETAIL)


async def _verify_token(request: Request, record: UserSession | None) -> None:
    """Check the per-session token, for sessions only.

    An anonymous state change -- the theme switch is the only one -- has no
    ambient credential behind it, so there is nothing an attacker gains by
    forging it that they could not do by asking the visitor to click a link.
    The Origin check above still applies to it.
    """
    if record is None:
        return
    presented = request.headers.get(csrf.CSRF_HEADER)
    if presented is None:
        # Reading the body here is unavoidable: with JavaScript disabled the
        # token arrives as a form field, and there is nowhere else to find it.
        # The limits have to match what the handler would have asked for,
        # because Starlette caches the parsed form and the handler's own call
        # will return this one -- limits and all.
        form = await request.form(
            max_files=MAX_FORM_FILES,
            max_fields=MAX_FORM_FIELDS,
            max_part_size=get_settings(request).max_upload_bytes,
        )
        raw = form.get(csrf.CSRF_FIELD)
        presented = raw if isinstance(raw, str) else None
    if csrf.verify(record.csrf_secret, presented):
        return
    log.warning(
        "csrf token rejected",
        path=request.url.path,
        user_dn=record.user_dn,
        present=presented is not None,
    )
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=csrf.REJECTION_DETAIL)


def identity_of(request: Request) -> Identity:
    """The identity :func:`security_gate` established for this request."""
    found: Identity = getattr(request.state, "identity", ANONYMOUS)
    return found


# --------------------------------------------------------------------- the rules


def require_role(required: Role) -> Callable[[Request], Coroutine[Any, Any, Identity]]:
    """A dependency admitting only ``required`` or better (3).

    ``admin`` is a superset of ``maintainer``, so the comparison in
    :meth:`Role.permits` is the whole rule -- there is no per-capability table
    to fall out of step with the one in the specification.
    """

    async def gate(request: Request) -> Identity:
        identity = identity_of(request)
        if identity.permits(required):
            return identity
        if not identity.authenticated:
            if request.method in csrf.SAFE_METHODS:
                raise LoginRequired(str(request.url))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Sign in to make changes.",
            )
        log.info(
            "permission refused",
            user_dn=identity.user_dn,
            role=identity.role.value if identity.role else None,
            required=required.value,
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"{FORBIDDEN_DETAIL} This needs the {required.label.lower()} role, and your "
                f"account has {identity.role.label.lower() if identity.role else 'none'}."
            ),
        )

    return gate


#: Pre-built so routes read as a statement of the rule rather than a call.
require_maintainer = require_role(Role.MAINTAINER)
require_admin = require_role(Role.ADMIN)


async def require_authenticated(request: Request) -> Identity:
    """Any signed-in user, of any role -- the job pages (8.1)."""
    identity = identity_of(request)
    if identity.authenticated:
        return identity
    if request.method in csrf.SAFE_METHODS:
        raise LoginRequired(str(request.url))
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sign in to continue.")
