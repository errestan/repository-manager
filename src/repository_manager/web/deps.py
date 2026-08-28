"""Request identity, CSRF enforcement and the role gate (specification.md 3, 7).

:func:`security_gate` is registered as an application-wide dependency, so it
runs before every handler in the application whether or not that handler asked
for it.  That is the point: a permission layer that has to be remembered on each
new route is a permission layer that will eventually be forgotten on one.  The
gate itself only *establishes* identity and rejects forged requests; deciding
what a given role may do is :func:`require_role`'s job, and a route with no
``require_role`` is anonymous by design (AD-16).

The REST API is the one place the gate takes a different path.  Requests under
``/api`` are authenticated by bearer token and by nothing else: the session
cookie is not read there, which is what makes CSRF irrelevant rather than
merely unlikely -- there is no ambient credential for a forged cross-origin
request to spend.  The reverse also holds: a bearer token is ignored everywhere
outside ``/api`` (7.4), so a leaked token cannot be replayed against the HTML
forms.
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
from repository_manager.auth.roles import RoleCache
from repository_manager.config import Settings
from repository_manager.jobs.queue import JobQueue
from repository_manager.logging import get_logger
from repository_manager.models import ApiToken, Role, TokenScope, UserSession
from repository_manager.models.base import utcnow
from repository_manager.services import tokens as token_service
from repository_manager.web.middleware import client_ip, route_path
from repository_manager.web.problems import ApiError

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
# form.  Two files is more than any form this application serves.
#
# The field bound is looser than it looks: the token form (7.4) renders one
# checkbox per repository, so a fixed dozen would have turned "an instance with
# thirteen repositories" into a form nobody can submit.  Parsing a couple of
# hundred short fields costs nothing, and the limit that actually bounds an
# abusive body is `max_part_size`, which is the configured upload cap.
MAX_FORM_FILES = 2
MAX_FORM_FIELDS = 256

#: Everything below this prefix is the REST API (8.2): token-authenticated,
#: JSON in and problem+json out, and never session-authenticated.  It is the
#: *versioned* prefix rather than ``/api``, which is what 7.4's "accepted on
#: ``/api/**`` only" allows and what keeps the human-readable reference page at
#: ``/api/docs`` an ordinary session-authenticated page -- it has a site header
#: to render, and rendering it signed out to a signed-in reader would be a
#: puzzle rather than a security property.  Kept in step with
#: :data:`repository_manager.web.routes.api.API_PREFIX`, which cannot be
#: imported here without a cycle.
API_ROOT = "/api/v1"

BEARER_SCHEME = "bearer"

#: Sent with a 401 so a client is told how to authenticate rather than left to
#: infer it.  ``realm`` names the API, not the deployment.
WWW_AUTHENTICATE = 'Bearer realm="repository-manager"'

CREDENTIAL_REJECTED = (
    "That API token is not valid. It may have been revoked, or it may have expired; "
    "mint a replacement on the tokens page."
)


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


@dataclass(frozen=True)
class TokenIdentity:
    """The token behind an API request, snapshotted (7.4).

    A snapshot for the same reason :class:`Identity` is one, and for one more:
    the intersection with the owner's directory role is computed per request
    from a live lookup, so nothing here is a permission by itself.  These are
    the *ceiling* -- ``scopes`` is what was granted at mint time and
    ``repositories`` is where it may be spent -- and :func:`require_scope` is
    where the two halves meet.
    """

    token_id: int
    owner_dn: str
    owner_username: str
    label: str
    prefix: str
    scopes: frozenset[TokenScope]
    repositories: tuple[str, ...] = ()

    @classmethod
    def of(cls, record: ApiToken) -> TokenIdentity:
        return cls(
            token_id=record.id,
            owner_dn=record.owner_dn,
            owner_username=record.owner_username,
            label=record.label,
            prefix=record.prefix,
            scopes=record.granted,
            repositories=record.repositories,
        )

    def covers(self, slug: str) -> bool:
        return not self.repositories or slug in self.repositories

    @property
    def audit_details(self) -> dict[str, Any]:
        """What the audit trail records about the credential itself.

        The prefix, never the token: it is enough to identify which row on the
        tokens page did this, and it is already stored in the clear there.
        """
        return {"token_id": self.token_id, "token_prefix": self.prefix, "token_label": self.label}


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


def get_role_cache(request: Request) -> RoleCache:
    cache: RoleCache = request.app.state.role_cache
    return cache


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


def is_api_request(request: Request) -> bool:
    """Whether this request is for the REST API rather than the web interface.

    Compared against the *routed* path, which is the request path with the
    deployment's mount prefix removed.  Reading ``request.url.path`` instead
    would answer "no" for every request under a sub-path deployment (13.5) --
    and answering "no" here means falling through to the session-authenticated
    branch, so the mistake would not be a 404 but a security boundary in the
    wrong place.
    """
    routed = route_path(request.scope)
    return routed == API_ROOT or routed.startswith(f"{API_ROOT}/")


def _bearer_token(request: Request) -> str | None:
    """The credential from ``Authorization: Bearer``, if there is one (7.4)."""
    header = request.headers.get("authorization")
    if not header:
        return None
    scheme, _, credential = header.partition(" ")
    if scheme.lower() != BEARER_SCHEME:
        return None
    return credential.strip() or None


async def _api_gate(request: Request, session: AsyncSession) -> None:
    """Authenticate an API request by bearer token, and by nothing else (7.4, 8.2).

    Three things do *not* happen here, each on purpose.

    The session cookie is not read, so a browser that happens to be signed in
    gets exactly what an anonymous client gets.  CSRF is therefore not checked:
    the attack it defends against is a forged request spending a credential the
    browser attaches automatically, and there is no such credential on this
    path.

    The owner's role is not resolved.  That costs a directory round trip and is
    only needed once something is actually required of the token, so it is left
    to :func:`require_scope` -- which means a read endpoint keeps working while
    the directory is down.

    A token that is presented and does not authenticate is refused outright,
    even on an endpoint that would have served an anonymous caller.  Quietly
    treating a dead token as anonymous would hand a CI job a 200 for a request
    it believed was authenticated, and the first anyone would know of it is a
    write failing much later.
    """
    request.state.identity = ANONYMOUS
    request.state.token = None

    presented = _bearer_token(request)
    if presented is None:
        return

    record = await token_service.authenticate(session, presented)
    if record is None:
        log.info(
            "api token rejected",
            path=request.url.path,
            client_ip=client_ip(request.scope),
        )
        raise ApiError(
            status.HTTP_401_UNAUTHORIZED,
            CREDENTIAL_REJECTED,
            headers={"www-authenticate": WWW_AUTHENTICATE},
        )

    # Recorded in the caller's transaction, so a request that goes on to be
    # refused does not update `last_used_at`.  That is the useful reading: the
    # column answers "is this token still doing anything?", and a refused
    # request is not the token working.  The refusal itself is logged above.
    token_service.touch(record)
    request.state.token = TokenIdentity.of(record)


async def security_gate(
    request: Request, session: Annotated[AsyncSession, Depends(db_session)]
) -> None:
    """Establish identity and reject forged state-changing requests (7.2, 7.3).

    Runs for every route in the application.  For an anonymous ``GET`` -- which
    is most traffic, since reads are unconditional (AD-16) -- it does no
    database work at all: the session lookup is skipped when there is no cookie
    to look up.
    """
    if is_api_request(request):
        await _api_gate(request, session)
        return

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


def token_of(request: Request) -> TokenIdentity | None:
    """The token :func:`_api_gate` accepted, or ``None`` for an anonymous call."""
    found: TokenIdentity | None = getattr(request.state, "token", None)
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


# ------------------------------------------------------------------ token rules


async def _owner_role(request: Request, identity: TokenIdentity) -> Role:
    """The token owner's role in the directory right now (7.4).

    Cached for the session revalidation interval; see
    :mod:`repository_manager.auth.roles` for why that is the right interval and
    what happens when the directory cannot be reached.
    """
    try:
        return await get_role_cache(request).resolve(get_authenticator(request), identity.owner_dn)
    except NoRoleAssignedError as exc:
        log.info("api token owner has lost access", owner_dn=identity.owner_dn)
        raise ApiError(
            status.HTTP_403_FORBIDDEN,
            "The account that owns this token is no longer a member of a group permitted "
            "to make changes, so the token can no longer be used.",
        ) from exc
    except LdapError as exc:
        raise ApiError(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The directory could not be reached, so this token's permissions could not be "
            "confirmed. Retry shortly.",
            headers={"retry-after": "30"},
        ) from exc


def require_scope(scope: TokenScope) -> Callable[[Request], Coroutine[Any, Any, TokenIdentity]]:
    """A dependency admitting only a token that really carries ``scope`` (7.4, 8.2).

    "Really" is three checks, and all three are here rather than spread across
    the handlers so that a new endpoint cannot be written that forgets one: the
    token must exist, the scope must survive intersection with the owner's
    current role, and the repository in the path must be inside the token's
    allow-list.

    The repository check reads the ``slug`` path parameter directly.  That is
    deliberate coupling: the alternative is each handler passing its own slug
    in, which is exactly the kind of per-route obligation this module exists to
    avoid.
    """

    async def gate(request: Request) -> TokenIdentity:
        identity = token_of(request)
        if identity is None:
            raise ApiError(
                status.HTTP_401_UNAUTHORIZED,
                "This endpoint needs an API token. Send it as an Authorization: Bearer header.",
                headers={"www-authenticate": WWW_AUTHENTICATE},
            )

        role = await _owner_role(request, identity)
        effective = token_service.effective_scopes(identity.scopes, role)
        if scope not in effective:
            granted = ", ".join(sorted(identity.scopes)) or "none"
            log.info(
                "api scope refused",
                token_id=identity.token_id,
                owner_dn=identity.owner_dn,
                required=scope.value,
                role=role.value,
                path=request.url.path,
            )
            raise ApiError(
                status.HTTP_403_FORBIDDEN,
                f"This needs the {scope.value} scope. This token carries {granted}, and its "
                f"owner has the {role.label.lower()} role.",
                required_scope=scope.value,
            )

        slug = request.path_params.get("slug")
        if isinstance(slug, str) and not identity.covers(slug):
            log.info(
                "api repository scope refused",
                token_id=identity.token_id,
                owner_dn=identity.owner_dn,
                slug=slug,
            )
            raise ApiError(
                status.HTTP_403_FORBIDDEN,
                f"This token is restricted to {', '.join(identity.repositories)} and may not "
                f"act on {slug}.",
            )
        return identity

    return gate


#: The only write scope there is, pre-built so a route reads as the rule.
require_write = require_scope(TokenScope.PACKAGE_WRITE)
