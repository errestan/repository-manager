"""Application factory (specification.md 13.5).

`create_app` takes settings explicitly so tests can build an application without
touching the process environment.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from starlette import status
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates

from repository_manager.__about__ import __version__
from repository_manager.auth.ldap import LdapAuthenticator
from repository_manager.auth.roles import RoleCache
from repository_manager.config import Settings
from repository_manager.db import create_engine, create_sessionmaker
from repository_manager.jobs.queue import JobQueue
from repository_manager.logging import configure_logging, get_logger
from repository_manager.services import publishing
from repository_manager.web import problems
from repository_manager.web.deps import LoginRequired, is_api_request, security_gate
from repository_manager.web.middleware import (
    ProxyHeadersMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from repository_manager.web.routes import (
    api,
    audit,
    auth,
    health,
    jobs,
    keys,
    preferences,
    reference,
    repositories,
    tokens,
)
from repository_manager.web.templating import build_templates, render

log = get_logger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

#: Where the machine-readable schema is served (8.2).  Under the versioned API
#: prefix rather than at the root, so a future ``/api/v2`` describes itself.
OPENAPI_URL = f"{api.API_PREFIX}/openapi.json"

API_DESCRIPTION = """\
Manage the contents of APT and RPM package repositories.

Read endpoints are anonymous. Write endpoints need an API token, sent as
`Authorization: Bearer`; a token can never do more than the account that minted
it may do at the time it is used.

Failures are RFC 9457 problem documents (`application/problem+json`).
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    engine = create_engine(settings)
    app.state.engine = engine
    sessionmaker = create_sessionmaker(engine)
    app.state.sessionmaker = sessionmaker

    # The worker pool lives for exactly as long as the application (6).  Starting
    # it here also runs restart recovery, which is what re-queues a regeneration
    # that was interrupted by the previous shutdown.
    queue = JobQueue(sessionmaker, settings)
    publishing.register_handlers(queue)
    app.state.queue = queue
    await queue.start()

    log.info(
        "application started",
        version=__version__,
        root_path=settings.effective_root_path or "/",
        env=settings.env,
        ldap_url=settings.ldap_url,
        ldap_encrypted=settings.ldap_uses_tls,
    )
    try:
        yield
    finally:
        await queue.stop()
        await engine.dispose()
        log.info("application stopped")


def create_app(settings: Settings, *, configure_logs: bool = True) -> FastAPI:
    if configure_logs:
        configure_logging(settings.log_format)

    templates = build_templates()

    app = FastAPI(
        title="Repository Manager",
        version=__version__,
        # Passing the prefix to FastAPI keeps generated OpenAPI server URLs and
        # docs links correct under a sub-path deployment (13.5).
        root_path=settings.effective_root_path,
        lifespan=lifespan,
        description=API_DESCRIPTION,
        # FastAPI's own Swagger UI and ReDoc pages load their assets from a
        # public CDN, which the Content-Security-Policy forbids (10.1); they
        # would render blank.  The reference page at /api/docs renders the same
        # schema from this origin instead -- see routes/reference.py.
        docs_url=None,
        redoc_url=None,
        openapi_url=OPENAPI_URL if settings.api_docs_enabled else None,
        # Application-wide, so identity resolution and the CSRF check cannot be
        # left off a new route by omission (7.3).
        dependencies=[Depends(security_gate)],
    )
    app.state.settings = settings
    app.state.templates = templates
    # Token owners' directory roles, remembered for the session revalidation
    # interval (7.4).  Held on the application rather than built per request,
    # which is the whole point of it.
    app.state.role_cache = RoleCache(settings.session_revalidate_after)
    # Replaceable on the app for tests and for a future alternative directory
    # backend; nothing outside this line constructs one.
    app.state.authenticator = LdapAuthenticator(settings)

    # Applied bottom-up: proxy resolution must run before anything reads the
    # scheme, the client IP, or the mount prefix.
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(ProxyHeadersMiddleware, settings=settings)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(preferences.router)
    app.include_router(keys.router)
    app.include_router(jobs.router)
    app.include_router(audit.router)
    app.include_router(tokens.router)
    app.include_router(repositories.router)
    app.include_router(api.router)
    if settings.api_docs_enabled:
        app.include_router(reference.router)

    app.openapi = _openapi_of(app)  # type: ignore[method-assign]
    _register_error_handlers(app, templates)
    return app


def _openapi_of(app: FastAPI) -> Callable[[], dict[str, Any]]:
    """Generate the schema once, with the bearer scheme the operations name.

    FastAPI derives ``securitySchemes`` from its own security dependencies, and
    this application's token gate is not one: it runs application-wide so that
    no route can be written without it (7.4).  The operations that need a token
    declare ``security`` themselves, and this supplies the definition they refer
    to -- without it the schema would name a scheme it never defines, which some
    generators reject and every reader has to guess at.
    """

    def openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        schema.setdefault("components", {})["securitySchemes"] = {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": (
                    "An API token from the tokens page, in the form rmt_<random>. "
                    "Accepted on /api/v1 only."
                ),
            }
        }
        app.openapi_schema = schema
        return schema

    return openapi


def _register_error_handlers(app: FastAPI, templates: Jinja2Templates) -> None:
    """Render errors as HTML pages, so a 404 is still navigable and accessible."""

    @app.exception_handler(problems.ApiError)
    async def api_error(request: Request, exc: problems.ApiError) -> Response:
        """Every deliberate API refusal, as a problem document (8.2)."""
        return problems.from_error(request, exc)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        # An API request gets JSON even when the failure came from the framework
        # rather than from a handler -- a 404 for an unrouted path, a 405 for the
        # wrong method.  A client that asked for JSON and got an HTML error page
        # would have to parse prose to find out what happened.
        if is_api_request(request):
            return problems.respond(request, exc.status_code, str(exc.detail))
        return render(
            templates,
            request,
            "error.html.j2",
            {"status_code": exc.status_code, "detail": exc.detail},
            status_code=exc.status_code,
        )

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired) -> Response:
        """Send an anonymous visitor to sign in, remembering where they were.

        A redirect rather than a 401 page: the destination is carried in the
        query string so the round trip ends where it started, which is the whole
        reason a page-level check is worth having over a blanket one.
        """
        target = request.url_for("login_form").include_query_params(next=exc.next_url)
        return RedirectResponse(str(target), status_code=status.HTTP_303_SEE_OTHER)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Response:
        log.info("request rejected", errors=len(exc.errors()))
        if is_api_request(request):
            return problems.respond(
                request,
                422,
                "The request did not match what this endpoint accepts.",
                errors=[
                    {"location": list(error["loc"]), "message": error["msg"]}
                    for error in exc.errors()
                ],
            )
        return render(
            templates,
            request,
            "error.html.j2",
            {"status_code": 422, "detail": "The submitted form was not valid."},
            status_code=422,
        )


def app_from_environment() -> FastAPI:
    """Entry point for `uvicorn repository_manager.web.app:app_from_environment`."""
    from repository_manager.config import load_settings

    return create_app(load_settings())
