"""Application factory (specification.md 13.5).

`create_app` takes settings explicitly so tests can build an application without
touching the process environment.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from starlette import status
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates

from repository_manager.__about__ import __version__
from repository_manager.auth.ldap import LdapAuthenticator
from repository_manager.config import Settings
from repository_manager.db import create_engine, create_sessionmaker
from repository_manager.jobs.queue import JobQueue
from repository_manager.logging import configure_logging, get_logger
from repository_manager.services import publishing
from repository_manager.web.deps import LoginRequired, security_gate
from repository_manager.web.middleware import (
    ProxyHeadersMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from repository_manager.web.routes import (
    audit,
    auth,
    health,
    jobs,
    keys,
    preferences,
    repositories,
)
from repository_manager.web.templating import build_templates, render

log = get_logger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


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
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        # Application-wide, so identity resolution and the CSRF check cannot be
        # left off a new route by omission (7.3).
        dependencies=[Depends(security_gate)],
    )
    app.state.settings = settings
    app.state.templates = templates
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
    app.include_router(repositories.router)

    _register_error_handlers(app, templates)
    return app


def _register_error_handlers(app: FastAPI, templates: Jinja2Templates) -> None:
    """Render errors as HTML pages, so a 404 is still navigable and accessible."""

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
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
