"""Jinja2 environment and the helpers templates rely on.

Every URL in a template goes through ``url_for`` so the mount prefix is applied
automatically (specification.md 13.5, AD-14).  A pre-commit hook rejects
root-relative literals in templates; this module is the sanctioned alternative.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, get_args

from jinja2 import StrictUndefined
from starlette.requests import Request
from starlette.responses import Response
from starlette.templating import Jinja2Templates

from repository_manager.__about__ import __version__
from repository_manager.web.deps import identity_of

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

Theme = Literal["light", "dark", "system"]
THEMES: tuple[str, ...] = get_args(Theme)
DEFAULT_THEME: Theme = "system"
THEME_COOKIE = "repoman_theme"

# One year: a display preference is not security-sensitive and re-asking is a
# worse experience than remembering.
THEME_COOKIE_MAX_AGE = 60 * 60 * 24 * 365


def read_theme(request: Request) -> Theme:
    """The theme this visitor chose, or 'system' when they have not chosen.

    Read server-side so the correct theme is in the very first byte of HTML;
    a client-side toggle would flash the wrong colours before it ran.
    """
    value = request.cookies.get(THEME_COOKIE)
    if value in THEMES:
        return value  # type: ignore[return-value]
    return DEFAULT_THEME


def csp_nonce(request: Request) -> str:
    return str(request.scope.get("csp_nonce", ""))


def current_path(request: Request) -> str:
    """The externally visible path of this request, prefix included.

    ``scope["path"]`` already carries the prefix under either proxy style --
    the one that passes it through in the path, and the one that strips it and
    is put back by :class:`~repository_manager.web.middleware.ProxyHeadersMiddleware`.
    Templates compare this against ``url_for(...).path`` to mark the current
    page, and that value carries the prefix exactly once.
    """
    return str(request.scope.get("path", "")) or "/"


def build_templates() -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    env = templates.env
    env.trim_blocks = True
    env.lstrip_blocks = True
    # Autoescaping is forced on rather than left to Jinja's default.  That
    # default is `select_autoescape`, which decides from the file extension and
    # only recognises .html/.htm/.xml -- every template here ends in .html.j2,
    # so it matched none of them and escaping was silently off.  Every template
    # in this project renders HTML, so the blanket setting is also the correct
    # one; a future non-HTML template must opt out explicitly with
    # `{% autoescape false %}` (10.2).
    env.autoescape = True
    # A typo in a template name should fail loudly in CI, not render a blank
    # region that nobody notices until a user reports a missing link.
    env.undefined = StrictUndefined
    return templates


def render(
    templates: Jinja2Templates,
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
) -> Response:
    """Render a template with the values every page needs already present."""
    # Identity and the CSRF token are added here rather than passed by each
    # route: a template that renders a form needs both, and a route that forgot
    # one would produce a page whose forms are silently rejected (7.3).
    identity = identity_of(request)
    payload: dict[str, Any] = {
        "request": request,
        "theme": read_theme(request),
        "themes": THEMES,
        "csp_nonce": csp_nonce(request),
        "current_path": current_path(request),
        "identity": identity,
        "csrf_token": identity.csrf_token,
        # Whether the API reference route exists at all (8.2, 12).  A template
        # that linked to it unconditionally would raise NoMatchFound on an
        # instance with the documentation switched off, which is a broken page
        # rather than a missing link.
        "api_docs": bool(request.app.state.settings.api_docs_enabled),
        # In the footer as well as at /healthz (14.4): a bug report that names
        # a version is worth several that do not.
        "version": __version__,
        **(context or {}),
    }
    return templates.TemplateResponse(
        request=request, name=name, context=payload, status_code=status_code
    )
