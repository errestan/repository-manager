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

    Composed here rather than read from ``request.url.path`` because the proxy
    middleware has already split the prefix into ``root_path``; recombining the
    two explicitly gives the same answer under either proxy style.
    """
    return f"{request.scope.get('root_path', '')}{request.scope.get('path', '')}" or "/"


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
    payload: dict[str, Any] = {
        "request": request,
        "theme": read_theme(request),
        "themes": THEMES,
        "csp_nonce": csp_nonce(request),
        "current_path": current_path(request),
        **(context or {}),
    }
    return templates.TemplateResponse(
        request=request, name=name, context=payload, status_code=status_code
    )
