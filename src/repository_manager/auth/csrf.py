"""CSRF defences (specification.md 7.3).

Two independent checks, because either one alone has a gap:

* A **per-session token** that must come back in the ``_csrf`` form field or the
  ``X-CSRF-Token`` header.  An attacker's page cannot read it, because reading
  it would require a same-origin response.
* An **Origin/Referer check** against the configured public URL.  This one needs
  no state at all and catches a forged request before any lookup happens.

Requests authenticating with a bearer token are exempt from both: there is no
ambient credential for another site to make the browser attach, so there is
nothing to forge.  That exemption arrives with the API in M5; for now every
state-changing route is a form.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

#: Hidden field in every form, and the header HTMX sends.
CSRF_FIELD = "_csrf"
CSRF_HEADER = "X-CSRF-Token"

#: Methods that cannot change state, so cannot need protecting.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

REJECTION_DETAIL = (
    "That form could not be submitted because its security token was missing or out of "
    "date. This usually means the page was left open long enough for the session to end. "
    "Reload the page and try again."
)


def new_secret() -> str:
    """A fresh per-session CSRF secret.

    32 bytes, matching the session token: this value is rendered into pages
    rather than kept back, but guessing it must still be infeasible.
    """
    return secrets.token_urlsafe(32)


def verify(expected: str, presented: str | None) -> bool:
    """Constant-time comparison (7.3).

    ``compare_digest`` needs both operands to exist and to be the same kind of
    string; the guard here is not an optimisation, it is what stops a missing
    token raising instead of returning False.
    """
    if not expected or not presented:
        return False
    return secrets.compare_digest(expected, presented)


def _origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def origin_is_allowed(
    *, origin: str | None, referer: str | None, expected: str, ambient_credentials: bool
) -> bool:
    """Whether this request's origin matches the deployment's public URL.

    ``Origin`` is preferred and ``Referer`` is the fallback, since a few
    configurations still strip the former.  When neither header is present the
    request did not come from a browser form at all -- and the decision then
    turns on ``ambient_credentials``: a scripted call carrying no session cookie
    has nothing to forge, whereas one that *does* carry a cookie must prove
    where it came from.
    """
    if origin is not None:
        # "null" is what a sandboxed iframe or a privacy extension sends; it is
        # not this deployment's origin, so it is not allowed to act as one.
        return _origin_of(origin) == expected
    if referer is not None:
        return _origin_of(referer) == expected
    return not ambient_credentials
