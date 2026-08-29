"""RFC 9457 problem details for the REST API (specification.md 8.2).

Every API failure is one JSON object with the same five members, so a CI script
can log ``.detail`` without knowing which endpoint refused it, and branch on
``.type`` without parsing prose.

``type`` is a URN rather than a URL.  RFC 9457 does not require the identifier
to resolve, and a URL here would either point at documentation that this
deployment may have switched off (``REPOMAN_API_DOCS_ENABLED=false``) or at
somebody else's hostname.  A URN is stable across every deployment and every
version, which is the only property a client matching on it actually needs.

The human-readable half is written for the person reading a failed pipeline
log, not for a browser: it says what to do next, because by the time anyone
sees it the job has already gone red.
"""

from __future__ import annotations

from typing import Any

from starlette import status
from starlette.requests import Request
from starlette.responses import JSONResponse

PROBLEM_MEDIA_TYPE = "application/problem+json"

# Written as literals because Starlette renamed both of these constants and
# still exports the old spelling with a deprecation warning; which name exists
# depends on the version FastAPI happens to pull in, and a status code is not
# something worth an import guard.
HTTP_413_TOO_LARGE = 413
HTTP_422_UNPROCESSABLE = 422

#: Namespace for ``type``.  Deliberately not a URL; see the module docstring.
TYPE_PREFIX = "urn:repository-manager:problem:"

#: The slug used when a failure has no more specific kind than its status code.
GENERIC_SLUG = "error"

#: Short titles by status.  A title names the *kind* of problem and stays the
#: same for every occurrence; the varying part belongs in ``detail`` (RFC 9457).
TITLES: dict[int, str] = {
    status.HTTP_400_BAD_REQUEST: "Bad request",
    status.HTTP_401_UNAUTHORIZED: "Authentication required",
    status.HTTP_403_FORBIDDEN: "Forbidden",
    status.HTTP_404_NOT_FOUND: "Not found",
    status.HTTP_405_METHOD_NOT_ALLOWED: "Method not allowed",
    status.HTTP_409_CONFLICT: "Conflict",
    HTTP_413_TOO_LARGE: "Upload too large",
    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: "Unsupported media type",
    HTTP_422_UNPROCESSABLE: "Request could not be processed",
    status.HTTP_429_TOO_MANY_REQUESTS: "Too many requests",
    status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal error",
    status.HTTP_503_SERVICE_UNAVAILABLE: "Service unavailable",
}

#: Slugs for the failures a client is likely to want to branch on, rather than
#: merely report.  Anything not listed here gets :data:`GENERIC_SLUG`.
SLUGS: dict[int, str] = {
    status.HTTP_401_UNAUTHORIZED: "unauthenticated",
    status.HTTP_403_FORBIDDEN: "forbidden",
    status.HTTP_404_NOT_FOUND: "not-found",
    status.HTTP_409_CONFLICT: "conflict",
    HTTP_413_TOO_LARGE: "upload-too-large",
    status.HTTP_429_TOO_MANY_REQUESTS: "rate-limited",
    status.HTTP_503_SERVICE_UNAVAILABLE: "unavailable",
}


class ApiError(Exception):
    """An API request failed in a way the caller is told about.

    Carries everything the response needs, so a service-layer refusal can be
    turned into a problem document at one place in the routing layer rather
    than at each ``raise``.
    """

    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        slug: str | None = None,
        title: str | None = None,
        headers: dict[str, str] | None = None,
        **extra: Any,
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.slug = slug or SLUGS.get(status_code, GENERIC_SLUG)
        self.title = title or TITLES.get(status_code, "Error")
        self.headers = headers or {}
        self.extra = extra


def build(
    request: Request,
    status_code: int,
    detail: str,
    *,
    slug: str | None = None,
    title: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """The problem document body.

    ``instance`` is the request's own path, which is what makes one entry in a
    pipeline log identifiable when several endpoints were called.
    """
    document: dict[str, Any] = {
        "type": f"{TYPE_PREFIX}{slug or SLUGS.get(status_code, GENERIC_SLUG)}",
        "title": title or TITLES.get(status_code, "Error"),
        "status": status_code,
        "detail": detail,
        "instance": str(request.url.path),
    }
    document.update({key: value for key, value in extra.items() if value is not None})
    return document


def respond(
    request: Request,
    status_code: int,
    detail: str,
    *,
    slug: str | None = None,
    title: str | None = None,
    headers: dict[str, str] | None = None,
    **extra: Any,
) -> JSONResponse:
    return JSONResponse(
        build(request, status_code, detail, slug=slug, title=title, **extra),
        status_code=status_code,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=headers,
    )


def from_error(request: Request, error: ApiError) -> JSONResponse:
    return respond(
        request,
        error.status_code,
        error.detail,
        slug=error.slug,
        title=error.title,
        headers=error.headers or None,
        **error.extra,
    )


#: A minimal JSON Schema for the document, so the generated OpenAPI describes
#: failures as precisely as it describes successes.  Written out rather than
#: derived from a Pydantic model because the extension members vary by endpoint
#: and RFC 9457 explicitly allows them.
PROBLEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "description": "Stable identifier for the kind of failure."},
        "title": {"type": "string"},
        "status": {"type": "integer"},
        "detail": {"type": "string", "description": "What went wrong, and what to do about it."},
        "instance": {"type": "string", "description": "Path of the request that failed."},
    },
    "required": ["type", "title", "status", "detail"],
}


def openapi_responses(*codes: int) -> dict[int | str, dict[str, Any]]:
    """Document these status codes as problem documents, for the schema (8.2)."""
    return {
        code: {
            "description": TITLES.get(code, "Error"),
            "content": {PROBLEM_MEDIA_TYPE: {"schema": PROBLEM_SCHEMA}},
        }
        for code in codes
    }
