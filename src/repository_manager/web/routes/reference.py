"""The human-readable API reference (specification.md 8.2, 11).

The specification asks for OpenAPI docs to be served.  FastAPI's built-in
Swagger UI and ReDoc pages cannot be: both fetch their JavaScript and CSS from
a public CDN, and the Content-Security-Policy this application sets allows no
remote origins and no inline script without a nonce (10.1).  A page that loads
nothing would render blank, and the honest options were to vendor a megabyte
and a half of Swagger UI, to weaken the CSP for one page, or to render the
schema here.

Rendering it here is the better trade, and not only on those grounds.  The
audience is someone wiring up a pipeline, who wants to see every endpoint at
once and copy a ``curl`` line out of it -- and Swagger UI's expand-one-at-a-time
interaction is a poor fit for that even before its own accessibility problems
are weighed against a WCAG 2.2 AA commitment (11).

The schema is the source: this route reads ``app.openapi()`` and reshapes it,
so an endpoint cannot be documented here and missing from the machine-readable
version, or the reverse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, Request
from starlette.responses import Response

from repository_manager.web.deps import get_templates
from repository_manager.web.problems import TYPE_PREFIX
from repository_manager.web.templating import render

router = APIRouter(tags=["api"])

#: Rendered in the order a pipeline uses them rather than alphabetically: find
#: the repository, look at what is published, publish, poll.
METHOD_ORDER = ["get", "post", "put", "patch", "delete"]


@dataclass(frozen=True)
class Parameter:
    name: str
    location: str
    required: bool
    description: str
    schema_type: str


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    summary: str
    description: str
    authenticated: bool
    parameters: list[Parameter] = field(default_factory=list)
    body: list[Parameter] = field(default_factory=list)
    statuses: list[tuple[str, str]] = field(default_factory=list)


def _type_of(schema: dict[str, Any]) -> str:
    """A one-word type for the table, flattening the ways JSON Schema says it."""
    if "type" in schema:
        return str(schema["type"])
    for key in ("anyOf", "oneOf", "allOf"):
        for member in schema.get(key, []):
            if isinstance(member, dict) and member.get("type") not in (None, "null"):
                return str(member["type"])
    return "string"


def _parameters(operation: dict[str, Any]) -> list[Parameter]:
    found = []
    for entry in operation.get("parameters", []):
        schema = entry.get("schema", {})
        found.append(
            Parameter(
                name=str(entry.get("name", "")),
                location=str(entry.get("in", "query")),
                required=bool(entry.get("required", False)),
                description=str(entry.get("description", "")),
                schema_type=_type_of(schema),
            )
        )
    return found


def _body(operation: dict[str, Any]) -> list[Parameter]:
    """The multipart fields of an upload, flattened out of the request body."""
    content = operation.get("requestBody", {}).get("content", {})
    schema = content.get("multipart/form-data", {}).get("schema", {})
    required = set(schema.get("required", []))
    return [
        Parameter(
            name=name,
            location="form",
            required=name in required,
            description=str(entry.get("description", "")),
            schema_type=str(entry.get("format") or entry.get("type") or "string"),
        )
        for name, entry in schema.get("properties", {}).items()
    ]


def _statuses(operation: dict[str, Any]) -> list[tuple[str, str]]:
    return sorted(
        (code, str(entry.get("description", "")))
        for code, entry in operation.get("responses", {}).items()
    )


def endpoints_of(schema: dict[str, Any]) -> list[Endpoint]:
    """Reshape an OpenAPI document into what the template renders."""
    found: list[Endpoint] = []
    for path, operations in schema.get("paths", {}).items():
        for method in METHOD_ORDER:
            operation = operations.get(method)
            if not isinstance(operation, dict):
                continue
            found.append(
                Endpoint(
                    method=method.upper(),
                    path=str(path),
                    summary=str(operation.get("summary", "")),
                    description=str(operation.get("description", "")),
                    authenticated=bool(operation.get("security")),
                    parameters=_parameters(operation),
                    body=_body(operation),
                    statuses=_statuses(operation),
                )
            )
    # Grouped by path so the two package operations sit together, and each
    # path's methods stay in METHOD_ORDER.
    found.sort(key=lambda endpoint: (endpoint.path.count("/"), endpoint.path))
    return found


@router.get("/api/docs", include_in_schema=False, name="api_reference")
async def api_reference(request: Request) -> Response:
    """The reference page.

    Anonymous, like the schema it renders: everything here describes endpoints
    that are themselves anonymous or refuse without a token, so publishing the
    shape of the API tells a reader nothing that trying it would not.

    A deployment that would rather not publish it sets
    ``REPOMAN_API_DOCS_ENABLED=false``.  That is handled by not registering this
    router at all rather than by a check here: an unregistered route answers 404
    from the routing table, which is one fewer place for the switch to be read
    and got wrong.
    """
    schema = request.app.openapi()
    # FastAPI registers the schema route unnamed, so there is no `url_for` for
    # it; the mount prefix has to be put back by hand (13.5).
    prefix = str(request.scope.get("root_path", ""))
    return render(
        get_templates(request),
        request,
        "api/reference.html.j2",
        {
            "endpoints": endpoints_of(schema),
            "schema_url": f"{prefix}{request.app.openapi_url}",
            "api_version": schema.get("info", {}).get("version", ""),
            "problem_prefix": TYPE_PREFIX,
        },
    )
