"""The permission matrix, exercised over HTTP (specification.md 3, 8.1).

Every route is listed once, with the role it requires.  Two things then follow
from that single list: each route is driven as an anonymous visitor, a
maintainer and an admin and checked against the matrix, and the list itself is
checked against the application's own routing table -- so a new endpoint that
nobody classified fails here rather than shipping unguarded.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette.routing import Mount

from repository_manager.auth import csrf
from repository_manager.models import Repository, Role
from tests.conftest import PUBLIC_URL, browser, sign_in
from tests.support import directory as fake_directory


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    #: ``None`` means anonymous: readable by anyone, unconditionally (AD-16).
    requires: Role | None


ENDPOINTS = [
    # -- anonymous reads (3, AD-16)
    Endpoint("GET", "/", None),
    Endpoint("GET", "/healthz", None),
    Endpoint("GET", "/readyz", None),
    Endpoint("GET", "/login", None),
    Endpoint("POST", "/login", None),
    Endpoint("POST", "/preferences/theme", None),
    Endpoint("GET", "/repositories/internal", None),
    Endpoint("GET", "/repositories/internal/packages", None),
    Endpoint("GET", "/keys", None),
    Endpoint("GET", "/keys/test-key/public.asc", None),
    # Signing out is deliberately idempotent and open: a session that has
    # already expired must still let the button work, rather than answering the
    # click with a permission error.
    Endpoint("POST", "/logout", None),
    # -- any signed-in user
    Endpoint("GET", "/jobs", Role.MAINTAINER),
    Endpoint("GET", "/jobs/1", Role.MAINTAINER),
    Endpoint("GET", "/audit", Role.MAINTAINER),
    # -- maintainer: package operations
    Endpoint("GET", "/repositories/internal/packages/upload", Role.MAINTAINER),
    Endpoint("POST", "/repositories/internal/packages/upload", Role.MAINTAINER),
    Endpoint("POST", "/repositories/internal/packages/1/delete", Role.MAINTAINER),
    Endpoint("POST", "/repositories/internal/regenerate", Role.MAINTAINER),
    # -- admin: the shape of the repository, and the keys
    Endpoint("GET", "/repositories/new", Role.ADMIN),
    Endpoint("POST", "/repositories/new", Role.ADMIN),
    Endpoint("GET", "/repositories/internal/distributions", Role.ADMIN),
    Endpoint("POST", "/repositories/internal/distributions", Role.ADMIN),
    # The fixture repository is APT, so these answer 404 for an admin -- which
    # is the point: the permission layer runs first, and only then does the
    # handler decide the route does not apply to this format.
    Endpoint("GET", "/repositories/internal/variants", Role.ADMIN),
    Endpoint("POST", "/repositories/internal/variants", Role.ADMIN),
    Endpoint("POST", "/keys", Role.ADMIN),
    Endpoint("POST", "/keys/test-key/delete", Role.ADMIN),
]


def ids(endpoints: list[Endpoint]) -> list[str]:
    return [f"{endpoint.method} {endpoint.path}" for endpoint in endpoints]


def allowed(response: object) -> bool:
    """Whether the permission layer let this request through.

    Anything that is not a refusal counts: a 404 for a package that does not
    exist, a 400 for an empty form and a 303 after a successful post all mean
    the request reached its handler, which is what these tests are about.

    A refusal is a 403, or a 303 to the login form -- sending someone who is not
    signed in to type a password is more use than telling them they may not.
    The destination is what separates that redirect from a successful one.
    """
    status = getattr(response, "status_code", 0)
    if status == 403:
        return False
    if status == 303:
        return "/login" not in str(getattr(response, "headers", {}).get("location", ""))
    return True


@pytest.fixture
def signed_out(manageable_app: FastAPI) -> Iterator[TestClient]:
    with browser(manageable_app) as client:
        yield client


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=ids(ENDPOINTS))
def test_anonymous_access_matches_the_matrix(
    signed_out: TestClient, apt_repository: Repository, endpoint: Endpoint
) -> None:
    response = signed_out.request(endpoint.method, endpoint.path, follow_redirects=False)
    assert allowed(response) is (endpoint.requires is None), response.status_code


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=ids(ENDPOINTS))
def test_maintainer_access_matches_the_matrix(
    maintainer_client: TestClient, apt_repository: Repository, endpoint: Endpoint
) -> None:
    response = maintainer_client.request(endpoint.method, endpoint.path, follow_redirects=False)
    expected = endpoint.requires is not Role.ADMIN
    assert allowed(response) is expected, response.status_code


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=ids(ENDPOINTS))
def test_admin_access_matches_the_matrix(
    admin_client: TestClient, apt_repository: Repository, endpoint: Endpoint
) -> None:
    response = admin_client.request(endpoint.method, endpoint.path, follow_redirects=False)
    assert allowed(response), response.status_code


# --------------------------------------------------------------- coverage of the list


def routed_endpoints(app: FastAPI) -> set[tuple[str, str]]:
    """Every (method, path) the application actually serves.

    ``app.routes`` does not hold the routes themselves: an included router
    appears there as one lazily-resolved object, so reading it directly finds
    nothing and the coverage check below would pass by vacuum.  Asking each
    entry to resolve itself is what produces the real table -- and
    :func:`test_the_route_walker_finds_the_application` is what stops this
    silently returning an empty set again if the internals move.
    """
    found: set[tuple[str, str]] = set()

    def record(candidate: object) -> None:
        resolve = getattr(candidate, "effective_candidates", None)
        if callable(resolve):
            for nested in resolve():
                record(nested)
            return
        path = getattr(candidate, "path", None)
        methods = getattr(candidate, "methods", None)
        if not path or not methods:
            return
        for method in methods:
            if method not in {"HEAD", "OPTIONS"}:
                found.add((method, str(path)))

    for route in app.routes:
        if isinstance(route, Mount):
            continue  # static files are not part of the permission matrix
        record(route)
    return found


def test_the_route_walker_finds_the_application(app: FastAPI) -> None:
    """Guards the guard: an empty walk would make the check below meaningless."""
    routes = routed_endpoints(app)
    assert ("GET", "/") in routes
    assert ("POST", "/keys/{name}/delete") in routes
    assert len(routes) >= len(ENDPOINTS)


def test_every_route_in_the_application_is_classified(app: FastAPI) -> None:
    """A new endpoint that nobody thought about fails here, not in production."""
    # The matrix is written with a concrete slug where the route has a
    # parameter, so compare on the shape rather than the literal.
    shapes = {(endpoint.method, _shape(endpoint.path)) for endpoint in ENDPOINTS}
    missing = {entry for entry in routed_endpoints(app) if entry not in shapes}
    assert not missing, f"routes with no entry in ENDPOINTS: {sorted(missing)}"


def _shape(path: str) -> str:
    """Turn a concrete test path back into its route template."""
    replacements = {
        "/repositories/internal": "/repositories/{slug}",
        "/keys/test-key": "/keys/{name}",
        "/packages/1/delete": "/packages/{publication_id}/delete",
        "/jobs/1": "/jobs/{job_id}",
    }
    for concrete, template in replacements.items():
        path = path.replace(concrete, template)
    return path


# --------------------------------------------------------------- refusal shape


def test_an_anonymous_page_request_is_sent_to_sign_in(signed_out: TestClient) -> None:
    response = signed_out.get("/repositories/new", follow_redirects=False)
    assert response.status_code == 303
    assert "/login" in response.headers["location"]
    assert "next=" in response.headers["location"]


def test_signing_in_returns_to_where_the_visitor_was_headed(
    manageable_app: FastAPI, apt_repository: Repository
) -> None:
    with browser(manageable_app) as client:
        redirect = client.get("/repositories/new", follow_redirects=False)
        target = str(redirect.headers["location"])
        form = client.get(target)
        assert "Sign in" in form.text

        landing = client.post(
            "/login",
            data={
                "username": fake_directory.ADMIN_USERNAME,
                "password": fake_directory.ADMIN_PASSWORD,
                "next": _next_from(form.text),
            },
            follow_redirects=False,
        )
    assert str(landing.headers["location"]).endswith("/repositories/new")


def _next_from(body: str) -> str:
    """The `next` field inside the login form.

    Scoped to that form on purpose: the theme switch in the header also posts a
    `next`, and it appears earlier in the document.
    """
    import re

    form = re.search(r'<form[^>]*action="[^"]*/login"[^>]*>(.*?)</form>', body, flags=re.DOTALL)
    assert form is not None, "no login form"
    match = re.search(r'name="next" value="([^"]*)"', form.group(1))
    assert match is not None
    return match.group(1)


def test_an_anonymous_post_is_refused_outright(signed_out: TestClient) -> None:
    """No redirect for a POST: replaying the body after login is not something
    the browser can do, so pretending otherwise would lose the submission."""
    response = signed_out.post("/repositories/internal/regenerate", follow_redirects=False)
    assert response.status_code == 403


def test_a_maintainer_is_told_which_role_is_missing(maintainer_client: TestClient) -> None:
    body = maintainer_client.get("/repositories/new").text
    assert "admin" in body.lower()


def test_a_maintainer_sees_no_administration_links(
    maintainer_client: TestClient, apt_repository: Repository
) -> None:
    """The interface must not offer what the role gate will refuse."""
    body = maintainer_client.get("/repositories/internal").text
    assert "Upload a package" in body
    assert "Manage distributions" not in body


def test_an_anonymous_visitor_sees_no_management_links(
    signed_out: TestClient, apt_repository: Repository
) -> None:
    body = signed_out.get("/repositories/internal").text
    assert "Upload a package" not in body
    assert "Sign in" in body


# --------------------------------------------------------------- reads stay open


READABLE = [
    "/",
    "/repositories/internal",
    "/repositories/internal/packages",
    "/keys",
    "/healthz",
    "/readyz",
]


@pytest.mark.parametrize("path", READABLE)
def test_reads_need_no_account(
    signed_out: TestClient, apt_repository: Repository, path: str
) -> None:
    """Read access is universal and unconditional (AD-16, 3)."""
    assert signed_out.get(path).status_code == 200, path


def test_listings_are_not_filtered_by_identity(
    signed_out: TestClient, admin_client: TestClient, sync_session: Session
) -> None:
    """There is no hidden repository state, so both views must agree (3)."""
    from repository_manager.models import RepositoryType

    sync_session.add(
        Repository(
            slug="hidden-nothing",
            name="Nothing Hidden",
            type=RepositoryType.APT,
            root_path="/tmp/nothing",
            retention_count=0,
        )
    )
    sync_session.commit()
    assert "Nothing Hidden" in signed_out.get("/").text
    assert "Nothing Hidden" in admin_client.get("/").text


# --------------------------------------------------------------- CSRF over HTTP


UNSAFE = [
    ("POST", "/repositories/internal/regenerate"),
    ("POST", "/keys"),
    ("POST", "/logout"),
]


@pytest.mark.parametrize(("method", "path"), UNSAFE)
def test_a_session_request_without_a_token_is_refused(
    admin_client: TestClient, apt_repository: Repository, method: str, path: str
) -> None:
    del admin_client.headers["x-csrf-token"]
    response = admin_client.request(method, path, follow_redirects=False)
    assert response.status_code == 403
    assert "security token" in response.text


@pytest.mark.parametrize(("method", "path"), UNSAFE)
def test_a_session_request_with_the_wrong_token_is_refused(
    admin_client: TestClient, apt_repository: Repository, method: str, path: str
) -> None:
    admin_client.headers["x-csrf-token"] = csrf.new_secret()
    response = admin_client.request(method, path, follow_redirects=False)
    assert response.status_code == 403


def test_the_token_may_be_sent_as_a_form_field(
    admin_client: TestClient, apt_repository: Repository
) -> None:
    """Which is how it arrives with JavaScript disabled (7.3, 11)."""
    token = admin_client.headers.pop("x-csrf-token")
    response = admin_client.post(
        "/repositories/internal/regenerate", data={"_csrf": token}, follow_redirects=False
    )
    assert response.status_code == 303


def test_a_cross_origin_post_is_refused_even_with_a_valid_token(
    admin_client: TestClient, apt_repository: Repository
) -> None:
    response = admin_client.post(
        "/repositories/internal/regenerate",
        headers={"origin": "https://evil.example"},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_a_post_with_no_origin_is_refused_when_it_carries_a_session(
    admin_client: TestClient, apt_repository: Repository
) -> None:
    del admin_client.headers["origin"]
    response = admin_client.post("/repositories/internal/regenerate", follow_redirects=False)
    assert response.status_code == 403


def test_the_anonymous_theme_form_still_works(signed_out: TestClient) -> None:
    """It has no ambient credential behind it, so it needs no token (7.3)."""
    response = signed_out.post(
        "/preferences/theme", data={"theme": "dark", "next": "/"}, follow_redirects=False
    )
    assert response.status_code == 303


def test_the_theme_form_carries_a_token_once_signed_in(admin_client: TestClient) -> None:
    """Whatever a signed-in browser posts must satisfy the same check."""
    del admin_client.headers["x-csrf-token"]
    assert (
        admin_client.post(
            "/preferences/theme", data={"theme": "dark", "next": "/"}, follow_redirects=False
        ).status_code
        == 403
    )
    token = _csrf_from(admin_client.get("/").text)
    assert (
        admin_client.post(
            "/preferences/theme",
            data={"theme": "dark", "next": "/", "_csrf": token},
            follow_redirects=False,
        ).status_code
        == 303
    )


def _csrf_from(body: str) -> str:
    import re

    match = re.search(r'name="_csrf" value="([^"]+)"', body)
    assert match is not None
    return match.group(1)


def test_every_state_changing_form_carries_a_token(
    admin_client: TestClient, apt_repository: Repository
) -> None:
    """Rendered pages must not contain a form the gate will then refuse."""
    import re

    pages = [
        "/",
        "/repositories/internal",
        "/repositories/internal/packages",
        "/repositories/internal/packages/upload",
        "/repositories/internal/distributions",
        "/repositories/new",
        "/keys",
        "/jobs",
        "/audit",
    ]
    for path in pages:
        body = admin_client.get(path).text
        for form in re.findall(r"<form\b.*?</form>", body, flags=re.DOTALL):
            if 'method="post"' not in form:
                continue
            assert 'name="_csrf"' in form, f"{path}: a POST form with no CSRF field"


def test_sign_in_itself_needs_no_token(manageable_app: FastAPI) -> None:
    """There is no session yet, so there is no per-session secret to send."""
    with browser(manageable_app) as client:
        response = client.post(
            "/login",
            data={
                "username": fake_directory.ADMIN_USERNAME,
                "password": fake_directory.ADMIN_PASSWORD,
            },
            follow_redirects=False,
        )
    assert response.status_code == 303


def test_the_public_origin_is_what_is_compared(manageable_app: FastAPI) -> None:
    """Not the Host header, which a caller controls (10.6)."""
    with browser(manageable_app) as client:
        sign_in(client, fake_directory.ADMIN_USERNAME, fake_directory.ADMIN_PASSWORD)
        response = client.post(
            "/preferences/theme",
            data={"theme": "dark", "next": "/"},
            headers={"origin": PUBLIC_URL, "host": "evil.example"},
            follow_redirects=False,
        )
    assert response.status_code == 303
