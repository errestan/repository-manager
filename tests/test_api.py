"""The REST API over HTTP (specification.md 8.2, 7.4).

Driven through the real application, with a real token in a real
``Authorization`` header, because the thing worth proving is not that the
handlers work but that the gate in front of them does: that a session cookie
gets a caller nowhere here, that a token restricted to one repository cannot
touch another, and that an owner who loses their directory role loses the
token with it.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from repository_manager.models import ApiToken, Repository, Role, SigningKey, TokenScope
from repository_manager.web.problems import PROBLEM_MEDIA_TYPE, TYPE_PREFIX
from repository_manager.web.routes import reference
from tests.conftest import (
    AppFactory,
    FakeCreaterepo,
    IssuedToken,
    Keyring,
    browser,
    issue_token,
    sign_in,
)
from tests.support import directory as fake_directory
from tests.support.debs import DebSpec, build_deb
from tests.support.directory import FakeDirectory
from tests.support.rpms import build_simple

API = "/api/v1"


def poll_job(client: TestClient, job_id: int, timeout: float = 20.0) -> dict[str, Any]:
    """Follow a job to a terminal state, the way the documented CI loop does."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body: dict[str, Any] = client.get(f"{API}/jobs/{job_id}").json()
        if body["finished"]:
            return body
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish")


@pytest.fixture
def published(admin_client: TestClient, repository_root: Path, signing_key: SigningKey) -> str:
    """An APT repository created through the web interface, ready to publish into.

    Created through the form rather than inserted, because a repository the API
    publishes into has to be one the rest of the application would have made --
    signed, with initial metadata already on disk.
    """
    response = admin_client.post(
        "/repositories/new",
        data={
            "name": "Internal APT",
            "root_path": str(repository_root / "internal"),
            "signing_key_id": str(signing_key.id),
            "retention": "all",
            "format": "apt",
            "codename": "bookworm",
            "components": "main contrib",
            "architectures": "amd64",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    return str(response.headers["location"]).rsplit("/", 1)[-1]


# ------------------------------------------------------------------ anonymous reads


def test_the_repository_list_needs_no_token(client: TestClient, apt_repository: Repository) -> None:
    """Read access is unconditional (AD-16), and the API says so too."""
    response = client.get(f"{API}/repositories")
    assert response.status_code == 200
    assert [entry["slug"] for entry in response.json()] == ["internal"]


def test_a_repository_reports_the_targets_an_upload_may_name(
    client: TestClient, apt_repository: Repository
) -> None:
    body = client.get(f"{API}/repositories/internal").json()
    assert body["type"] == "apt"
    assert body["distributions"] == [
        {
            "codename": "bookworm",
            "suite": None,
            "components": ["contrib", "main"],
            "architectures": ["all", "amd64"],
        }
    ]


def test_an_rpm_repository_reports_its_variants(
    client: TestClient, rpm_repository: Repository
) -> None:
    body = client.get(f"{API}/repositories/el9").json()
    assert body["variants"] == [{"name": "el9", "arch": "x86_64"}]


def test_a_repository_reports_where_clients_fetch_it(
    client: TestClient, apt_repository: Repository
) -> None:
    body = client.get(f"{API}/repositories/internal").json()
    assert body["url"].endswith("/repos/internal")


def test_an_unknown_repository_is_a_problem_document(client: TestClient) -> None:
    response = client.get(f"{API}/repositories/nope")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith(PROBLEM_MEDIA_TYPE)
    body = response.json()
    assert body["type"] == f"{TYPE_PREFIX}not-found"
    assert body["status"] == 404
    assert body["instance"] == f"{API}/repositories/nope"


def test_an_unrouted_api_path_is_json_not_html(client: TestClient) -> None:
    """A framework 404 must not answer a JSON client with an error page."""
    response = client.get(f"{API}/nothing-here")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith(PROBLEM_MEDIA_TYPE)


def test_a_web_page_404_is_still_html(client: TestClient) -> None:
    response = client.get("/repositories/nope")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")


# ------------------------------------------------------------------ credentials


def test_a_dead_token_is_refused_even_on_an_anonymous_endpoint(
    app: FastAPI, sync_session: Session, apt_repository: Repository
) -> None:
    """Silently serving anonymous results would hide a broken pipeline (7.4)."""
    revoked = issue_token(sync_session, revoked=True)
    with browser(app) as client:
        response = client.get(f"{API}/repositories", headers=revoked.header)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


def test_a_token_is_ignored_outside_the_api(
    app: FastAPI, write_token: IssuedToken, apt_repository: Repository
) -> None:
    """7.4: bearer tokens are accepted on /api/v1 only."""
    with browser(app) as client:
        response = client.get(
            "/repositories/internal/packages/upload",
            headers=write_token.header,
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert "/login" in response.headers["location"]


def test_a_signed_in_session_cannot_write_through_the_api(
    manageable_app: FastAPI, apt_repository: Repository
) -> None:
    """The cookie is never read under /api/v1, so an admin browser is anonymous there."""
    with browser(manageable_app) as client:
        sign_in(client, fake_directory.ADMIN_USERNAME, fake_directory.ADMIN_PASSWORD)
        response = client.post(f"{API}/repositories/internal/regenerate")
    assert response.status_code == 401


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Basic cm9vdDpodW50ZXIy", "Bearer ", "Token rmt_x", "Bearer rmt_nonsense"],
)
def test_a_credential_that_is_not_ours_never_authenticates(
    app: FastAPI, apt_repository: Repository, header: str
) -> None:
    with browser(app) as client:
        response = client.post(
            f"{API}/repositories/internal/regenerate", headers={"authorization": header}
        )
    assert response.status_code == 401


def test_a_read_only_token_may_not_write(
    app: FastAPI, read_token: IssuedToken, apt_repository: Repository
) -> None:
    with browser(app) as client:
        response = client.post(f"{API}/repositories/internal/regenerate", headers=read_token.header)
    assert response.status_code == 403
    body = response.json()
    assert body["required_scope"] == TokenScope.PACKAGE_WRITE.value
    assert "package:read" in body["detail"]


def test_a_token_scoped_to_another_repository_is_refused(
    app: FastAPI, sync_session: Session, apt_repository: Repository
) -> None:
    scoped = issue_token(sync_session, repositories=("elsewhere",))
    with browser(app) as client:
        response = client.post(f"{API}/repositories/internal/regenerate", headers=scoped.header)
    assert response.status_code == 403
    assert "elsewhere" in response.json()["detail"]


def test_a_token_scoped_to_this_repository_is_admitted(
    app: FastAPI, sync_session: Session, apt_repository: Repository
) -> None:
    scoped = issue_token(sync_session, repositories=("internal", "other"))
    with browser(app) as client:
        response = client.post(f"{API}/repositories/internal/regenerate", headers=scoped.header)
    assert response.status_code == 202


def test_an_owner_who_loses_their_group_loses_the_token(
    app: FastAPI,
    directory: FakeDirectory,
    write_token: IssuedToken,
    apt_repository: Repository,
) -> None:
    """Effective permission is scopes intersected with the current role (7.4)."""
    directory.users[fake_directory.MAINTAINER_USERNAME].role = None
    with browser(app) as client:
        response = client.post(
            f"{API}/repositories/internal/regenerate", headers=write_token.header
        )
    assert response.status_code == 403
    assert "no longer a member" in response.json()["detail"]


def test_an_owner_demoted_below_maintainer_could_not_have_written(
    app: FastAPI, sync_session: Session, apt_repository: Repository, directory: FakeDirectory
) -> None:
    """A read-scoped token still reads once its owner is only a maintainer."""
    read_only = issue_token(sync_session, scopes=(TokenScope.PACKAGE_READ,))
    directory.users[fake_directory.MAINTAINER_USERNAME].role = Role.MAINTAINER
    with browser(app) as client:
        response = client.get(f"{API}/jobs/1", headers=read_only.header)
    # 404 because there is no job 1, not 403: the scope check passed.
    assert response.status_code == 404


def test_a_directory_outage_does_not_break_reads(
    app: FastAPI,
    directory: FakeDirectory,
    write_token: IssuedToken,
    apt_repository: Repository,
) -> None:
    """The role is only resolved when a scope is required, so reads keep working."""
    directory.unavailable = True
    with browser(app) as client:
        response = client.get(f"{API}/repositories/internal", headers=write_token.header)
    assert response.status_code == 200


def test_a_directory_outage_is_reported_as_such_on_a_write(
    app: FastAPI,
    directory: FakeDirectory,
    write_token: IssuedToken,
    apt_repository: Repository,
) -> None:
    directory.unavailable = True
    with browser(app) as client:
        response = client.post(
            f"{API}/repositories/internal/regenerate", headers=write_token.header
        )
    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"


def test_the_directory_is_not_asked_again_within_the_interval(
    app: FastAPI,
    directory: FakeDirectory,
    write_token: IssuedToken,
    apt_repository: Repository,
) -> None:
    """Otherwise every upload in a pipeline would be an LDAP round trip (7.4)."""
    with browser(app) as client:
        for _ in range(3):
            client.post(f"{API}/repositories/internal/regenerate", headers=write_token.header)
    assert directory.role_lookups == 1


def test_using_a_token_records_when(
    app: FastAPI, sync_session: Session, write_token: IssuedToken, apt_repository: Repository
) -> None:
    with browser(app) as client:
        client.get(f"{API}/repositories", headers=write_token.header)
    sync_session.expire_all()
    stored = sync_session.get(ApiToken, write_token.record_id)
    assert stored is not None
    assert stored.last_used_at is not None


# ------------------------------------------------------------------ publishing


def _upload(
    client: TestClient,
    slug: str,
    deb: Path,
    *,
    filename: str = "package.deb",
    **fields: str,
) -> Any:
    return client.post(
        f"{API}/repositories/{slug}/packages",
        data=fields or {"distribution": "bookworm", "component": "main"},
        files={"file": (filename, deb.read_bytes())},
    )


@pytest.fixture
def token_client(manageable_app: FastAPI, write_token: IssuedToken) -> Iterator[TestClient]:
    """A second client onto the same application, presenting a token.

    Separate from ``admin_client`` on purpose: reusing that one would carry a
    session cookie into every API call, and these tests are partly about the
    cookie counting for nothing there.
    """
    with browser(manageable_app) as client:
        client.headers.update(write_token.header)
        yield client


def test_a_package_is_published_and_a_job_is_queued(
    token_client: TestClient, published: str, repository_root: Path, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    response = _upload(token_client, published, deb)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["created"] is True
    assert body["package"]["name"] == "alpha"
    assert body["package"]["full_version"] == "1.0-1"
    assert body["package"]["target"] == "bookworm/main"
    assert body["job_id"] is not None

    assert poll_job(token_client, body["job_id"])["state"] == "succeeded"
    index = repository_root / "internal/dists/bookworm/main/binary-amd64/Packages"
    assert "Package: alpha" in index.read_text()


def test_the_package_path_is_where_a_client_would_fetch_it(
    token_client: TestClient, published: str, repository_root: Path, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    path = _upload(token_client, published, deb).json()["package"]["path"]
    assert path.startswith("pool/")
    assert (repository_root / "internal" / path).is_file()


def test_the_uploaded_filename_is_never_used_as_a_path(
    token_client: TestClient, published: str, repository_root: Path, tmp_path: Path
) -> None:
    """The stored path comes from parsed metadata alone (10.2)."""
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    response = _upload(token_client, published, deb, filename="../../../../tmp/evil.deb")
    assert response.status_code == 201
    assert "evil" not in response.json()["package"]["path"]
    assert not (repository_root.parent / "evil.deb").exists()


def test_an_identical_re_upload_is_a_success_that_changed_nothing(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    """A retried pipeline step must not fail (5.1)."""
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    assert _upload(token_client, published, deb).status_code == 201

    again = _upload(token_client, published, deb)
    assert again.status_code == 200
    assert again.json()["created"] is False
    assert again.json()["job_id"] is None


def test_the_same_version_with_different_bytes_is_a_conflict(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    first = build_deb(DebSpec(name="alpha", version="1.0-1", description="one"), tmp_path / "a.deb")
    second = build_deb(
        DebSpec(name="alpha", version="1.0-1", description="two"), tmp_path / "b.deb"
    )
    assert _upload(token_client, published, first).status_code == 201

    response = _upload(token_client, published, second)
    assert response.status_code == 409
    assert response.json()["type"] == f"{TYPE_PREFIX}conflict"


def test_the_same_file_may_be_published_to_a_second_component(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    assert _upload(token_client, published, deb).status_code == 201
    second = _upload(token_client, published, deb, distribution="bookworm", component="contrib")
    assert second.status_code == 201
    assert second.json()["package"]["target"] == "bookworm/contrib"


def test_an_upload_with_no_target_names_the_ones_that_exist(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    response = token_client.post(
        f"{API}/repositories/{published}/packages",
        files={"file": ("alpha.deb", deb.read_bytes())},
    )
    assert response.status_code == 400
    assert "bookworm/main" in response.json()["detail"]


def test_an_unknown_target_is_refused(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    response = _upload(token_client, published, deb, distribution="trixie", component="main")
    assert response.status_code == 404


def test_an_upload_with_no_file_says_what_to_send(token_client: TestClient, published: str) -> None:
    response = token_client.post(
        f"{API}/repositories/{published}/packages",
        data={"distribution": "bookworm", "component": "main"},
    )
    assert response.status_code == 400
    assert "file=@" in response.json()["detail"]


def test_something_that_is_not_a_package_is_refused(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    junk = tmp_path / "junk.deb"
    junk.write_bytes(b"this is not an ar archive")
    response = _upload(token_client, published, junk)
    assert response.status_code == 400
    assert response.headers["content-type"].startswith(PROBLEM_MEDIA_TYPE)


def test_an_upload_over_the_limit_is_reported_as_too_large(
    make_app: AppFactory,
    repository_root: Path,
    scratch_keyring: Keyring,
    signing_key: SigningKey,
    sync_session: Session,
) -> None:
    """Enforced while reading the body, not from a client-supplied length (5.1)."""
    app = make_app(max_upload_bytes=256, gnupghome=str(scratch_keyring.home))
    token = issue_token(sync_session)
    with browser(app) as client:
        sign_in(client, fake_directory.ADMIN_USERNAME, fake_directory.ADMIN_PASSWORD)
        client.post(
            "/repositories/new",
            data={
                "name": "Small",
                "root_path": str(repository_root / "small"),
                "signing_key_id": str(signing_key.id),
                "retention": "all",
                "format": "apt",
                "codename": "bookworm",
                "components": "main",
                "architectures": "amd64",
            },
        )
        response = client.post(
            f"{API}/repositories/small/packages",
            data={"distribution": "bookworm", "component": "main"},
            files={"file": ("big.deb", b"x" * 4096)},
            headers=token.header,
        )
    assert response.status_code == 413
    assert response.json()["type"] == f"{TYPE_PREFIX}upload-too-large"


# ------------------------------------------------------------------ listing


def test_a_published_package_appears_in_the_listing(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    _upload(token_client, published, deb)

    body = token_client.get(f"{API}/repositories/{published}/packages").json()
    assert body["total"] == 1
    assert body["packages"][0]["name"] == "alpha"
    assert body["packages"][0]["uploaded_via"] == "token"


def test_the_name_filter_is_exact(token_client: TestClient, published: str, tmp_path: Path) -> None:
    """Unlike the web interface's search: a script asking about `libfoo` does
    not want `libfoo-dev` back."""
    for name in ("libfoo", "libfoo-dev"):
        _upload(
            token_client,
            published,
            build_deb(DebSpec(name=name, version="1.0-1"), tmp_path / f"{name}.deb"),
        )
    body = token_client.get(
        f"{API}/repositories/{published}/packages", params={"name": "libfoo"}
    ).json()
    assert [entry["name"] for entry in body["packages"]] == ["libfoo"]


def test_the_component_filter_narrows_to_one_target(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    _upload(token_client, published, deb)
    _upload(token_client, published, deb, distribution="bookworm", component="contrib")

    body = token_client.get(
        f"{API}/repositories/{published}/packages", params={"component": "contrib"}
    ).json()
    assert body["total"] == 1
    assert body["packages"][0]["target"] == "bookworm/contrib"


def test_the_distribution_filter_narrows_the_listing(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    _upload(token_client, published, deb)

    matched = token_client.get(
        f"{API}/repositories/{published}/packages", params={"distribution": "bookworm"}
    ).json()
    missed = token_client.get(
        f"{API}/repositories/{published}/packages", params={"distribution": "trixie"}
    ).json()
    assert matched["total"] == 1
    assert missed["total"] == 0


def test_the_architecture_filter_narrows_the_listing(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    for architecture in ("amd64", "all"):
        _upload(
            token_client,
            published,
            build_deb(
                DebSpec(name=f"pkg-{architecture}", version="1.0-1", architecture=architecture),
                tmp_path / f"{architecture}.deb",
            ),
        )
    body = token_client.get(
        f"{API}/repositories/{published}/packages", params={"arch": "all"}
    ).json()
    assert [entry["architecture"] for entry in body["packages"]] == ["all"]


def test_a_filter_that_does_not_apply_to_the_format_is_ignored(
    client: TestClient, rpm_repository: Repository
) -> None:
    """A generic CI script should not have to know which format it is talking to."""
    response = client.get(f"{API}/repositories/el9/packages", params={"component": "main"})
    assert response.status_code == 200


def test_the_listing_is_paginated(token_client: TestClient, published: str, tmp_path: Path) -> None:
    for index in range(3):
        _upload(
            token_client,
            published,
            build_deb(DebSpec(name=f"pkg{index}", version="1.0-1"), tmp_path / f"{index}.deb"),
        )
    body = token_client.get(
        f"{API}/repositories/{published}/packages", params={"per_page": 2}
    ).json()
    assert body["total"] == 3
    assert body["pages"] == 2
    assert len(body["packages"]) == 2


# ------------------------------------------------------------------ removal


def test_a_publication_is_removed_by_the_id_the_listing_gave(
    token_client: TestClient, published: str, repository_root: Path, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    created = _upload(token_client, published, deb).json()
    poll_job(token_client, created["job_id"])

    response = token_client.delete(
        f"{API}/repositories/{published}/packages/{created['package']['id']}"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["file_deleted"] is True
    assert poll_job(token_client, body["job_id"])["state"] == "succeeded"
    assert not (repository_root / "internal" / created["package"]["path"]).exists()


def test_removing_one_of_two_targets_keeps_the_file(
    token_client: TestClient, published: str, repository_root: Path, tmp_path: Path
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    first = _upload(token_client, published, deb).json()
    _upload(token_client, published, deb, distribution="bookworm", component="contrib")

    body = token_client.delete(
        f"{API}/repositories/{published}/packages/{first['package']['id']}"
    ).json()
    assert body["file_deleted"] is False
    assert (repository_root / "internal" / first["package"]["path"]).is_file()


def test_removing_something_that_is_not_there_is_a_problem_document(
    token_client: TestClient, published: str
) -> None:
    response = token_client.delete(f"{API}/repositories/{published}/packages/9999")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith(PROBLEM_MEDIA_TYPE)


# ------------------------------------------------------------------ jobs


def test_regeneration_returns_the_job_it_queued(token_client: TestClient, published: str) -> None:
    response = token_client.post(f"{API}/repositories/{published}/regenerate")
    assert response.status_code == 202
    assert poll_job(token_client, response.json()["id"])["state"] == "succeeded"


def test_a_job_cannot_be_read_without_a_token(
    client: TestClient, apt_repository: Repository
) -> None:
    """Job logs carry subprocess output, which the anonymous surface does not (8.1)."""
    assert client.get(f"{API}/jobs/1").status_code == 401


def test_a_job_for_a_repository_outside_the_token_scope_is_not_found(
    manageable_app: FastAPI, published: str, sync_session: Session
) -> None:
    """404 rather than 403: which job ids exist is not something to confirm."""
    with browser(manageable_app) as unrestricted:
        unrestricted.headers.update(issue_token(sync_session).header)
        job_id = unrestricted.post(f"{API}/repositories/{published}/regenerate").json()["id"]

        scoped = issue_token(sync_session, repositories=("elsewhere",), label="scoped")
        response = unrestricted.get(f"{API}/jobs/{job_id}", headers=scoped.header)
    assert response.status_code == 404


# ------------------------------------------------------------------ audit


def test_a_token_upload_is_attributed_to_its_owner_and_its_token(
    token_client: TestClient,
    admin_client: TestClient,
    published: str,
    write_token: IssuedToken,
    tmp_path: Path,
) -> None:
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    _upload(token_client, published, deb)

    entries = admin_client.get("/audit").text
    assert "Upload package" in entries
    assert fake_directory.MAINTAINER_USERNAME in entries


# ------------------------------------------------------------------ schema and docs


def test_the_schema_describes_every_api_endpoint(client: TestClient) -> None:
    schema = client.get(f"{API}/openapi.json").json()
    assert set(schema["paths"]) == {
        f"{API}/repositories",
        f"{API}/repositories/{{slug}}",
        f"{API}/repositories/{{slug}}/packages",
        f"{API}/repositories/{{slug}}/packages/{{publication_id}}",
        f"{API}/repositories/{{slug}}/regenerate",
        f"{API}/jobs/{{job_id}}",
    }


def test_the_schema_defines_the_scheme_its_operations_name(client: TestClient) -> None:
    schema = client.get(f"{API}/openapi.json").json()
    named = {
        scheme
        for operations in schema["paths"].values()
        for operation in operations.values()
        for requirement in operation.get("security", [])
        for scheme in requirement
    }
    assert named == {"bearerAuth"}
    assert set(schema["components"]["securitySchemes"]) >= named


def test_the_upload_body_is_documented(client: TestClient) -> None:
    """It is parsed by hand, so FastAPI cannot infer it; the schema still has it."""
    schema = client.get(f"{API}/openapi.json").json()
    operation = schema["paths"][f"{API}/repositories/{{slug}}/packages"]["post"]
    body = operation["requestBody"]["content"]["multipart/form-data"]["schema"]
    assert set(body["properties"]) == {"file", "distribution", "component", "variant"}
    assert body["required"] == ["file"]


def test_the_reference_page_lists_the_endpoints(client: TestClient) -> None:
    page = client.get("/api/docs")
    assert page.status_code == 200
    assert f"{API}/repositories/{{slug}}/packages" in page.text


def test_the_reference_page_loads_nothing_from_another_origin(client: TestClient) -> None:
    """The CSP allows no remote origins, so a CDN-backed page would render blank."""
    page = client.get("/api/docs").text
    assert "https://cdn" not in page
    assert "unpkg" not in page


def test_the_documentation_can_be_switched_off(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    app = make_app(api_docs_enabled=False)
    with browser(app) as client:
        assert client.get("/api/docs").status_code == 404
        assert client.get(f"{API}/openapi.json").status_code == 404
        # The API itself keeps working; only its description goes away.
        assert client.get(f"{API}/repositories").status_code == 200


def test_switching_the_documentation_off_removes_the_link(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    """A template linking to a route that is not registered would fail to render."""
    app = make_app(api_docs_enabled=False)
    with browser(app) as client:
        home = client.get("/")
    assert home.status_code == 200
    assert "/api/docs" not in home.text


# ------------------------------------------------------------------ RPM


@pytest.fixture
def rpm_published(
    admin_client: TestClient,
    repository_root: Path,
    signing_key: SigningKey,
    fake_createrepo: FakeCreaterepo,
) -> str:
    response = admin_client.post(
        "/repositories/new",
        data={
            "name": "Enterprise Linux 9",
            "root_path": str(repository_root / "el9"),
            "signing_key_id": str(signing_key.id),
            "retention": "all",
            "format": "rpm",
            "variant_name": "el9",
            "variant_arch": "x86_64",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    return str(response.headers["location"]).rsplit("/", 1)[-1]


def test_an_rpm_is_published_into_a_named_variant(
    token_client: TestClient, rpm_published: str, repository_root: Path, tmp_path: Path
) -> None:
    rpm = build_simple(tmp_path / "hello.rpm", name="hello", version="1.0", release="1.el9")
    response = token_client.post(
        f"{API}/repositories/{rpm_published}/packages",
        data={"variant": "el9/x86_64"},
        files={"file": ("hello.rpm", rpm.read_bytes())},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["package"]["target"] == "el9/x86_64"
    assert body["package"]["release"] == "1.el9"
    assert body["package"]["path"] == "el9/x86_64/Packages/hello-1.0-1.el9.x86_64.rpm"
    assert (repository_root / "el9" / body["package"]["path"]).is_file()


def test_a_variant_written_without_its_architecture_is_refused(
    token_client: TestClient, rpm_published: str, tmp_path: Path
) -> None:
    """A variant is a name *and* an architecture; guessing between them would surprise."""
    rpm = build_simple(tmp_path / "hello.rpm", name="hello", version="1.0", release="1.el9")
    response = token_client.post(
        f"{API}/repositories/{rpm_published}/packages",
        data={"variant": "el9"},
        files={"file": ("hello.rpm", rpm.read_bytes())},
    )
    assert response.status_code == 400
    assert "name/arch" in response.json()["detail"]


def test_an_unknown_variant_names_the_ones_that_exist(
    token_client: TestClient, rpm_published: str, tmp_path: Path
) -> None:
    rpm = build_simple(tmp_path / "hello.rpm", name="hello", version="1.0", release="1.el9")
    response = token_client.post(
        f"{API}/repositories/{rpm_published}/packages",
        data={"variant": "el8/x86_64"},
        files={"file": ("hello.rpm", rpm.read_bytes())},
    )
    assert response.status_code == 404
    assert "el9/x86_64" in response.json()["detail"]


def test_the_variant_filter_narrows_an_rpm_listing(
    token_client: TestClient, rpm_published: str, tmp_path: Path
) -> None:
    rpm = build_simple(tmp_path / "hello.rpm", name="hello", version="1.0", release="1.el9")
    token_client.post(
        f"{API}/repositories/{rpm_published}/packages",
        data={"variant": "el9/x86_64"},
        files={"file": ("hello.rpm", rpm.read_bytes())},
    )
    matched = token_client.get(
        f"{API}/repositories/{rpm_published}/packages", params={"variant": "el9/x86_64"}
    ).json()
    missed = token_client.get(
        f"{API}/repositories/{rpm_published}/packages", params={"variant": "el9/aarch64"}
    ).json()
    assert matched["total"] == 1
    assert missed["total"] == 0


# ------------------------------------------------------------------ the reference page


def test_the_reference_reads_a_type_out_of_either_json_schema_spelling() -> None:
    """A parameter that gains a `| None` becomes anyOf; the table still names it."""
    assert reference._type_of({"type": "integer"}) == "integer"
    assert reference._type_of({"anyOf": [{"type": "string"}, {"type": "null"}]}) == "string"
    assert reference._type_of({}) == "string"


def test_the_reference_flattens_a_multipart_body_into_fields() -> None:
    endpoints = reference.endpoints_of(
        {
            "paths": {
                "/x": {
                    "post": {
                        "summary": "Upload",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["file"],
                                        "properties": {
                                            "file": {"type": "string", "format": "binary"},
                                            "variant": {"type": "string", "description": "x"},
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "Made"}},
                    }
                }
            }
        }
    )
    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.authenticated is True
    assert [(field.name, field.required) for field in endpoint.body] == [
        ("file", True),
        ("variant", False),
    ]
    assert endpoint.statuses == [("201", "Made")]


def test_an_endpoint_with_no_token_requirement_is_marked_anonymous() -> None:
    endpoints = reference.endpoints_of(
        {"paths": {"/x": {"get": {"summary": "Read", "responses": {}}}}}
    )
    assert endpoints[0].authenticated is False


# ------------------------------------------------------------------ retention (5.3)


def test_an_upload_reports_what_retention_removed(
    token_client: TestClient, admin_client: TestClient, published: str, tmp_path: Path
) -> None:
    """A nightly pipeline should see in its own log which builds went away."""
    admin_client.post(
        f"/repositories/{published}/settings",
        data={
            "name": "Internal APT",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": _first_key_id(admin_client, published),
            "retention": "count",
            "retention_count": "1",
        },
    )
    for version in ("1.0-1", "1.1-1"):
        response = _upload(
            token_client,
            published,
            build_deb(DebSpec(name="alpha", version=version), tmp_path / f"a{version}.deb"),
        )
        assert response.status_code == 201, response.text

    assert response.json()["pruned"] == ["alpha 1.0-1 (amd64) from bookworm/main"]


def test_nothing_is_pruned_when_every_version_is_kept(
    token_client: TestClient, published: str, tmp_path: Path
) -> None:
    for version in ("1.0-1", "1.1-1"):
        response = _upload(
            token_client,
            published,
            build_deb(DebSpec(name="alpha", version=version), tmp_path / f"a{version}.deb"),
        )
    assert response.json()["pruned"] == []


def _first_key_id(client: TestClient, slug: str) -> str:
    match = re.search(r'<option value="(\d+)"', client.get(f"/repositories/{slug}/settings").text)
    assert match, "no signing key offered"
    return match.group(1)


# ------------------------------------------------------------------ rate limiting (10.3)


def test_a_flood_of_rejected_tokens_is_throttled(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    """Guessing a token must cost the guesser, not just this database."""
    app = make_app(credential_failure_burst=2, credential_failure_rate_per_minute=1)
    with browser(app) as client:
        statuses = [
            client.get(
                f"{API}/repositories",
                headers={"authorization": f"Bearer rmt_{'x' * 43}"},
            ).status_code
            for _ in range(4)
        ]
    assert statuses[:2] == [401, 401]
    assert statuses[-1] == 429


def test_the_throttled_answer_is_a_problem_document(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    app = make_app(credential_failure_burst=1, credential_failure_rate_per_minute=1)
    with browser(app) as client:
        client.get(f"{API}/repositories", headers={"authorization": f"Bearer rmt_{'x' * 43}"})
        response = client.get(
            f"{API}/repositories", headers={"authorization": f"Bearer rmt_{'x' * 43}"}
        )
    assert response.status_code == 429
    assert response.headers["content-type"].startswith(PROBLEM_MEDIA_TYPE)
    body = response.json()
    assert body["type"] == f"{TYPE_PREFIX}rate-limited"
    assert int(response.headers["retry-after"]) >= 1
    assert body["retry_after"] >= 1


def test_a_good_token_is_never_slowed_by_someone_elses_guessing(
    make_app: AppFactory, sync_session: Session, apt_repository: Repository
) -> None:
    """Failures are what is counted, so a working pipeline never meets the limit."""
    app = make_app(credential_failure_burst=1, credential_failure_rate_per_minute=1)
    token = issue_token(sync_session)
    with browser(app) as client:
        for _ in range(3):
            client.get(f"{API}/repositories", headers={"authorization": f"Bearer rmt_{'x' * 43}"})
        for _ in range(10):
            assert client.get(f"{API}/repositories", headers=token.header).status_code == 200


def test_uploads_are_throttled_per_token(
    make_app: AppFactory,
    scratch_keyring: Keyring,
    signing_key: SigningKey,
    sync_session: Session,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    app = make_app(gnupghome=str(scratch_keyring.home), upload_burst=1, upload_rate_per_minute=1)
    token = issue_token(sync_session)
    with browser(app) as admin:
        sign_in(admin, fake_directory.ADMIN_USERNAME, fake_directory.ADMIN_PASSWORD)
        created = admin.post(
            "/repositories/new",
            data={
                "name": "Throttled",
                "root_path": str(repository_root / "throttled"),
                "signing_key_id": str(signing_key.id),
                "retention": "all",
                "format": "apt",
                "codename": "bookworm",
                "components": "main",
                "architectures": "amd64",
            },
            follow_redirects=False,
        )
        slug = str(created.headers["location"]).rsplit("/", 1)[-1]

    with browser(app) as pipeline:
        pipeline.headers.update(token.header)
        statuses = []
        for index in range(3):
            deb = build_deb(
                DebSpec(name="alpha", version=f"1.{index}-1"), tmp_path / f"a{index}.deb"
            )
            statuses.append(
                pipeline.post(
                    f"{API}/repositories/{slug}/packages",
                    data={"distribution": "bookworm", "component": "main"},
                    files={"file": (deb.name, deb.read_bytes())},
                ).status_code
            )
    assert statuses[0] == 201
    assert 429 in statuses[1:]
