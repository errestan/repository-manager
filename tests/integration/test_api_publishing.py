"""The documented CI flow, end to end, judged by apt (specification.md 8.2, 13.6).

Every other API test stops at the HTTP response.  This one carries on: it mints
a token the way a person would, publishes with it the way ``docs/api.md`` says
to, waits for the job the way the documented loop waits, and then points a real
``apt-get`` at the result.

That last step is what makes the test worth its runtime.  An API that returns
201 and a job that reports "succeeded" are both this application marking its own
homework; apt installing the package is not.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from repository_manager.models import SigningKey
from tests.conftest import browser, sign_in
from tests.integration.aptclient import APT_CACHE, APT_GET, IsolatedApt
from tests.support import directory as fake_directory
from tests.support.debs import DebSpec, build_deb

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        APT_GET is None or APT_CACHE is None,
        reason="apt-get and apt-cache are required to verify the published repository",
    ),
]

API = "/api/v1"
CODENAME = "bookworm"
POLL_TIMEOUT_SECONDS = 30.0


def mint_a_token(app: FastAPI) -> str:
    """Create a token through the page a person would use, and read it once.

    Going through the form rather than inserting a row is the point: the flow
    ``docs/api.md`` describes starts on that page, and a token that cannot be
    obtained the documented way is not usable however well the API works.
    """
    with browser(app) as client:
        sign_in(client, fake_directory.ADMIN_USERNAME, fake_directory.ADMIN_PASSWORD)
        page = client.post(
            "/tokens",
            data={
                "label": "integration pipeline",
                "scopes": ["package:read", "package:write"],
                "lifetime_days": "1",
            },
        )
    assert page.status_code == 200, page.text
    match = re.search(r'<code class="token-secret">(rmt_[A-Za-z0-9_-]+)</code>', page.text)
    assert match, "the token was not shown"
    return match.group(1)


def wait_for(client: TestClient, job_id: int) -> dict[str, Any]:
    """The loop from docs/api.md: poll until finished, then read the state."""
    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        job: dict[str, Any] = client.get(f"{API}/jobs/{job_id}").json()
        if job["finished"]:
            return job
        time.sleep(0.1)
    raise AssertionError(f"job {job_id} did not finish")


@pytest.fixture
def repository_slug(
    admin_client: TestClient, repository_root: Path, signing_key: SigningKey
) -> str:
    """A signed APT repository, created through the web interface."""
    response = admin_client.post(
        "/repositories/new",
        data={
            "name": "Pipeline",
            "root_path": str(repository_root / "pipeline"),
            "signing_key_id": str(signing_key.id),
            "retention": "all",
            "format": "apt",
            "codename": CODENAME,
            "components": "main",
            "architectures": "amd64",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    return str(response.headers["location"]).rsplit("/", 1)[-1]


@pytest.fixture
def token(manageable_app: FastAPI, sync_session: Session) -> str:
    return mint_a_token(manageable_app)


def test_a_package_published_through_the_api_is_installable(
    manageable_app: FastAPI,
    repository_slug: str,
    repository_root: Path,
    signing_key: SigningKey,
    token: str,
    tmp_path: Path,
) -> None:
    """Mint, publish, poll, install -- the whole promise of this milestone."""
    deb = build_deb(DebSpec(name="hello", version="1.0-1"), tmp_path / "hello.deb")

    with browser(manageable_app) as pipeline:
        pipeline.headers.update({"authorization": f"Bearer {token}"})
        upload = pipeline.post(
            f"{API}/repositories/{repository_slug}/packages",
            data={"distribution": CODENAME, "component": "main"},
            files={"file": ("hello_1.0-1_amd64.deb", deb.read_bytes())},
        )
        assert upload.status_code == 201, upload.text
        published = upload.json()
        assert wait_for(pipeline, published["job_id"])["state"] == "succeeded"

    root = repository_root / "pipeline"
    apt = IsolatedApt(tmp_path / "aptroot", root, root / f"{signing_key.name}.asc")
    apt.configure(CODENAME, "main")

    refreshed = apt.update()
    assert refreshed.ok, refreshed.output

    policy = apt.policy("hello")
    assert policy.ok, policy.output
    assert "Candidate: 1.0-1" in policy.stdout

    # The path the API reported is the path apt fetches from.
    assert (root / published["package"]["path"]).is_file()


def test_a_second_version_published_later_becomes_the_candidate(
    manageable_app: FastAPI,
    repository_slug: str,
    repository_root: Path,
    signing_key: SigningKey,
    token: str,
    tmp_path: Path,
) -> None:
    """The regenerate-over-an-existing-tree path, which is the common one."""
    with browser(manageable_app) as pipeline:
        pipeline.headers.update({"authorization": f"Bearer {token}"})
        for version in ("1.0-1", "1.1-1"):
            deb = build_deb(
                DebSpec(name="hello", version=version), tmp_path / f"hello-{version}.deb"
            )
            response = pipeline.post(
                f"{API}/repositories/{repository_slug}/packages",
                data={"distribution": CODENAME, "component": "main"},
                files={"file": (f"hello_{version}_amd64.deb", deb.read_bytes())},
            )
            assert response.status_code == 201, response.text
            assert wait_for(pipeline, response.json()["job_id"])["state"] == "succeeded"

    root = repository_root / "pipeline"
    apt = IsolatedApt(tmp_path / "aptroot", root, root / f"{signing_key.name}.asc")
    apt.configure(CODENAME, "main")
    assert apt.update().ok

    policy = apt.policy("hello")
    assert "Candidate: 1.1-1" in policy.stdout
    assert "1.0-1" in policy.stdout


def test_apt_stops_offering_a_package_removed_through_the_api(
    manageable_app: FastAPI,
    repository_slug: str,
    repository_root: Path,
    signing_key: SigningKey,
    token: str,
    tmp_path: Path,
) -> None:
    deb = build_deb(DebSpec(name="hello", version="1.0-1"), tmp_path / "hello.deb")
    root = repository_root / "pipeline"
    apt = IsolatedApt(tmp_path / "aptroot", root, root / f"{signing_key.name}.asc")
    apt.configure(CODENAME, "main")

    with browser(manageable_app) as pipeline:
        pipeline.headers.update({"authorization": f"Bearer {token}"})
        published = pipeline.post(
            f"{API}/repositories/{repository_slug}/packages",
            data={"distribution": CODENAME, "component": "main"},
            files={"file": ("hello.deb", deb.read_bytes())},
        ).json()
        assert wait_for(pipeline, published["job_id"])["state"] == "succeeded"
        assert apt.update().ok
        assert apt.policy("hello").ok

        removal = pipeline.delete(
            f"{API}/repositories/{repository_slug}/packages/{published['package']['id']}"
        )
        assert removal.status_code == 200, removal.text
        assert wait_for(pipeline, removal.json()["job_id"])["state"] == "succeeded"

    assert apt.update().ok
    # `apt-cache show` fails outright for a package no index mentions, which is
    # a clearer answer than `policy`, which prints a stanza either way.
    assert not apt.show("hello").ok
    assert not (root / published["package"]["path"]).exists()


def test_a_revoked_token_cannot_publish(
    manageable_app: FastAPI, repository_slug: str, token: str, tmp_path: Path
) -> None:
    """Revocation takes effect on the next request, not on the next interval."""
    with browser(manageable_app) as owner:
        sign_in(owner, fake_directory.ADMIN_USERNAME, fake_directory.ADMIN_PASSWORD)
        page = owner.get("/tokens").text
        match = re.search(r'action="[^"]*/tokens/(\d+)/revoke"', page)
        assert match, "no revoke control rendered"
        owner.post(f"/tokens/{match.group(1)}/revoke")

    deb = build_deb(DebSpec(name="hello", version="1.0-1"), tmp_path / "hello.deb")
    with browser(manageable_app) as pipeline:
        pipeline.headers.update({"authorization": f"Bearer {token}"})
        response = pipeline.post(
            f"{API}/repositories/{repository_slug}/packages",
            data={"distribution": CODENAME, "component": "main"},
            files={"file": ("hello.deb", deb.read_bytes())},
        )
    assert response.status_code == 401
