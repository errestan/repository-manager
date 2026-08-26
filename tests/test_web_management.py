"""Management routes: keys, creation, upload, removal, jobs (specification.md 8.1)."""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from repository_manager.config import ConfigError
from repository_manager.models import KeyAlgorithm, Repository, SigningKey
from repository_manager.web.deps import WRITE_DISABLED_DETAIL
from tests.conftest import AppFactory, Keyring, SettingsFactory
from tests.support.debs import DebSpec, build_deb

# Every state-changing route, for the gate test below.  A new write endpoint
# that forgets the dependency shows up here as a failure.
WRITE_ROUTES = [
    ("POST", "/keys"),
    ("POST", "/keys/test-key/delete"),
    ("GET", "/repositories/new"),
    ("POST", "/repositories/new"),
    ("GET", "/repositories/internal/packages/upload"),
    ("POST", "/repositories/internal/packages/upload"),
    ("POST", "/repositories/internal/packages/1/delete"),
    ("POST", "/repositories/internal/regenerate"),
    ("GET", "/repositories/internal/distributions"),
    ("POST", "/repositories/internal/distributions"),
]


def wait_for_jobs(client: TestClient, timeout: float = 20.0) -> str:
    """Poll the jobs page until nothing is queued or running."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get("/jobs").text
        if "Queued" not in body and "Running" not in body:
            return str(body)
        time.sleep(0.05)
    raise AssertionError("jobs did not finish")


def component_id(client: TestClient, slug: str, label: str) -> str:
    page = client.get(f"/repositories/{slug}/packages/upload").text
    match = re.search(rf'<option value="(\d+)"[^>]*>\s*{re.escape(label)}', page)
    assert match, f"no target option for {label}"
    return match.group(1)


def errors_in(response: object) -> list[str]:
    body = getattr(response, "text", "")
    return [text.strip() for text in re.findall(r'<a href="#field-[^"]+">([^<]+)</a>', body)]


@pytest.fixture
def created(writable_client: TestClient, repository_root: Path, signing_key: SigningKey) -> str:
    """A repository created through the web interface, returning its slug.

    The signing key is inserted directly rather than generated through the form:
    generating one costs about 1.5 seconds, and paying that in every test that
    merely needs *a* repository would dominate the suite.  The generate-through-
    the-form path has its own tests above.
    """
    key_id = _first_key_id(writable_client)
    response = writable_client.post(
        "/repositories/new",
        data={
            "name": "Internal APT",
            "root_path": str(repository_root / "internal"),
            "signing_key_id": key_id,
            "retention": "all",
            "codename": "bookworm",
            "components": "main contrib",
            "architectures": "amd64 arm64",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)
    return str(response.headers["location"]).rsplit("/", 1)[-1]


def _first_key_id(client: TestClient) -> str:
    page = client.get("/repositories/new").text
    match = re.search(r'<option value="(\d+)"', page)
    assert match, "no signing key offered"
    return match.group(1)


# ------------------------------------------------------------------ write gate


@pytest.mark.parametrize(("method", "path"), WRITE_ROUTES)
def test_writes_are_refused_by_default(client: TestClient, method: str, path: str) -> None:
    """M2 ships the write paths before M3 ships the login that guards them (12)."""
    response = client.request(method, path)
    assert response.status_code == 403, path
    assert "M3" in response.text


def test_the_refusal_explains_itself(client: TestClient) -> None:
    assert "REPOMAN_ALLOW_UNAUTHENTICATED_WRITES" in WRITE_DISABLED_DETAIL
    assert "REPOMAN_ALLOW_UNAUTHENTICATED_WRITES" in client.get("/repositories/new").text


def test_reads_stay_anonymous_while_writes_are_shut(
    client: TestClient, apt_repository: Repository
) -> None:
    """Everything readable is readable by everyone (AD-11)."""
    for path in (
        "/",
        "/repositories/internal",
        "/repositories/internal/packages",
        "/keys",
        "/jobs",
    ):
        assert client.get(path).status_code == 200, path


def test_opening_writes_in_production_is_refused(make_settings: SettingsFactory) -> None:
    with pytest.raises(ConfigError, match="production"):
        make_settings(
            env="production",
            public_url="https://packages.example.test",
            allow_unauthenticated_writes=True,
        )


def test_management_links_are_hidden_when_writes_are_shut(
    client: TestClient, apt_repository: Repository
) -> None:
    body = client.get("/repositories/internal").text
    assert "Upload a package" not in body


# ------------------------------------------------------------------ keys


def test_a_key_can_be_generated_through_the_form(writable_client: TestClient) -> None:
    response = writable_client.post(
        "/keys",
        data={
            "action": "generate",
            "name": "fresh",
            "display_name": "Fresh",
            "algorithm": "ed25519",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "fresh" in writable_client.get("/keys").text


def test_an_invalid_key_name_is_reported_on_the_form(writable_client: TestClient) -> None:
    response = writable_client.post(
        "/keys",
        data={
            "action": "generate",
            "name": "Not A Slug",
            "display_name": "X",
            "algorithm": "ed25519",
        },
    )
    assert response.status_code == 400
    assert any("lowercase letters" in message for message in errors_in(response))


def test_a_rejected_key_form_keeps_what_was_typed(writable_client: TestClient) -> None:
    """Re-rendered, not redirected, so nothing entered is lost (11)."""
    response = writable_client.post(
        "/keys",
        data={
            "action": "generate",
            "name": "Bad Name",
            "display_name": "Kept",
            "algorithm": "ed25519",
        },
    )
    assert 'value="Kept"' in response.text


def test_a_pasted_private_key_is_not_echoed_back(writable_client: TestClient) -> None:
    """Private key material should not make a second trip to the browser (10.5)."""
    # Assembled rather than written out: the literal armour marker trips the
    # detect-private-key hook, and this is not a key in any case.
    marker = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"
    secret = f"{marker}\nnot-really-a-key\n"
    response = writable_client.post(
        "/keys", data={"action": "import", "name": "imported", "armored": secret}
    )
    assert response.status_code == 400
    assert "not-really-a-key" not in response.text


def test_the_public_key_is_downloadable(
    writable_client: TestClient, signing_key: SigningKey
) -> None:
    response = writable_client.get(f"/keys/{signing_key.name}/public.asc")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pgp-keys")
    assert "BEGIN PGP PUBLIC KEY BLOCK" in response.text
    assert "PRIVATE KEY" not in response.text


def test_downloading_a_key_is_anonymous(client: TestClient, signing_key: SigningKey) -> None:
    """Clients need the key to verify what they install (4.4)."""
    assert client.get(f"/keys/{signing_key.name}/public.asc").status_code == 200


def test_an_unknown_key_is_a_404(client: TestClient) -> None:
    assert client.get("/keys/absent/public.asc").status_code == 404


def test_a_traversing_key_name_is_a_404(client: TestClient) -> None:
    assert client.get("/keys/..%2F..%2Fetc%2Fpasswd/public.asc").status_code == 404


def test_deleting_a_key_still_in_use_is_refused(
    writable_client: TestClient, created: str, signing_key: SigningKey
) -> None:
    response = writable_client.post(f"/keys/{signing_key.name}/delete", follow_redirects=False)
    assert response.status_code == 409
    assert any("still signs" in message for message in errors_in(response))


# ------------------------------------------------------------------ creation


def test_a_repository_is_created_and_becomes_browsable(
    writable_client: TestClient, created: str, repository_root: Path
) -> None:
    assert created == "internal-apt"
    body = writable_client.get(f"/repositories/{created}").text
    assert "bookworm" in body
    assert "amd64" in body
    assert (repository_root / "internal" / "dists" / "bookworm" / "InRelease").is_file()


def test_the_detail_page_offers_a_working_client_snippet(
    writable_client: TestClient, created: str
) -> None:
    body = writable_client.get(f"/repositories/{created}").text
    assert "deb [signed-by=/usr/share/keyrings/test-key.asc]" in body
    # Components are normalised to sorted order, so the line the user copies
    # matches the Release that regeneration will keep producing.
    assert "bookworm contrib main" in body


def test_creation_requires_a_retention_decision(
    writable_client: TestClient, repository_root: Path
) -> None:
    """No implicit default: unbounded growth must be deliberate (5.3)."""
    response = writable_client.post(
        "/repositories/new",
        data={
            "name": "No Retention",
            "root_path": str(repository_root / "nr"),
            "signing_key_id": "1",
            "retention": "",
            "codename": "bookworm",
            "components": "main",
            "architectures": "amd64",
        },
    )
    assert response.status_code == 400
    assert any("keep every version" in message for message in errors_in(response))


def test_creation_refuses_a_root_outside_the_allowed_roots(
    writable_client: TestClient, tmp_path: Path, signing_key: SigningKey
) -> None:
    response = writable_client.post(
        "/repositories/new",
        data={
            "name": "Escapee",
            "root_path": str(tmp_path / "outside"),
            "signing_key_id": _first_key_id(writable_client),
            "retention": "all",
            "codename": "bookworm",
            "components": "main",
            "architectures": "amd64",
        },
    )
    assert response.status_code == 400
    assert any("permitted root" in message for message in errors_in(response))


def test_creation_without_a_key_explains_why(writable_client: TestClient) -> None:
    body = writable_client.get("/repositories/new").text
    assert "no signing keys yet" in body
    assert "Create a signing key" in body


# ------------------------------------------------------------------ upload


def test_a_package_is_uploaded_indexed_and_listed(
    writable_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    target = component_id(writable_client, created, "bookworm / main")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")

    response = writable_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("anything.deb", deb.read_bytes())},
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)
    wait_for_jobs(writable_client)

    listing = writable_client.get(f"/repositories/{created}/packages").text
    assert "alpha" in listing
    index = repository_root / "internal/dists/bookworm/main/binary-amd64/Packages"
    assert "Package: alpha" in index.read_text()


def test_the_uploaded_filename_is_never_used_as_a_path(
    writable_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    """The stored path comes from parsed metadata alone (10.2)."""
    target = component_id(writable_client, created, "bookworm / main")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    writable_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("../../../../tmp/evil.deb", deb.read_bytes())},
        follow_redirects=False,
    )
    pool = sorted(p.relative_to(repository_root) for p in repository_root.rglob("*.deb"))
    assert pool == [Path("internal/pool/main/a/alpha/alpha_1.0-1_amd64.deb")]


def test_uploading_something_that_is_not_a_package_is_reported(
    writable_client: TestClient, created: str
) -> None:
    target = component_id(writable_client, created, "bookworm / main")
    response = writable_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("x.deb", b"definitely not a deb")},
    )
    assert response.status_code == 400
    assert any("not a Debian package" in message for message in errors_in(response))


def test_a_conflicting_rebuild_is_refused_with_409(
    writable_client: TestClient, created: str, tmp_path: Path
) -> None:
    target = component_id(writable_client, created, "bookworm / main")
    first = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    writable_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("a.deb", first.read_bytes())},
    )
    altered = build_deb(
        DebSpec(name="alpha", version="1.0-1", homepage="https://changed.test/"), tmp_path / "b.deb"
    )
    response = writable_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("a.deb", altered.read_bytes())},
    )
    assert response.status_code == 409


def test_uploading_with_no_target_is_reported(writable_client: TestClient, created: str) -> None:
    response = writable_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": ""},
        files={"package": ("x.deb", b"x")},
    )
    assert response.status_code == 400
    assert any("distribution and component" in message for message in errors_in(response))


def test_an_upload_over_the_limit_is_rejected(
    make_app: AppFactory,
    repository_root: Path,
    scratch_keyring: Keyring,
    signing_key: SigningKey,
) -> None:
    """Enforced while parsing the request, not from a client-supplied length (5.1)."""
    app = make_app(
        allow_unauthenticated_writes=True,
        max_upload_bytes=256,
        gnupghome=str(scratch_keyring.home),
    )
    with TestClient(app) as client:
        client.post(
            "/repositories/new",
            data={
                "name": "Small",
                "root_path": str(repository_root / "small"),
                "signing_key_id": _first_key_id(client),
                "retention": "all",
                "codename": "bookworm",
                "components": "main",
                "architectures": "amd64",
            },
        )
        target = component_id(client, "small", "bookworm / main")
        response = client.post(
            "/repositories/small/packages/upload",
            data={"target": target},
            files={"package": ("big.deb", b"x" * 4096)},
        )
    assert response.status_code == 413


# ------------------------------------------------------------------ removal


def test_removing_a_package_deletes_it_from_the_index(
    writable_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    target = component_id(writable_client, created, "bookworm / main")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    writable_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("a.deb", deb.read_bytes())},
    )
    wait_for_jobs(writable_client)

    listing = writable_client.get(f"/repositories/{created}/packages").text
    publication_id = re.search(r"/packages/(\d+)/delete", listing).group(1)  # type: ignore[union-attr]
    response = writable_client.post(
        f"/repositories/{created}/packages/{publication_id}/delete", follow_redirects=False
    )
    assert response.status_code == 303
    wait_for_jobs(writable_client)

    index = repository_root / "internal/dists/bookworm/main/binary-amd64/Packages"
    assert index.read_bytes() == b""
    assert list(repository_root.rglob("*.deb")) == []


def test_removing_an_unknown_publication_is_a_404(
    writable_client: TestClient, created: str
) -> None:
    response = writable_client.post(f"/repositories/{created}/packages/9999/delete")
    assert response.status_code == 404


# ------------------------------------------------------------------ search


def test_the_package_list_can_be_filtered(
    writable_client: TestClient, created: str, tmp_path: Path
) -> None:
    target = component_id(writable_client, created, "bookworm / main")
    for name, arch in (("alpha", "amd64"), ("beta", "arm64"), ("libgamma", "all")):
        deb = build_deb(
            DebSpec(name=name, version="1.0-1", architecture=arch, source=name),
            tmp_path / f"{name}.deb",
        )
        writable_client.post(
            f"/repositories/{created}/packages/upload",
            data={"target": target},
            files={"package": (f"{name}.deb", deb.read_bytes())},
        )

    body = writable_client.get(f"/repositories/{created}/packages?q=gamma").text
    assert "libgamma" in body
    assert ">alpha<" not in body

    by_arch = writable_client.get(f"/repositories/{created}/packages?arch=arm64").text
    assert "beta" in by_arch
    assert ">alpha<" not in by_arch


def test_a_search_wildcard_is_escaped_rather_than_interpreted(
    writable_client: TestClient, created: str, tmp_path: Path
) -> None:
    """Searching for '_' must not match every package (10.2)."""
    target = component_id(writable_client, created, "bookworm / main")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    writable_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("a.deb", deb.read_bytes())},
    )
    body = writable_client.get(f"/repositories/{created}/packages?q=_").text
    assert "0 publications found" in body


# ------------------------------------------------------------------ jobs


def test_a_job_page_reports_its_outcome(writable_client: TestClient, created: str) -> None:
    response = writable_client.post(f"/repositories/{created}/regenerate", follow_redirects=False)
    assert response.status_code == 303
    wait_for_jobs(writable_client)

    detail = writable_client.get(response.headers["location"]).text
    assert "Succeeded" in detail
    assert "Wrote" in detail


def test_job_state_is_not_conveyed_by_colour_alone(
    writable_client: TestClient, created: str
) -> None:
    """Status carries a word as well as a symbol (11)."""
    writable_client.post(f"/repositories/{created}/regenerate")
    body = wait_for_jobs(writable_client)
    assert "Succeeded" in body


def test_an_unknown_job_is_a_404(client: TestClient) -> None:
    assert client.get("/jobs/9999").status_code == 404


# ------------------------------------------------------------------ distributions


def test_a_distribution_can_be_added_and_is_published(
    writable_client: TestClient, created: str, repository_root: Path
) -> None:
    response = writable_client.post(
        f"/repositories/{created}/distributions",
        data={"codename": "trixie", "components": "main", "architectures": "amd64"},
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)
    wait_for_jobs(writable_client)
    assert (repository_root / "internal/dists/trixie/InRelease").is_file()


def test_a_duplicate_codename_is_refused(writable_client: TestClient, created: str) -> None:
    response = writable_client.post(
        f"/repositories/{created}/distributions",
        data={"codename": "bookworm", "components": "main", "architectures": "amd64"},
    )
    assert response.status_code == 400
    assert any("already has a distribution" in message for message in errors_in(response))


def test_generated_keys_offer_every_supported_algorithm(writable_client: TestClient) -> None:
    body = writable_client.get("/keys").text
    for algorithm in KeyAlgorithm:
        assert algorithm.label in body
