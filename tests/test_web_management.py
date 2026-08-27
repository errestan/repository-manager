"""Management routes: keys, creation, upload, removal, jobs (specification.md 8.1)."""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from repository_manager.models import KeyAlgorithm, SigningKey
from repository_manager.web.deps import MAX_FORM_FIELDS
from tests.conftest import AppFactory, Keyring, browser, sign_in
from tests.support.debs import DebSpec, build_deb
from tests.support.directory import ADMIN_PASSWORD, ADMIN_USERNAME


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
def created(admin_client: TestClient, repository_root: Path, signing_key: SigningKey) -> str:
    """A repository created through the web interface, returning its slug.

    The signing key is inserted directly rather than generated through the form:
    generating one costs about 1.5 seconds, and paying that in every test that
    merely needs *a* repository would dominate the suite.  The generate-through-
    the-form path has its own tests above.
    """
    key_id = _first_key_id(admin_client)
    response = admin_client.post(
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


# ------------------------------------------------------------------ keys


def test_a_key_can_be_generated_through_the_form(admin_client: TestClient) -> None:
    response = admin_client.post(
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
    assert "fresh" in admin_client.get("/keys").text


def test_an_invalid_key_name_is_reported_on_the_form(admin_client: TestClient) -> None:
    response = admin_client.post(
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


def test_a_rejected_key_form_keeps_what_was_typed(admin_client: TestClient) -> None:
    """Re-rendered, not redirected, so nothing entered is lost (11)."""
    response = admin_client.post(
        "/keys",
        data={
            "action": "generate",
            "name": "Bad Name",
            "display_name": "Kept",
            "algorithm": "ed25519",
        },
    )
    assert 'value="Kept"' in response.text


def test_a_pasted_private_key_is_not_echoed_back(admin_client: TestClient) -> None:
    """Private key material should not make a second trip to the browser (10.5)."""
    # Assembled rather than written out: the literal armour marker trips the
    # detect-private-key hook, and this is not a key in any case.
    marker = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"
    secret = f"{marker}\nnot-really-a-key\n"
    response = admin_client.post(
        "/keys", data={"action": "import", "name": "imported", "armored": secret}
    )
    assert response.status_code == 400
    assert "not-really-a-key" not in response.text


def test_the_public_key_is_downloadable(admin_client: TestClient, signing_key: SigningKey) -> None:
    response = admin_client.get(f"/keys/{signing_key.name}/public.asc")
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
    admin_client: TestClient, created: str, signing_key: SigningKey
) -> None:
    response = admin_client.post(f"/keys/{signing_key.name}/delete", follow_redirects=False)
    assert response.status_code == 409
    assert any("still signs" in message for message in errors_in(response))


# ------------------------------------------------------------------ creation


def test_a_repository_is_created_and_becomes_browsable(
    admin_client: TestClient, created: str, repository_root: Path
) -> None:
    assert created == "internal-apt"
    body = admin_client.get(f"/repositories/{created}").text
    assert "bookworm" in body
    assert "amd64" in body
    assert (repository_root / "internal" / "dists" / "bookworm" / "InRelease").is_file()


def test_the_detail_page_offers_a_working_client_snippet(
    admin_client: TestClient, created: str
) -> None:
    body = admin_client.get(f"/repositories/{created}").text
    assert "deb [signed-by=/usr/share/keyrings/test-key.asc]" in body
    # Components are normalised to sorted order, so the line the user copies
    # matches the Release that regeneration will keep producing.
    assert "bookworm contrib main" in body


def test_creation_requires_a_retention_decision(
    admin_client: TestClient, repository_root: Path
) -> None:
    """No implicit default: unbounded growth must be deliberate (5.3)."""
    response = admin_client.post(
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
    admin_client: TestClient, tmp_path: Path, signing_key: SigningKey
) -> None:
    response = admin_client.post(
        "/repositories/new",
        data={
            "name": "Escapee",
            "root_path": str(tmp_path / "outside"),
            "signing_key_id": _first_key_id(admin_client),
            "retention": "all",
            "codename": "bookworm",
            "components": "main",
            "architectures": "amd64",
        },
    )
    assert response.status_code == 400
    assert any("permitted root" in message for message in errors_in(response))


def test_creation_without_a_key_explains_why(admin_client: TestClient) -> None:
    body = admin_client.get("/repositories/new").text
    assert "no signing keys yet" in body
    assert "Create a signing key" in body


# ------------------------------------------------------------------ upload


def test_a_package_is_uploaded_indexed_and_listed(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    target = component_id(admin_client, created, "bookworm / main")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")

    response = admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("anything.deb", deb.read_bytes())},
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)
    wait_for_jobs(admin_client)

    listing = admin_client.get(f"/repositories/{created}/packages").text
    assert "alpha" in listing
    index = repository_root / "internal/dists/bookworm/main/binary-amd64/Packages"
    assert "Package: alpha" in index.read_text()


def test_the_uploaded_filename_is_never_used_as_a_path(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    """The stored path comes from parsed metadata alone (10.2)."""
    target = component_id(admin_client, created, "bookworm / main")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("../../../../tmp/evil.deb", deb.read_bytes())},
        follow_redirects=False,
    )
    pool = sorted(p.relative_to(repository_root) for p in repository_root.rglob("*.deb"))
    assert pool == [Path("internal/pool/main/a/alpha/alpha_1.0-1_amd64.deb")]


def test_uploading_something_that_is_not_a_package_is_reported(
    admin_client: TestClient, created: str
) -> None:
    target = component_id(admin_client, created, "bookworm / main")
    response = admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("x.deb", b"definitely not a deb")},
    )
    assert response.status_code == 400
    assert any("not a Debian package" in message for message in errors_in(response))


def test_a_conflicting_rebuild_is_refused_with_409(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    target = component_id(admin_client, created, "bookworm / main")
    first = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("a.deb", first.read_bytes())},
    )
    altered = build_deb(
        DebSpec(name="alpha", version="1.0-1", homepage="https://changed.test/"), tmp_path / "b.deb"
    )
    response = admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("a.deb", altered.read_bytes())},
    )
    assert response.status_code == 409


def test_uploading_with_no_target_is_reported(admin_client: TestClient, created: str) -> None:
    response = admin_client.post(
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
    app = make_app(max_upload_bytes=256, gnupghome=str(scratch_keyring.home))
    with browser(app) as client:
        sign_in(client, ADMIN_USERNAME, ADMIN_PASSWORD)
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
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    target = component_id(admin_client, created, "bookworm / main")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("a.deb", deb.read_bytes())},
    )
    wait_for_jobs(admin_client)

    listing = admin_client.get(f"/repositories/{created}/packages").text
    publication_id = re.search(r"/packages/(\d+)/delete", listing).group(1)  # type: ignore[union-attr]
    response = admin_client.post(
        f"/repositories/{created}/packages/{publication_id}/delete", follow_redirects=False
    )
    assert response.status_code == 303
    wait_for_jobs(admin_client)

    index = repository_root / "internal/dists/bookworm/main/binary-amd64/Packages"
    assert index.read_bytes() == b""
    assert list(repository_root.rglob("*.deb")) == []


def test_removing_an_unknown_publication_is_a_404(admin_client: TestClient, created: str) -> None:
    response = admin_client.post(f"/repositories/{created}/packages/9999/delete")
    assert response.status_code == 404


# ------------------------------------------------------------------ search


def test_the_package_list_can_be_filtered(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    target = component_id(admin_client, created, "bookworm / main")
    for name, arch in (("alpha", "amd64"), ("beta", "arm64"), ("libgamma", "all")):
        deb = build_deb(
            DebSpec(name=name, version="1.0-1", architecture=arch, source=name),
            tmp_path / f"{name}.deb",
        )
        admin_client.post(
            f"/repositories/{created}/packages/upload",
            data={"target": target},
            files={"package": (f"{name}.deb", deb.read_bytes())},
        )

    body = admin_client.get(f"/repositories/{created}/packages?q=gamma").text
    assert "libgamma" in body
    assert ">alpha<" not in body

    by_arch = admin_client.get(f"/repositories/{created}/packages?arch=arm64").text
    assert "beta" in by_arch
    assert ">alpha<" not in by_arch


def test_a_search_wildcard_is_escaped_rather_than_interpreted(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    """Searching for '_' must not match every package (10.2)."""
    target = component_id(admin_client, created, "bookworm / main")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target},
        files={"package": ("a.deb", deb.read_bytes())},
    )
    body = admin_client.get(f"/repositories/{created}/packages?q=_").text
    assert "0 publications found" in body


# ------------------------------------------------------------------ jobs


def test_a_job_page_reports_its_outcome(admin_client: TestClient, created: str) -> None:
    response = admin_client.post(f"/repositories/{created}/regenerate", follow_redirects=False)
    assert response.status_code == 303
    wait_for_jobs(admin_client)

    detail = admin_client.get(response.headers["location"]).text
    assert "Succeeded" in detail
    assert "Wrote" in detail


def test_job_state_is_not_conveyed_by_colour_alone(admin_client: TestClient, created: str) -> None:
    """Status carries a word as well as a symbol (11)."""
    admin_client.post(f"/repositories/{created}/regenerate")
    body = wait_for_jobs(admin_client)
    assert "Succeeded" in body


def test_an_unknown_job_is_a_404(admin_client: TestClient) -> None:
    assert admin_client.get("/jobs/9999").status_code == 404


# ------------------------------------------------------------------ distributions


def test_a_distribution_can_be_added_and_is_published(
    admin_client: TestClient, created: str, repository_root: Path
) -> None:
    response = admin_client.post(
        f"/repositories/{created}/distributions",
        data={"codename": "trixie", "components": "main", "architectures": "amd64"},
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)
    wait_for_jobs(admin_client)
    assert (repository_root / "internal/dists/trixie/InRelease").is_file()


def test_a_duplicate_codename_is_refused(admin_client: TestClient, created: str) -> None:
    response = admin_client.post(
        f"/repositories/{created}/distributions",
        data={"codename": "bookworm", "components": "main", "architectures": "amd64"},
    )
    assert response.status_code == 400
    assert any("already has a distribution" in message for message in errors_in(response))


def test_generated_keys_offer_every_supported_algorithm(admin_client: TestClient) -> None:
    body = admin_client.get("/keys").text
    for algorithm in KeyAlgorithm:
        assert algorithm.label in body


def test_a_package_larger_than_one_mebibyte_uploads(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    """A real package is bigger than any of Starlette's default form limits.

    The no-JavaScript path is the one worth guarding: the CSRF token arrives as
    a form field, so the security gate has to read the multipart body before the
    handler does, and Starlette caches whatever the first read produced.  Both
    reads therefore have to ask for the same limits, or the handler silently
    gets a form parsed under someone else's.
    """
    target = component_id(admin_client, created, "bookworm / main")
    package = build_deb(
        DebSpec(
            name="chunky",
            version="1.0-1",
            architecture="amd64",
            # Random bytes, so gzip cannot shrink the .deb back under the limit.
            payload={"./usr/lib/chunky/blob": os.urandom(2 * 1024 * 1024)},
        ),
        tmp_path / "chunky.deb",
    ).read_bytes()
    assert len(package) > 1024 * 1024, "fixture is not actually over the limit"

    # No X-CSRF-Token header: the hidden form field is the path a browser with
    # JavaScript disabled takes, and it is the one that makes the check parse
    # the multipart body itself.
    token = admin_client.headers.pop("x-csrf-token")
    response = admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target, "_csrf": token},
        files={"package": ("chunky.deb", package)},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text


def test_the_form_limits_survive_the_csrf_check(admin_client: TestClient, created: str) -> None:
    """The gate reads the body first, so its limits become the handler's (5.1).

    Sending more fields than the application's own limit allows must still be
    refused -- if the gate parsed with Starlette's much larger defaults, the
    handler's stricter request would be ignored, because the form is cached and
    the handler's own call returns whatever the first read produced.

    The status is 400 rather than 413 because Starlette turns a parser refusal
    into ``HTTPException(400)`` before anything here sees it; the page is still
    this application's error page.
    """
    token = admin_client.headers.pop("x-csrf-token")
    payload = {f"filler{index}": "x" for index in range(MAX_FORM_FIELDS + 5)}
    response = admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"_csrf": token, **payload},
        files={"package": ("x.deb", b"not a package")},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "Maximum number of fields" in response.text
    assert response.headers["content-type"].startswith("text/html")
