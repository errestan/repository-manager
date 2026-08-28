"""The RPM half of the web interface (specification.md 4.2, 4.3, 5.1, 8.1).

Every flow here is driven through the forms a browser would submit, with no
JavaScript, because that is the contract the interface makes (11).
``createrepo_c`` is the stand-in from ``conftest``; the real tool is exercised
in ``tests/integration``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from repository_manager.models import SigningKey
from tests.conftest import FakeCreaterepo
from tests.support.rpms import RpmSpec, build_rpm, build_simple


def errors_in(response: object) -> list[str]:
    body = getattr(response, "text", "")
    return [text.strip() for text in re.findall(r'<a href="#field-[^"]+">([^<]+)</a>', body)]


def _first_key_id(client: TestClient) -> str:
    page = client.get("/repositories/new").text
    match = re.search(r'<option value="(\d+)"', page)
    assert match, "no signing key offered"
    return match.group(1)


def target_id(client: TestClient, slug: str, label: str) -> str:
    """The option value the upload form renders for one variant."""
    page = client.get(f"/repositories/{slug}/packages/upload").text
    match = re.search(rf'<option value="(\d+)"[^>]*>{re.escape(label)}</option>', page)
    assert match, f"{label} is not offered as a target"
    return match.group(1)


@pytest.fixture
def created(
    admin_client: TestClient,
    repository_root: Path,
    signing_key: SigningKey,
    fake_createrepo: FakeCreaterepo,
) -> str:
    """An RPM repository created through the web interface, returning its slug."""
    response = admin_client.post(
        "/repositories/new",
        data={
            "name": "Enterprise Linux 9",
            "root_path": str(repository_root / "el9"),
            "signing_key_id": _first_key_id(admin_client),
            "retention": "all",
            "format": "rpm",
            "variant_name": "el9",
            "variant_arch": "x86_64",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)
    return str(response.headers["location"]).rsplit("/", 1)[-1]


# ------------------------------------------------------------------ creation


def test_an_rpm_repository_is_created_and_becomes_browsable(
    admin_client: TestClient, created: str, repository_root: Path
) -> None:
    body = admin_client.get(f"/repositories/{created}").text

    assert "Enterprise Linux 9" in body
    assert "RPM" in body
    assert "el9" in body
    assert (repository_root / "el9" / "el9" / "x86_64" / "repodata" / "repomd.xml").is_file()
    assert (repository_root / "el9" / "el9" / "x86_64" / "repodata" / "repomd.xml.asc").is_file()


def test_the_format_is_a_required_choice(
    admin_client: TestClient, repository_root: Path, signing_key: SigningKey
) -> None:
    """The one decision that cannot be undone is never guessed at (4.3)."""
    response = admin_client.post(
        "/repositories/new",
        data={
            "name": "Undecided",
            "root_path": str(repository_root / "undecided"),
            "signing_key_id": _first_key_id(admin_client),
            "retention": "all",
            "variant_name": "el9",
            "variant_arch": "x86_64",
        },
    )
    assert response.status_code == 400
    assert any("APT or RPM" in message for message in errors_in(response))


def test_an_rpm_repository_still_needs_a_variant(
    admin_client: TestClient,
    repository_root: Path,
    signing_key: SigningKey,
    fake_createrepo: FakeCreaterepo,
) -> None:
    response = admin_client.post(
        "/repositories/new",
        data={
            "name": "Variantless",
            "root_path": str(repository_root / "variantless"),
            "signing_key_id": _first_key_id(admin_client),
            "retention": "all",
            "format": "rpm",
        },
    )
    assert response.status_code == 400
    assert any("Variant name is required" in message for message in errors_in(response))


def test_the_creation_form_offers_both_subdivisions_without_javascript(
    admin_client: TestClient, signing_key: SigningKey
) -> None:
    body = admin_client.get("/repositories/new").text

    assert "First distribution" in body
    assert "First variant" in body
    assert 'name="variant_name"' in body
    assert 'name="codename"' in body
    assert "<script" not in body


# ------------------------------------------------------------------ variants


def test_a_variant_can_be_added_and_is_published(
    admin_client: TestClient, created: str, repository_root: Path
) -> None:
    response = admin_client.post(
        f"/repositories/{created}/variants",
        data={"variant_name": "el8", "variant_arch": "aarch64"},
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)

    body = admin_client.get(f"/repositories/{created}/variants").text
    assert "el8/aarch64" in body
    # The rebuild is queued rather than done inline, so the tree appears when
    # the job runs (5.4).
    assert admin_client.get("/jobs").text.count("Regenerate metadata") >= 1


def test_a_duplicate_variant_is_refused(admin_client: TestClient, created: str) -> None:
    response = admin_client.post(
        f"/repositories/{created}/variants",
        data={"variant_name": "el9", "variant_arch": "x86_64"},
    )
    assert response.status_code == 400
    assert any("already has a variant" in message for message in errors_in(response))


def test_a_variant_name_that_could_escape_the_root_is_refused(
    admin_client: TestClient, created: str
) -> None:
    response = admin_client.post(
        f"/repositories/{created}/variants",
        data={"variant_name": "../..", "variant_arch": "x86_64"},
    )
    assert response.status_code == 400
    assert any("traverse upward" in message for message in errors_in(response))


def test_the_variants_page_is_not_offered_for_an_apt_repository(
    admin_client: TestClient, repository_root: Path, signing_key: SigningKey
) -> None:
    admin_client.post(
        "/repositories/new",
        data={
            "name": "Debian",
            "root_path": str(repository_root / "debian"),
            "signing_key_id": _first_key_id(admin_client),
            "retention": "all",
            "format": "apt",
            "codename": "bookworm",
            "components": "main",
            "architectures": "amd64",
        },
    )
    assert admin_client.get("/repositories/debian/variants").status_code == 404
    assert admin_client.get("/repositories/debian/distributions").status_code == 200


# -------------------------------------------------------------------- upload


def test_a_package_is_uploaded_into_a_variant_and_listed(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    package = build_simple(tmp_path / "any-name.rpm", name="example", version="1.0")
    response = admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target_id(admin_client, created, "el9/x86_64")},
        files={"package": ("uploaded.rpm", package.read_bytes())},
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)

    body = admin_client.get(f"/repositories/{created}/packages").text
    assert "example" in body
    assert "el9/x86_64" in body
    assert (
        repository_root / "el9" / "el9" / "x86_64" / "Packages" / "example-1.0-1.el9.x86_64.rpm"
    ).is_file()


def test_a_deb_uploaded_to_an_rpm_repository_is_reported_clearly(
    admin_client: TestClient, created: str
) -> None:
    """The commonest mistake, and the message says which signature was expected."""
    response = admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target_id(admin_client, created, "el9/x86_64")},
        files={"package": ("example.deb", b"!<arch>\n" + b"x" * 200)},
    )
    assert response.status_code == 400
    assert any("0xEDABEEDB" in message for message in errors_in(response))


def test_a_package_for_the_wrong_architecture_is_refused(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    package = build_simple(tmp_path / "a.rpm", name="example", architecture="aarch64")
    response = admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target_id(admin_client, created, "el9/x86_64")},
        files={"package": ("a.rpm", package.read_bytes())},
    )
    assert response.status_code == 400
    assert any("publishes x86_64 and noarch only" in message for message in errors_in(response))


def test_a_source_package_is_refused(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    package = build_rpm(RpmSpec(name="example", source_rpm=None), tmp_path / "a.src.rpm")
    response = admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target_id(admin_client, created, "el9/x86_64")},
        files={"package": ("a.src.rpm", package.read_bytes())},
    )
    assert response.status_code == 400
    assert any("source package" in message for message in errors_in(response))


def test_the_upload_form_asks_for_an_rpm(admin_client: TestClient, created: str) -> None:
    body = admin_client.get(f"/repositories/{created}/packages/upload").text

    assert 'accept=".rpm,application/x-rpm"' in body
    assert "Choose a variant…" in body
    assert ".src.rpm" in body


def test_a_removed_package_leaves_the_variant_in_place(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    package = build_simple(tmp_path / "a.rpm", name="example")
    admin_client.post(
        f"/repositories/{created}/packages/upload",
        data={"target": target_id(admin_client, created, "el9/x86_64")},
        files={"package": ("a.rpm", package.read_bytes())},
    )
    body = admin_client.get(f"/repositories/{created}/packages").text
    publication_id = re.search(r"/packages/(\d+)/delete", body)
    assert publication_id

    response = admin_client.post(
        f"/repositories/{created}/packages/{publication_id.group(1)}/delete",
        follow_redirects=False,
    )
    assert response.status_code == 303

    variant = repository_root / "el9" / "el9" / "x86_64"
    assert list((variant / "Packages").glob("*.rpm")) == []
    assert (variant / "Packages").is_dir()


# --------------------------------------------------------------- client setup


def test_the_detail_page_offers_a_usable_repo_file(admin_client: TestClient, created: str) -> None:
    """A ``.repo`` file a user can paste and have work first time (4.4)."""
    body = admin_client.get(f"/repositories/{created}").text

    assert "[enterprise-linux-9-el9-x86_64]" in body
    assert "baseurl=https://packages.example.test/repos/enterprise-linux-9/el9/x86_64" in body
    assert "gpgcheck=1" in body
    assert "repo_gpgcheck=1" in body
    assert "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-test-key" in body
    assert "/etc/yum.repos.d/enterprise-linux-9.repo" in body
    # The apt spelling must not leak into an RPM page.
    assert "sources.list" not in body


def test_each_variant_gets_its_own_repo_section(admin_client: TestClient, created: str) -> None:
    admin_client.post(
        f"/repositories/{created}/variants",
        data={"variant_name": "el8", "variant_arch": "aarch64"},
    )
    body = admin_client.get(f"/repositories/{created}").text

    assert "[enterprise-linux-9-el9-x86_64]" in body
    assert "[enterprise-linux-9-el8-aarch64]" in body


def test_the_package_filter_offers_noarch_rather_than_all(
    admin_client: TestClient, created: str
) -> None:
    body = admin_client.get(f"/repositories/{created}/packages").text

    assert ">noarch</option>" in body
    assert ">all</option>" not in body
