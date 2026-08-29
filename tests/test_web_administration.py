"""Settings, retention, rescan and removal through the forms (specification.md 8.1).

The destructive half of the interface, driven the way a browser drives it.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from repository_manager.models import Repository, SigningKey
from tests.conftest import AppFactory, FakeCreaterepo, Keyring, browser, sign_in
from tests.support import directory as fake_directory
from tests.support.debs import DebSpec, build_deb
from tests.support.rpms import build_simple


def errors_in(response: object) -> list[str]:
    body = getattr(response, "text", "")
    return [text.strip() for text in re.findall(r'<a href="#field-[^"]+">([^<]+)</a>', body)]


def delete_id(page: str, kind: str, label: str) -> str:
    """The id of the remove control that belongs to ``label``.

    Matched by looking forward from the label to the form action rather than by
    position in the list: the settings page orders targets by name, so an
    index would silently point at a different one the moment a test adds a
    variant that sorts earlier.
    """
    match = re.search(rf"<code>{re.escape(label)}</code>.*?/{kind}/(\d+)/delete", page, re.DOTALL)
    assert match, f"no {kind} remove control for {label}"
    return match.group(1)


def wait_for_jobs(client: TestClient, timeout: float = 20.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get("/jobs").text
        if "Queued" not in body and "Running" not in body:
            return str(body)
        time.sleep(0.05)
    raise AssertionError("jobs did not finish")


@pytest.fixture
def created(admin_client: TestClient, repository_root: Path, signing_key: SigningKey) -> str:
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
    assert response.status_code == 303, errors_in(response)
    return str(response.headers["location"]).rsplit("/", 1)[-1]


def upload(client: TestClient, slug: str, deb: Path, label: str = "bookworm / main") -> None:
    page = client.get(f"/repositories/{slug}/packages/upload").text
    match = re.search(rf'<option value="(\d+)"[^>]*>\s*{re.escape(label)}', page)
    assert match, f"no target for {label}"
    response = client.post(
        f"/repositories/{slug}/packages/upload",
        data={"target": match.group(1)},
        files={"package": (deb.name, deb.read_bytes())},
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)


# ------------------------------------------------------------------ settings


def test_the_settings_page_shows_what_can_be_changed(
    admin_client: TestClient, created: str
) -> None:
    body = admin_client.get(f"/repositories/{created}/settings").text
    assert "Internal APT" in body
    assert 'name="retention"' in body
    assert 'name="signing_key_id"' in body


def test_a_name_change_is_saved_and_rebuilds_the_metadata(
    admin_client: TestClient, created: str, repository_root: Path
) -> None:
    """The name becomes the Origin and Label in every Release file (4.1)."""
    response = admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Renamed",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": _key_id(admin_client, created),
            "retention": "all",
            "retention_count": "5",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)
    assert "saved=name" in str(response.headers["location"])
    wait_for_jobs(admin_client)

    release = (repository_root / "internal" / "dists" / "bookworm" / "Release").read_text()
    assert "Origin: Renamed" in release


def test_a_description_change_does_not_queue_a_rebuild(
    admin_client: TestClient, created: str
) -> None:
    """Nothing on disk depends on it, and a job list full of no-ops is noise."""
    before = admin_client.get("/jobs").text.count("Regenerate metadata")
    admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Internal APT",
            "description": "Now with a description",
            "origin": "",
            "label": "",
            "signing_key_id": _key_id(admin_client, created),
            "retention": "all",
            "retention_count": "5",
        },
    )
    assert admin_client.get("/jobs").text.count("Regenerate metadata") == before


def test_saving_an_unchanged_form_says_so(admin_client: TestClient, created: str) -> None:
    response = admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Internal APT",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": _key_id(admin_client, created),
            "retention": "all",
            "retention_count": "5",
        },
        follow_redirects=False,
    )
    assert "unchanged=1" in str(response.headers["location"])


def test_an_invalid_retention_count_is_reported_on_the_form(
    admin_client: TestClient, created: str
) -> None:
    response = admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Internal APT",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": _key_id(admin_client, created),
            "retention": "count",
            "retention_count": "0",
        },
    )
    assert response.status_code == 400
    assert any("at least one version" in message for message in errors_in(response))


def _key_id(client: TestClient, slug: str) -> str:
    page = client.get(f"/repositories/{slug}/settings").text
    match = re.search(r'<option value="(\d+)"', page)
    assert match, "no signing key offered"
    return match.group(1)


# ------------------------------------------------------------------ key rotation


def test_rotating_the_key_re_signs_and_removes_the_old_public_key(
    admin_client: TestClient, created: str, repository_root: Path
) -> None:
    """The old key must not be left sitting in the tree looking authoritative."""
    root = repository_root / "internal"
    assert (root / "test-key.asc").is_file()

    admin_client.post(
        "/keys",
        data={
            "action": "generate",
            "name": "rotated",
            "display_name": "Rotated",
            "algorithm": "ed25519",
        },
    )
    page = admin_client.get(f"/repositories/{created}/settings").text
    new_id = re.search(r'<option value="(\d+)"[^>]*>rotated<', page)
    assert new_id, "the new key is not offered"

    response = admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Internal APT",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": new_id.group(1),
            "retention": "all",
            "retention_count": "5",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, errors_in(response)
    wait_for_jobs(admin_client)

    assert (root / "rotated.asc").is_file()
    assert not (root / "test-key.asc").exists()


# ------------------------------------------------------------------ retention


def test_the_settings_page_says_how_many_would_be_pruned(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    for version in ("1.0-1", "1.1-1", "1.2-1"):
        upload(
            admin_client,
            created,
            build_deb(DebSpec(name="alpha", version=version), tmp_path / f"a{version}.deb"),
        )
    admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Internal APT",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": _key_id(admin_client, created),
            "retention": "count",
            "retention_count": "1",
        },
    )
    body = admin_client.get(f"/repositories/{created}/settings").text
    assert "2 package publication(s)" in body


def test_lowering_the_count_does_not_prune_by_itself(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    """5.3: it takes effect on the next publish, or when explicitly applied."""
    for version in ("1.0-1", "1.1-1"):
        upload(
            admin_client,
            created,
            build_deb(DebSpec(name="alpha", version=version), tmp_path / f"a{version}.deb"),
        )
    admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Internal APT",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": _key_id(admin_client, created),
            "retention": "count",
            "retention_count": "1",
        },
    )
    pool = repository_root / "internal" / "pool" / "main" / "a" / "alpha"
    assert len(list(pool.glob("*.deb"))) == 2


def test_applying_retention_removes_the_backlog(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    for version in ("1.0-1", "1.1-1", "1.2-1"):
        upload(
            admin_client,
            created,
            build_deb(DebSpec(name="alpha", version=version), tmp_path / f"a{version}.deb"),
        )
    admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Internal APT",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": _key_id(admin_client, created),
            "retention": "count",
            "retention_count": "1",
        },
    )
    response = admin_client.post(f"/repositories/{created}/retention", follow_redirects=False)
    assert response.status_code == 303
    assert "pruned=2" in str(response.headers["location"])
    wait_for_jobs(admin_client)

    pool = repository_root / "internal" / "pool" / "main" / "a" / "alpha"
    assert [path.name for path in pool.glob("*.deb")] == ["alpha_1.2-1_amd64.deb"]
    index = repository_root / "internal/dists/bookworm/main/binary-amd64/Packages"
    assert "1.0-1" not in index.read_text()


def test_publishing_prunes_the_package_it_published(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Internal APT",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": _key_id(admin_client, created),
            "retention": "count",
            "retention_count": "2",
        },
    )
    for version in ("1.0-1", "1.1-1", "1.2-1"):
        upload(
            admin_client,
            created,
            build_deb(DebSpec(name="alpha", version=version), tmp_path / f"a{version}.deb"),
        )
    wait_for_jobs(admin_client)

    pool = repository_root / "internal" / "pool" / "main" / "a" / "alpha"
    assert sorted(path.name for path in pool.glob("*.deb")) == [
        "alpha_1.1-1_amd64.deb",
        "alpha_1.2-1_amd64.deb",
    ]


def test_a_prune_is_audited_per_package(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    admin_client.post(
        f"/repositories/{created}/settings",
        data={
            "name": "Internal APT",
            "description": "",
            "origin": "",
            "label": "",
            "signing_key_id": _key_id(admin_client, created),
            "retention": "count",
            "retention_count": "1",
        },
    )
    for version in ("1.0-1", "1.1-1"):
        upload(
            admin_client,
            created,
            build_deb(DebSpec(name="alpha", version=version), tmp_path / f"a{version}.deb"),
        )
    assert "Prune old version" in admin_client.get("/audit").text


# ------------------------------------------------------------------ rescan


def test_a_rescan_reports_drift_without_changing_anything(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    upload(
        admin_client, created, build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    )
    wait_for_jobs(admin_client)

    pool = repository_root / "internal" / "pool" / "main" / "a" / "alpha"
    stolen = next(pool.glob("*.deb"))
    stolen.unlink()

    response = admin_client.post(f"/repositories/{created}/rescan", follow_redirects=False)
    assert response.status_code == 303
    wait_for_jobs(admin_client)

    body = admin_client.get(str(response.headers["location"])).text
    assert "missing from disk" in body
    assert "alpha_1.0-1_amd64.deb" in body
    assert "Nothing was changed" in body


def test_a_maintainer_may_rescan(maintainer_client: TestClient, apt_repository: Repository) -> None:
    """It changes nothing, so it does not need an administrator (5.4)."""
    response = maintainer_client.post("/repositories/internal/rescan", follow_redirects=False)
    assert response.status_code == 303


# ------------------------------------------------------------------ removing targets


def test_an_empty_distribution_can_be_removed(
    admin_client: TestClient, created: str, repository_root: Path
) -> None:
    admin_client.post(
        f"/repositories/{created}/distributions",
        data={"codename": "trixie", "components": "main", "architectures": "amd64"},
    )
    wait_for_jobs(admin_client)
    page = admin_client.get(f"/repositories/{created}/settings").text
    trixie = delete_id(page, "distributions", "trixie")
    response = admin_client.post(
        f"/repositories/{created}/distributions/{trixie}/delete", follow_redirects=False
    )
    assert response.status_code == 303, errors_in(response)
    assert not (repository_root / "internal" / "dists" / "trixie").exists()
    assert (repository_root / "internal" / "dists" / "bookworm").is_dir()


def test_a_distribution_with_packages_is_refused(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    """The cascade would delete them, so the answer is no rather than quietly yes."""
    upload(
        admin_client, created, build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    )
    ids = re.findall(
        r"/distributions/(\d+)/delete", admin_client.get(f"/repositories/{created}/settings").text
    )
    response = admin_client.post(f"/repositories/{created}/distributions/{ids[0]}/delete")
    assert response.status_code == 409
    assert any("still publishes 1 package" in message for message in errors_in(response))


def test_an_empty_variant_can_be_removed(
    admin_client: TestClient,
    repository_root: Path,
    signing_key: SigningKey,
    fake_createrepo: FakeCreaterepo,
) -> None:
    created = admin_client.post(
        "/repositories/new",
        data={
            "name": "EL9",
            "root_path": str(repository_root / "el9"),
            "signing_key_id": str(signing_key.id),
            "retention": "all",
            "format": "rpm",
            "variant_name": "el9",
            "variant_arch": "x86_64",
        },
        follow_redirects=False,
    )
    slug = str(created.headers["location"]).rsplit("/", 1)[-1]
    admin_client.post(
        f"/repositories/{slug}/variants", data={"variant_name": "el9", "variant_arch": "aarch64"}
    )
    wait_for_jobs(admin_client)

    page = admin_client.get(f"/repositories/{slug}/settings").text
    aarch64 = delete_id(page, "variants", "el9/aarch64")
    response = admin_client.post(
        f"/repositories/{slug}/variants/{aarch64}/delete", follow_redirects=False
    )
    assert response.status_code == 303, errors_in(response)
    assert not (repository_root / "el9" / "el9" / "aarch64").exists()
    assert (repository_root / "el9" / "el9" / "x86_64").is_dir()


def test_a_variant_with_packages_is_refused(
    admin_client: TestClient,
    repository_root: Path,
    signing_key: SigningKey,
    fake_createrepo: FakeCreaterepo,
    tmp_path: Path,
) -> None:
    created = admin_client.post(
        "/repositories/new",
        data={
            "name": "EL9",
            "root_path": str(repository_root / "el9"),
            "signing_key_id": str(signing_key.id),
            "retention": "all",
            "format": "rpm",
            "variant_name": "el9",
            "variant_arch": "x86_64",
        },
        follow_redirects=False,
    )
    slug = str(created.headers["location"]).rsplit("/", 1)[-1]
    upload(
        admin_client,
        slug,
        build_simple(tmp_path / "hello.rpm", name="hello", version="1.0", release="1.el9"),
        label="el9/x86_64",
    )
    page = admin_client.get(f"/repositories/{slug}/settings").text
    response = admin_client.post(
        f"/repositories/{slug}/variants/{delete_id(page, 'variants', 'el9/x86_64')}/delete"
    )
    assert response.status_code == 409


# ------------------------------------------------------------------ deregistration


def test_the_confirmation_page_says_what_is_at_stake(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    upload(
        admin_client, created, build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    )
    body = admin_client.get(f"/repositories/{created}/delete").text
    assert "1 package" in body
    assert "cannot be undone" in body


def test_deregistering_keeps_the_files(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    upload(
        admin_client, created, build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    )
    response = admin_client.post(f"/repositories/{created}/delete", data={}, follow_redirects=False)
    assert response.status_code == 303
    assert "purged=0" in str(response.headers["location"])

    assert (repository_root / "internal" / "dists" / "bookworm" / "Release").is_file()
    assert created not in admin_client.get("/").text
    assert admin_client.get(f"/repositories/{created}").status_code == 404


def test_purging_needs_the_slug_typed(
    admin_client: TestClient, created: str, repository_root: Path
) -> None:
    """A checkbox is one misplaced click; the irreversible half asks for more."""
    response = admin_client.post(
        f"/repositories/{created}/delete", data={"purge": "1", "confirm": "wrong"}
    )
    assert response.status_code == 400
    assert any("Type internal-apt exactly" in message for message in errors_in(response))
    assert (repository_root / "internal").is_dir()


def test_purging_deletes_the_tree(
    admin_client: TestClient, created: str, repository_root: Path, tmp_path: Path
) -> None:
    upload(
        admin_client, created, build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    )
    response = admin_client.post(
        f"/repositories/{created}/delete",
        data={"purge": "1", "confirm": created},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "purged=1" in str(response.headers["location"])
    assert not (repository_root / "internal").exists()


def test_a_purge_is_audited_as_a_purge(admin_client: TestClient, created: str) -> None:
    admin_client.post(f"/repositories/{created}/delete", data={"purge": "1", "confirm": created})
    assert "Purge repository files" in admin_client.get("/audit").text


def test_the_audit_trail_outlives_the_repository(
    admin_client: TestClient, created: str, tmp_path: Path
) -> None:
    """Deregistration is soft so the log still names something real (9)."""
    upload(
        admin_client, created, build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    )
    admin_client.post(f"/repositories/{created}/delete", data={"purge": "1", "confirm": created})
    audit = admin_client.get("/audit").text
    assert "Upload package" in audit
    assert "Internal APT" in audit


# ------------------------------------------------------------------ rate limiting


def test_a_flood_of_uploads_is_throttled(
    make_app: AppFactory,
    scratch_keyring: Keyring,
    signing_key: SigningKey,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    app = make_app(gnupghome=str(scratch_keyring.home), upload_burst=2, upload_rate_per_minute=1)
    with browser(app) as client:
        sign_in(client, fake_directory.ADMIN_USERNAME, fake_directory.ADMIN_PASSWORD)
        csrf = re.search(r'name="_csrf" value="([^"]+)"', client.get("/").text)
        assert csrf, "no CSRF field rendered"
        client.headers["x-csrf-token"] = csrf.group(1)
        created = client.post(
            "/repositories/new",
            data={
                "name": "Busy",
                "root_path": str(repository_root / "busy"),
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

        page = client.get(f"/repositories/{slug}/packages/upload").text
        option = re.search(r'<option value="(\d+)"', page)
        assert option, "no upload target offered"
        target = option.group(1)
        statuses = []
        for index in range(4):
            deb = build_deb(
                DebSpec(name="alpha", version=f"1.{index}-1"), tmp_path / f"a{index}.deb"
            )
            statuses.append(
                client.post(
                    f"/repositories/{slug}/packages/upload",
                    data={"target": target},
                    files={"package": (deb.name, deb.read_bytes())},
                    follow_redirects=False,
                ).status_code
            )

    assert statuses[:2] == [303, 303]
    assert 429 in statuses[2:]
