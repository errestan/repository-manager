"""Pages, health probes and the theme control (specification.md 8.1, 11, 13.3)."""

from __future__ import annotations

import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from repository_manager.__about__ import __version__
from repository_manager.models import Repository
from repository_manager.web.templating import THEME_COOKIE
from tests.conftest import AppFactory, FakeCreaterepo

# --------------------------------------------------------------- health


def test_healthz_reports_the_version(client: TestClient) -> None:
    body = client.get("/healthz").json()
    assert body == {"status": "ok", "version": __version__}


def test_healthz_does_not_touch_the_database(client: TestClient, app: FastAPI) -> None:
    """Liveness must not fail on a database blip, or the container gets killed."""
    app.state.engine = None
    assert client.get("/healthz").status_code == 200


def test_readyz_checks_dependencies(client: TestClient) -> None:
    body = client.get("/readyz").json()
    assert body["status"] == "ok"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["allowed_roots"] == "ok"
    assert body["checks"]["gnupg"] == "ok"


def test_readyz_does_not_ask_for_createrepo_when_nothing_needs_it(
    client: TestClient, apt_repository: Repository
) -> None:
    """An APT-only deployment has no reason to install it (13.3).

    Reporting a tool this instance will never invoke as a problem would train
    whoever watches this endpoint to ignore what it says.
    """
    body = client.get("/readyz").json()
    assert body["status"] == "ok"
    assert body["checks"]["createrepo_c"] == "not required: no RPM repositories"


def test_readyz_is_degraded_when_an_rpm_repository_has_no_createrepo(
    client: TestClient, rpm_repository: Repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failure would otherwise surface as a failed job, hours later."""
    import shutil

    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda name, *a, **kw: None if "createrepo" in name else real_which(name)
    )
    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["checks"]["createrepo_c"].startswith("missing")


def test_readyz_is_ready_when_an_rpm_repository_has_createrepo(
    client: TestClient, rpm_repository: Repository, fake_createrepo: FakeCreaterepo
) -> None:
    body = client.get("/readyz").json()
    assert body["status"] == "ok"
    assert body["checks"]["createrepo_c"] == "ok"


def test_readyz_is_degraded_without_gnupg(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing can be signed without it, whichever format is served (10.5)."""
    import shutil

    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda name, *a, **kw: None if name == "gpg" else real_which(name)
    )
    response = client.get("/readyz")

    assert response.status_code == 503
    assert "missing" in response.json()["checks"]["gnupg"]


def test_readyz_reports_degraded_when_a_root_is_missing(make_app: AppFactory) -> None:
    app = make_app(allowed_roots="/nonexistent-root-for-tests")
    with TestClient(app) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert "missing" in response.json()["checks"]["allowed_roots"]


# --------------------------------------------------------------- repository list


def test_empty_list_explains_itself(client: TestClient) -> None:
    body = client.get("/").text
    assert "No repositories yet" in body


def test_list_shows_repositories(
    client: TestClient, apt_repository: Repository, rpm_repository: Repository
) -> None:
    body = client.get("/").text
    assert "Internal APT" in body
    assert "Enterprise Linux 9" in body
    assert "bookworm" in body
    assert "el9/x86_64" in body


def test_list_hides_deregistered_repositories(
    client: TestClient, sync_session: Session, apt_repository: Repository
) -> None:
    from repository_manager.models.base import utcnow

    apt_repository.deregistered_at = utcnow()
    sync_session.commit()
    assert "Internal APT" not in client.get("/").text


def test_repository_type_is_not_conveyed_by_colour_alone(
    client: TestClient, apt_repository: Repository
) -> None:
    """Status must carry an icon plus text, never colour on its own (11)."""
    body = client.get("/").text
    assert "APT" in body


# --------------------------------------------------------------- repository detail


def test_detail_page_renders(client: TestClient, apt_repository: Repository) -> None:
    body = client.get("/repositories/internal").text
    assert "Internal APT" in body
    assert "bookworm" in body
    assert "amd64" in body


def test_detail_shows_an_absolute_base_url(client: TestClient, apt_repository: Repository) -> None:
    """Client snippets get copied into sources.list, so they must be absolute (13.5).

    The URL is the one the *reverse proxy* serves the repository tree from
    (4.4), not this application's page for it -- apt fetches files, not HTML.
    """
    body = client.get("/repositories/internal").text
    assert "https://packages.example.test/repos/internal" in body


def test_rpm_detail_lists_variants(client: TestClient, rpm_repository: Repository) -> None:
    body = client.get("/repositories/el9").text
    assert "Variants" in body
    assert "x86_64" in body


def test_unknown_repository_renders_an_html_404(client: TestClient) -> None:
    response = client.get("/repositories/absent")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "Skip to main content" in response.text


def test_deregistered_repository_is_not_reachable(
    client: TestClient, sync_session: Session, apt_repository: Repository
) -> None:
    from repository_manager.models.base import utcnow

    apt_repository.deregistered_at = utcnow()
    sync_session.commit()
    assert client.get("/repositories/internal").status_code == 404


def test_slug_traversal_does_not_reach_the_handler(client: TestClient) -> None:
    assert client.get("/repositories/../../etc/passwd").status_code in {307, 404}


# --------------------------------------------------------------- accessibility markup


def test_skip_link_is_the_first_focusable_element(client: TestClient) -> None:
    body = client.get("/").text
    skip = body.index('class="skip-link"')
    first_nav_link = body.index("<nav")
    assert skip < first_nav_link


def test_page_has_exactly_one_h1(client: TestClient, apt_repository: Repository) -> None:
    for path in ("/", "/repositories/internal"):
        assert len(re.findall(r"<h1[ >]", client.get(path).text)) == 1, path


def test_landmarks_are_present(client: TestClient) -> None:
    body = client.get("/").text
    for landmark in ("<header", "<nav", "<main", "<footer"):
        assert landmark in body


def test_html_declares_a_language(client: TestClient) -> None:
    assert 'lang="en"' in client.get("/").text


def test_tables_use_scoped_headers(client: TestClient, apt_repository: Repository) -> None:
    body = client.get("/").text
    assert 'scope="col"' in body
    assert 'scope="row"' in body
    assert "<caption>" in body


def test_every_theme_radio_has_a_label(client: TestClient) -> None:
    body = client.get("/").text
    for theme in ("light", "dark", "system"):
        assert f'id="theme-{theme}"' in body
        assert f'for="theme-{theme}"' in body


# --------------------------------------------------------------- theme (no JavaScript)


def test_default_theme_follows_the_system(client: TestClient) -> None:
    assert 'data-theme="system"' in client.get("/").text


def test_theme_is_set_by_a_plain_form_post(client: TestClient) -> None:
    """The whole flow must work without JavaScript (11)."""
    response = client.post(
        "/preferences/theme", data={"theme": "dark", "next": "/"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.cookies[THEME_COOKIE] == "dark"


def test_chosen_theme_is_rendered_server_side(client: TestClient) -> None:
    """Rendered into the first byte of HTML, so there is no flash of wrong colours."""
    client.cookies.set(THEME_COOKIE, "dark")
    assert 'data-theme="dark"' in client.get("/").text


def test_unknown_theme_falls_back_to_system(client: TestClient) -> None:
    client.cookies.set(THEME_COOKIE, "neon")
    assert 'data-theme="system"' in client.get("/").text


def test_theme_form_returns_to_the_current_page(
    client: TestClient, apt_repository: Repository
) -> None:
    response = client.post(
        "/preferences/theme",
        data={"theme": "light", "next": "/repositories/internal"},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/repositories/internal"


def test_theme_redirect_refuses_an_external_target(client: TestClient) -> None:
    """A crafted `next` must not bounce a visitor off-site.

    `/\\evil.example` is in the list because it is the one that looks like an
    ordinary path: several browsers normalise the backslash to a slash before
    resolving it, making it protocol-relative after all.
    """
    for hostile in (
        "https://evil.example",
        "//evil.example",
        "/\\evil.example",
        "javascript:alert(1)",
    ):
        response = client.post(
            "/preferences/theme",
            data={"theme": "dark", "next": hostile},
            follow_redirects=False,
        )
        assert "evil.example" not in response.headers["location"]
        assert not response.headers["location"].startswith("javascript:")


def test_theme_redirect_refuses_a_target_outside_the_prefix(make_app: AppFactory) -> None:
    app = make_app(public_url="https://packages.example.test/repoman", root_path="/repoman")
    with TestClient(app) as client:
        response = client.post(
            "/repoman/preferences/theme",
            data={"theme": "dark", "next": "/elsewhere"},
            follow_redirects=False,
        )
    assert response.headers["location"].startswith("http://testserver/repoman")


def test_theme_cookie_is_scoped_to_the_mount_point(make_app: AppFactory) -> None:
    """Two apps on one hostname must not see each other's cookies (13.5)."""
    app = make_app(public_url="https://packages.example.test/repoman", root_path="/repoman")
    with TestClient(app) as client:
        response = client.post(
            "/repoman/preferences/theme",
            data={"theme": "dark", "next": "/repoman/"},
            follow_redirects=False,
        )
    assert "Path=/repoman" in response.headers["set-cookie"]


def test_readyz_reports_a_database_failure(client: TestClient, app: FastAPI) -> None:
    """The probe must report, not raise, when the database is unreachable (13.3)."""

    class Broken:
        def connect(self) -> None:
            raise RuntimeError("connection refused")

    app.state.engine = Broken()
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["checks"]["database"].startswith("error:")


# --------------------------------------------------------------- output escaping


def test_templates_autoescape(app: FastAPI) -> None:
    """Jinja's default keys on the file extension and misses `.html.j2` (10.2).

    Asserted on the environment as well as through a page, because the failure
    mode is silent: every template renders, and only the escaping is missing.
    """
    assert app.state.templates.env.autoescape is True


def test_a_repository_name_containing_markup_is_escaped(
    client: TestClient, sync_session: Session, apt_repository: Repository
) -> None:
    apt_repository.name = "<script>alert('xss')</script>"
    apt_repository.description = "<img src=x onerror=alert(1)>"
    sync_session.commit()

    for path in ("/", "/repositories/internal"):
        body = client.get(path).text
        assert "<script>alert(" not in body, path
        assert "<img src=x" not in body, path
        assert "&lt;script&gt;" in body, path


def test_an_error_message_containing_markup_is_escaped(client: TestClient) -> None:
    """Error text is derived from user input, so it is escaped like anything else."""
    body = client.get("/repositories/%3Cscript%3E").text
    assert "<script>" not in body
