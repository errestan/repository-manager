"""axe-core audits and the no-JavaScript path (specification.md 11).

Marked ``e2e`` so CI runs them in the dedicated dual-mount job.
"""

from __future__ import annotations

import pytest
from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Browser, BrowserContext, Page, expect

from repository_manager.auth.ldap import GENERIC_FAILURE
from repository_manager.auth.sessions import SESSION_COOKIE
from tests.e2e.conftest import ADMIN_SESSION_TOKEN, LOGOUT_SESSION_TOKEN

pytestmark = pytest.mark.e2e

axe = Axe()


def scripting_disabled(
    browser: Browser, *, root_path: str = "", session_token: str | None = None
) -> BrowserContext:
    """A context with JavaScript off, optionally carrying a seeded session.

    Every flow has to work without scripting (11), and the management flows are
    the ones most likely to quietly depend on it.
    """
    context = browser.new_context(java_script_enabled=False)
    if session_token:
        context.add_cookies(
            [
                {
                    "name": SESSION_COOKIE,
                    "value": session_token,
                    "domain": "127.0.0.1",
                    "path": root_path or "/",
                    "httpOnly": True,
                    "secure": False,
                    "sameSite": "Lax",
                }
            ]
        )
    return context


def _audit(page: Page) -> None:
    results = axe.run(page)
    if results.violations_count:
        pytest.fail(f"axe-core found accessibility violations:\n{results.generate_report()}")


def test_every_page_passes_axe(page: Page, pages: list[str]) -> None:
    for url in pages:
        page.goto(url)
        _audit(page)


def test_no_request_404s_while_browsing(page: Page, pages: list[str]) -> None:
    """A missing stylesheet under a prefix is the classic sub-path regression."""
    failures: list[str] = []
    page.on(
        "response",
        lambda response: (
            failures.append(f"{response.status} {response.url}") if response.status >= 400 else None
        ),
    )
    for url in pages:
        page.goto(url)
    assert not failures, failures


def test_stylesheet_actually_loads(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/")
    # If the CSS 404s the body keeps the browser default, so this catches a
    # prefix mistake that a status-code check on the document alone would miss.
    background = page.evaluate("getComputedStyle(document.body).backgroundColor")
    assert background not in ("", "rgba(0, 0, 0, 0)"), background


def test_skip_link_is_first_and_reaches_main(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/")
    page.keyboard.press("Tab")
    focused = page.evaluate("document.activeElement.className")
    assert "skip-link" in focused
    page.keyboard.press("Enter")
    assert page.evaluate("document.activeElement.id") == "main-content"


def test_navigation_and_detail_page(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/")
    expect(page.get_by_role("heading", name="Repositories", level=1)).to_be_visible()
    page.get_by_role("link", name="Internal APT").click()
    expect(page.get_by_role("heading", name="Internal APT", level=1)).to_be_visible()
    expect(page.get_by_text("bookworm", exact=True).first).to_be_visible()


def test_theme_switch_works_without_javascript(browser: Browser, live_server: str) -> None:
    """Every flow must work with JavaScript disabled (11)."""
    context = browser.new_context(java_script_enabled=False)
    try:
        page = context.new_page()
        page.goto(f"{live_server}/")
        assert page.locator("html").get_attribute("data-theme") == "system"

        page.get_by_label("Dark").check()
        page.get_by_role("button", name="Apply").click()

        assert page.locator("html").get_attribute("data-theme") == "dark"
        # And it survives a fresh navigation, rendered server-side.
        page.goto(f"{live_server}/repositories/internal")
        assert page.locator("html").get_attribute("data-theme") == "dark"
    finally:
        context.close()


def test_pages_are_reachable_without_javascript(browser: Browser, pages: list[str]) -> None:
    context = browser.new_context(java_script_enabled=False)
    try:
        page = context.new_page()
        for url in pages:
            response = page.goto(url)
            assert response is not None
            assert response.status == 200, url
            assert page.locator("h1").count() == 1, url
    finally:
        context.close()


def test_dark_theme_also_passes_axe(page: Page, live_server: str, pages: list[str]) -> None:
    """Contrast has to hold in both themes, not only the default one."""
    page.goto(f"{live_server}/")
    page.get_by_label("Dark").check()
    page.get_by_role("button", name="Apply").click()
    for url in pages:
        page.goto(url)
        assert page.locator("html").get_attribute("data-theme") == "dark"
        _audit(page)


# --------------------------------------------------------------- forms (M2)


def test_a_rejected_form_is_accessible(signed_in: Page, live_server: str) -> None:
    """Error states are where accessibility usually breaks, so audit one (11).

    Retention has no browser-side `required`, deliberately: the choice must be
    made explicitly (5.3), and leaving it unset is the natural way to reach the
    server-rendered error state.
    """
    signed_in.goto(f"{live_server}/repositories/new")
    signed_in.fill("#field-name", "Audited")
    signed_in.fill("#field-root_path", "/not/an/allowed/root")
    signed_in.check("#field-format-apt")
    signed_in.fill("#field-codename", "bookworm")
    signed_in.fill("#field-components", "main")
    signed_in.fill("#field-architectures", "amd64")
    signed_in.select_option("#field-signing_key_id", index=1)
    signed_in.get_by_role("button", name="Create repository").click()

    signed_in.wait_for_selector(".error-summary")
    _audit(signed_in)


def test_form_errors_are_summarised_and_linked(signed_in: Page, live_server: str) -> None:
    """Each entry in the summary must reach the field it came from (11)."""
    signed_in.goto(f"{live_server}/repositories/new")
    signed_in.fill("#field-name", "Audited")
    signed_in.fill("#field-root_path", "/not/an/allowed/root")
    signed_in.check("#field-format-apt")
    signed_in.fill("#field-codename", "bookworm")
    signed_in.fill("#field-components", "main")
    signed_in.fill("#field-architectures", "amd64")
    signed_in.select_option("#field-signing_key_id", index=1)
    signed_in.get_by_role("button", name="Create repository").click()

    summary = signed_in.locator(".error-summary")
    assert summary.get_attribute("role") == "alert"
    links = summary.locator("a")
    assert links.count() >= 1
    for index in range(links.count()):
        target = links.nth(index).get_attribute("href") or ""
        assert target.startswith("#field-")
        assert signed_in.locator(target).count() == 1, target


def test_every_input_has_a_label(page: Page, pages: list[str]) -> None:
    """No control may be left without an accessible name (11)."""
    for url in pages:
        page.goto(url)
        controls = page.locator("input:not([type=hidden]), select, textarea")
        for index in range(controls.count()):
            control = controls.nth(index)
            identifier = control.get_attribute("id")
            assert identifier, f"unlabelled control on {url}"
            assert page.locator(f'label[for="{identifier}"], legend#{identifier}').count() >= 1, (
                f"no label for #{identifier} on {url}"
            )


def test_the_upload_form_works_without_javascript(
    browser: Browser, live_server: str, root_path: str
) -> None:
    """Uploading is a plain multipart POST, with no scripting involved (11)."""
    context = scripting_disabled(browser, root_path=root_path, session_token=ADMIN_SESSION_TOKEN)
    try:
        page = context.new_page()
        page.goto(f"{live_server}/repositories/internal/packages/upload")
        form = page.locator("form[enctype='multipart/form-data']")
        assert form.count() == 1
        assert form.get_attribute("method") == "post"
        assert page.locator("#field-package").get_attribute("type") == "file"
    finally:
        context.close()


def test_job_state_is_readable_as_text(signed_in: Page, live_server: str) -> None:
    """Status carries a word, never colour or a symbol alone (11)."""
    signed_in.goto(f"{live_server}/jobs")
    body = signed_in.locator("main").inner_text()
    assert "Succeeded" in body
    assert "Failed" in body


def test_a_failed_job_explains_itself(signed_in: Page, live_server: str) -> None:
    signed_in.goto(f"{live_server}/jobs/2")
    assert "signing key is not present" in signed_in.locator("main").inner_text()
    _audit(signed_in)


def test_the_client_setup_snippet_is_absolute(page: Page, live_server: str) -> None:
    """Copied into sources.list, so a relative URL would be useless (4.4, 13.5)."""
    page.goto(f"{live_server}/repositories/internal")
    # Two snippets are shown: the key install, then the sources.list line.
    snippets = page.locator("pre.snippet")
    sources_line = snippets.nth(1).inner_text()
    assert sources_line.startswith("deb [signed-by=")
    assert "http://127.0.0.1" in sources_line
    assert "/repos/internal bookworm" in sources_line


# --------------------------------------------------------------- auth (M3)


def test_every_management_page_passes_axe(signed_in: Page, management_pages: list[str]) -> None:
    """The role-gated pages are audited too, not only the anonymous ones."""
    for url in management_pages:
        signed_in.goto(url)
        _audit(signed_in)


def test_management_pages_are_reachable_without_javascript(
    browser: Browser, management_pages: list[str], root_path: str
) -> None:
    context = scripting_disabled(browser, root_path=root_path, session_token=ADMIN_SESSION_TOKEN)
    try:
        page = context.new_page()
        for url in management_pages:
            response = page.goto(url)
            assert response is not None
            assert response.status == 200, url
            assert page.locator("h1").count() == 1, url
    finally:
        context.close()


def test_an_anonymous_visitor_is_sent_to_sign_in(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/repositories/new")
    expect(page.get_by_role("heading", name="Sign in", level=1)).to_be_visible()


def test_signing_in_is_a_plain_form(browser: Browser, live_server: str) -> None:
    """The one page that must never need scripting: it is where a locked-out
    person starts (11)."""
    context = scripting_disabled(browser)
    try:
        page = context.new_page()
        page.goto(f"{live_server}/login")
        form = page.locator("form[action$='/login']")
        assert form.count() == 1
        assert form.get_attribute("method") == "post"
        assert page.locator("#field-password").get_attribute("type") == "password"
    finally:
        context.close()


def test_a_failed_login_is_accessible_and_uninformative(page: Page, live_server: str) -> None:
    """No directory is reachable here, which is one of the two failure kinds --
    and it has to look exactly like the other one (7.1)."""
    page.goto(f"{live_server}/login")
    page.fill("#field-username", "ada")
    page.fill("#field-password", "whatever")
    page.get_by_role("button", name="Sign in").click()

    page.wait_for_selector(".error-summary")
    body = page.locator("main").inner_text()
    assert GENERIC_FAILURE in body
    # Nothing that would tell an unauthenticated caller which failure it was.
    for leak in ("unreachable", "no such user", "connection", "timed out", "ldap"):
        assert leak not in body.lower(), leak
    _audit(page)


def test_the_password_is_not_echoed_back_after_a_failure(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/login")
    page.fill("#field-username", "ada")
    page.fill("#field-password", "a-distinctive-password")
    page.get_by_role("button", name="Sign in").click()

    page.wait_for_selector(".error-summary")
    assert page.locator("#field-password").input_value() == ""
    assert "a-distinctive-password" not in page.content()


def test_the_header_shows_who_is_signed_in(signed_in: Page, live_server: str) -> None:
    signed_in.goto(f"{live_server}/")
    header = signed_in.locator("header").inner_text()
    assert "Ada Admin" in header
    assert "Admin" in header


def test_signing_out_works_without_javascript(
    browser: Browser, live_server: str, root_path: str
) -> None:
    # Its own session, because the click below destroys it and the whole suite
    # shares one database.
    context = scripting_disabled(browser, root_path=root_path, session_token=LOGOUT_SESSION_TOKEN)
    try:
        page = context.new_page()
        page.goto(f"{live_server}/")
        page.get_by_role("button", name="Sign out").click()
        expect(page.get_by_role("link", name="Sign in")).to_be_visible()
        assert "Ada Admin" not in page.locator("header").inner_text()
    finally:
        context.close()


def test_the_audit_table_carries_words_not_only_colour(signed_in: Page, live_server: str) -> None:
    signed_in.goto(f"{live_server}/audit")
    body = signed_in.locator("main").inner_text()
    for word in ("Success", "Failure", "Denied"):
        assert word in body, word


def test_every_management_input_has_a_label(signed_in: Page, management_pages: list[str]) -> None:
    for url in management_pages:
        signed_in.goto(url)
        controls = signed_in.locator("input:not([type=hidden]), select, textarea")
        for index in range(controls.count()):
            control = controls.nth(index)
            identifier = control.get_attribute("id")
            assert identifier, f"unlabelled control on {url}"
            assert (
                signed_in.locator(f'label[for="{identifier}"], legend#{identifier}').count() >= 1
            ), f"no label for #{identifier} on {url}"


def test_a_new_token_is_announced_where_it_can_be_read(signed_in: Page, live_server: str) -> None:
    """The secret exists once, so the region carrying it interrupts (11).

    role="alert" rather than "status": a confirmation that is merely polite can
    be missed, and this one cannot be recovered if it is.
    """
    signed_in.goto(f"{live_server}/tokens")
    signed_in.fill("#field-label", "release pipeline")
    signed_in.check("#field-scopes-1")
    # By name, not `button[type=submit]`: the theme switch in the header is the
    # first submit button on every page.
    signed_in.get_by_role("button", name="Create token").click()

    alert = signed_in.locator('[role="alert"]#new-token')
    expect(alert).to_be_visible()
    expect(alert.locator("code.token-secret")).to_contain_text("rmt_")


def test_the_token_is_not_shown_a_second_time(signed_in: Page, live_server: str) -> None:
    signed_in.goto(f"{live_server}/tokens")
    signed_in.fill("#field-label", "release pipeline")
    signed_in.check("#field-scopes-1")
    signed_in.get_by_role("button", name="Create token").click()
    secret = signed_in.locator("code.token-secret").inner_text()

    signed_in.goto(f"{live_server}/tokens")
    assert secret not in signed_in.content()


def test_the_api_reference_needs_no_remote_assets(page: Page, live_server: str) -> None:
    """The CSP allows no remote origins, so a CDN-backed docs page would be blank."""
    external: list[str] = []
    page.on(
        "request",
        lambda request: (
            external.append(request.url) if not request.url.startswith(live_server) else None
        ),
    )
    page.goto(f"{live_server}/api/docs")
    expect(page.locator("h1")).to_have_text("REST API")
    assert not external, external
