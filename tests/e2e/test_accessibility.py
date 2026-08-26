"""axe-core audits and the no-JavaScript path (specification.md 11).

Marked ``e2e`` so CI runs them in the dedicated dual-mount job.
"""

from __future__ import annotations

import pytest
from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Browser, Page, expect

pytestmark = pytest.mark.e2e

axe = Axe()


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


def test_a_rejected_form_is_accessible(page: Page, live_server: str) -> None:
    """Error states are where accessibility usually breaks, so audit one (11).

    Retention has no browser-side `required`, deliberately: the choice must be
    made explicitly (5.3), and leaving it unset is the natural way to reach the
    server-rendered error state.
    """
    page.goto(f"{live_server}/repositories/new")
    page.fill("#field-name", "Audited")
    page.fill("#field-root_path", "/not/an/allowed/root")
    page.fill("#field-codename", "bookworm")
    page.fill("#field-components", "main")
    page.fill("#field-architectures", "amd64")
    page.select_option("#field-signing_key_id", index=1)
    page.get_by_role("button", name="Create repository").click()

    page.wait_for_selector(".error-summary")
    _audit(page)


def test_form_errors_are_summarised_and_linked(page: Page, live_server: str) -> None:
    """Each entry in the summary must reach the field it came from (11)."""
    page.goto(f"{live_server}/repositories/new")
    page.fill("#field-name", "Audited")
    page.fill("#field-root_path", "/not/an/allowed/root")
    page.fill("#field-codename", "bookworm")
    page.fill("#field-components", "main")
    page.fill("#field-architectures", "amd64")
    page.select_option("#field-signing_key_id", index=1)
    page.get_by_role("button", name="Create repository").click()

    summary = page.locator(".error-summary")
    assert summary.get_attribute("role") == "alert"
    links = summary.locator("a")
    assert links.count() >= 1
    for index in range(links.count()):
        target = links.nth(index).get_attribute("href") or ""
        assert target.startswith("#field-")
        assert page.locator(target).count() == 1, target


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


def test_the_upload_form_works_without_javascript(browser: Browser, live_server: str) -> None:
    """Uploading is a plain multipart POST, with no scripting involved (11)."""
    context = browser.new_context(java_script_enabled=False)
    try:
        page = context.new_page()
        page.goto(f"{live_server}/repositories/internal/packages/upload")
        form = page.locator("form[enctype='multipart/form-data']")
        assert form.count() == 1
        assert form.get_attribute("method") == "post"
        assert page.locator("#field-package").get_attribute("type") == "file"
    finally:
        context.close()


def test_job_state_is_readable_as_text(page: Page, live_server: str) -> None:
    """Status carries a word, never colour or a symbol alone (11)."""
    page.goto(f"{live_server}/jobs")
    body = page.locator("main").inner_text()
    assert "Succeeded" in body
    assert "Failed" in body


def test_a_failed_job_explains_itself(page: Page, live_server: str) -> None:
    page.goto(f"{live_server}/jobs/2")
    assert "signing key is not present" in page.locator("main").inner_text()
    _audit(page)


def test_the_client_setup_snippet_is_absolute(page: Page, live_server: str) -> None:
    """Copied into sources.list, so a relative URL would be useless (4.4, 13.5)."""
    page.goto(f"{live_server}/repositories/internal")
    # Two snippets are shown: the key install, then the sources.list line.
    snippets = page.locator("pre.snippet")
    sources_line = snippets.nth(1).inner_text()
    assert sources_line.startswith("deb [signed-by=")
    assert "http://127.0.0.1" in sources_line
    assert "/repos/internal bookworm" in sources_line
