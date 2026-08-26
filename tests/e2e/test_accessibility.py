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
    expect(page.get_by_text("bookworm")).to_be_visible()


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
