"""The version appears in several files, so they are checked against each other.

None of this tests behaviour.  It exists because the alternative to a test is
remembering, and the failure mode of forgetting -- a badge claiming 0.1.0 over a
0.3.0 release -- is the kind that survives for months because it looks fine.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from repository_manager.__about__ import __version__

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

#: The version badge, as `img.shields.io/badge/version-<version>%20...`.
BADGE = re.compile(r"img\.shields\.io/badge/version-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)")

#: A GitHub Actions status badge and the workflow file it names.
WORKFLOW_BADGE = re.compile(r"/actions/workflows/(?P<workflow>[a-z-]+\.yml)/badge\.svg")


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text(encoding="utf-8")


def test_the_version_badge_matches_the_package(readme: str) -> None:
    match = BADGE.search(readme)
    assert match, "no version badge in README.md"
    assert match.group("version") == __version__, (
        "the README version badge is out of date; see the release steps in CONTRIBUTING.md"
    )


def test_the_status_line_names_the_same_version(readme: str) -> None:
    assert f"**Status: {__version__}" in readme


def test_every_status_badge_names_a_workflow_that_exists(readme: str) -> None:
    """A badge for a renamed workflow renders as "no status" and looks broken."""
    named = {match.group("workflow") for match in WORKFLOW_BADGE.finditer(readme)}
    assert named, "no workflow status badges in README.md"
    for workflow in named:
        assert (ROOT / ".github" / "workflows" / workflow).is_file(), workflow


def test_the_badges_have_real_alternative_text(readme: str) -> None:
    """An image whose alt text is "badge" tells a screen reader nothing (11)."""
    for alt, _ in re.findall(r"\[!\[([^\]]*)\]\(([^)]+)\)\]", readme):
        assert alt.strip(), "a badge has empty alt text"
        assert alt.strip().lower() not in {"badge", "build", "status", "image"}, alt


def test_the_changelog_documents_this_version() -> None:
    """Belt to test_changelog's braces: that one reads the file, this one the tree."""
    assert f"## [{__version__}]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
