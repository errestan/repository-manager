"""The release notes the workflow quotes (specification.md 14.4).

A release is the one thing here that cannot be undone, so the script that
decides what it says is worth testing before it runs for the first time.
"""

from __future__ import annotations

import pytest
from scripts.changelog_section import CHANGELOG, section

from repository_manager.__about__ import __version__

SAMPLE = """# Changelog

Preamble that belongs to no version.

## [Unreleased]

Nothing yet.

## [0.2.0] — 2026-09-01

### Added

- A thing.

## [0.1.0] — 2026-08-29

### Added

- The first thing.

[0.1.0]: https://example.test
"""


def test_a_section_stops_at_the_next_version() -> None:
    assert section(SAMPLE, "0.2.0") == "### Added\n\n- A thing."


def test_the_last_section_stops_at_the_end() -> None:
    body = section(SAMPLE, "0.1.0")
    assert "The first thing" in body
    assert "0.2.0" not in body


def test_a_tag_may_carry_its_v_prefix() -> None:
    """The workflow passes `GITHUB_REF_NAME`, which is `v0.1.0`."""
    assert section(SAMPLE, "v0.1.0") == section(SAMPLE, "0.1.0")


def test_the_preamble_is_never_included() -> None:
    """A release whose notes are the whole changelog is a release nobody reads."""
    assert "Preamble" not in section(SAMPLE, "0.2.0")


def test_an_unknown_version_fails_loudly() -> None:
    with pytest.raises(SystemExit, match="No changelog section"):
        section(SAMPLE, "9.9.9")


def test_the_current_version_has_notes_to_publish() -> None:
    """The check that would otherwise fail during a release, run on every commit."""
    body = section(CHANGELOG.read_text(encoding="utf-8"), __version__)
    assert len(body) > 200, "the changelog entry looks like a placeholder"
