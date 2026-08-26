"""Scaffolding smoke tests.

These exist so CI has something meaningful to run from the first commit, and so a
broken entry point or version mismatch is caught immediately.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

import repository_manager
from repository_manager.cli import build_parser, main


def test_version_is_exported() -> None:
    assert isinstance(repository_manager.__version__, str)
    assert repository_manager.__version__


@pytest.mark.parametrize(
    "argv",
    [
        ["serve"],
        ["serve", "--host", "0.0.0.0", "--port", "9000"],
        ["db", "upgrade"],
        ["db", "revision", "-m", "add repositories"],
        ["check-config"],
        ["rescan", "internal-apt"],
    ],
)
def test_documented_subcommands_parse(argv: list[str]) -> None:
    """The CLI surface is specified in 13.1; keep it and the docs in step."""
    build_parser().parse_args(argv)


@pytest.mark.parametrize("argv", [[], ["nonesuch"], ["db"]])
def test_invalid_invocations_are_rejected(argv: list[str]) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)


def test_version_flag_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "repository_manager.cli", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert repository_manager.__version__ in result.stdout


@pytest.mark.parametrize("command", ["serve", "check-config"])
def test_unimplemented_commands_fail_loudly(command: str) -> None:
    """Stubs must not exit 0 and imply success."""
    assert main([command]) != 0
