"""Command-line behaviour (specification.md 13.1)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from repository_manager.cli import main

REQUIRED = ("REPOMAN_ALLOWED_ROOTS", "REPOMAN_PUBLIC_URL", "REPOMAN_SECRET_KEY")


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("REPOMAN_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("REPOMAN_PUBLIC_URL", "https://packages.example.test")
    monkeypatch.setenv("REPOMAN_SECRET_KEY", "c" * 32)
    monkeypatch.setenv("REPOMAN_DATABASE_URL", url)
    monkeypatch.delenv("REPOMAN_CONFIG_FILE", raising=False)
    monkeypatch.delenv("REPOMAN_ROOT_PATH", raising=False)
    return url


def test_check_config_reports_the_resolved_settings(
    configured: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check-config"]) == 0
    out = capsys.readouterr().out
    assert "Configuration is valid." in out
    assert "https://packages.example.test" in out


def test_check_config_never_prints_the_secret(
    configured: str, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["check-config"])
    assert "c" * 32 not in capsys.readouterr().out


def test_check_config_reports_an_unset_proxy_list_explicitly(
    configured: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unset means "ignore all forwarded headers", which is worth stating (10.6)."""
    main(["check-config"])
    assert "forwarded headers ignored" in capsys.readouterr().out


@pytest.mark.parametrize("missing", REQUIRED)
def test_missing_configuration_exits_two_with_a_message(
    configured: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    missing: str,
) -> None:
    monkeypatch.delenv(missing)
    with pytest.raises(SystemExit) as excinfo:
        main(["check-config"])
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert missing in err
    assert "specification.md" in err


def test_invalid_configuration_does_not_raise_a_traceback(
    configured: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("REPOMAN_PUBLIC_URL", "not-a-url")
    with pytest.raises(SystemExit):
        main(["check-config"])
    assert "REPOMAN_PUBLIC_URL" in capsys.readouterr().err


def test_db_upgrade_creates_the_schema(
    configured: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["db", "upgrade"]) == 0
    assert "up to date" in capsys.readouterr().out
    tables = {
        row[0]
        for row in sqlite3.connect(tmp_path / "cli.db").execute(
            "select name from sqlite_master where type='table'"
        )
    }
    assert "repository" in tables
    assert "alembic_version" in tables


def test_db_upgrade_is_idempotent(configured: str) -> None:
    assert main(["db", "upgrade"]) == 0
    assert main(["db", "upgrade"]) == 0


def test_rescan_is_still_a_stub(configured: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rescan", "internal"]) != 0
    assert "not implemented yet" in capsys.readouterr().err
