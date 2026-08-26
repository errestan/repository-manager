"""The migrations must describe exactly what the models describe.

Catching drift here rather than in CI means "changed a model, forgot the
migration" fails on the developer's machine, in the same run as the change.
"""

from __future__ import annotations

from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from repository_manager import migrate
from repository_manager.models import Base

EXPECTED_TABLES = {
    "repository",
    "apt_distribution",
    "apt_component",
    "apt_architecture",
    "rpm_variant",
}


def test_upgrade_creates_the_expected_tables(database_url: str) -> None:
    engine = create_engine(database_url.replace("+aiosqlite", ""))
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    assert tables >= EXPECTED_TABLES
    assert "alembic_version" in tables


def test_migrations_match_the_models(database_url: str) -> None:
    """A non-empty diff means a model changed without a matching migration."""
    engine = create_engine(database_url.replace("+aiosqlite", ""))
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={"compare_type": True, "target_metadata": Base.metadata},
            )
            diff = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()
    assert diff == [], f"models and migrations have drifted: {diff}"


def test_downgrade_reverses_the_initial_migration(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'down.db'}"
    migrate.upgrade(url)
    migrate.downgrade(url, "base")

    engine = create_engine(url.replace("+aiosqlite", ""))
    try:
        remaining = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    assert remaining <= {"alembic_version"}, remaining


def test_migrations_ship_inside_the_package() -> None:
    """`db upgrade` must work from a pip install, where there is no checkout."""
    assert (migrate.MIGRATIONS_DIR / "env.py").is_file()
    versions = list((migrate.MIGRATIONS_DIR / "versions").glob("*.py"))
    assert versions, "no migration scripts found in the package"


def test_migration_scripts_do_not_import_application_models() -> None:
    """Old migrations must keep working as the models move on."""
    for script in (migrate.MIGRATIONS_DIR / "versions").glob("*.py"):
        text = script.read_text(encoding="utf-8")
        assert "repository_manager" not in text, script.name
