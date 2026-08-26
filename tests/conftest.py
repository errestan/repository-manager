"""Shared fixtures.

Tests run against a real migrated database rather than ``metadata.create_all``.
That costs a little startup time and buys a standing guarantee that the
migrations and the models have not drifted apart.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as create_sync_engine
from sqlalchemy.orm import Session

from repository_manager import migrate
from repository_manager.config import Settings, load_settings
from repository_manager.models import (
    AptArchitecture,
    AptComponent,
    AptDistribution,
    Repository,
    RepositoryType,
    RpmVariant,
)
from repository_manager.web.app import create_app

SECRET = "t" * 32

# Factories, so a test can vary one setting without rebuilding the whole fixture
# chain. Keyword arguments are forwarded to Settings.
SettingsFactory = Callable[..., Settings]
AppFactory = Callable[..., FastAPI]


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    """A migrated, file-backed SQLite database, unique to each test."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    migrate.upgrade(url)
    return url


@pytest.fixture
def sync_session(database_url: str) -> Iterator[Session]:
    """A synchronous session for seeding, avoiding event-loop juggling in tests."""
    engine = create_sync_engine(database_url.replace("+aiosqlite", ""))
    with Session(engine) as session:
        yield session
    engine.dispose()


@pytest.fixture
def make_settings(database_url: str) -> SettingsFactory:
    def factory(**overrides: object) -> Settings:
        defaults: dict[str, object] = {
            "allowed_roots": "/tmp",
            "public_url": "https://packages.example.test",
            "secret_key": SECRET,
            "database_url": database_url,
            "env": "development",
            "log_format": "console",
        }
        return load_settings(**{**defaults, **overrides})

    return factory


@pytest.fixture
def settings(make_settings: SettingsFactory) -> Settings:
    built: Settings = make_settings()
    return built


@pytest.fixture
def make_app(make_settings: SettingsFactory) -> AppFactory:
    def factory(**overrides: object) -> FastAPI:
        return create_app(make_settings(**overrides), configure_logs=False)

    return factory


@pytest.fixture
def app(make_app: AppFactory) -> FastAPI:
    built: FastAPI = make_app()
    return built


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def apt_repository(sync_session: Session) -> Repository:
    repository = Repository(
        slug="internal",
        name="Internal APT",
        type=RepositoryType.APT,
        root_path="/tmp/internal",
        retention_count=3,
        description="Company-built Debian packages",
    )
    repository.distributions.append(
        AptDistribution(
            codename="bookworm",
            components=[AptComponent(name="main"), AptComponent(name="contrib")],
            architectures=[AptArchitecture(name="amd64"), AptArchitecture(name="all")],
        )
    )
    sync_session.add(repository)
    sync_session.commit()
    sync_session.refresh(repository)
    return repository


@pytest.fixture
def rpm_repository(sync_session: Session) -> Repository:
    repository = Repository(
        slug="el9",
        name="Enterprise Linux 9",
        type=RepositoryType.RPM,
        root_path="/tmp/el9",
        retention_count=0,
    )
    repository.variants.append(RpmVariant(name="el9", arch="x86_64"))
    sync_session.add(repository)
    sync_session.commit()
    sync_session.refresh(repository)
    return repository
