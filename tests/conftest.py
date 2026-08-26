"""Shared fixtures.

Tests run against a real migrated database rather than ``metadata.create_all``.
That costs a little startup time and buys a standing guarantee that the
migrations and the models have not drifted apart.
"""

from __future__ import annotations

import shutil
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as create_sync_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session

from repository_manager import migrate
from repository_manager.config import Settings, load_settings
from repository_manager.db import create_engine, create_sessionmaker
from repository_manager.models import (
    AptArchitecture,
    AptComponent,
    AptDistribution,
    KeyAlgorithm,
    Repository,
    RepositoryType,
    RpmVariant,
    SigningKey,
)
from repository_manager.security.gpg import GnuPG
from repository_manager.web.app import create_app

SECRET = "t" * 32

# The name every fixture key is registered under.
TEST_KEY_NAME = "test-key"

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
def make_settings(database_url: str, keyring: Keyring, repository_root: Path) -> SettingsFactory:
    def factory(**overrides: object) -> Settings:
        defaults: dict[str, object] = {
            "allowed_roots": str(repository_root),
            "public_url": "https://packages.example.test",
            "secret_key": SECRET,
            "database_url": database_url,
            "env": "development",
            "log_format": "console",
            "gnupghome": str(keyring.home),
        }
        return load_settings(**{**defaults, **overrides})

    return factory


@pytest.fixture
def writable_app(make_app: AppFactory, scratch_keyring: Keyring) -> FastAPI:
    """An application with the M2 interim write gate opened (12).

    Pointed at a *scratch* keyring: anything driving the write routes can
    generate or delete keys, and doing that in the session-wide keyring would
    leak into whichever test ran next.
    """
    built: FastAPI = make_app(
        allow_unauthenticated_writes=True, gnupghome=str(scratch_keyring.home)
    )
    return built


@pytest.fixture
def writable_client(writable_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(writable_app) as test_client:
        yield test_client


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


# --------------------------------------------------------------------- signing


@dataclass(frozen=True)
class Keyring:
    """A prepared GnuPG home and the key inside it."""

    home: Path
    fingerprint: str
    armored: str
    name: str = TEST_KEY_NAME


@pytest.fixture(scope="session")
def keyring(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Keyring]:
    """One keyring for the whole session, holding one unprotected key.

    Session-scoped because generating a key costs about three seconds no matter
    which algorithm is chosen -- almost all of it agent startup rather than
    arithmetic -- and per-test generation would add minutes to the suite.

    The key has no passphrase on purpose.  Signing with a protected key runs the
    string-to-key derivation every time (measured at ~660ms per signature versus
    ~4ms without), which would dominate the runtime of every test that publishes
    anything.  Passphrase handling has its own tests, which build their own keys.
    """
    home = tmp_path_factory.mktemp("keyring") / "gnupg"
    gpg = GnuPG(home)
    info = gpg.generate_key(
        "Repository Manager test key <test-key@example.test>", KeyAlgorithm.ED25519
    )
    try:
        yield Keyring(
            home=home,
            fingerprint=info.fingerprint,
            armored=gpg.export_public(info.fingerprint),
        )
    finally:
        gpg.shutdown()


@pytest.fixture
def scratch_keyring(keyring: Keyring, tmp_path: Path) -> Iterator[Keyring]:
    """A private copy of the session keyring, for tests that modify it.

    Copying costs milliseconds; generating does not.  Anything that imports or
    deletes a key must use this, or it corrupts the shared fixture for whatever
    runs next.
    """
    home = tmp_path / "scratch-gnupg"
    shutil.copytree(keyring.home, home)
    home.chmod(0o700)
    replacement = Keyring(home=home, fingerprint=keyring.fingerprint, armored=keyring.armored)
    try:
        yield replacement
    finally:
        GnuPG(home).shutdown()


@pytest.fixture
async def sessionmaker(settings: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """An async session factory bound to this test's migrated database."""
    engine = create_engine(settings)
    try:
        yield create_sessionmaker(engine)
    finally:
        await engine.dispose()


@pytest.fixture
def repository_root(tmp_path: Path) -> Path:
    """An allowed root that repositories may be created inside."""
    root = tmp_path / "srv"
    root.mkdir()
    return root


@pytest.fixture
def signing_key(sync_session: Session, keyring: Keyring) -> SigningKey:
    """The session keyring's key, registered in the database."""
    key = SigningKey(
        name=keyring.name,
        fingerprint=keyring.fingerprint,
        algorithm=KeyAlgorithm.ED25519,
        uid="Repository Manager test key <test-key@example.test>",
        public_key_armored=keyring.armored,
        passphrase_ref=None,
    )
    sync_session.add(key)
    sync_session.commit()
    sync_session.refresh(key)
    return key
