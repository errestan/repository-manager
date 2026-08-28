"""Shared fixtures.

Tests run against a real migrated database rather than ``metadata.create_all``.
That costs a little startup time and buys a standing guarantee that the
migrations and the models have not drifted apart.
"""

from __future__ import annotations

import os
import re
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
from tests.support import directory as fake_directory
from tests.support.directory import FakeDirectory

SECRET = "t" * 32

# The origin every fixture client presents, and the base URL they address.
#
# Both matter.  A browser sends `Origin` on every state-changing request and the
# security gate insists on it whenever a session cookie is attached (7.3), so a
# client that omits it is not simulating a browser -- it is simulating an
# attacker.  And because the public URL is https, session cookies are marked
# Secure, which means a client addressing http://testserver would hold the
# cookie and never send it: the tests would silently run signed out.
PUBLIC_URL = "https://packages.example.test"


def browser(app: FastAPI) -> TestClient:
    """A client that behaves like a browser talking to this deployment."""
    return TestClient(app, base_url=PUBLIC_URL, headers={"origin": PUBLIC_URL})


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
            "public_url": PUBLIC_URL,
            "secret_key": SECRET,
            "database_url": database_url,
            "env": "development",
            "log_format": "console",
            "gnupghome": str(keyring.home),
            # No directory is contacted in the unit suite -- `make_app` swaps in
            # a fake authenticator -- but the settings still have to be valid,
            # because refusing to start on a half-configured directory is
            # itself a behaviour worth not breaking (7.1).
            "ldap_url": "ldaps://directory.example.test",
            "ldap_user_base_dn": fake_directory.BASE_DN,
            "ldap_group_admin": "cn=repo-admins,ou=groups,dc=example,dc=test",
            "ldap_group_maintainer": "cn=repo-maintainers,ou=groups,dc=example,dc=test",
        }
        return load_settings(**{**defaults, **overrides})

    return factory


@pytest.fixture
def settings(make_settings: SettingsFactory) -> Settings:
    built: Settings = make_settings()
    return built


@pytest.fixture
def directory() -> FakeDirectory:
    """The accounts the web tests sign in as (see tests/support/directory.py)."""
    return fake_directory.populated()


@pytest.fixture
def make_app(make_settings: SettingsFactory, directory: FakeDirectory) -> AppFactory:
    def factory(**overrides: object) -> FastAPI:
        built = create_app(make_settings(**overrides), configure_logs=False)
        # Swapped in rather than mocked at import time, so every layer above the
        # directory -- sessions, CSRF, roles, audit -- runs its real code.
        built.state.authenticator = directory
        return built

    return factory


@pytest.fixture
def app(make_app: AppFactory) -> FastAPI:
    built: FastAPI = make_app()
    return built


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with browser(app) as test_client:
        yield test_client


# --------------------------------------------------------------------- signed in


@pytest.fixture
def manageable_app(make_app: AppFactory, scratch_keyring: Keyring) -> FastAPI:
    """An application whose keyring a test may safely modify.

    Anything driving the key routes can generate or delete keys, and doing that
    in the session-wide keyring would leak into whichever test ran next.
    """
    built: FastAPI = make_app(gnupghome=str(scratch_keyring.home))
    return built


def sign_in(test_client: TestClient, username: str, password: str) -> TestClient:
    """Log a client in through the real form, and carry its CSRF token.

    Going through ``POST /login`` rather than inserting a session row is what
    makes these fixtures worth having: every test that uses one has also proved
    that the login flow still works.
    """
    response = test_client.post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )
    assert response.status_code == 303, response.text
    test_client.headers["x-csrf-token"] = csrf_token_of(test_client)
    return test_client


def csrf_token_of(test_client: TestClient) -> str:
    """Read the token this session's pages are rendering into their forms."""
    body = test_client.get("/").text
    match = re.search(r'name="_csrf" value="([^"]+)"', body)
    assert match is not None, "no CSRF field rendered"
    return match.group(1)


@pytest.fixture
def admin_client(manageable_app: FastAPI) -> Iterator[TestClient]:
    with browser(manageable_app) as test_client:
        yield sign_in(test_client, fake_directory.ADMIN_USERNAME, fake_directory.ADMIN_PASSWORD)


@pytest.fixture
def maintainer_client(manageable_app: FastAPI) -> Iterator[TestClient]:
    with browser(manageable_app) as test_client:
        yield sign_in(
            test_client, fake_directory.MAINTAINER_USERNAME, fake_directory.MAINTAINER_PASSWORD
        )


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


# ------------------------------------------------------------------ createrepo_c


#: A stand-in for ``createrepo_c`` that writes just enough ``repodata`` to be
#: signed and read back.  It records the argv it was given, so a test can assert
#: on the flags without needing the real tool.
FAKE_CREATEREPO = """#!/usr/bin/env python3
import os, pathlib, sys

target = pathlib.Path(sys.argv[-1])
log = pathlib.Path(__file__).with_suffix(".log")
with log.open("a") as handle:
    handle.write("\\x00".join(sys.argv[1:]) + "\\n")

if os.environ.get("FAKE_CREATEREPO_FAIL"):
    sys.stderr.write("createrepo_c: refusing, as this test asked it to\\n")
    raise SystemExit(1)

packages = sorted(p.name for p in (target / "Packages").glob("*.rpm"))
repodata = target / "repodata"
repodata.mkdir(parents=True, exist_ok=True)
(repodata / "repomd.xml").write_text(
    "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n"
    "<repomd xmlns=\\"http://linux.duke.edu/metadata/repo\\">\\n"
    "  <revision>0</revision>\\n"
    + "".join(f"  <!-- {name} -->\\n" for name in packages)
    + "</repomd>\\n"
)
"""


@dataclass(frozen=True)
class FakeCreaterepo:
    """Where the stand-in lives, and what it has been asked to do."""

    binary: Path

    @property
    def invocations(self) -> list[list[str]]:
        log = self.binary.with_suffix(".log")
        if not log.is_file():
            return []
        return [line.split("\x00") for line in log.read_text().splitlines()]


@pytest.fixture
def fake_createrepo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeCreaterepo:
    """Put a stand-in ``createrepo_c`` on PATH for the whole process.

    The unit suite has to run on a machine with no RPM tooling -- which includes
    every developer box that is not Fedora, and every CI job here except the
    integration one.  What these tests are checking is this application's half
    of the arrangement: that the tool is invoked with the right arguments in the
    right directory, that its failure becomes a job failure with its own words
    in it, and that ``repomd.xml`` is signed afterwards.  Whether createrepo_c
    produces valid metadata is createrepo_c's business, and is proved against
    the real binary and a real ``dnf`` in tests/integration.

    PATH is patched rather than a setting introduced, so the lookup under test
    is the same ``shutil.which`` call a deployment makes.
    """
    directory = tmp_path / "fake-bin"
    directory.mkdir()
    binary = directory / "createrepo_c"
    binary.write_text(FAKE_CREATEREPO)
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ['PATH']}")
    return FakeCreaterepo(binary=binary)


@pytest.fixture
def failing_createrepo(
    fake_createrepo: FakeCreaterepo, monkeypatch: pytest.MonkeyPatch
) -> FakeCreaterepo:
    """The same stand-in, told to exit non-zero with something on stderr."""
    monkeypatch.setenv("FAKE_CREATEREPO_FAIL", "1")
    return fake_createrepo
