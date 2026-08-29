"""End-to-end fixtures: a real server, driven by a real browser.

The whole suite runs twice in CI -- once at ``/`` and once at ``/repoman`` --
driven by ``REPOMAN_ROOT_PATH``.  Running the same assertions at both mounts is
what keeps sub-path support from quietly rotting (specification.md 13.5, AD-14).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest
from playwright.sync_api import Page
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from repository_manager import migrate
from repository_manager.auth.sessions import SESSION_COOKIE
from repository_manager.models import (
    ActorType,
    AptArchitecture,
    AptComponent,
    AptDistribution,
    AuditAction,
    AuditLog,
    AuditOutcome,
    Job,
    JobState,
    JobType,
    KeyAlgorithm,
    Package,
    PackagePublication,
    Repository,
    RepositoryType,
    Role,
    RpmVariant,
    SigningKey,
    UserSession,
)
from repository_manager.models.base import utcnow

STARTUP_TIMEOUT_SECONDS = 45

# Fixed values, so the cookie fixtures need no plumbing back from the seeder.
# Only the hash reaches the database, exactly as in production (7.2).
ADMIN_SESSION_TOKEN = "e2e-admin-session-token"
#: A second session, for the one test that ends the session it is using.  The
#: whole suite shares one server and one database, so signing out of the shared
#: session would silently leave every later test anonymous.
LOGOUT_SESSION_TOKEN = "e2e-logout-session-token"
ADMIN_DN = "uid=ada,ou=people,dc=example,dc=test"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="session")
def root_path() -> str:
    """The mount prefix under test, normalised the way Settings would."""
    raw = os.environ.get("REPOMAN_ROOT_PATH", "").strip().strip("/")
    return f"/{raw}" if raw else ""


@pytest.fixture(scope="session")
def live_server(tmp_path_factory: pytest.TempPathFactory, root_path: str) -> Iterator[str]:
    """Start the application exactly as an operator would, and yield its base URL."""
    workdir = tmp_path_factory.mktemp("e2e")
    database = workdir / "e2e.db"
    url = f"sqlite+aiosqlite:///{database}"

    migrate.upgrade(url)
    _seed(url)

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}{root_path}"

    environment = {
        **os.environ,
        "REPOMAN_DATABASE_URL": url,
        "REPOMAN_ALLOWED_ROOTS": str(workdir),
        "REPOMAN_PUBLIC_URL": base_url,
        "REPOMAN_ROOT_PATH": root_path,
        "REPOMAN_SECRET_KEY": "e" * 32,
        # http is only acceptable outside production; the config refuses
        # otherwise, which is itself covered by the unit tests.
        "REPOMAN_ENV": "development",
        "REPOMAN_LOG_FORMAT": "console",
        # No directory is reachable from this job, and none is needed: the
        # admin session below is seeded directly into the database, which is
        # where sessions live (7.2).  The address still has to be configured,
        # and pointing it at a closed port is what lets the login-failure page
        # be audited as well -- an unreachable directory and a wrong password
        # produce the same page by design (7.1).
        "REPOMAN_LDAP_URL": "ldap://127.0.0.1:1",
        "REPOMAN_LDAP_ALLOW_INSECURE": "true",
        "REPOMAN_LDAP_USER_BASE_DN": "ou=people,dc=example,dc=test",
        "REPOMAN_LDAP_GROUP_ADMIN": "cn=repo-admins,ou=groups,dc=example,dc=test",
        "REPOMAN_LDAP_GROUP_MAINTAINER": "cn=repo-maintainers,ou=groups,dc=example,dc=test",
        # Keeps the failed-login audit quick rather than waiting out a default
        # connect timeout on a closed port.
        "REPOMAN_LDAP_TIMEOUT_SECONDS": "2",
    }

    # The log goes to a file, never to a pipe.  An unread PIPE only holds about
    # 64KB before the writer blocks, which manifests much later as the server
    # mysteriously ceasing to answer part-way through a run.
    log_path = workdir / "server.log"
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            [sys.executable, "-m", "repository_manager.cli", "serve", "--port", str(port)],
            env=environment,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )

        try:
            _wait_until_ready(process, f"{base_url}/healthz", log_path)
            yield base_url
        finally:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=10)
            if process.poll() is None:  # pragma: no cover - only on a wedged server
                process.kill()


def _wait_until_ready(process: subprocess.Popen[str], probe: str, log_path: Path) -> None:
    def log() -> str:
        return log_path.read_text(encoding="utf-8") if log_path.exists() else ""

    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited with {process.returncode}:\n{log()}")
        try:
            with urlopen(probe, timeout=2) as response:
                if response.status == 200:
                    return
        except (URLError, OSError, TimeoutError):
            time.sleep(0.2)
    raise RuntimeError(f"server did not become ready within {STARTUP_TIMEOUT_SECONDS}s:\n{log()}")


def _seed(url: str) -> None:
    engine = create_engine(url.replace("+aiosqlite", ""))
    with Session(engine) as session:
        apt = Repository(
            slug="internal",
            name="Internal APT",
            type=RepositoryType.APT,
            root_path="/tmp/internal",
            retention_count=3,
            description="Company-built Debian packages",
        )
        apt.distributions.append(
            AptDistribution(
                codename="bookworm",
                components=[AptComponent(name="main"), AptComponent(name="contrib")],
                architectures=[AptArchitecture(name="amd64"), AptArchitecture(name="all")],
            )
        )
        rpm = Repository(
            slug="el9",
            name="Enterprise Linux 9",
            type=RepositoryType.RPM,
            root_path="/tmp/el9",
            retention_count=5,
        )
        rpm.variants.append(RpmVariant(name="el9", arch="x86_64"))

        # A key row only: no keyring is involved, because nothing in these tests
        # signs anything.  It exists so the detail page can render the client
        # setup snippet and the key download link.
        key = SigningKey(
            name="internal",
            fingerprint="A" * 40,
            algorithm=KeyAlgorithm.ED25519,
            uid="Internal repository signing key <internal@example.test>",
            public_key_armored=(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot-a-real-key\n"
                "-----END PGP PUBLIC KEY BLOCK-----\n"
            ),
        )
        session.add(key)
        session.flush()
        apt.signing_key_id = key.id

        session.add_all([apt, rpm])
        session.flush()
        _seed_packages(session, apt)
        _seed_jobs(session, apt)
        _seed_session(session)
        _seed_audit(session)
        session.commit()
    engine.dispose()


def _seed_session(session: Session) -> None:
    """An admin session, so the management pages can be audited (7.2).

    Written straight into the table rather than obtained by logging in: no
    directory is reachable from this job, and a session *is* a row -- inserting
    one exercises the same lookup a real login would produce.  The revalidation
    deadline is far out so no request tries to reach the directory.
    """
    now = utcnow()
    for token in (ADMIN_SESSION_TOKEN, LOGOUT_SESSION_TOKEN):
        session.add(
            UserSession(
                token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
                user_dn=ADMIN_DN,
                username="ada",
                display_name="Ada Admin",
                role=Role.ADMIN,
                csrf_secret=f"e2e-csrf-{token}",
                created_at=now,
                last_seen_at=now,
                expires_at=now + dt.timedelta(days=1),
                revalidate_after=now + dt.timedelta(days=1),
            )
        )


def _seed_audit(session: Session) -> None:
    """One entry of each outcome, so the audit table has all three renderings."""
    for action, outcome, target in (
        (AuditAction.LOGIN, AuditOutcome.SUCCESS, None),
        (AuditAction.PACKAGE_UPLOAD, AuditOutcome.SUCCESS, "alpha_1.2-1_amd64.deb"),
        (AuditAction.KEY_DELETE, AuditOutcome.FAILURE, "internal"),
        (AuditAction.REPOSITORY_CREATE, AuditOutcome.DENIED, "restricted"),
    ):
        session.add(
            AuditLog(
                actor=ADMIN_DN,
                actor_type=ActorType.USER,
                action=action,
                outcome=outcome,
                target=target,
                source_ip="203.0.113.7",
            )
        )


def _seed_packages(session: Session, repository: Repository) -> None:
    """Enough rows for the package table to have something to render."""
    main = repository.distributions[0].components[0]
    for name, version, architecture in (
        ("alpha", "1.0-1", "amd64"),
        ("alpha", "1.2-1", "amd64"),
        ("libgamma", "3.1-1", "all"),
    ):
        package = Package(
            repository_id=repository.id,
            name=name,
            source_name=name,
            version=version,
            architecture=architecture,
            relative_path=f"pool/main/{name[0]}/{name}/{name}_{version}_{architecture}.deb",
            size=4096,
            sha256="0" * 64,
            control_json={"Package": name, "Version": version, "Architecture": architecture},
        )
        package.publications.append(PackagePublication(component_id=main.id))
        session.add(package)


def _seed_jobs(session: Session, repository: Repository) -> None:
    """One job of each interesting outcome, so both renderings are audited."""
    session.add(
        Job(
            type=JobType.REGENERATE_METADATA,
            repository_id=repository.id,
            state=JobState.SUCCEEDED,
            progress=100,
            log="Regenerating metadata for internal.\nWrote 8 index files.\n",
            actor="web",
        )
    )
    session.add(
        Job(
            type=JobType.REGENERATE_METADATA,
            repository_id=repository.id,
            state=JobState.FAILED,
            progress=30,
            log="Regenerating metadata for internal.\n",
            error="The signing key is not present in the keyring.",
            actor="web",
        )
    )


@pytest.fixture
def pages(live_server: str) -> list[str]:
    """The pages any visitor can reach, at whichever prefix is under test."""
    return [
        f"{live_server}/",
        f"{live_server}/login",
        f"{live_server}/repositories/internal",
        f"{live_server}/repositories/el9",
        f"{live_server}/repositories/internal/packages",
        f"{live_server}/keys",
        f"{live_server}/api/docs",
    ]


@pytest.fixture
def management_pages(live_server: str) -> list[str]:
    """The pages that need a role, audited through a signed-in browser (3)."""
    return [
        f"{live_server}/repositories/internal/packages/upload",
        f"{live_server}/repositories/internal/distributions",
        f"{live_server}/repositories/el9/packages/upload",
        f"{live_server}/repositories/el9/variants",
        f"{live_server}/repositories/new",
        f"{live_server}/jobs",
        f"{live_server}/jobs/1",
        f"{live_server}/jobs/2",
        f"{live_server}/audit",
        f"{live_server}/tokens",
        f"{live_server}/repositories/internal/settings",
        f"{live_server}/repositories/internal/delete",
        f"{live_server}/repositories/el9/settings",
    ]


@pytest.fixture
def signed_in(page: Page, live_server: str, root_path: str) -> Page:
    """A browser carrying the seeded admin session.

    The cookie is set on the context rather than typed into the login form,
    because no directory is reachable here.  Everything downstream of the cookie
    -- session lookup, role gate, CSRF token in every form -- is the real thing.
    """
    page.context.add_cookies(
        [
            {
                "name": SESSION_COOKIE,
                "value": ADMIN_SESSION_TOKEN,
                "domain": "127.0.0.1",
                "path": root_path or "/",
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax",
            }
        ]
    )
    return page
