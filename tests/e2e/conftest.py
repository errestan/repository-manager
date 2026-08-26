"""End-to-end fixtures: a real server, driven by a real browser.

The whole suite runs twice in CI -- once at ``/`` and once at ``/repoman`` --
driven by ``REPOMAN_ROOT_PATH``.  Running the same assertions at both mounts is
what keeps sub-path support from quietly rotting (specification.md 13.5, AD-14).
"""

from __future__ import annotations

import contextlib
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
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from repository_manager import migrate
from repository_manager.models import (
    AptArchitecture,
    AptComponent,
    AptDistribution,
    Repository,
    RepositoryType,
    RpmVariant,
)

STARTUP_TIMEOUT_SECONDS = 45


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
        session.add_all([apt, rpm])
        session.commit()
    engine.dispose()


@pytest.fixture
def pages(live_server: str) -> list[str]:
    """Every page the suite audits, at whichever prefix is under test."""
    return [
        f"{live_server}/",
        f"{live_server}/repositories/internal",
        f"{live_server}/repositories/el9",
    ]
