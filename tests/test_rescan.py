"""Drift between the database and the disk (specification.md 5.4).

Every test here breaks the tree deliberately and then asks what the rescan
noticed.  The one property worth as much as the detection is that it detects
without touching anything: each case checks that the file it complained about
is exactly as it left it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.config import Settings
from repository_manager.models import KeyAlgorithm, Repository, SigningKey
from repository_manager.services import packages as package_service
from repository_manager.services import repositories as repository_service
from repository_manager.services import rescan
from repository_manager.services.repositories import DistributionSpec
from tests.conftest import Keyring
from tests.support.debs import DebSpec, build_deb

Sessionmaker = async_sessionmaker[AsyncSession]


@pytest.fixture
async def session(sessionmaker: Sessionmaker) -> AsyncIterator[AsyncSession]:
    async with sessionmaker() as active:
        yield active
        await active.commit()


@pytest.fixture
async def published(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> Repository:
    """An APT repository with two packages actually on disk."""
    key = SigningKey(
        name=keyring.name,
        fingerprint=keyring.fingerprint,
        algorithm=KeyAlgorithm.ED25519,
        uid="Repository Manager test key <test-key@example.test>",
        public_key_armored=keyring.armored,
    )
    session.add(key)
    await session.flush()

    repository = await repository_service.create_apt_repository(
        session,
        settings,
        name="Drift",
        root_path=str(repository_root / "drift"),
        signing_key_id=key.id,
        retention_count=0,
        distributions=(
            DistributionSpec(codename="bookworm", components=("main",), architectures=("amd64",)),
        ),
    )
    distribution = repository.distributions[0]
    component = distribution.components[0]
    for name in ("alpha", "beta"):
        built = build_deb(DebSpec(name=name, version="1.0-1"), tmp_path / f"{name}.deb")

        async def chunks(payload: bytes = b"") -> AsyncIterator[bytes]:
            yield payload

        staged = await package_service.stage_upload(
            Path(repository.root_path),
            chunks(built.read_bytes()),
            max_bytes=settings.max_upload_bytes,
        )
        await package_service.publish_deb(
            session,
            settings,
            repository=repository,
            distribution=distribution,
            component=component,
            staged=staged,
        )
    await session.flush()
    return repository


def pool_file(repository: Repository, name: str) -> Path:
    root = Path(repository.root_path)
    found = sorted(root.rglob(f"{name}_*.deb"))
    assert found, f"no pool file for {name}"
    return found[0]


# ------------------------------------------------------------------ agreement


async def test_an_untouched_repository_reports_no_drift(
    session: AsyncSession, settings: Settings, published: Repository
) -> None:
    report = await rescan.scan(session, settings, published)
    assert report.clean
    assert report.checked_rows == 2
    assert report.checked_files == 2
    assert "No drift found" in "\n".join(report.lines())


async def test_generated_metadata_is_not_drift(
    session: AsyncSession, settings: Settings, published: Repository
) -> None:
    """`Packages`, `Release`, `InRelease` and the exported key are our output."""
    root = Path(published.root_path)
    assert (root / "dists" / "bookworm" / "Release").is_file()
    report = await rescan.scan(session, settings, published)
    assert report.clean


# ------------------------------------------------------------------ drift


async def test_a_deleted_file_is_reported_as_missing(
    session: AsyncSession, settings: Settings, published: Repository
) -> None:
    pool_file(published, "alpha").unlink()
    report = await rescan.scan(session, settings, published)

    assert not report.clean
    assert [entry.path for entry in report.missing] == ["pool/main/a/alpha/alpha_1.0-1_amd64.deb"]
    assert not report.modified
    assert not report.untracked


async def test_an_edited_file_is_reported_as_modified(
    session: AsyncSession, settings: Settings, published: Repository
) -> None:
    target = pool_file(published, "alpha")
    target.write_bytes(target.read_bytes() + b"tampered")

    report = await rescan.scan(session, settings, published)
    assert [entry.path for entry in report.modified] == ["pool/main/a/alpha/alpha_1.0-1_amd64.deb"]
    # Reported, not repaired: the bytes are exactly as the test left them.
    assert target.read_bytes().endswith(b"tampered")


async def test_a_package_nobody_uploaded_is_reported_as_untracked(
    session: AsyncSession, settings: Settings, published: Repository, tmp_path: Path
) -> None:
    smuggled = Path(published.root_path) / "pool" / "main" / "z" / "zeta"
    smuggled.mkdir(parents=True)
    built = build_deb(DebSpec(name="zeta", version="9.9-9"), tmp_path / "zeta.deb")
    (smuggled / "zeta_9.9-9_amd64.deb").write_bytes(built.read_bytes())

    report = await rescan.scan(session, settings, published)
    assert [entry.path for entry in report.untracked] == ["pool/main/z/zeta/zeta_9.9-9_amd64.deb"]
    # Still there afterwards: the operator decides, not the job.
    assert (smuggled / "zeta_9.9-9_amd64.deb").is_file()


async def test_every_kind_of_drift_is_reported_at_once(
    session: AsyncSession, settings: Settings, published: Repository, tmp_path: Path
) -> None:
    pool_file(published, "alpha").unlink()
    target = pool_file(published, "beta")
    target.write_bytes(b"not a package any more")
    stray = Path(published.root_path) / "pool" / "main" / "stray.rpm"
    stray.write_bytes(b"\xed\xab\xee\xdb")

    report = await rescan.scan(session, settings, published)
    assert report.total == 3
    assert report.summary == "1 missing, 1 modified, 1 untracked."


async def test_the_report_says_what_to_do(
    session: AsyncSession, settings: Settings, published: Repository
) -> None:
    pool_file(published, "alpha").unlink()
    lines = "\n".join((await rescan.scan(session, settings, published)).lines())
    assert "Nothing was changed" in lines
    assert "Re-upload what is missing" in lines


# ------------------------------------------------------------------ what is walked


async def test_a_half_received_upload_is_not_drift(
    session: AsyncSession, settings: Settings, published: Repository
) -> None:
    """`.incoming` exists to hold transient files; reporting them is noise (5.1)."""
    incoming = Path(published.root_path) / package_service.INCOMING_DIRNAME
    incoming.mkdir(exist_ok=True)
    (incoming / "upload-abc.part.deb").write_bytes(b"partial")

    report = await rescan.scan(session, settings, published)
    assert report.clean


def test_the_walk_finds_both_formats_and_nothing_else(tmp_path: Path) -> None:
    for relative in (
        "pool/main/a/alpha/alpha.deb",
        "el9/x86_64/Packages/hello.rpm",
        "dists/bookworm/Release",
        "key.asc",
        "el9/x86_64/repodata/repomd.xml",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"x")

    found = {str(path.relative_to(tmp_path)) for path in rescan.walk_packages(tmp_path)}
    assert found == {"pool/main/a/alpha/alpha.deb", "el9/x86_64/Packages/hello.rpm"}


def test_a_long_list_is_truncated_rather_than_dumped() -> None:
    """A restore gone wrong can produce thousands; a log that is all list is unread."""
    report = rescan.DriftReport(checked_rows=0, checked_files=2000)
    report.untracked = [rescan.Difference(f"pool/x/{index}.deb") for index in range(2000)]
    lines = report.lines()
    assert sum(1 for line in lines if line.startswith("  - ")) == rescan.LISTED_LIMIT
    assert any("and 1975 more" in line for line in lines)
