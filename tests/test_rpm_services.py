"""Creating, publishing into and regenerating RPM repositories (4.2, 4.3, 5.1).

``createrepo_c`` is the stand-in from ``conftest`` throughout: what is under
test is this application's sequencing -- rows before files, the file's path
derived from its header, one publication per variant, the regeneration job
reaching the right generator -- none of which depends on the real tool being
present.  The real tool, and a real ``dnf`` reading what it produced, are in
``tests/integration``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.config import Settings
from repository_manager.jobs.queue import JobContext
from repository_manager.models import (
    KeyAlgorithm,
    Package,
    PackagePublication,
    Repository,
    RepositoryType,
    RpmVariant,
    SigningKey,
)
from repository_manager.services import packages as package_service
from repository_manager.services import publishing
from repository_manager.services import repositories as repository_service
from repository_manager.services.packages import UploadError
from repository_manager.services.repositories import RepositoryServiceError, VariantSpec
from tests.conftest import FakeCreaterepo, Keyring
from tests.support.rpms import RpmSpec, build_rpm, build_simple

EL9 = VariantSpec(name="el9", arch="x86_64")
EL8 = VariantSpec(name="el8", arch="aarch64")


@pytest.fixture
async def session(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with sessionmaker() as active:
        yield active
        await active.commit()


async def register(session: AsyncSession, keyring: Keyring) -> SigningKey:
    key = SigningKey(
        name=keyring.name,
        fingerprint=keyring.fingerprint,
        algorithm=KeyAlgorithm.ED25519,
        uid="Repository Manager test key <test-key@example.test>",
        public_key_armored=keyring.armored,
    )
    session.add(key)
    await session.flush()
    return key


async def build_repository(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    root: Path,
    *,
    variants: tuple[VariantSpec, ...] = (EL9,),
) -> Repository:
    key = await register(session, keyring)
    return await repository_service.create_rpm_repository(
        session,
        settings,
        name="Enterprise Linux",
        root_path=str(root),
        signing_key_id=key.id,
        retention_count=0,
        variants=variants,
    )


async def stage(root: Path, source: Path, settings: Settings) -> Path:
    payload = source.read_bytes()

    async def chunks() -> AsyncIterator[bytes]:
        yield payload

    return await package_service.stage_upload(root, chunks(), max_bytes=settings.max_upload_bytes)


# ------------------------------------------------------------------- creation


async def test_creating_an_rpm_repository_writes_a_signed_empty_tree(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    """Clients can add the repository and run dnf makecache immediately (4.3)."""
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)

    assert repository.type is RepositoryType.RPM
    assert repository.slug == "enterprise-linux"
    variant = root / "el9" / "x86_64"
    assert (variant / "Packages").is_dir()
    assert (variant / "repodata" / "repomd.xml").is_file()
    assert (variant / "repodata" / "repomd.xml.asc").is_file()
    # The armoured public key is exported into the root under the name every
    # `gpgkey=` line in the wild expects (4.2).
    assert f"RPM-GPG-KEY-{keyring.name}" in [entry.name for entry in root.iterdir()]


async def test_an_rpm_repository_needs_at_least_one_variant(
    session: AsyncSession, settings: Settings, keyring: Keyring, repository_root: Path
) -> None:
    key = await register(session, keyring)
    with pytest.raises(RepositoryServiceError, match="at least one variant"):
        await repository_service.create_rpm_repository(
            session,
            settings,
            name="Empty",
            root_path=str(repository_root / "empty"),
            signing_key_id=key.id,
            retention_count=0,
            variants=(),
        )


async def test_a_variant_name_that_could_escape_the_root_is_refused(
    session: AsyncSession, settings: Settings, keyring: Keyring, repository_root: Path
) -> None:
    """The check lives in the generator and is reused here rather than repeated."""
    key = await register(session, keyring)
    with pytest.raises(RepositoryServiceError, match="traverse upward"):
        await repository_service.create_rpm_repository(
            session,
            settings,
            name="Escapee",
            root_path=str(repository_root / "escapee"),
            signing_key_id=key.id,
            retention_count=0,
            variants=(VariantSpec(name="..", arch="x86_64"),),
        )


async def test_a_missing_createrepo_is_reported_at_creation_not_at_first_upload(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovering it days later, from an upload, is the worse of the two."""
    import shutil

    # Only createrepo_c is hidden: blanking `which` entirely would also hide
    # gpg, and the test would then pass for the wrong reason.
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda name, *a, **kw: None if "createrepo" in name else real_which(name)
    )
    key = await register(session, keyring)
    with pytest.raises(RepositoryServiceError, match="not installed"):
        await repository_service.create_rpm_repository(
            session,
            settings,
            name="No Tool",
            root_path=str(repository_root / "notool"),
            signing_key_id=key.id,
            retention_count=0,
            variants=(EL9,),
        )


async def test_a_variant_can_be_added_afterwards(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "el")

    variant = await repository_service.add_variant(session, repository, EL8)

    assert variant.name == "el8"
    assert variant.arch == "aarch64"
    stored = await session.scalars(
        select(RpmVariant).where(RpmVariant.repository_id == repository.id)
    )
    assert sorted(f"{v.name}/{v.arch}" for v in stored) == ["el8/aarch64", "el9/x86_64"]


async def test_a_duplicate_variant_is_refused(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "el")
    with pytest.raises(RepositoryServiceError, match="already has a variant"):
        await repository_service.add_variant(session, repository, EL9)


async def test_variants_are_refused_on_an_apt_repository(session: AsyncSession) -> None:
    repository = Repository(
        slug="internal", name="Internal", type=RepositoryType.APT, root_path="/srv/i"
    )
    session.add(repository)
    await session.flush()

    with pytest.raises(RepositoryServiceError, match="Only RPM repositories"):
        await repository_service.add_variant(session, repository, EL9)


# -------------------------------------------------------------------- upload


async def test_an_uploaded_package_lands_in_the_variants_packages_directory(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    variant = repository.variants[0]
    source = build_simple(tmp_path / "whatever.rpm", name="example", version="1.0")

    outcome = await package_service.publish_rpm(
        session,
        settings,
        repository=repository,
        variant=variant,
        staged=await stage(root, source, settings),
    )

    assert outcome.created
    assert outcome.package.relative_path == ("el9/x86_64/Packages/example-1.0-1.el9.x86_64.rpm")
    assert (root / outcome.package.relative_path).is_file()
    assert outcome.package.release == "1.el9"


async def test_the_uploaded_filename_is_never_used_as_a_path(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    """The header decides where the file goes, not whatever was uploaded (10.2)."""
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    source = build_simple(tmp_path / "...%2F...%2Fpasswd.rpm", name="example")

    outcome = await package_service.publish_rpm(
        session,
        settings,
        repository=repository,
        variant=repository.variants[0],
        staged=await stage(root, source, settings),
    )

    assert outcome.package.relative_path.startswith("el9/x86_64/Packages/")
    assert "passwd" not in outcome.package.relative_path


async def test_a_package_for_another_architecture_is_refused(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    """A variant *is* an architecture, so a mismatch is not publishable anywhere in it."""
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    source = build_simple(tmp_path / "a.rpm", name="example", architecture="aarch64")

    with pytest.raises(UploadError, match="publishes x86_64 and noarch only"):
        await package_service.publish_rpm(
            session,
            settings,
            repository=repository,
            variant=repository.variants[0],
            staged=await stage(root, source, settings),
        )


async def test_a_noarch_package_is_accepted_by_any_variant(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    source = build_simple(tmp_path / "a.rpm", name="example", architecture="noarch")

    outcome = await package_service.publish_rpm(
        session,
        settings,
        repository=repository,
        variant=repository.variants[0],
        staged=await stage(root, source, settings),
    )
    assert outcome.package.architecture == "noarch"


async def test_a_source_package_is_refused_at_upload(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    source = build_rpm(RpmSpec(name="example", source_rpm=None), tmp_path / "a.src.rpm")

    with pytest.raises(UploadError, match="source package"):
        await package_service.publish_rpm(
            session,
            settings,
            repository=repository,
            variant=repository.variants[0],
            staged=await stage(root, source, settings),
        )


async def test_two_releases_of_one_version_are_different_packages(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    """``release`` is part of an RPM's identity, and APT has no equivalent (4.2).

    Matching on name and version alone would make ``foo-1.0-2`` look like a
    re-upload of ``foo-1.0-1`` with different bytes, and the second would be
    refused as a conflict.
    """
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    variant = repository.variants[0]

    for release in ("1.el9", "2.el9"):
        source = build_simple(tmp_path / f"{release}.rpm", name="example", release=release)
        outcome = await package_service.publish_rpm(
            session,
            settings,
            repository=repository,
            variant=variant,
            staged=await stage(root, source, settings),
        )
        assert outcome.created

    stored = await session.scalars(select(Package).where(Package.repository_id == repository.id))
    assert sorted(package.release or "" for package in stored) == ["1.el9", "2.el9"]


async def test_re_uploading_identical_bytes_is_a_no_op_success(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    """A CI job that retries an upload should not fail (5.1)."""
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    source = build_simple(tmp_path / "a.rpm", name="example")

    first = await package_service.publish_rpm(
        session,
        settings,
        repository=repository,
        variant=repository.variants[0],
        staged=await stage(root, source, settings),
    )
    second = await package_service.publish_rpm(
        session,
        settings,
        repository=repository,
        variant=repository.variants[0],
        staged=await stage(root, source, settings),
    )

    assert first.created
    assert not second.created
    assert second.package.id == first.package.id


async def test_the_same_nevra_with_different_bytes_is_a_conflict(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    """A client that already installed the old file would never be told (5.1)."""
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    variant = repository.variants[0]

    original = build_simple(tmp_path / "a.rpm", name="example")
    await package_service.publish_rpm(
        session,
        settings,
        repository=repository,
        variant=variant,
        staged=await stage(root, original, settings),
    )
    altered = build_simple(
        tmp_path / "b.rpm", name="example", payload={"./usr/share/doc/example/README": b"changed"}
    )

    with pytest.raises(UploadError) as raised:
        await package_service.publish_rpm(
            session,
            settings,
            repository=repository,
            variant=variant,
            staged=await stage(root, altered, settings),
        )
    assert raised.value.status_code == 409
    assert "example-1.0-1.el9.x86_64" in str(raised.value)


async def test_one_file_serves_two_variants(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    """A noarch package published twice is one row and two publications (9).

    Its path is fixed by the first variant it landed in, which is why the
    second publication is a database row rather than a second copy on disk.
    """
    root = repository_root / "el"
    repository = await build_repository(
        session, settings, keyring, root, variants=(EL9, VariantSpec(name="el8", arch="x86_64"))
    )
    source = build_simple(tmp_path / "a.rpm", name="example", architecture="noarch")

    outcomes = [
        await package_service.publish_rpm(
            session,
            settings,
            repository=repository,
            variant=variant,
            staged=await stage(root, source, settings),
        )
        for variant in repository.variants
    ]

    assert all(outcome.created for outcome in outcomes)
    assert outcomes[0].package.id == outcomes[1].package.id
    publications = await session.scalars(
        select(PackagePublication).where(PackagePublication.package_id == outcomes[0].package.id)
    )
    assert len(list(publications)) == 2


# -------------------------------------------------------------------- removal


async def test_removing_the_last_publication_deletes_the_file_but_keeps_the_variant(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    """``Packages/`` is structure, not litter: createrepo_c indexes it either way."""
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    source = build_simple(tmp_path / "a.rpm", name="example")
    outcome = await package_service.publish_rpm(
        session,
        settings,
        repository=repository,
        variant=repository.variants[0],
        staged=await stage(root, source, settings),
    )
    stored = root / outcome.package.relative_path
    publication = await package_service.load_publication(
        session, repository, outcome.package.publications[0].id
    )

    removed = await package_service.remove_publication(session, settings, repository, publication)

    assert removed
    assert not stored.exists()
    assert (root / "el9" / "x86_64" / "Packages").is_dir()


# --------------------------------------------------------------- regeneration


async def test_the_regeneration_job_reindexes_every_variant(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    sessionmaker: async_sessionmaker[AsyncSession],
    fake_createrepo: FakeCreaterepo,
) -> None:
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root, variants=(EL9, EL8))
    await session.commit()

    context = JobContext(
        job_id=0, repository_id=repository.id, settings=settings, sessionmaker=sessionmaker
    )
    fake_createrepo.binary.with_suffix(".log").unlink(missing_ok=True)

    await publishing.regenerate_metadata(context)

    indexed = {invocation[-1] for invocation in fake_createrepo.invocations}
    assert indexed == {str(root / "el9" / "x86_64"), str(root / "el8" / "aarch64")}


async def test_a_failing_createrepo_becomes_a_job_failure_with_its_own_words(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    sessionmaker: async_sessionmaker[AsyncSession],
    fake_createrepo: FakeCreaterepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The job log is where an operator looks, so the tool's own message goes there (6)."""
    root = repository_root / "el"
    repository = await build_repository(session, settings, keyring, root)
    await session.commit()
    monkeypatch.setenv("FAKE_CREATEREPO_FAIL", "1")

    context = JobContext(
        job_id=0, repository_id=repository.id, settings=settings, sessionmaker=sessionmaker
    )
    with pytest.raises(publishing.PublishError, match="refusing, as this test asked it to"):
        await publishing.regenerate_metadata(context)


async def test_the_plan_describes_the_tree_and_asks_nothing_about_packages(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    fake_createrepo: FakeCreaterepo,
) -> None:
    """createrepo_c reads the files itself, so the database is never consulted (4.2)."""
    repository = await build_repository(
        session, settings, keyring, repository_root / "el", variants=(EL9, EL8)
    )
    await publishing.load_for_publish(session, repository.id)

    plan = await publishing.build_rpm_plan(session, repository)

    assert sorted(variant.path for variant in plan.variants) == ["el8/aarch64", "el9/x86_64"]
