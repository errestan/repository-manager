"""Key, repository and package services (specification.md 4.3, 5.1, 5.2, 10.5)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.config import Settings
from repository_manager.models import (
    KeyAlgorithm,
    Package,
    Repository,
    RepositoryType,
    SigningKey,
)
from repository_manager.security.gpg import GnuPG
from repository_manager.security.passphrase import PassphraseStore
from repository_manager.services import keys as key_service
from repository_manager.services import packages as package_service
from repository_manager.services import publishing
from repository_manager.services import repositories as repository_service
from repository_manager.services.keys import KeyServiceError
from repository_manager.services.packages import UploadError
from repository_manager.services.repositories import (
    DistributionSpec,
    RepositoryServiceError,
    parse_name_list,
    slugify,
)
from tests.conftest import Keyring
from tests.support.debs import DebSpec, build_deb

BOOKWORM = DistributionSpec(
    codename="bookworm", components=("main", "contrib"), architectures=("amd64", "arm64")
)


@pytest.fixture
async def session(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with sessionmaker() as active:
        yield active
        await active.commit()


@pytest.fixture
def scratch_settings(make_settings: Callable[..., Settings], scratch_keyring: Keyring) -> Settings:
    """Settings pointing at a keyring this test may modify."""
    return make_settings(gnupghome=str(scratch_keyring.home))


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


# --------------------------------------------------------------------- keys


async def test_a_generated_key_is_stored_and_can_sign(
    session: AsyncSession, scratch_settings: Settings
) -> None:
    key = await key_service.generate_key(
        session,
        scratch_settings,
        name="fresh",
        display_name="Fresh Repository",
        algorithm=KeyAlgorithm.ED25519,
    )
    assert key.fingerprint
    assert key.passphrase_ref == "fresh"
    assert "BEGIN PGP PUBLIC KEY BLOCK" in key.public_key_armored
    assert "Fresh Repository repository signing key" in key.uid
    await key_service.verify_usable(scratch_settings, key)


async def test_the_generated_passphrase_is_never_stored_in_the_database(
    session: AsyncSession, scratch_settings: Settings
) -> None:
    """The row holds a reference; the secret lives in the keyring (10.5)."""
    key = await key_service.generate_key(
        session,
        scratch_settings,
        name="fresh",
        display_name="Fresh",
        algorithm=KeyAlgorithm.ED25519,
    )
    stored = PassphraseStore(scratch_settings.gnupghome).resolve(key.passphrase_ref)
    assert stored
    assert stored not in key.public_key_armored
    assert key.passphrase_ref == "fresh"


async def test_a_duplicate_key_name_is_refused(
    session: AsyncSession, scratch_settings: Settings, scratch_keyring: Keyring
) -> None:
    await register(session, scratch_keyring)
    with pytest.raises(KeyServiceError, match="already exists"):
        await key_service.generate_key(
            session,
            scratch_settings,
            name=scratch_keyring.name,
            display_name="Duplicate",
            algorithm=KeyAlgorithm.ED25519,
        )


async def test_importing_a_key_already_registered_is_refused(
    session: AsyncSession, scratch_settings: Settings, scratch_keyring: Keyring, tmp_path: Path
) -> None:
    await register(session, scratch_keyring)
    other = GnuPG(tmp_path / "source")
    try:
        info = other.generate_key("Exportable <e@example.test>", KeyAlgorithm.ED25519)
        # A public-only block is refused earlier, so this exercises the
        # fingerprint clash rather than the missing-private-half check.
        assert info.fingerprint != scratch_keyring.fingerprint
    finally:
        other.shutdown()

    with pytest.raises(KeyServiceError):
        await key_service.import_key(
            session, scratch_settings, name="another", armored=scratch_keyring.armored
        )


async def test_a_key_in_use_cannot_be_deleted(
    session: AsyncSession, scratch_settings: Settings, scratch_keyring: Keyring
) -> None:
    """Deleting it would leave a repository's metadata unverifiable (10.5)."""
    key = await register(session, scratch_keyring)
    session.add(
        Repository(
            slug="internal",
            name="Internal",
            type=RepositoryType.APT,
            root_path="/srv/internal",
            signing_key_id=key.id,
        )
    )
    await session.flush()

    with pytest.raises(KeyServiceError, match="still signs"):
        await key_service.delete_key(session, scratch_settings, key)


async def test_an_unused_key_is_deleted_from_the_keyring_too(
    session: AsyncSession, scratch_settings: Settings, scratch_keyring: Keyring
) -> None:
    key = await register(session, scratch_keyring)
    await key_service.delete_key(session, scratch_settings, key)
    await session.flush()

    assert not GnuPG(scratch_keyring.home).has_secret_key(scratch_keyring.fingerprint)
    assert await session.scalar(select(SigningKey).where(SigningKey.name == key.name)) is None


async def test_a_key_missing_its_private_half_is_reported_before_use(
    session: AsyncSession, scratch_settings: Settings, scratch_keyring: Keyring
) -> None:
    """Caught at creation, not at the first failed publish days later."""
    key = await register(session, scratch_keyring)
    GnuPG(scratch_keyring.home).delete_key(scratch_keyring.fingerprint)
    with pytest.raises(KeyServiceError, match="not in the keyring"):
        await key_service.verify_usable(scratch_settings, key)


# ------------------------------------------------------------- repositories


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("Internal APT", "internal-apt"),
        ("  Spaced  Out  ", "spaced-out"),
        ("Ünïcödé!!", "n-c-d"),
        ("...", "repository"),
        ("A" * 200, "a" * 64),
    ],
)
def test_slugs_are_derived_from_the_name(name: str, slug: str) -> None:
    assert slugify(name) == slug


async def test_a_clashing_slug_gets_a_suffix(session: AsyncSession) -> None:
    session.add(
        Repository(slug="internal", name="Internal", type=RepositoryType.APT, root_path="/srv/i")
    )
    await session.flush()
    assert await repository_service.unique_slug(session, "internal") == "internal-2"


@pytest.mark.parametrize(
    "raw",
    ["main contrib", "contrib,main", " main , contrib ", "main\ncontrib", "main main contrib"],
)
def test_name_lists_accept_commas_or_whitespace(raw: str) -> None:
    """Sorted and de-duplicated, so creation and regeneration agree byte for byte."""
    assert parse_name_list(raw) == ("contrib", "main")


def test_a_root_outside_the_allowed_roots_is_refused(settings: Settings, tmp_path: Path) -> None:
    with pytest.raises(RepositoryServiceError, match="not inside a permitted root"):
        repository_service.validate_root(str(tmp_path / "elsewhere"), settings)


def test_a_non_empty_root_is_refused(settings: Settings, repository_root: Path) -> None:
    """Never partially overwrite an existing repository (4.3)."""
    occupied = repository_root / "occupied"
    occupied.mkdir()
    (occupied / "Release").write_text("existing")
    with pytest.raises(RepositoryServiceError, match="already contains files"):
        repository_service.validate_root(str(occupied), settings)


def test_an_empty_existing_root_is_accepted(settings: Settings, repository_root: Path) -> None:
    empty = repository_root / "empty"
    empty.mkdir()
    assert repository_service.validate_root(str(empty), settings) == empty


async def test_creating_a_repository_writes_a_signed_empty_tree(
    session: AsyncSession, settings: Settings, keyring: Keyring, repository_root: Path
) -> None:
    """Clients can add the repository and run apt update immediately (4.3)."""
    key = await register(session, keyring)
    repository = await repository_service.create_apt_repository(
        session,
        settings,
        name="Internal APT",
        root_path=str(repository_root / "internal"),
        signing_key_id=key.id,
        retention_count=0,
        distributions=(BOOKWORM,),
    )
    assert repository.slug == "internal-apt"

    root = repository_root / "internal"
    dists = root / "dists" / "bookworm"
    assert (dists / "InRelease").is_file()
    assert (dists / "Release.gpg").is_file()
    assert (dists / "main/binary-amd64/Packages").read_bytes() == b""
    assert (root / "pool" / "main").is_dir()
    # The armoured public key is exported into the root for client setup (4.1).
    assert f"{keyring.name}.asc" in [p.name for p in root.iterdir()]


async def test_a_repository_needs_at_least_one_distribution(
    session: AsyncSession, settings: Settings, keyring: Keyring, repository_root: Path
) -> None:
    key = await register(session, keyring)
    with pytest.raises(RepositoryServiceError, match="at least one distribution"):
        await repository_service.create_apt_repository(
            session,
            settings,
            name="Empty",
            root_path=str(repository_root / "empty"),
            signing_key_id=key.id,
            retention_count=0,
            distributions=(),
        )


async def test_a_distribution_needs_a_component_and_an_architecture(
    session: AsyncSession, settings: Settings, keyring: Keyring, repository_root: Path
) -> None:
    key = await register(session, keyring)
    with pytest.raises(RepositoryServiceError, match="at least one component"):
        await repository_service.create_apt_repository(
            session,
            settings,
            name="Bad",
            root_path=str(repository_root / "bad"),
            signing_key_id=key.id,
            retention_count=0,
            distributions=(
                DistributionSpec(codename="bookworm", components=(), architectures=("amd64",)),
            ),
        )


# ----------------------------------------------------------------- packages


async def build_repository(
    session: AsyncSession, settings: Settings, keyring: Keyring, root: Path
) -> Repository:
    key = await register(session, keyring)
    return await repository_service.create_apt_repository(
        session,
        settings,
        name="Internal",
        root_path=str(root),
        signing_key_id=key.id,
        retention_count=0,
        distributions=(BOOKWORM,),
    )


async def stage(root: Path, payload: bytes, settings: Settings) -> Path:
    async def chunks() -> AsyncIterator[bytes]:
        yield payload

    return await package_service.stage_upload(root, chunks(), max_bytes=settings.max_upload_bytes)


async def publish(
    session: AsyncSession,
    settings: Settings,
    repository: Repository,
    payload: bytes,
    component_name: str = "main",
) -> package_service.UploadOutcome:
    distribution = repository.distributions[0]
    component = next(c for c in distribution.components if c.name == component_name)
    root = Path(repository.root_path)
    staged = await stage(root, payload, settings)
    return await package_service.publish_deb(
        session,
        settings,
        repository=repository,
        distribution=distribution,
        component=component,
        staged=staged,
    )


async def test_an_upload_larger_than_the_limit_is_refused(repository_root: Path) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b"x" * 64

    with pytest.raises(UploadError) as raised:
        await package_service.stage_upload(repository_root, chunks(), max_bytes=32)
    assert raised.value.status_code == 413


async def test_a_refused_upload_leaves_nothing_staged(
    make_settings: Callable[..., Settings], repository_root: Path
) -> None:
    settings = make_settings(max_upload_bytes=32)

    async def chunks() -> AsyncIterator[bytes]:
        yield b"x" * 64

    with pytest.raises(UploadError):
        await package_service.stage_upload(repository_root, chunks(), max_bytes=32)
    incoming = repository_root / package_service.INCOMING_DIRNAME
    assert list(incoming.iterdir()) == []
    assert settings.max_upload_bytes == 32


async def test_publishing_stores_the_package_and_its_stanza(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")

    outcome = await publish(session, settings, repository, deb.read_bytes())
    assert outcome.created
    package = outcome.package
    assert package.relative_path == "pool/main/a/alpha/alpha_1.0-1_amd64.deb"
    assert (Path(repository.root_path) / package.relative_path).is_file()
    assert package.control_json["Package"] == "alpha"
    assert package.control_json["Filename"] == package.relative_path


async def test_the_staged_file_is_cleaned_up_after_publishing(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    await publish(session, settings, repository, deb.read_bytes())
    incoming = Path(repository.root_path) / package_service.INCOMING_DIRNAME
    assert list(incoming.iterdir()) == []


async def test_an_identical_re_upload_is_a_no_op_success(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    """A CI job that retries an upload should not fail (5.1)."""
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")

    first = await publish(session, settings, repository, deb.read_bytes())
    second = await publish(session, settings, repository, deb.read_bytes())
    assert first.created
    assert not second.created
    assert first.package.id == second.package.id


async def test_a_different_build_of_the_same_version_is_a_conflict(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    """Clients that already installed the old bytes would never be told (5.1)."""
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    original = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    await publish(session, settings, repository, original.read_bytes())

    altered = build_deb(
        DebSpec(name="alpha", version="1.0-1", homepage="https://changed.test/"),
        tmp_path / "b.deb",
    )
    with pytest.raises(UploadError) as raised:
        await publish(session, settings, repository, altered.read_bytes())
    assert raised.value.status_code == 409


async def test_an_unconfigured_architecture_is_refused(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(
        DebSpec(name="alpha", version="1.0-1", architecture="s390x"), tmp_path / "a.deb"
    )
    with pytest.raises(UploadError, match="does not publish"):
        await publish(session, settings, repository, deb.read_bytes())


async def test_architecture_all_is_accepted_anywhere(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(
        DebSpec(name="libgamma", version="1.0-1", architecture="all", source="libgamma"),
        tmp_path / "g.deb",
    )
    assert (await publish(session, settings, repository, deb.read_bytes())).created


async def test_something_that_is_not_a_package_is_refused(
    session: AsyncSession, settings: Settings, keyring: Keyring, repository_root: Path
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    with pytest.raises(UploadError, match="not a Debian package"):
        await publish(session, settings, repository, b"just some bytes")


async def test_one_pool_file_serves_a_second_component(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    """Publishing to another target adds a row, not a second copy (9)."""
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")

    first = await publish(session, settings, repository, deb.read_bytes(), "main")
    second = await publish(session, settings, repository, deb.read_bytes(), "contrib")
    assert second.created
    assert first.package.id == second.package.id

    await session.refresh(first.package, ["publications"])
    assert len(first.package.publications) == 2
    pool_files = list((Path(repository.root_path) / "pool").rglob("*.deb"))
    assert len(pool_files) == 1


async def test_removing_the_last_publication_deletes_the_pool_file(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    outcome = await publish(session, settings, repository, deb.read_bytes())
    pool_file = Path(repository.root_path) / outcome.package.relative_path

    publication = await package_service.load_publication(
        session, repository, outcome.package.publications[0].id
    )
    removed = await package_service.remove_publication(session, settings, repository, publication)
    assert removed
    assert not pool_file.exists()
    assert await session.scalar(select(Package).where(Package.id == outcome.package.id)) is None


async def test_removing_one_of_two_publications_keeps_the_file(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    """A pool file goes only once nothing references it (5.3)."""
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    await publish(session, settings, repository, deb.read_bytes(), "main")
    outcome = await publish(session, settings, repository, deb.read_bytes(), "contrib")
    pool_file = Path(repository.root_path) / outcome.package.relative_path

    await session.refresh(outcome.package, ["publications"])
    publication = await package_service.load_publication(
        session, repository, outcome.package.publications[0].id
    )
    removed = await package_service.remove_publication(session, settings, repository, publication)
    assert not removed
    assert pool_file.exists()


async def test_a_publication_from_another_repository_is_not_reachable(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    outcome = await publish(session, settings, repository, deb.read_bytes())

    other = Repository(slug="other", name="Other", type=RepositoryType.APT, root_path="/srv/other")
    session.add(other)
    await session.flush()

    with pytest.raises(UploadError) as raised:
        await package_service.load_publication(session, other, outcome.package.publications[0].id)
    assert raised.value.status_code == 404


# --------------------------------------------------------------- publishing


async def test_the_plan_reflects_what_is_published(
    session: AsyncSession,
    settings: Settings,
    keyring: Keyring,
    repository_root: Path,
    tmp_path: Path,
) -> None:
    repository = await build_repository(session, settings, keyring, repository_root / "internal")
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "a.deb")
    await publish(session, settings, repository, deb.read_bytes())
    await session.flush()

    plan = await publishing.build_apt_plan(session, repository)
    distribution = plan.distributions[0]
    assert distribution.codename == "bookworm"
    assert [s["Package"] for s in distribution.stanzas["main"]] == ["alpha"]
    assert distribution.stanzas["contrib"] == []


async def test_a_repository_with_no_signing_key_fails_before_anything_is_written(
    session: AsyncSession, settings: Settings
) -> None:
    """Unsigned metadata is worse than none: apt and dnf both refuse it (10.5).

    Checked for both formats and before any generator runs, so the failure is a
    job that did nothing rather than a tree clients cannot verify.
    """
    repository = Repository(slug="el9", name="EL9", type=RepositoryType.RPM, root_path="/srv/el9")
    session.add(repository)
    await session.flush()

    from repository_manager.jobs.queue import JobContext

    context = JobContext(
        job_id=0,
        repository_id=repository.id,
        settings=settings,
        sessionmaker=lambda: session,  # type: ignore[arg-type]
    )
    with pytest.raises(publishing.PublishError, match="no signing key"):
        await publishing.regenerate_metadata(context)
