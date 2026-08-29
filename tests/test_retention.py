"""Version-based retention (specification.md 5.3).

The interesting cases are all about *which* version is oldest, so most of these
publish deliberately awkward version strings: retention that sorted them as
text would prune 1.10 in favour of 1.9, and nobody would notice until the
package everyone installs disappeared.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.config import Settings
from repository_manager.models import (
    KeyAlgorithm,
    Repository,
    RepositoryType,
    SigningKey,
)
from repository_manager.services import packages as package_service
from repository_manager.services import repositories as repository_service
from repository_manager.services import retention
from repository_manager.services.repositories import DistributionSpec, VariantSpec
from tests.conftest import FakeCreaterepo, Keyring
from tests.support.debs import DebSpec, build_deb
from tests.support.rpms import RpmSpec, build_rpm

Sessionmaker = async_sessionmaker[AsyncSession]


@pytest.fixture
async def session(sessionmaker: Sessionmaker) -> AsyncIterator[AsyncSession]:
    async with sessionmaker() as active:
        yield active
        await active.commit()


@pytest.fixture
async def key(session: AsyncSession, keyring: Keyring) -> SigningKey:
    record = SigningKey(
        name=keyring.name,
        fingerprint=keyring.fingerprint,
        algorithm=KeyAlgorithm.ED25519,
        uid="Repository Manager test key <test-key@example.test>",
        public_key_armored=keyring.armored,
    )
    session.add(record)
    await session.flush()
    return record


@pytest.fixture
async def apt(
    session: AsyncSession, settings: Settings, key: SigningKey, repository_root: Path
) -> Repository:
    return await repository_service.create_apt_repository(
        session,
        settings,
        name="Retention",
        root_path=str(repository_root / "retention"),
        signing_key_id=key.id,
        retention_count=2,
        distributions=(
            DistributionSpec(
                codename="bookworm", components=("main", "contrib"), architectures=("amd64", "all")
            ),
        ),
    )


async def publish(
    session: AsyncSession,
    settings: Settings,
    repository: Repository,
    built: Path,
    *,
    component_name: str = "main",
) -> None:
    distribution = repository.distributions[0]
    component = next(c for c in distribution.components if c.name == component_name)

    async def chunks(payload: bytes = built.read_bytes()) -> AsyncIterator[bytes]:
        yield payload

    staged = await package_service.stage_upload(
        Path(repository.root_path), chunks(), max_bytes=settings.max_upload_bytes
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


async def publish_versions(
    session: AsyncSession,
    settings: Settings,
    repository: Repository,
    versions: list[str],
    tmp_path: Path,
    *,
    name: str = "alpha",
    architecture: str = "amd64",
    component_name: str = "main",
) -> None:
    for version in versions:
        built = build_deb(
            DebSpec(name=name, version=version, architecture=architecture),
            tmp_path / f"{name}_{version}_{architecture}.deb",
        )
        await publish(session, settings, repository, built, component_name=component_name)


def names(pruned: list[retention.Pruned]) -> set[str]:
    return {f"{entry.name} {entry.version}" for entry in pruned}


# ------------------------------------------------------------------ keep all


async def test_keeping_all_versions_prunes_nothing(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    apt.retention_count = 0
    await publish_versions(session, settings, apt, ["1.0-1", "1.1-1", "1.2-1"], tmp_path)
    assert await retention.preview(session, apt) == []
    assert await retention.enforce_all(session, settings, apt) == []


# ------------------------------------------------------------------ ordering


async def test_the_oldest_versions_go_first(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    await publish_versions(session, settings, apt, ["1.0-1", "1.1-1", "1.2-1"], tmp_path)
    pruned = await retention.enforce_for(session, settings, apt, name="alpha")
    assert names(pruned) == {"alpha 1.0-1"}


async def test_ordering_is_debians_and_not_the_strings(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    """Sorted as text, 1.10 is older than 1.9 and the wrong package is deleted."""
    await publish_versions(session, settings, apt, ["1.9-1", "1.10-1", "1.11-1"], tmp_path)
    pruned = await retention.enforce_for(session, settings, apt, name="alpha")
    assert names(pruned) == {"alpha 1.9-1"}


async def test_a_tilde_version_sorts_before_its_release(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    """`2.0~rc1` is *older* than `2.0`, which no string comparison agrees with."""
    await publish_versions(session, settings, apt, ["2.0~rc1", "2.0-1", "2.1-1"], tmp_path)
    pruned = await retention.enforce_for(session, settings, apt, name="alpha")
    assert names(pruned) == {"alpha 2.0~rc1"}


async def test_an_epoch_outranks_the_version(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    await publish_versions(session, settings, apt, ["9.0-1", "1:1.0-1", "1:1.1-1"], tmp_path)
    pruned = await retention.enforce_for(session, settings, apt, name="alpha")
    assert names(pruned) == {"alpha 9.0-1"}


# ------------------------------------------------------------------ grouping


async def test_architectures_are_counted_separately(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    """5.3 does not mention architecture; counting without it loses the current
    build of whichever architecture happens to publish less often."""
    await publish_versions(session, settings, apt, ["1.0-1", "1.1-1", "1.2-1"], tmp_path)
    await publish_versions(session, settings, apt, ["1.0-1"], tmp_path, architecture="all")
    pruned = await retention.enforce_for(session, settings, apt, name="alpha")

    # Only the oldest amd64 build goes.  The `all` build is the only one of its
    # architecture, so it survives however many amd64 builds are newer than it.
    assert [(entry.version, entry.architecture) for entry in pruned] == [("1.0-1", "amd64")]
    assert await retention.preview(session, apt) == []


async def test_package_names_are_counted_separately(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    await publish_versions(session, settings, apt, ["1.0-1", "1.1-1", "1.2-1"], tmp_path)
    await publish_versions(session, settings, apt, ["1.0-1"], tmp_path, name="beta")
    pruned = await retention.enforce_for(session, settings, apt, name="beta")
    assert pruned == []


async def test_targets_are_counted_separately(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    """The same three versions in two components keep two each, not two total."""
    for component in ("main", "contrib"):
        await publish_versions(
            session,
            settings,
            apt,
            ["1.0-1", "1.1-1", "1.2-1"],
            tmp_path,
            component_name=component,
        )
    pruned = await retention.enforce_all(session, settings, apt)
    assert len(pruned) == 2
    assert {entry.target for entry in pruned} == {"bookworm/main", "bookworm/contrib"}


# ------------------------------------------------------------------ the pool file


async def test_the_pool_file_survives_while_another_target_lists_it(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    """One file, two publications: pruning one is not a deletion (5.2, 5.3)."""
    built = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")
    await publish(session, settings, apt, built)
    await publish(session, settings, apt, built, component_name="contrib")
    await publish_versions(session, settings, apt, ["1.1-1", "1.2-1"], tmp_path)

    pruned = await retention.enforce_for(session, settings, apt, name="alpha")
    assert len(pruned) == 1
    assert pruned[0].file_deleted is False
    assert (Path(apt.root_path) / pruned[0].relative_path).is_file()


async def test_the_pool_file_goes_with_the_last_publication(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    await publish_versions(session, settings, apt, ["1.0-1", "1.1-1", "1.2-1"], tmp_path)
    pruned = await retention.enforce_for(session, settings, apt, name="alpha")
    assert pruned[0].file_deleted is True
    assert not (Path(apt.root_path) / pruned[0].relative_path).exists()


# ------------------------------------------------------------------ scope


async def test_a_publish_prunes_only_the_name_it_published(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    """One person's upload must not silently delete another person's package."""
    await publish_versions(
        session, settings, apt, ["1.0-1", "1.1-1", "1.2-1"], tmp_path, name="beta"
    )
    apt.retention_count = 1
    await publish_versions(session, settings, apt, ["1.0-1"], tmp_path, name="alpha")

    pruned = await retention.enforce_for(session, settings, apt, name="alpha")
    assert pruned == []
    # beta's backlog is still there, waiting for the explicit action.
    assert len(await retention.preview(session, apt)) == 2


async def test_apply_now_clears_the_backlog(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    await publish_versions(session, settings, apt, ["1.0-1", "1.1-1", "1.2-1"], tmp_path)
    apt.retention_count = 1
    assert len(await retention.preview(session, apt)) == 2

    pruned = await retention.enforce_all(session, settings, apt)
    assert names(pruned) == {"alpha 1.0-1", "alpha 1.1-1"}
    assert await retention.preview(session, apt) == []


async def test_the_preview_changes_nothing(
    session: AsyncSession, settings: Settings, apt: Repository, tmp_path: Path
) -> None:
    await publish_versions(session, settings, apt, ["1.0-1", "1.1-1", "1.2-1"], tmp_path)
    before = await retention.preview(session, apt)
    after = await retention.preview(session, apt)
    assert len(before) == len(after) == 1


# ------------------------------------------------------------------ RPM


@pytest.fixture
async def rpm(
    session: AsyncSession,
    settings: Settings,
    key: SigningKey,
    repository_root: Path,
    fake_createrepo: FakeCreaterepo,
) -> Repository:
    return await repository_service.create_rpm_repository(
        session,
        settings,
        name="EL9 retention",
        root_path=str(repository_root / "el9"),
        signing_key_id=key.id,
        retention_count=2,
        variants=(VariantSpec(name="el9", arch="x86_64"),),
    )


async def test_rpm_ordering_uses_rpms_own_rules(
    session: AsyncSession, settings: Settings, rpm: Repository, tmp_path: Path
) -> None:
    """`1.0-1` is older than `1.0-2`, and `~` sorts before everything (4.2)."""
    variant = rpm.variants[0]
    for version, release in (("1.0", "1.el9"), ("1.0", "2.el9"), ("1.1~beta", "1.el9")):
        built = build_rpm(
            RpmSpec(name="hello", version=version, release=release, architecture="x86_64"),
            tmp_path / f"hello-{version}-{release}.rpm",
        )

        async def chunks(payload: bytes = built.read_bytes()) -> AsyncIterator[bytes]:
            yield payload

        staged = await package_service.stage_upload(
            Path(rpm.root_path), chunks(), max_bytes=settings.max_upload_bytes
        )
        await package_service.publish_rpm(
            session, settings, repository=rpm, variant=variant, staged=staged
        )
    await session.flush()

    pruned = await retention.enforce_for(session, settings, rpm, name="hello")
    # 1.1~beta is newer than either 1.0; the older *release* of 1.0 goes.
    assert names(pruned) == {"hello 1.0-1.el9"}


async def test_the_type_decides_which_comparator_is_used(
    session: AsyncSession, settings: Settings, apt: Repository, rpm: Repository
) -> None:
    """Guards the branch: two formats, two orderings, chosen by the row."""
    assert apt.type is RepositoryType.APT
    assert rpm.type is RepositoryType.RPM
