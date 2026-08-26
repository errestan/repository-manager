"""The generated repository, judged by apt itself (specification.md 4.1, AD-2).

Every other test asserts that the output *looks* right.  These assert that apt
accepts it -- and, just as importantly, that apt rejects it once it has been
tampered with.  A repository that apt accepts unconditionally would be worse
than one it rejects: it would mean the signature and hash chain was decorative.
"""

from __future__ import annotations

import gzip
import lzma
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.config import Settings
from repository_manager.models import KeyAlgorithm, Repository, SigningKey
from repository_manager.security.gpg import GnuPG
from repository_manager.services import keys as key_service
from repository_manager.services import packages as package_service
from repository_manager.services import publishing
from repository_manager.services import repositories as repository_service
from repository_manager.services.repositories import DistributionSpec
from tests.conftest import Keyring
from tests.integration.aptclient import APT_CACHE, APT_GET, IsolatedApt
from tests.support.debs import DebSpec, build_deb

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        APT_GET is None or APT_CACHE is None,
        reason="apt-get and apt-cache are required to verify the generated repository",
    ),
]

CODENAME = "bookworm"
PACKAGES = [
    DebSpec(name="alpha", version="1.0-1", architecture="amd64"),
    DebSpec(name="alpha", version="1.2-1", architecture="amd64"),
    DebSpec(name="beta", version="2:0.9-2", architecture="amd64", source="beta-src"),
    DebSpec(name="libgamma", version="3.1-1", architecture="all", source="libgamma"),
    DebSpec(name="delta", version="1.0-1", architecture="arm64"),
]


@pytest.fixture
async def session(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
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
    """A repository with several packages published and its metadata written."""
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
        name="Integration",
        root_path=str(repository_root / "integration"),
        signing_key_id=key.id,
        retention_count=0,
        distributions=(
            DistributionSpec(
                codename=CODENAME, components=("main",), architectures=("amd64", "arm64")
            ),
        ),
    )

    distribution = repository.distributions[0]
    component = distribution.components[0]
    for spec in PACKAGES:
        built = build_deb(spec, tmp_path / f"{spec.name}_{spec.version}_{spec.architecture}.deb")

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

    plan = await publishing.build_apt_plan(session, repository)
    publishing.write_apt_metadata(
        Path(repository.root_path),
        plan,
        signer=key_service.build_signer(settings, key),
        key_name=key.name,
        public_key=key.public_key_armored,
    )
    return repository


@pytest.fixture
def apt(published: Repository, keyring: Keyring, tmp_path: Path) -> IsolatedApt:
    root = Path(published.root_path)
    client = IsolatedApt(tmp_path / "aptroot", root, root / f"{keyring.name}.asc")
    client.configure(CODENAME, "main")
    return client


@pytest.fixture
def dists(published: Repository) -> Path:
    return Path(published.root_path) / "dists" / CODENAME


# ------------------------------------------------------------------ acceptance


def test_apt_accepts_the_repository(apt: IsolatedApt) -> None:
    """The whole point: signature verified, every index hash matched."""
    result = apt.update()
    assert result.ok, result.output


def test_apt_sees_every_published_version(apt: IsolatedApt) -> None:
    assert apt.update().ok
    policy = apt.policy("alpha")
    assert policy.ok, policy.output
    assert "1.0-1" in policy.stdout
    assert "1.2-1" in policy.stdout
    # apt picks the candidate using Debian version ordering, not string order.
    assert "Candidate: 1.2-1" in policy.stdout


def test_an_epoch_is_preserved_in_the_index_but_not_the_filename(apt: IsolatedApt) -> None:
    """dpkg omits the epoch from filenames and tools rely on that (4.1)."""
    assert apt.update().ok
    shown = apt.show("beta")
    assert shown.ok, shown.output
    assert "Version: 2:0.9-2" in shown.stdout
    assert "beta_0.9-2_amd64.deb" in shown.stdout


def test_an_architecture_all_package_is_visible_to_an_amd64_client(apt: IsolatedApt) -> None:
    """apt only fetches indices for its own architectures (4.1)."""
    assert apt.update().ok
    shown = apt.show("libgamma")
    assert shown.ok, shown.output
    assert "Architecture: all" in shown.stdout


def test_a_package_for_another_architecture_is_not_offered(apt: IsolatedApt) -> None:
    assert apt.update().ok
    assert not apt.show("delta").ok


def test_apt_downloads_a_package_and_its_hash_matches(apt: IsolatedApt, tmp_path: Path) -> None:
    """Downloading checks the .deb against the SHA256 recorded in the index."""
    assert apt.update().ok
    result = apt.download("libgamma")
    assert result.ok, result.output


def test_the_exported_public_key_is_what_apt_trusts(
    published: Repository, keyring: Keyring
) -> None:
    """The armoured key in the repository root is the one clients install (4.3)."""
    exported = (Path(published.root_path) / f"{keyring.name}.asc").read_text()
    assert "BEGIN PGP PUBLIC KEY BLOCK" in exported
    assert "PRIVATE KEY" not in exported


# ------------------------------------------------------------------ rejection


def _rewrite_all_index_forms(binary: Path, replacement: bytes) -> None:
    """Change Packages and both compressed forms together.

    apt fetches whichever variant it prefers -- in practice Packages.gz -- so
    editing only the uncompressed file proves nothing.
    """
    (binary / "Packages").write_bytes(replacement)
    (binary / "Packages.gz").write_bytes(gzip.compress(replacement, 9, mtime=0))
    (binary / "Packages.xz").write_bytes(lzma.compress(replacement, format=lzma.FORMAT_XZ))


def test_apt_rejects_a_modified_index(apt: IsolatedApt, dists: Path) -> None:
    assert apt.update().ok

    binary = dists / "main" / "binary-amd64"
    tampered = (binary / "Packages").read_bytes().replace(b"Version: 1.0-1", b"Version: 9.9-9")
    _rewrite_all_index_forms(binary, tampered)

    result = apt.update()
    assert not result.ok
    assert "Hash Sum mismatch" in result.output


def test_apt_rejects_a_modified_inrelease(apt: IsolatedApt, dists: Path) -> None:
    assert apt.update().ok

    inline = dists / "InRelease"
    inline.write_bytes(inline.read_bytes().replace(b"Origin: Integration", b"Origin: Substitute"))

    result = apt.update()
    assert not result.ok
    assert "BADSIG" in result.output or "not signed" in result.output


def test_the_detached_signature_path_also_works(apt: IsolatedApt, dists: Path) -> None:
    """Older clients fetch Release + Release.gpg rather than InRelease (4.1)."""
    (dists / "InRelease").unlink()
    result = apt.update()
    assert result.ok, result.output


def test_apt_rejects_a_modified_release_when_only_the_detached_form_exists(
    apt: IsolatedApt, dists: Path
) -> None:
    (dists / "InRelease").unlink()
    release = dists / "Release"
    release.write_bytes(release.read_bytes().replace(b"Origin: Integration", b"Origin: Substitute"))

    result = apt.update()
    assert not result.ok


def test_apt_rejects_metadata_signed_by_an_untrusted_key(
    apt: IsolatedApt, published: Repository, keyring: Keyring, tmp_path: Path
) -> None:
    """Replacing the trusted key must not make an unrelated signature acceptable."""
    assert apt.update().ok

    stranger = GnuPG(tmp_path / "stranger")
    try:
        other = stranger.generate_key("Stranger <s@example.test>", KeyAlgorithm.ED25519)
        (Path(published.root_path) / f"{keyring.name}.asc").write_text(
            stranger.export_public(other.fingerprint)
        )
    finally:
        stranger.shutdown()

    result = apt.update()
    assert not result.ok
    assert "NO_PUBKEY" in result.output or "not signed" in result.output


async def test_removing_a_package_removes_it_from_what_apt_sees(
    apt: IsolatedApt,
    published: Repository,
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Regeneration rebuilds the tree rather than merging into it (5.2)."""
    assert apt.update().ok
    assert "1.0-1" in apt.policy("alpha").stdout

    await session.refresh(published, ["packages"])
    for package in [p for p in published.packages if p.name == "alpha"]:
        await session.refresh(package, ["publications"])
        publication = await package_service.load_publication(
            session, published, package.publications[0].id
        )
        await package_service.remove_publication(session, settings, published, publication)
    await session.flush()

    plan = await publishing.build_apt_plan(session, published)
    key = await session.get(SigningKey, published.signing_key_id)
    assert key is not None
    publishing.write_apt_metadata(
        Path(published.root_path),
        plan,
        signer=key_service.build_signer(settings, key),
        key_name=key.name,
        public_key=key.public_key_armored,
    )

    result = apt.update()
    assert result.ok, result.output
    # Gone from the index, and gone from the pool: nothing references it now.
    assert not apt.show("alpha").ok
    assert list(Path(published.root_path).rglob("alpha_*.deb")) == []
