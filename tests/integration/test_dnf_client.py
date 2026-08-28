"""The generated RPM repository, judged by dnf itself (specification.md 4.2, AD-2).

This is the test that makes AD-2 safe on the RPM side.  Every other test in the
suite asserts that this application *invoked* ``createrepo_c`` correctly and
signed what came out; these assert that a real ``dnf`` reads the result, finds
the packages, and refuses the repository once the metadata has been tampered
with.  A dnf that accepted it unconditionally would mean the signature was
decorative.

The packages are built by ``rpmbuild``, not by this project.  A generated index
is only worth as much as the packages behind it, and indexing packages that
this repository's own code produced would prove that two halves of the same
codebase agree with each other.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.config import Settings
from repository_manager.metadata import repodata
from repository_manager.models import KeyAlgorithm, Repository, SigningKey
from repository_manager.security.gpg import GnuPG
from repository_manager.services import keys as key_service
from repository_manager.services import packages as package_service
from repository_manager.services import publishing
from repository_manager.services import repositories as repository_service
from repository_manager.services.repositories import VariantSpec
from tests.conftest import Keyring
from tests.integration.dnfclient import (
    CREATEREPO,
    DNF,
    RPMBUILD,
    IsolatedDnf,
    build_rpm,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        DNF is None or RPMBUILD is None or CREATEREPO is None,
        reason="dnf, rpmbuild and createrepo_c are required to verify the generated repository",
    ),
]

VARIANT = VariantSpec(name="el9", arch="x86_64")
VARIANT_PATH = "el9/x86_64"

#: One ordinary package, one with an epoch, one noarch, one with a second
#: release of the same version.  Between them these cover every part of a NEVRA
#: that this application has to read out of a header and put back into a path.
PACKAGES = (
    {"name": "alpha", "version": "1.0", "release": "1.el9"},
    {"name": "alpha", "version": "1.0", "release": "2.el9"},
    {"name": "beta", "version": "0.9", "release": "1.el9", "epoch": 2},
    {"name": "gamma", "version": "3.1", "release": "1.el9", "arch": "noarch"},
)


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
    """A repository with real packages published and its metadata generated."""
    key = SigningKey(
        name=keyring.name,
        fingerprint=keyring.fingerprint,
        algorithm=KeyAlgorithm.ED25519,
        uid="Repository Manager test key <test-key@example.test>",
        public_key_armored=keyring.armored,
    )
    session.add(key)
    await session.flush()

    repository = await repository_service.create_rpm_repository(
        session,
        settings,
        name="Integration",
        root_path=str(repository_root / "integration"),
        signing_key_id=key.id,
        retention_count=0,
        variants=(VARIANT,),
    )
    variant = repository.variants[0]

    workspace = tmp_path / "rpmbuild"
    for spec in PACKAGES:
        built = build_rpm(workspace, **spec)

        async def chunks(payload: bytes = built.read_bytes()) -> AsyncIterator[bytes]:
            yield payload

        staged = await package_service.stage_upload(
            Path(repository.root_path), chunks(), max_bytes=settings.max_upload_bytes
        )
        await package_service.publish_rpm(
            session,
            settings,
            repository=repository,
            variant=variant,
            staged=staged,
        )
    await session.flush()

    plan = await publishing.build_rpm_plan(session, repository)
    publishing.write_rpm_metadata(
        Path(repository.root_path),
        plan,
        signer=key_service.build_signer(settings, key),
        key_name=key.name,
        public_key=key.public_key_armored,
    )
    return repository


@pytest.fixture
def dnf(published: Repository, keyring: Keyring, tmp_path: Path) -> IsolatedDnf:
    root = Path(published.root_path)
    client = IsolatedDnf(
        tmp_path / "dnfroot", root, root / repodata.public_key_filename(keyring.name)
    )
    client.configure("integration", VARIANT_PATH)
    return client


def _repodata(published: Repository) -> Path:
    return Path(published.root_path) / VARIANT_PATH / repodata.REPODATA_DIRNAME


def repomd(published: Repository) -> Path:
    return _repodata(published) / repodata.REPOMD_FILENAME


def signature_path(published: Repository) -> Path:
    return _repodata(published) / repodata.REPOMD_SIGNATURE_FILENAME


def _primary_xml(published: Repository) -> str:
    """The uncompressed ``primary.xml`` createrepo_c wrote for this variant."""
    import gzip

    (primary,) = _repodata(published).glob("*primary.xml.gz")
    return gzip.decompress(primary.read_bytes()).decode()


# ------------------------------------------------------------------- structure


def test_the_generated_tree_matches_the_documented_layout(published: Repository) -> None:
    """The layout in 4.2 is a contract with whoever reads the tree."""
    variant = Path(published.root_path) / VARIANT_PATH

    assert (variant / "Packages" / "alpha-1.0-1.el9.x86_64.rpm").is_file()
    assert (variant / "Packages" / "gamma-3.1-1.el9.noarch.rpm").is_file()
    assert (variant / "repodata" / "repomd.xml").is_file()
    assert (variant / "repodata" / "repomd.xml.asc").is_file()

    body = (variant / "repodata" / "repomd.xml").read_text()
    for kind in ("primary", "filelists", "other"):
        assert f'type="{kind}"' in body
    # The compression is pinned rather than left to createrepo_c's default,
    # which has changed between releases.
    assert ".xml.gz" in body
    # sqlite metadata is deliberately not produced: nothing dnf supports has
    # read it since yum was retired.
    assert "sqlite" not in body


def test_the_epoch_is_kept_in_the_metadata_but_not_in_the_filename(
    published: Repository,
) -> None:
    """rpm's own convention, and the one every tool reading a filename assumes."""
    variant = Path(published.root_path) / VARIANT_PATH

    assert (variant / "Packages" / "beta-0.9-1.el9.x86_64.rpm").is_file()
    assert not list((variant / "Packages").glob("*2:*"))


def test_the_locations_in_primary_xml_are_relative_to_the_variant(
    published: Repository,
) -> None:
    """A wrong ``location href`` produces a 404 at install time, not at index time.

    Worth asserting directly: it is the one part of the output that depends on
    which directory ``createrepo_c`` was pointed at, and a dnf failure caused by
    it would say only that a package could not be downloaded.
    """
    assert 'href="Packages/alpha-1.0-1.el9.x86_64.rpm"' in _primary_xml(published)


# ------------------------------------------------------------------- signature


def test_the_repomd_signature_verifies_against_the_repositorys_key(
    published: Repository, keyring: Keyring
) -> None:
    """The claim this application actually makes about an RPM repository (4.2)."""
    verified = GnuPG(keyring.home).verify_detached(
        repomd(published).read_bytes(), signature_path(published).read_bytes()
    )
    assert verified


def test_the_signature_does_not_verify_once_the_metadata_is_edited(
    published: Repository, keyring: Keyring
) -> None:
    """The half that matters: a signature that always verifies is decorative."""
    target = repomd(published)
    signature = signature_path(published).read_bytes()
    target.write_bytes(target.read_bytes().replace(b"<revision>", b"<revision>1"))

    assert not GnuPG(keyring.home).verify_detached(target.read_bytes(), signature)


def test_the_public_key_is_exported_under_the_name_repo_files_expect(
    published: Repository, keyring: Keyring
) -> None:
    exported = Path(published.root_path) / f"RPM-GPG-KEY-{keyring.name}"

    assert exported.is_file()
    assert "BEGIN PGP PUBLIC KEY BLOCK" in exported.read_text()


# ------------------------------------------------------------------------ dnf


def test_dnf_refreshes_the_repository_and_verifies_its_signature(dnf: IsolatedDnf) -> None:
    result = dnf.makecache()
    assert result.ok, result.output


def test_dnf_finds_every_published_package(dnf: IsolatedDnf) -> None:
    assert dnf.makecache().ok
    result = dnf.repoquery("--queryformat", "%{name}-%{evr}.%{arch}")

    assert result.ok, result.output
    found = set(result.stdout.split())
    assert {
        "alpha-1.0-1.el9.x86_64",
        "alpha-1.0-2.el9.x86_64",
        "beta-2:0.9-1.el9.x86_64",
        "gamma-3.1-1.el9.noarch",
    } <= found


def test_dnf_picks_the_newer_release_of_the_same_version(dnf: IsolatedDnf) -> None:
    """rpm's own version ordering, applied by rpm rather than by this project.

    The same comparison drives retention (5.3), so confirming dnf agrees with
    it here is worth more than another unit test of the algorithm.
    """
    assert dnf.makecache().ok
    result = dnf.repoquery("--latest-limit", "1", "--queryformat", "%{name}-%{evr}", "alpha")

    assert result.ok, result.output
    assert "alpha-1.0-2.el9" in result.stdout


def test_the_recorded_checksum_describes_the_file_that_is_there(
    published: Repository,
) -> None:
    """The digest a client will check the download against (4.2).

    Asserted against the file rather than through a dnf install, which would
    need root: what could go wrong here is the index describing a file that was
    replaced afterwards, and comparing the two catches exactly that.
    """
    import hashlib

    variant = Path(published.root_path) / VARIANT_PATH
    package = variant / "Packages" / "alpha-1.0-2.el9.x86_64.rpm"
    digest = hashlib.sha256(package.read_bytes()).hexdigest()

    assert digest in _primary_xml(published)


def test_dnf_rejects_the_repository_once_repomd_is_tampered_with(
    published: Repository, dnf: IsolatedDnf
) -> None:
    """The signature has to be load-bearing, not ornamental.

    ``repomd.xml`` is edited and its signature left alone, which is exactly what
    a tampering mirror would produce.
    """
    assert dnf.makecache().ok, "the untampered repository must refresh first"

    target = repomd(published)
    target.write_bytes(target.read_bytes().replace(b"<revision>", b"<revision>1"))

    result = dnf.makecache()
    assert not result.ok, (
        f"dnf accepted a repomd.xml that does not match its signature:\n{result.output}"
    )


def test_dnf_rejects_the_repository_when_the_signature_is_missing(
    published: Repository, dnf: IsolatedDnf
) -> None:
    """An unsigned repository must fail rather than quietly degrade to unverified."""
    assert dnf.makecache().ok
    signature_path(published).unlink()

    result = dnf.makecache()
    assert not result.ok, f"dnf accepted a repository with no signature:\n{result.output}"


# ------------------------------------------------------------------ round trip


async def test_a_later_upload_is_indexed_and_visible_to_dnf(
    session: AsyncSession,
    settings: Settings,
    published: Repository,
    keyring: Keyring,
    dnf: IsolatedDnf,
    tmp_path: Path,
) -> None:
    """``--update`` has to add the new package, not merely rewrite what was there.

    This is the flow an upload actually takes: file into the variant, then a
    regeneration over a ``repodata`` that already exists.  The first publish is
    a different code path in ``createrepo_c`` from every publish after it, and
    only this one is the common case.
    """
    assert dnf.makecache().ok
    before = dnf.repoquery("--queryformat", "%{name}")
    assert "delta" not in before.stdout

    built = build_rpm(tmp_path / "rpmbuild", name="delta", version="4.2", release="1.el9")

    async def chunks() -> AsyncIterator[bytes]:
        yield built.read_bytes()

    staged = await package_service.stage_upload(
        Path(published.root_path), chunks(), max_bytes=settings.max_upload_bytes
    )
    await package_service.publish_rpm(
        session,
        settings,
        repository=published,
        variant=published.variants[0],
        staged=staged,
    )
    await session.flush()

    key = published.signing_key
    assert key is not None
    publishing.write_rpm_metadata(
        Path(published.root_path),
        await publishing.build_rpm_plan(session, published),
        signer=key_service.build_signer(settings, key),
        key_name=key.name,
        public_key=key.public_key_armored,
    )

    assert dnf.makecache().ok
    after = dnf.repoquery("--queryformat", "%{name}-%{evr}.%{arch}")
    assert "delta-4.2-1.el9.x86_64" in after.stdout, after.output


# ---------------------------------------------------------------- the binary


def test_the_real_createrepo_accepts_the_arguments_this_project_passes(
    tmp_path: Path,
) -> None:
    """The stand-in in the unit suite cannot catch an option a release removed.

    Worth its own test rather than being left implied by the fixtures above: if
    this breaks, the failure names the option rather than reporting a
    repository that would not refresh.
    """
    variant = repodata.VariantPlan(name="el9", arch="x86_64")
    repodata.create_skeleton(tmp_path, repodata.RepositoryPlan(variants=(variant,)))

    repodata.run_createrepo(variant.directory(tmp_path))

    assert (variant.directory(tmp_path) / "repodata" / "repomd.xml").is_file()
