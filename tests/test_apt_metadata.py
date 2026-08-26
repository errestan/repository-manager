"""Pure-Python APT index generation (specification.md 4.1, AD-2)."""

from __future__ import annotations

import datetime as dt
import gzip
import lzma
from pathlib import Path

import pytest

from repository_manager.metadata import apt
from repository_manager.metadata.deb import read_deb
from tests.support.debs import DebSpec, build_deb

MOMENT = dt.datetime(2026, 8, 26, 12, 30, 45, tzinfo=dt.UTC)


class RecordingSigner:
    """A stand-in signer, so index generation is testable without a keyring."""

    def __init__(self) -> None:
        self.clearsigned: list[bytes] = []
        self.detached: list[bytes] = []

    def clearsign(self, data: bytes) -> bytes:
        self.clearsigned.append(data)
        return b"-----BEGIN PGP SIGNED MESSAGE-----\n\n" + data + b"-----END-----\n"

    def detach_sign(self, data: bytes) -> bytes:
        self.detached.append(data)
        return b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n"


@pytest.fixture
def signer() -> RecordingSigner:
    return RecordingSigner()


def stanza_for(tmp_path: Path, **spec: object) -> dict[str, str]:
    built = build_deb(DebSpec(**spec), tmp_path / f"{spec.get('name', 'x')}.deb")  # type: ignore[arg-type]
    metadata = read_deb(built)
    return metadata.stanza(metadata.pool_path("main"))


def plan_with(
    *stanzas: dict[str, str], architectures: tuple[str, ...] = ("amd64",)
) -> apt.RepositoryPlan:
    return apt.RepositoryPlan(
        origin="Example",
        label="Example Label",
        distributions=(
            apt.DistributionPlan(
                codename="bookworm",
                suite="stable",
                description="Example repository",
                architectures=architectures,
                components=("main",),
                stanzas={"main": list(stanzas)},
            ),
        ),
    )


# ------------------------------------------------------------------ rendering


def test_a_multi_line_description_is_folded_correctly() -> None:
    """Continuation lines need a leading space; a blank one becomes ' .'."""
    rendered = apt.render_field("Description", "short\nlong line\n\nafter a gap")
    assert rendered == "Description: short\n long line\n .\n after a gap"


def test_stanza_fields_come_out_in_a_stable_order() -> None:
    stanza = {"SHA256": "d", "Package": "alpha", "Version": "1.0", "Architecture": "amd64"}
    rendered = apt.render_stanza(stanza)
    assert rendered.index("Package:") < rendered.index("Version:") < rendered.index("SHA256:")


def test_unknown_control_fields_are_kept_rather_than_dropped() -> None:
    """A field we have never seen still belongs in the index."""
    rendered = apt.render_stanza({"Package": "alpha", "Built-Using": "gcc-13 (= 13.2)"})
    assert "Built-Using: gcc-13 (= 13.2)" in rendered


def test_an_empty_index_is_an_empty_file() -> None:
    """A repository with no packages is still one apt can add (4.3)."""
    assert apt.render_packages([]) == b""


def test_the_release_date_is_rfc_2822_in_utc() -> None:
    assert apt.format_release_date(MOMENT) == "Wed, 26 Aug 2026 12:30:45 UTC"


def test_the_release_date_is_independent_of_the_local_timezone() -> None:
    """%a and %b are locale-dependent, so the names are spelled out (4.1)."""
    other_zone = MOMENT.astimezone(dt.timezone(dt.timedelta(hours=9)))
    assert apt.format_release_date(other_zone) == "Wed, 26 Aug 2026 12:30:45 UTC"


def test_release_omits_valid_until() -> None:
    """Metadata must never expire on clients (AD-15)."""
    release = apt.render_release(
        plan_with().distributions[0], origin="Example", label="L", files=[], moment=MOMENT
    )
    assert "Valid-Until" not in release


def test_release_lists_architectures_and_components() -> None:
    plan = plan_with(architectures=("amd64", "arm64"))
    release = apt.render_release(
        plan.distributions[0], origin="Example", label="L", files=[], moment=MOMENT
    )
    assert "Architectures: amd64 arm64" in release
    assert "Components: main" in release
    assert "Codename: bookworm" in release
    assert "Suite: stable" in release


# ------------------------------------------------------------------ generation


def test_generation_writes_the_expected_tree(tmp_path: Path, signer: RecordingSigner) -> None:
    root = tmp_path / "repo"
    plan = plan_with(stanza_for(tmp_path, name="alpha", version="1.0-1"))
    apt.create_skeleton(root, plan)
    apt.generate(root, plan, signer=signer, moment=MOMENT)

    dists = root / "dists" / "bookworm"
    for expected in ("Release", "InRelease", "Release.gpg"):
        assert (dists / expected).is_file(), expected
    binary = dists / "main" / "binary-amd64"
    for expected in ("Packages", "Packages.gz", "Packages.xz", "Release"):
        assert (binary / expected).is_file(), expected


def test_the_compressed_indices_decompress_to_the_plain_one(
    tmp_path: Path, signer: RecordingSigner
) -> None:
    """apt fetches a compressed variant; an inconsistent one is a hash mismatch."""
    root = tmp_path / "repo"
    plan = plan_with(stanza_for(tmp_path, name="alpha", version="1.0-1"))
    apt.generate(root, plan, signer=signer, moment=MOMENT)

    binary = root / "dists/bookworm/main/binary-amd64"
    plain = (binary / "Packages").read_bytes()
    assert gzip.decompress((binary / "Packages.gz").read_bytes()) == plain
    assert lzma.decompress((binary / "Packages.xz").read_bytes()) == plain


def test_release_hashes_match_the_files_on_disk(tmp_path: Path, signer: RecordingSigner) -> None:
    import hashlib

    root = tmp_path / "repo"
    plan = plan_with(stanza_for(tmp_path, name="alpha", version="1.0-1"))
    apt.generate(root, plan, signer=signer, moment=MOMENT)

    dists = root / "dists/bookworm"
    release = (dists / "Release").read_text()
    checked = 0
    for line in release.splitlines():
        if not line.startswith(" "):
            continue
        digest, size, relative = line.split()
        if len(digest) != 64:  # only verify the SHA256 block
            continue
        target = dists / relative
        raw = target.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest, relative
        assert int(size) == len(raw), relative
        checked += 1
    assert checked == 4


def test_architecture_all_packages_appear_in_every_architecture(
    tmp_path: Path, signer: RecordingSigner
) -> None:
    """apt only fetches indices for architectures it is configured for (4.1)."""
    root = tmp_path / "repo"
    plan = plan_with(
        stanza_for(tmp_path, name="alpha", version="1.0-1", architecture="amd64"),
        stanza_for(
            tmp_path, name="libgamma", version="2.0-1", architecture="all", source="libgamma"
        ),
        architectures=("amd64", "arm64"),
    )
    apt.generate(root, plan, signer=signer, moment=MOMENT)

    amd64 = (root / "dists/bookworm/main/binary-amd64/Packages").read_text()
    arm64 = (root / "dists/bookworm/main/binary-arm64/Packages").read_text()
    assert "Package: libgamma" in amd64
    assert "Package: libgamma" in arm64
    assert "Package: alpha" in amd64
    assert "Package: alpha" not in arm64


def test_generation_is_byte_identical_when_nothing_changed(
    tmp_path: Path, signer: RecordingSigner
) -> None:
    """Deterministic output makes "did anything change?" answerable (4.1)."""
    root = tmp_path / "repo"
    plan = plan_with(stanza_for(tmp_path, name="alpha", version="1.0-1"))
    apt.generate(root, plan, signer=signer, moment=MOMENT)
    first = {
        path.relative_to(root): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    apt.generate(root, plan, signer=signer, moment=MOMENT)
    second = {
        path.relative_to(root): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    assert first == second


def test_both_signature_forms_cover_the_release_bytes(
    tmp_path: Path, signer: RecordingSigner
) -> None:
    """InRelease and Release.gpg must sign exactly what was written (4.1)."""
    root = tmp_path / "repo"
    apt.generate(root, plan_with(), signer=signer, moment=MOMENT)
    release = (root / "dists/bookworm/Release").read_bytes()
    assert signer.clearsigned == [release]
    assert signer.detached == [release]


def test_regeneration_replaces_removed_packages(tmp_path: Path, signer: RecordingSigner) -> None:
    """The tree is rebuilt, not merged: a removed package must disappear (5.2)."""
    root = tmp_path / "repo"
    with_alpha = plan_with(stanza_for(tmp_path, name="alpha", version="1.0-1"))
    apt.generate(root, with_alpha, signer=signer, moment=MOMENT)
    assert "alpha" in (root / "dists/bookworm/main/binary-amd64/Packages").read_text()

    apt.generate(root, plan_with(), signer=signer, moment=MOMENT)
    assert (root / "dists/bookworm/main/binary-amd64/Packages").read_bytes() == b""


def test_no_staging_directory_survives_generation(tmp_path: Path, signer: RecordingSigner) -> None:
    root = tmp_path / "repo"
    apt.generate(root, plan_with(), signer=signer, moment=MOMENT)
    leftovers = [p.name for p in (root / "dists").iterdir() if p.name.startswith(".")]
    assert leftovers == []


def test_a_failed_generation_leaves_the_previous_tree_intact(tmp_path: Path) -> None:
    """A signing failure must not take the live repository down with it (5.4)."""
    root = tmp_path / "repo"
    good = RecordingSigner()
    apt.generate(
        root,
        plan_with(stanza_for(tmp_path, name="alpha", version="1.0-1")),
        signer=good,
        moment=MOMENT,
    )
    before = (root / "dists/bookworm/Release").read_bytes()

    class Failing(RecordingSigner):
        def clearsign(self, data: bytes) -> bytes:
            raise RuntimeError("the signing key is unavailable")

    with pytest.raises(RuntimeError):
        apt.generate(root, plan_with(), signer=Failing(), moment=MOMENT)

    assert (root / "dists/bookworm/Release").read_bytes() == before
    assert "alpha" in (root / "dists/bookworm/main/binary-amd64/Packages").read_text()


def test_the_skeleton_creates_pool_directories(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    apt.create_skeleton(root, plan_with())
    assert (root / "pool" / "main").is_dir()
    assert (root / "dists").is_dir()
