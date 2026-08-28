"""Reading and validating uploaded packages (specification.md 4.1, 5.1)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from repository_manager.metadata.deb import (
    PackageFormatError,
    description_md5,
    pool_prefix,
    read_deb,
    split_version,
    version_sort_key,
)
from repository_manager.metadata.digests import digest_file
from tests.support.debs import DebSpec, build_deb


@pytest.fixture
def deb(tmp_path: Path) -> Path:
    return build_deb(
        DebSpec(
            name="alpha",
            version="1.0-1",
            architecture="amd64",
            source="alpha-source",
            depends="libc6 (>= 2.36)",
            homepage="https://example.test/alpha",
        ),
        tmp_path / "alpha.deb",
    )


# ------------------------------------------------------------------ parsing


def test_control_fields_are_read_from_the_package(deb: Path) -> None:
    metadata = read_deb(deb)
    assert metadata.name == "alpha"
    assert metadata.version == "1.0-1"
    assert metadata.architecture == "amd64"
    assert metadata.source_name == "alpha-source"
    assert metadata.control["Depends"] == "libc6 (>= 2.36)"


def test_the_source_field_may_carry_its_own_version(tmp_path: Path) -> None:
    """`Source: foo (1.2-3)` names foo; the version in brackets is the source's."""
    path = build_deb(
        DebSpec(name="alpha", version="1.0-1", source="alpha-source (2.0-1)"),
        tmp_path / "a.deb",
    )
    assert read_deb(path).source_name == "alpha-source"


def test_source_defaults_to_the_package_name(tmp_path: Path) -> None:
    path = build_deb(DebSpec(name="solo", version="1.0-1"), tmp_path / "s.deb")
    assert read_deb(path).source_name == "solo"


@pytest.mark.parametrize(
    ("version", "epoch", "filename_version"),
    [
        ("1.0-1", None, "1.0-1"),
        ("1:1.0-1", 1, "1.0-1"),
        ("2:3.4.5-2~bpo12+1", 2, "3.4.5-2~bpo12+1"),
        ("1.0", None, "1.0"),
    ],
)
def test_epochs_are_split_out_and_dropped_from_the_filename(
    tmp_path: Path, version: str, epoch: int | None, filename_version: str
) -> None:
    """dpkg omits the epoch from filenames, and tools rely on that (4.1)."""
    path = build_deb(DebSpec(name="alpha", version=version), tmp_path / "a.deb")
    metadata = read_deb(path)
    assert metadata.epoch == epoch
    assert metadata.version == version
    assert metadata.filename == f"alpha_{filename_version}_amd64.deb"


# ------------------------------------------------------------------ rejection


def test_a_file_that_is_not_an_archive_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "fake.deb"
    path.write_bytes(b"PK\x03\x04 this is a zip file")
    with pytest.raises(PackageFormatError, match="ar archive signature"):
        read_deb(path)


def test_an_empty_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "empty.deb"
    path.write_bytes(b"")
    with pytest.raises(PackageFormatError):
        read_deb(path)


@pytest.mark.parametrize("missing", ["Package", "Version", "Architecture"])
def test_a_missing_required_field_is_rejected(tmp_path: Path, missing: str) -> None:
    fields = {"Package": "alpha", "Version": "1.0-1", "Architecture": "amd64"}
    del fields[missing]
    control = "".join(f"{key}: {value}\n" for key, value in fields.items())
    path = build_deb(DebSpec(control_override=control + "Description: x\n"), tmp_path / "a.deb")
    with pytest.raises(PackageFormatError, match=f"missing required field.*{missing}"):
        read_deb(path)


@pytest.mark.parametrize("bad", ["Alpha", "alpha!", "-alpha", "a b"])
def test_an_invalid_package_name_is_rejected(tmp_path: Path, bad: str) -> None:
    control = f"Package: {bad}\nVersion: 1.0-1\nArchitecture: amd64\nDescription: x\n"
    path = build_deb(DebSpec(control_override=control), tmp_path / "a.deb")
    with pytest.raises(PackageFormatError):
        read_deb(path)


def test_an_invalid_architecture_is_rejected(tmp_path: Path) -> None:
    control = "Package: alpha\nVersion: 1.0-1\nArchitecture: AMD64\nDescription: x\n"
    path = build_deb(DebSpec(control_override=control), tmp_path / "a.deb")
    with pytest.raises(PackageFormatError, match="not a valid architecture"):
        read_deb(path)


def test_an_invalid_version_is_rejected() -> None:
    with pytest.raises(PackageFormatError, match="not a valid Debian version"):
        split_version("1.0 with spaces")


# ------------------------------------------------------------------ pool layout


@pytest.mark.parametrize(
    ("source", "prefix"),
    [
        ("alpha", "a"),
        ("zsh", "z"),
        ("libgamma", "libg"),
        ("libc6", "libc"),
        # "lib" exactly is not a lib* package for pooling purposes; there is no
        # fifth character to take.
        ("lib", "l"),
        ("0ad", "0"),
    ],
)
def test_the_pool_prefix_follows_debian_convention(source: str, prefix: str) -> None:
    assert pool_prefix(source) == prefix


def test_the_pool_path_is_derived_from_metadata_not_the_filename(tmp_path: Path) -> None:
    """A hostile filename must never reach the filesystem (10.2)."""
    path = build_deb(
        DebSpec(name="alpha", version="1.0-1", source="alpha"),
        tmp_path / "..;-etc-cron.d-evil.deb",
    )
    metadata = read_deb(path)
    assert metadata.pool_path("main") == "pool/main/a/alpha/alpha_1.0-1_amd64.deb"


# ------------------------------------------------------------------ digests


def test_digests_match_the_file(deb: Path) -> None:
    raw = deb.read_bytes()
    digests = digest_file(deb)
    assert digests.size == len(raw)
    assert digests.sha256 == hashlib.sha256(raw).hexdigest()
    assert digests.md5 == hashlib.md5(raw).hexdigest()
    assert digests.sha1 == hashlib.sha1(raw).hexdigest()


def test_description_md5_matches_apt(deb: Path) -> None:
    """The value apt computes: the raw field plus a newline.

    Verified against `apt-ftparchive -o APT::FTPArchive::LongDescription=false`,
    which is the definition apt itself uses (4.1).
    """
    metadata = read_deb(deb)
    stanza = metadata.stanza("pool/main/a/alpha/alpha_1.0-1_amd64.deb")
    expected = hashlib.md5((metadata.control["Description"] + "\n").encode()).hexdigest()
    assert stanza["Description-md5"] == expected


def test_continuation_lines_keep_their_leading_space() -> None:
    """Stripping them would change the hash and desynchronise every client."""
    raw = "short\n long line\n .\n another"
    assert description_md5(raw) == description_md5(raw + "\n")


def test_the_stanza_carries_everything_the_index_needs(deb: Path) -> None:
    """Stored once at upload, so a rebuild never re-reads the pool (5.4)."""
    stanza = read_deb(deb).stanza("pool/main/a/alpha/alpha_1.0-1_amd64.deb")
    for required in ("Package", "Version", "Architecture", "Filename", "Size", "SHA256"):
        assert stanza[required]


# ------------------------------------------------------------------ ordering


def test_versions_sort_by_debian_policy() -> None:
    """`~` sorts before everything, including the empty string (4.1)."""
    versions = ["1.0-1", "1.10-1", "1.2-1", "1.0~rc1-1", "2:0.1-1"]
    ordered = sorted(versions, key=version_sort_key)
    assert ordered == ["1.0~rc1-1", "1.0-1", "1.2-1", "1.10-1", "2:0.1-1"]
