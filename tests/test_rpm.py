"""Reading and validating uploaded RPM packages (specification.md 4.2, 5.1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from repository_manager.metadata.deb import PackageFormatError
from repository_manager.metadata.rpm import (
    Evr,
    compare_evr,
    read_lead,
    read_rpm,
    rpm_vercmp,
    version_sort_key,
)
from tests.support.rpms import RpmSpec, build_rpm, build_simple

# ------------------------------------------------------------- version ordering

# Verbatim from rpm's own tests/rpmvercmp.at.  Copied rather than paraphrased:
# these are the cases upstream considers definitive, and the ones a
# reimplementation gets wrong are never the ones you would have thought to
# invent.  Retention deletes packages based on this ordering (5.3), so "close
# enough" is not a standard it can be held to.
VERCMP_CASES: tuple[tuple[str, str, int], ...] = (
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0),
    ("2.0", "2.0.1", -1),
    ("2.0.1", "2.0", 1),
    ("2.0.1a", "2.0.1a", 0),
    ("2.0.1a", "2.0.1", 1),
    ("2.0.1", "2.0.1a", -1),
    ("5.5p1", "5.5p1", 0),
    ("5.5p1", "5.5p2", -1),
    ("5.5p2", "5.5p1", 1),
    ("5.5p10", "5.5p10", 0),
    ("5.5p1", "5.5p10", -1),
    ("5.5p10", "5.5p1", 1),
    ("10xyz", "10.1xyz", -1),
    ("10.1xyz", "10xyz", 1),
    ("xyz10", "xyz10", 0),
    ("xyz10", "xyz10.1", -1),
    ("xyz10.1", "xyz10", 1),
    ("xyz.4", "xyz.4", 0),
    ("xyz.4", "8", -1),
    ("8", "xyz.4", 1),
    ("xyz.4", "2", -1),
    ("2", "xyz.4", 1),
    ("5.5p2", "5.6p1", -1),
    ("5.6p1", "5.5p2", 1),
    ("5.6p1", "6.5p1", -1),
    ("6.5p1", "5.6p1", 1),
    ("6.0.rc1", "6.0", 1),
    ("6.0", "6.0.rc1", -1),
    ("10b2", "10a1", 1),
    ("10a2", "10b2", -1),
    ("1.0aa", "1.0aa", 0),
    ("1.0a", "1.0aa", -1),
    ("1.0aa", "1.0a", 1),
    ("10.0001", "10.0001", 0),
    ("10.0001", "10.1", 0),
    ("10.1", "10.0001", 0),
    ("10.0001", "10.0039", -1),
    ("10.0039", "10.0001", 1),
    ("4.999.9", "5.0", -1),
    ("5.0", "4.999.9", 1),
    ("20101121", "20101121", 0),
    ("20101121", "20101122", -1),
    ("20101122", "20101121", 1),
    ("2_0", "2_0", 0),
    ("2.0", "2_0", 0),
    ("2_0", "2.0", 0),
    # RhBug:178798 -- non-alphanumerics are separators and nothing more.
    ("a", "a", 0),
    ("a+", "a+", 0),
    ("a+", "a_", 0),
    ("a_", "a+", 0),
    ("+a", "+a", 0),
    ("+a", "_a", 0),
    ("_a", "+a", 0),
    ("+_", "+_", 0),
    ("_+", "+_", 0),
    ("_+", "_+", 0),
    ("+", "_", 0),
    ("_", "+", 0),
    # Tilde: sorts before everything, including the end of the string.
    ("1.0~rc1", "1.0~rc1", 0),
    ("1.0~rc1", "1.0", -1),
    ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~rc2", "1.0~rc1", 1),
    ("1.0~rc1~git123", "1.0~rc1~git123", 0),
    ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0~rc1", "1.0~rc1~git123", 1),
    # Caret: the mirror image -- before everything *except* the end.
    ("1.0^", "1.0^", 0),
    ("1.0^", "1.0", 1),
    ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0^git1", 0),
    ("1.0^git1", "1.0", 1),
    ("1.0", "1.0^git1", -1),
    ("1.0^git1", "1.0^git2", -1),
    ("1.0^git2", "1.0^git1", 1),
    ("1.0^git1", "1.01", -1),
    ("1.01", "1.0^git1", 1),
    ("1.0^20160101", "1.0^20160101", 0),
    ("1.0^20160101", "1.0.1", -1),
    ("1.0.1", "1.0^20160101", 1),
    ("1.0^20160101^git1", "1.0^20160101^git1", 0),
    ("1.0^20160102", "1.0^20160101^git1", 1),
    ("1.0^20160101^git1", "1.0^20160102", -1),
    # The two together.
    ("1.0~rc1^git1", "1.0~rc1^git1", 0),
    ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc1^git1", -1),
    ("1.0^git1~pre", "1.0^git1~pre", 0),
    ("1.0^git1", "1.0^git1~pre", 1),
    ("1.0^git1~pre", "1.0^git1", -1),
)


@pytest.mark.parametrize(("one", "two", "expected"), VERCMP_CASES)
def test_rpm_vercmp_matches_rpms_own_test_vectors(one: str, two: str, expected: int) -> None:
    assert rpm_vercmp(one, two) == expected


def test_a_non_ascii_digit_is_a_separator_not_a_number() -> None:
    """rpm's ``risdigit`` is ASCII; ``str.isdigit`` is not.

    U+0663 ARABIC-INDIC DIGIT THREE is a digit to Python and punctuation to
    rpm, so rpm sees no segment there at all and these two compare equal.  The
    assertion is equality rather than mere inequality precisely because that is
    the half a Unicode-aware check would get wrong: it would find a numeric
    segment on one side and none on the other, and call the versions different.
    """
    assert rpm_vercmp("1.٣", "1") == 0


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        (Evr(0, "1.0", "1"), Evr(0, "1.0", "2")),
        (Evr(0, "1.0", "2"), Evr(0, "1.1", "1")),
        # An epoch outranks everything, which is the whole point of having one.
        (Evr(0, "9.0", "9"), Evr(1, "1.0", "1")),
        (Evr(1, "1.0", "1"), Evr(2, "0.1", "1")),
        # A missing epoch means zero, not "unknown".
        (Evr(0, "1.0", "1"), Evr(1, "1.0", "1")),
        (Evr(0, "1.0~rc1", "1"), Evr(0, "1.0", "1")),
    ],
)
def test_labelcompare_orders_epoch_then_version_then_release(older: Evr, newer: Evr) -> None:
    assert compare_evr(older, newer) == -1
    assert compare_evr(newer, older) == 1
    assert compare_evr(older, older) == 0


def test_version_sort_key_orders_a_realistic_release_history() -> None:
    """The ordering retention would use to decide what to prune (5.3)."""
    history = [
        (None, "1.10", "1.el9"),
        (None, "1.2", "1.el9"),
        (None, "1.2", "2.el9"),
        (None, "2.0~rc1", "1.el9"),
        (None, "2.0", "1.el9"),
        (1, "0.1", "1.el9"),
    ]
    ordered = sorted(history, key=lambda row: version_sort_key(*row))
    assert [f"{v}-{r}" for _, v, r in ordered] == [
        "1.2-1.el9",
        "1.2-2.el9",
        "1.10-1.el9",
        "2.0~rc1-1.el9",
        "2.0-1.el9",
        # The epoch bump, which supersedes every version above it.
        "0.1-1.el9",
    ]


def test_evr_renders_the_way_rpm_prints_it() -> None:
    assert str(Evr(0, "1.0", "1.el9")) == "1.0-1.el9"
    assert str(Evr(2, "1.0", "1.el9")) == "2:1.0-1.el9"


# --------------------------------------------------------------------- parsing


def test_a_package_is_parsed_into_its_nevra(tmp_path: Path) -> None:
    package = build_simple(
        tmp_path / "any-name.rpm", name="example", version="1.0", release="1.el9"
    )
    metadata = read_rpm(package)

    assert metadata.name == "example"
    assert metadata.version == "1.0"
    assert metadata.release == "1.el9"
    assert metadata.architecture == "x86_64"
    assert metadata.epoch is None
    assert metadata.nevra == "example-1.0-1.el9.x86_64"


def test_the_stored_filename_comes_from_the_header_not_the_upload(tmp_path: Path) -> None:
    """The uploaded name is never used to build a path (10.2)."""
    package = build_simple(tmp_path / "..%2Fetc%2Fcron.d%2Fevil.rpm", name="example")
    metadata = read_rpm(package)

    assert metadata.filename == "example-1.0-1.el9.x86_64.rpm"
    assert metadata.variant_path("el9/x86_64") == (
        "el9/x86_64/Packages/example-1.0-1.el9.x86_64.rpm"
    )


def test_the_epoch_is_kept_on_the_row_but_left_out_of_the_filename(tmp_path: Path) -> None:
    """rpm omits the epoch from a filename, and so does every tool reading one."""
    metadata = read_rpm(build_simple(tmp_path / "a.rpm", epoch=2))

    assert metadata.epoch == 2
    assert metadata.nevra == "example-2:1.0-1.el9.x86_64"
    assert "2:" not in metadata.filename


def test_the_source_package_name_is_taken_from_sourcerpm(tmp_path: Path) -> None:
    package = build_rpm(
        RpmSpec(name="libfoo-devel", source_rpm="libfoo-1.0-1.el9.src.rpm"), tmp_path / "a.rpm"
    )
    assert read_rpm(package).source_name == "libfoo"


def test_an_unreadable_sourcerpm_falls_back_to_the_binary_name(tmp_path: Path) -> None:
    """Grouping in the interface is not worth refusing a usable package over."""
    package = build_rpm(RpmSpec(name="example", source_rpm="not a source rpm"), tmp_path / "a.rpm")
    assert read_rpm(package).source_name == "example"


def test_header_fields_are_collected_and_the_licence_tag_is_renamed(tmp_path: Path) -> None:
    """``rpmfile`` still calls tag 1014 ``copyright``; the interface should not."""
    metadata = read_rpm(build_simple(tmp_path / "a.rpm", license="MIT"))

    assert metadata.header["license"] == "MIT"
    assert "copyright" not in metadata.header
    assert metadata.header["summary"] == "An example package"
    assert metadata.header["buildtime"] == "1700000000"


def test_the_digests_cover_the_whole_file(tmp_path: Path) -> None:
    import hashlib

    package = build_simple(tmp_path / "a.rpm")
    metadata = read_rpm(package)
    raw = package.read_bytes()

    assert metadata.digests.size == len(raw)
    assert metadata.digests.sha256 == hashlib.sha256(raw).hexdigest()


def test_the_lead_reports_a_binary_package(tmp_path: Path) -> None:
    package_type, _ = read_lead(build_simple(tmp_path / "a.rpm"))
    assert package_type == 0


# ------------------------------------------------------------------ rejections


def test_a_file_that_is_not_an_rpm_is_refused_before_parsing(tmp_path: Path) -> None:
    """A .deb selected by mistake is the common case, and gets a useful message."""
    wrong = tmp_path / "example.rpm"
    wrong.write_bytes(b"!<arch>\n" + b"x" * 200)

    with pytest.raises(PackageFormatError, match="0xEDABEEDB"):
        read_rpm(wrong)


def test_a_truncated_upload_is_refused(tmp_path: Path) -> None:
    truncated = tmp_path / "short.rpm"
    truncated.write_bytes(b"\xed\xab\xee\xdb")

    with pytest.raises(PackageFormatError, match="upload completed"):
        read_rpm(truncated)


def test_a_source_package_is_refused(tmp_path: Path) -> None:
    """A .src.rpm in a binary variant would be offered to clients that cannot use it."""
    package = build_rpm(RpmSpec(name="example", source_rpm=None), tmp_path / "a.src.rpm")

    with pytest.raises(PackageFormatError, match="source package"):
        read_rpm(package)


def test_a_binary_lead_hiding_a_source_header_is_still_refused(tmp_path: Path) -> None:
    """The lead is advisory in modern rpm; the header has the final say."""
    package = build_rpm(RpmSpec(name="example", omit=frozenset({"sourcerpm"})), tmp_path / "a.rpm")
    with pytest.raises(PackageFormatError, match="SOURCERPM"):
        read_rpm(package)


@pytest.mark.parametrize("tag", ["name", "version", "release", "arch"])
def test_a_missing_required_tag_is_named_in_the_message(tmp_path: Path, tag: str) -> None:
    package = build_rpm(RpmSpec(name="example", omit=frozenset({tag})), tmp_path / "a.rpm")

    with pytest.raises(PackageFormatError, match="missing required tag"):
        read_rpm(package)


@pytest.mark.parametrize(
    "spec",
    [
        # '-' separates version from release, so neither may contain one.
        RpmSpec(name="example", version="1.0-beta"),
        RpmSpec(name="example", release="1-el9"),
        RpmSpec(name="example", version="1.0/../etc"),
        RpmSpec(name="example", release="1.el9/x86_64"),
    ],
    ids=["version-hyphen", "release-hyphen", "version-traversal", "release-slash"],
)
def test_a_version_or_release_that_would_break_a_filename_is_refused(
    tmp_path: Path, spec: RpmSpec
) -> None:
    package = build_rpm(spec, tmp_path / "a.rpm")

    with pytest.raises(PackageFormatError, match="not a valid RPM"):
        read_rpm(package)


@pytest.mark.parametrize("name", ["../evil", "with space", "-leading"])
def test_a_package_name_that_is_not_a_package_name_is_refused(tmp_path: Path, name: str) -> None:
    package = build_rpm(RpmSpec(name=name), tmp_path / "a.rpm")

    with pytest.raises(PackageFormatError, match="characters rpm does not allow"):
        read_rpm(package)


@pytest.mark.parametrize("architecture", ["x86 64", "../x86_64", ""])
def test_an_invalid_architecture_is_refused(tmp_path: Path, architecture: str) -> None:
    package = build_rpm(RpmSpec(name="example", architecture=architecture), tmp_path / "a.rpm")

    with pytest.raises(PackageFormatError):
        read_rpm(package)


def test_noarch_is_accepted(tmp_path: Path) -> None:
    """The RPM spelling of ``Architecture: all`` (5.1)."""
    metadata = read_rpm(build_simple(tmp_path / "a.rpm", architecture="noarch"))
    assert metadata.architecture == "noarch"
    assert metadata.filename.endswith(".noarch.rpm")
