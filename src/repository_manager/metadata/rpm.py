"""Reading and validating uploaded ``.rpm`` files (specification.md 4.2, 5.1).

The ``rpm`` Python bindings are deliberately not a dependency.  They are built
against the distribution's own librpm and are not installable from PyPI, so
depending on them would make the wheel uninstallable on exactly the Debian and
Ubuntu hosts this application is most often deployed on.  ``rpmfile`` reads the
header structure in pure Python, which is all that is needed to establish a
package's identity.

As with ``.deb``, nothing here trusts the uploaded filename: the NEVRA comes
from the package's own header, and the path it is stored at is derived from
that (10.2).

Unlike APT, the index is *not* built from what this module returns.
``createrepo_c`` re-reads every file in the variant directory to build
``repodata`` (AD-2), so the header fields kept on the row are there for the
interface to show and for the audit trail -- not to be rendered into metadata.
"""

from __future__ import annotations

import functools
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repository_manager.metadata.deb import PackageFormatError
from repository_manager.metadata.digests import FileDigests, digest_file

# Every RPM starts with this, followed by the rest of a 96-byte lead (5.1).
RPM_MAGIC = b"\xed\xab\xee\xdb"
LEAD_SIZE = 96
LEAD_STRUCT = struct.Struct("!4sBBhh66shh16s")

#: Lead ``type`` field: 0 is a binary package, 1 a source package.
LEAD_TYPE_BINARY = 0
LEAD_TYPE_SOURCE = 1

#: Where packages live inside a variant directory (4.2).
PACKAGES_DIRNAME = "Packages"

# rpm's own grammar.  A name may contain almost anything printable, but the
# NEVRA is parsed back out of filenames by every RPM tool in existence, so a
# name containing '-' or a version containing '/' would produce a filename
# nothing could take apart again.
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$")
# Version and release may not contain '-': it is the separator between them.
EVR_PATTERN = re.compile(r"^[A-Za-z0-9._+~^]+$")
ARCHITECTURE_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")

#: Architecture-independent packages, the RPM spelling of Debian's ``all``.
ARCH_NOARCH = "noarch"

# `foo-1.0-1.src.rpm` -- the source package a binary was built from.
SOURCE_RPM_PATTERN = re.compile(r"^(.+)-[^-]+-[^-]+\.(?:no)?src\.rpm$")

# Header tags copied onto the row.  Deliberately a fixed list rather than
# "everything rpmfile returned": a header carries per-file arrays that can run
# to thousands of entries, and none of it belongs in a JSON column.
HEADER_FIELDS: tuple[str, ...] = (
    "summary",
    "description",
    "copyright",
    "url",
    "vendor",
    "packager",
    "group",
    "sourcerpm",
    "buildhost",
    "os",
    "rpmversion",
)

#: Integer header tags copied onto the row, rendered as decimal strings.
HEADER_INT_FIELDS: tuple[str, ...] = ("size", "buildtime", "archivesize")

#: Tag 1014 has been RPMTAG_LICENSE since rpm 4.0, but ``rpmfile`` still calls
#: it by its 1990s name.  Renamed on the way in so the interface does not have
#: to explain why a package's licence is labelled "copyright".
HEADER_RENAMES: Mapping[str, str] = {"copyright": "license"}


# --------------------------------------------------------------------- version ordering


def _is_digit(char: str) -> bool:
    # ASCII only, deliberately: ``str.isdigit`` is true for characters such as
    # U+0663 ARABIC-INDIC DIGIT THREE, which rpm's own `risdigit` rejects.
    return "0" <= char <= "9"


def _is_alpha(char: str) -> bool:
    return ("a" <= char <= "z") or ("A" <= char <= "Z")


def _is_alnum(char: str) -> bool:
    return _is_digit(char) or _is_alpha(char)


def rpm_vercmp(one: str, two: str) -> int:
    """rpm's ``rpmvercmp``, transcribed from ``rpmio/rpmvercmp.c``.

    Returns -1, 0 or 1.  Transcribed rather than invented because the rules are
    genuinely surprising -- ``~`` sorts *before* an empty segment so that
    ``1.0~rc1`` precedes ``1.0``, ``^`` sorts after it, separators are ignored
    entirely, and a numeric segment always outranks an alphabetic one.  Getting
    any of that wrong prunes the wrong package under a retention policy (5.3).
    """
    if one == two:
        return 0

    index_one, index_two = 0, 0
    end_one, end_two = len(one), len(two)

    while index_one < end_one or index_two < end_two:
        # Separators carry no meaning: `1.0-1` and `1_0_1` compare equal.
        while index_one < end_one and not _is_alnum(one[index_one]) and one[index_one] not in "~^":
            index_one += 1
        while index_two < end_two and not _is_alnum(two[index_two]) and two[index_two] not in "~^":
            index_two += 1

        head_one = one[index_one] if index_one < end_one else ""
        head_two = two[index_two] if index_two < end_two else ""

        # A tilde sorts before everything, including the end of the string, so
        # that a pre-release orders below the release it precedes.
        if head_one == "~" or head_two == "~":
            if head_one != "~":
                return 1
            if head_two != "~":
                return -1
            index_one += 1
            index_two += 1
            continue

        # A caret is the mirror image: it sorts before everything *except* the
        # end of the string, so `1.0^git1` is newer than `1.0` but older than
        # `1.1`.
        if head_one == "^" or head_two == "^":
            if not head_one:
                return -1
            if not head_two:
                return 1
            if head_one != "^":
                return 1
            if head_two != "^":
                return -1
            index_one += 1
            index_two += 1
            continue

        if not head_one or not head_two:
            break

        start_one, start_two = index_one, index_two
        numeric = _is_digit(head_one)
        matches = _is_digit if numeric else _is_alpha
        while index_one < end_one and matches(one[index_one]):
            index_one += 1
        while index_two < end_two and matches(two[index_two]):
            index_two += 1

        segment_one = one[start_one:index_one]
        segment_two = two[start_two:index_two]

        # Different segment types: a number always beats a letter, which is why
        # `1.1` is newer than `1.a`.
        if not segment_two:
            return 1 if numeric else -1

        if numeric:
            # Leading zeros carry no value, so the longer run of significant
            # digits is simply the larger number.
            segment_one = segment_one.lstrip("0")
            segment_two = segment_two.lstrip("0")
            if len(segment_one) != len(segment_two):
                return 1 if len(segment_one) > len(segment_two) else -1

        if segment_one != segment_two:
            return 1 if segment_one > segment_two else -1

    # Every segment matched.  Whichever string has characters left over -- and
    # they can only be separators by now -- is the newer one.
    if index_one >= end_one and index_two >= end_two:
        return 0
    return -1 if index_one >= end_one else 1


@dataclass(frozen=True)
class Evr:
    """An epoch/version/release triple, rpm's unit of comparison."""

    epoch: int = 0
    version: str = ""
    release: str = ""

    def __str__(self) -> str:
        rendered = f"{self.version}-{self.release}" if self.release else self.version
        return f"{self.epoch}:{rendered}" if self.epoch else rendered


def compare_evr(one: Evr, two: Evr) -> int:
    """rpm's ``labelCompare``: epoch first, then version, then release.

    A missing epoch is 0, not "unknown".  That is what makes an epoch bump the
    only reliable way to supersede a version that was numbered too high.
    """
    if one.epoch != two.epoch:
        return 1 if one.epoch > two.epoch else -1
    version = rpm_vercmp(one.version, two.version)
    if version:
        return version
    return rpm_vercmp(one.release, two.release)


_EvrKey = functools.cmp_to_key(compare_evr)


def version_sort_key(epoch: int | None, version: str, release: str) -> Any:
    """RPM version ordering, for retention and "newest first" listings (4.2)."""
    return _EvrKey(Evr(epoch=epoch or 0, version=version, release=release))


# --------------------------------------------------------------------------- parsing


@dataclass(frozen=True)
class RpmMetadata:
    """A validated ``.rpm``, ready to be placed in a variant and indexed."""

    name: str
    source_name: str
    version: str
    release: str
    epoch: int | None
    architecture: str
    header: Mapping[str, str]
    digests: FileDigests

    @property
    def evr(self) -> Evr:
        return Evr(epoch=self.epoch or 0, version=self.version, release=self.release)

    @property
    def nevra(self) -> str:
        """The package's full identity, as ``rpm -q`` prints it."""
        return f"{self.name}-{self.evr}.{self.architecture}"

    @property
    def filename(self) -> str:
        """The canonical filename, which omits the epoch as rpm itself does."""
        return f"{self.name}-{self.version}-{self.release}.{self.architecture}.rpm"

    def variant_path(self, variant: str) -> str:
        """Where this package lives under the repository root (4.2)."""
        return f"{variant}/{PACKAGES_DIRNAME}/{self.filename}"


def read_lead(path: Path) -> tuple[int, int]:
    """Return the lead's ``(type, architecture number)``, checking the magic.

    Checked before anything else touches the file, so a truncated upload or a
    mistakenly selected ``.deb`` is refused by this application rather than by
    a parser deep inside a library (5.1).
    """
    with path.open("rb") as handle:
        lead = handle.read(LEAD_SIZE)
    if len(lead) < LEAD_SIZE or not lead.startswith(RPM_MAGIC):
        raise PackageFormatError(
            "That file is not an RPM package: it does not begin with the RPM lead "
            "signature 0xEDABEEDB. Check that you selected a .rpm and that the upload "
            "completed."
        )
    _, _, _, package_type, architecture_number, _, _, _, _ = LEAD_STRUCT.unpack(lead)
    return int(package_type), int(architecture_number)


def _text(raw: object) -> str:
    """Decode one header value, whatever shape ``rpmfile`` handed back.

    Header strings are bytes; i18n strings can arrive as a list of locales, of
    which the first is the C one; and ``surrogateescape`` is used because a
    package built on a mis-configured host really can carry a Latin-1 summary,
    and refusing the upload over an accented character in a description would
    be absurd.
    """
    if isinstance(raw, list | tuple):
        raw = raw[0] if raw else b""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="surrogateescape").strip()
    if raw is None:
        return ""
    return str(raw).strip()


def _integer(raw: object) -> int | None:
    if isinstance(raw, list | tuple):
        raw = raw[0] if raw else None
    if isinstance(raw, int):
        return raw
    return None


def _collect_header(headers: Mapping[str, Any]) -> dict[str, str]:
    fields = {name: _text(headers[name]) for name in HEADER_FIELDS if headers.get(name) is not None}
    for name in HEADER_INT_FIELDS:
        value = _integer(headers.get(name))
        if value is not None:
            fields[name] = str(value)
    return {HEADER_RENAMES.get(name, name): value for name, value in fields.items() if value}


def _source_name(headers: Mapping[str, Any], *, fallback: str) -> str:
    """The source package's name, taken from ``sourcerpm``.

    Only used for grouping in the interface -- RPM has no pool prefix to
    compute -- so a value that cannot be parsed falls back to the binary name rather
    than failing an upload that is otherwise perfectly good.
    """
    raw = _text(headers.get("sourcerpm"))
    if not raw:
        return fallback
    match = SOURCE_RPM_PATTERN.match(raw)
    if not match or not NAME_PATTERN.match(match.group(1)):
        return fallback
    return match.group(1)


def read_rpm(path: Path) -> RpmMetadata:
    """Parse and validate an ``.rpm``, or explain why it cannot be used."""
    import rpmfile

    package_type, _ = read_lead(path)
    if package_type == LEAD_TYPE_SOURCE:
        raise PackageFormatError(
            "That is a source package (.src.rpm). This repository publishes binary "
            "packages; build it first and upload the result."
        )

    try:
        with rpmfile.open(str(path)) as archive:
            headers = dict(archive.headers)
    except Exception as exc:  # any parse failure means the upload is unusable
        raise PackageFormatError(f"The package's header could not be read: {exc}") from exc

    name = _text(headers.get("name"))
    version = _text(headers.get("version"))
    release = _text(headers.get("release"))
    architecture = _text(headers.get("arch"))

    missing = [
        field
        for field, value in (
            ("Name", name),
            ("Version", version),
            ("Release", release),
            ("Arch", architecture),
        )
        if not value
    ]
    if missing:
        raise PackageFormatError(
            f"The package's header is missing required tag(s): {', '.join(missing)}."
        )

    # A binary package always records the source it was built from; a source
    # package never does.  The lead is checked above, but it is only advisory
    # in modern rpm, so the header has the final say.
    if headers.get("sourcepackage") is not None or not headers.get("sourcerpm"):
        raise PackageFormatError(
            "That package has no SOURCERPM tag, which means it is a source package. "
            "This repository publishes binary packages only."
        )

    if not NAME_PATTERN.match(name):
        raise PackageFormatError(f"Package name {name!r} contains characters rpm does not allow.")
    for field, value in (("Version", version), ("Release", release)):
        if not EVR_PATTERN.match(value):
            raise PackageFormatError(
                f"{field} {value!r} is not a valid RPM {field.lower()} string: it may contain "
                "only letters, digits and '. _ + ~ ^'."
            )
    if not ARCHITECTURE_PATTERN.match(architecture):
        raise PackageFormatError(f"Architecture {architecture!r} is not a valid architecture name.")

    return RpmMetadata(
        name=name,
        source_name=_source_name(headers, fallback=name),
        version=version,
        release=release,
        # rpm stores no epoch at all rather than storing zero, and the two mean
        # the same thing; `None` is kept so the row records what the package
        # actually said (9).
        epoch=_integer(headers.get("serial")),
        architecture=architecture,
        header=_collect_header(headers),
        digests=digest_file(path),
    )
