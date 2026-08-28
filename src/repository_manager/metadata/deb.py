"""Reading and validating uploaded ``.deb`` files (specification.md 4.1, 5.1).

Nothing here trusts the uploaded filename.  The package's identity comes from
its own control data, and the pool path is derived from that -- so a file
called ``../../etc/cron.d/evil`` is simply stored as whatever its control file
says it is (10.2).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from repository_manager.metadata.digests import FileDigests, digest_file

# Every ar archive, and therefore every .deb, starts with this (5.1).
DEB_MAGIC = b"!<arch>\n"

# Debian package and version grammar, from Debian Policy 5.6.1 and 5.6.12.
PACKAGE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+._-]+$")
VERSION_PATTERN = re.compile(r"^(?:(\d+):)?([A-Za-z0-9.+~:-]+?)(?:-([A-Za-z0-9+.~]+))?$")
ARCHITECTURE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# `Source: foo (1.2-3)` -- the parenthesised version is the source's, not ours.
SOURCE_PATTERN = re.compile(r"^(\S+)(?:\s+\(([^)]*)\))?$")

# Packages beginning `lib` are pooled four characters deep, everything else one.
# This exists so `pool/main/l/` does not accumulate tens of thousands of entries.
LIB_PREFIX = "lib"
LIB_PREFIX_LENGTH = 4


class PackageFormatError(Exception):
    """The uploaded file is not a usable Debian package.

    The message is shown to whoever uploaded it, so it says what is wrong and
    what to do, not merely that validation failed.
    """


@dataclass(frozen=True)
class DebMetadata:
    """A validated ``.deb``, ready to be placed in the pool and indexed."""

    name: str
    source_name: str
    version: str
    epoch: int | None
    architecture: str
    control: Mapping[str, str]
    digests: FileDigests

    @property
    def version_without_epoch(self) -> str:
        """The version as it appears in a filename.

        dpkg omits the epoch from the filename, so ``1:1.0-1`` is stored as
        ``foo_1.0-1_amd64.deb``.  Following that convention matters: tools that
        map a filename back to a package assume it.
        """
        _, _, remainder = self.version.partition(":")
        return remainder or self.version

    @property
    def filename(self) -> str:
        return f"{self.name}_{self.version_without_epoch}_{self.architecture}.deb"

    def pool_path(self, component: str) -> str:
        """Where this package lives under the repository root (4.1)."""
        prefix = pool_prefix(self.source_name)
        return f"pool/{component}/{prefix}/{self.source_name}/{self.filename}"

    def stanza(self, relative_path: str) -> dict[str, str]:
        """The complete ``Packages`` entry for this package.

        Built once, at upload time, and stored on the row: regenerating an index
        then needs only the database, and never has to re-read (or re-trust)
        every file in the pool (5.4).
        """
        fields: dict[str, str] = dict(self.control)
        fields["Filename"] = relative_path
        fields["Size"] = str(self.digests.size)
        fields["MD5sum"] = self.digests.md5
        fields["SHA1"] = self.digests.sha1
        fields["SHA256"] = self.digests.sha256
        description = fields.get("Description")
        if description is not None:
            fields["Description-md5"] = description_md5(description)
        return fields


def pool_prefix(source_name: str) -> str:
    if source_name.startswith(LIB_PREFIX) and len(source_name) > len(LIB_PREFIX):
        return source_name[:LIB_PREFIX_LENGTH]
    return source_name[:1]


def description_md5(description: str) -> str:
    """apt's ``Description-md5``: the raw field value plus a trailing newline.

    "Raw" means continuation lines keep their leading space, exactly as the
    field appears in the control file.  Verified against ``apt-ftparchive -o
    APT::FTPArchive::LongDescription=false``, which is the definition apt
    itself uses.
    """
    payload = description if description.endswith("\n") else description + "\n"
    return hashlib.md5(payload.encode("utf-8"), usedforsecurity=False).hexdigest()


def check_magic(path: Path) -> None:
    """Reject anything that is not an ar archive before parsing it (5.1)."""
    with path.open("rb") as handle:
        header = handle.read(len(DEB_MAGIC))
    if header != DEB_MAGIC:
        raise PackageFormatError(
            "That file is not a Debian package: it does not begin with the ar archive "
            "signature '!<arch>'. Check that you selected a .deb and that the upload "
            "completed."
        )


def split_version(version: str) -> tuple[int | None, str]:
    """Separate the epoch from the rest, validating the whole against policy."""
    match = VERSION_PATTERN.match(version)
    if not match:
        raise PackageFormatError(
            f"Version {version!r} is not a valid Debian version string (Debian Policy 5.6.12)."
        )
    epoch = int(match.group(1)) if match.group(1) else None
    return epoch, version


def _control_to_dict(control: Any) -> dict[str, str]:
    # Deb822 is mapping-like but not a Mapping; copying it here gives the rest
    # of the codebase a plain dict that is JSON-serialisable as-is.
    return {str(key): str(value) for key, value in control.items()}


def read_deb(path: Path) -> DebMetadata:
    """Parse and validate a ``.deb``, or explain why it cannot be used."""
    from debian.debfile import DebError, DebFile

    check_magic(path)

    try:
        control = _control_to_dict(DebFile(str(path)).debcontrol())
    except DebError as exc:
        # The usual cause is a control member compressed with zstd on a host
        # with no `unzstd`: python-debian shells out for that format.
        raise PackageFormatError(
            f"The package's control information could not be read ({exc}). If it mentions "
            "'unzstd', install the 'zstd' package -- newer dpkg compresses packages with it."
        ) from exc
    except Exception as exc:  # any parse failure means the upload is unusable
        raise PackageFormatError(f"The package could not be parsed: {exc}") from exc

    name = control.get("Package", "").strip()
    version = control.get("Version", "").strip()
    architecture = control.get("Architecture", "").strip()

    missing = [
        field
        for field, value in (
            ("Package", name),
            ("Version", version),
            ("Architecture", architecture),
        )
        if not value
    ]
    if missing:
        raise PackageFormatError(
            f"The package's control file is missing required field(s): {', '.join(missing)}."
        )
    if not PACKAGE_NAME_PATTERN.match(name):
        raise PackageFormatError(f"Package name {name!r} is not valid under Debian Policy 5.6.1.")
    if not ARCHITECTURE_PATTERN.match(architecture):
        raise PackageFormatError(f"Architecture {architecture!r} is not a valid architecture name.")

    epoch, version = split_version(version)
    source_name = _source_name(control, fallback=name)

    return DebMetadata(
        name=name,
        source_name=source_name,
        version=version,
        epoch=epoch,
        architecture=architecture,
        control=control,
        digests=digest_file(path),
    )


def _source_name(control: Mapping[str, str], *, fallback: str) -> str:
    raw = control.get("Source", "").strip()
    if not raw:
        return fallback
    match = SOURCE_PATTERN.match(raw)
    if not match:
        raise PackageFormatError(f"Source field {raw!r} is not in the expected form.")
    source = match.group(1)
    if not PACKAGE_NAME_PATTERN.match(source):
        raise PackageFormatError(f"Source package name {source!r} is not valid.")
    return source


def version_sort_key(version: str) -> Any:
    """Debian's own version ordering, for retention and "newest first" listings.

    Deliberately delegated to ``debian.debian_support`` rather than
    reimplemented: version comparison has more edge cases (``~``, empty
    revisions, epochs) than anyone remembers, and getting it wrong prunes the
    wrong package.
    """
    from debian.debian_support import Version

    return Version(version)
