"""RPM metadata generation via ``createrepo_c`` (specification.md 4.2, AD-2).

APT indices are plain text and are emitted here in pure Python; RPM metadata is
not.  ``primary``/``filelists``/``other`` XML, the digests threaded between
them and ``repomd.xml`` itself are a large, versioned format with a reference
implementation that every client is tested against, and reimplementing it would
buy nothing but a new source of "repository is broken" reports.

``createrepo_c`` is invoked as a subprocess rather than through its Python
bindings.  The bindings are a compiled extension that ships with the
distribution package and is not installable from PyPI, so importing them would
make this application uninstallable wherever it is not; the binary, in
contrast, is a documented dependency an operator installs once (13.1).

Signing is this module's own work: ``createrepo_c`` does not sign anything, and
an unsigned ``repomd.xml`` is a repository a correctly configured ``dnf``
refuses to use.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from repository_manager.security.paths import atomic_write_bytes, ensure_directory

#: The binary an operator installs (13.1).  Overridable so a deployment that
#: keeps it outside ``PATH`` is not forced to symlink it.
CREATEREPO_BINARY = "createrepo_c"

PACKAGES_DIRNAME = "Packages"
REPODATA_DIRNAME = "repodata"
REPOMD_FILENAME = "repomd.xml"
REPOMD_SIGNATURE_FILENAME = "repomd.xml.asc"

# Long enough for a repository of real size on slow storage, short enough that a
# wedged subprocess is reported rather than holding the repository lock forever.
CREATEREPO_TIMEOUT_SECONDS = 3600.0

# Variant names are path segments, and this is the only place a configured
# string becomes one, so the grammar is narrow on purpose (4.2, 10.4).
SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: Segments that would traverse upward or restart the path, refused explicitly
#: rather than left to the pattern, so the reason a name was rejected is clear.
FORBIDDEN_SEGMENTS = frozenset({"", ".", ".."})


class RepodataError(Exception):
    """Metadata could not be generated; the message reaches the job log."""


class Signer(Protocol):
    """The one signature ``repomd.xml`` needs (4.2).

    A protocol rather than a concrete GnuPG dependency, matching
    :class:`repository_manager.metadata.apt.Signer`: this module stays testable
    without a keyring and the signing implementation stays swappable.
    """

    def detach_sign(self, data: bytes) -> bytes: ...


def validate_segment(value: str, *, field: str) -> str:
    if value in FORBIDDEN_SEGMENTS or "/" in value or "\\" in value:
        raise RepodataError(
            f"{field} {value!r} is not a usable directory name: it must be a single path "
            "segment and may not traverse upward."
        )
    if not SEGMENT_PATTERN.match(value):
        raise RepodataError(
            f"{field} {value!r} may contain only letters, digits and '. _ -', and must start "
            "with a letter or digit."
        )
    return value


@dataclass(frozen=True)
class VariantPlan:
    """One independently indexed subtree, e.g. ``el9/x86_64`` (4.2)."""

    name: str
    arch: str

    def __post_init__(self) -> None:
        validate_segment(self.name, field="Variant name")
        validate_segment(self.arch, field="Variant architecture")

    @property
    def path(self) -> str:
        """The variant's location relative to the repository root."""
        return f"{self.name}/{self.arch}"

    def directory(self, root: Path) -> Path:
        return root / self.name / self.arch

    def packages_directory(self, root: Path) -> Path:
        return self.directory(root) / PACKAGES_DIRNAME


@dataclass(frozen=True)
class RepositoryPlan:
    """A whole RPM repository, as the generator sees it."""

    variants: tuple[VariantPlan, ...] = ()


@dataclass(frozen=True)
class VariantResult:
    """What one variant's regeneration produced."""

    variant: str
    packages: int
    signed: bool


def public_key_filename(key_name: str) -> str:
    """Where the armoured public key sits in the repository root (4.2).

    The ``RPM-GPG-KEY-`` prefix is the convention every distribution uses and
    the name every published ``gpgkey=`` line expects.
    """
    return f"RPM-GPG-KEY-{key_name}"


def repodata_directory(root: Path, variant: VariantPlan) -> Path:
    return variant.directory(root) / REPODATA_DIRNAME


def repomd_path(root: Path, variant: VariantPlan) -> Path:
    return repodata_directory(root, variant) / REPOMD_FILENAME


def create_skeleton(root: Path, plan: RepositoryPlan) -> None:
    """Create the directory tree a new RPM repository needs (4.3)."""
    ensure_directory(root)
    for variant in plan.variants:
        ensure_directory(variant.packages_directory(root))


def resolve_binary(binary: str = CREATEREPO_BINARY) -> str:
    """Locate ``createrepo_c``, or say plainly what is missing.

    An absolute path is taken as given; anything else is looked up on ``PATH``.
    The message names the package to install because the alternative -- a
    ``FileNotFoundError`` from ``subprocess`` in a job log -- tells an operator
    nothing they can act on.
    """
    if "/" in binary:
        if Path(binary).is_file():
            return binary
        raise RepodataError(f"{binary} does not exist, so RPM metadata cannot be generated.")
    found = shutil.which(binary)
    if found is None:
        raise RepodataError(
            f"{binary} is not installed, so RPM metadata cannot be generated. Install the "
            "'createrepo-c' package (Debian/Ubuntu) or 'createrepo_c' (Fedora/RHEL)."
        )
    return found


def count_packages(directory: Path) -> int:
    """How many ``.rpm`` files the variant holds, for the job log."""
    packages = directory / PACKAGES_DIRNAME
    if not packages.is_dir():
        return 0
    return sum(1 for entry in packages.iterdir() if entry.is_file() and entry.suffix == ".rpm")


def run_createrepo(directory: Path, *, binary: str = CREATEREPO_BINARY) -> str:
    """Index ``directory`` in place, returning what the tool said.

    ``--update`` reuses the digests already recorded for files that have not
    changed, which turns a re-index of a large repository from minutes into
    milliseconds; on a directory with no ``repodata`` yet it simply builds one
    from scratch.

    ``--general-compress-type=gz`` pins the compression of the primary,
    filelists and other indices.  Left to itself ``createrepo_c`` picks a
    default that has changed between releases, and the on-disk layout in 4.2 is
    a contract with whoever is reading the tree -- including the reference nginx
    configuration and anyone debugging with ``zcat``.

    ``--no-database`` omits the sqlite copies of that same data.  ``dnf`` has
    resolved against the XML through libsolv since it replaced ``yum``, so the
    databases would double the size of every ``repodata`` directory to serve a
    client that no supported distribution ships.
    """
    executable = resolve_binary(binary)
    command = [
        executable,
        "--update",
        "--no-database",
        "--general-compress-type=gz",
        str(directory),
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, path validated above
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=CREATEREPO_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RepodataError(
            f"{executable} did not finish within {CREATEREPO_TIMEOUT_SECONDS:.0f} seconds "
            f"for {directory}."
        ) from exc
    except OSError as exc:
        raise RepodataError(f"{executable} could not be run: {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RepodataError(
            f"{executable} failed for {directory} (exit {completed.returncode}): "
            f"{detail or 'no output'}"
        )
    return (completed.stdout or "").strip()


def sign_repomd(root: Path, variant: VariantPlan, signer: Signer) -> None:
    """Write the detached armoured signature beside ``repomd.xml`` (4.2)."""
    repomd = repomd_path(root, variant)
    if not repomd.is_file():
        raise RepodataError(
            f"{repomd} was not written, so there is nothing to sign. This usually means "
            "createrepo_c reported success without producing metadata."
        )
    signature = signer.detach_sign(repomd.read_bytes())
    atomic_write_bytes(repodata_directory(root, variant) / REPOMD_SIGNATURE_FILENAME, signature)


def generate_variant(
    root: Path,
    variant: VariantPlan,
    *,
    signer: Signer,
    binary: str = CREATEREPO_BINARY,
) -> VariantResult:
    """Regenerate and sign one variant's ``repodata``.

    The signing key is exercised on a throwaway payload *before* createrepo_c
    runs.  Nothing else in this sequence can be undone: once createrepo_c has
    swapped the new ``repodata`` into place, a signing failure would leave the
    tree carrying fresh metadata under a stale signature, which every client
    reads as tampering.  Failing early costs one cheap signature and turns that
    outcome into a job that failed without touching anything.
    """
    ensure_directory(variant.packages_directory(root))
    directory = variant.directory(root)
    signer.detach_sign(b"repository-manager signing probe\n")

    run_createrepo(directory, binary=binary)
    sign_repomd(root, variant, signer)
    return VariantResult(variant=variant.path, packages=count_packages(directory), signed=True)


def generate(
    root: Path,
    plan: RepositoryPlan,
    *,
    signer: Signer,
    binary: str = CREATEREPO_BINARY,
) -> dict[str, VariantResult]:
    """Regenerate every variant in the repository.

    One job covers the whole repository (AD-8), but each variant is a separate
    ``createrepo_c --update`` over its own tree, so an upload into
    ``el9/x86_64`` leaves ``el8/aarch64`` byte-for-byte as it was: ``--update``
    finds nothing changed there and rewrites nothing.  That is what 4.2 means
    by regenerating variants independently -- one repository's rebuild never
    turns into a rebuild of every tree it owns.
    """
    return {
        variant.path: generate_variant(root, variant, signer=signer, binary=binary)
        for variant in plan.variants
    }
