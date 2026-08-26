"""Pure-Python APT index generation (specification.md 4.1, AD-2).

No ``apt-ftparchive``, no ``dpkg-scanpackages``: the whole ``dists`` tree is
produced from data already in the database, which means metadata can be
regenerated on a host with no Debian tooling installed at all, and a
regeneration costs one query rather than a walk over every file in the pool.

The output is deterministic -- stanzas are sorted, compression timestamps are
zeroed -- so regenerating an unchanged repository produces byte-identical
indices.  That is what makes "did anything actually change?" answerable, and it
keeps signatures stable for clients that cache aggressively.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import lzma
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from repository_manager.security.paths import (
    atomic_replace_tree,
    atomic_write_bytes,
    ensure_directory,
    force_remove_tree,
)

# Field order for a `Packages` stanza.  RFC822 fields are unordered as far as
# apt is concerned, but a fixed order is what makes the output reproducible.
# Anything not listed is appended alphabetically, so a control field we have
# never seen still reaches the index rather than being silently dropped.
PACKAGES_FIELD_ORDER: tuple[str, ...] = (
    "Package",
    "Source",
    "Version",
    "Essential",
    "Installed-Size",
    "Maintainer",
    "Original-Maintainer",
    "Architecture",
    "Multi-Arch",
    "Replaces",
    "Provides",
    "Depends",
    "Pre-Depends",
    "Recommends",
    "Suggests",
    "Conflicts",
    "Breaks",
    "Enhances",
    "Filename",
    "Size",
    "MD5sum",
    "SHA1",
    "SHA256",
    "Section",
    "Priority",
    "Homepage",
    "Description",
    "Description-md5",
)

RELEASE_FIELD_ORDER: tuple[str, ...] = (
    "Origin",
    "Label",
    "Suite",
    "Codename",
    "Date",
    "Architectures",
    "Components",
    "Description",
)

# `Architecture: all` packages are listed in *every* architecture's index,
# because apt does not look outside the architectures it was configured for.
ARCH_ALL = "all"

# The three hash blocks apt looks for in a Release file, newest first.  MD5Sum
# and SHA1 are present for compatibility with older clients only.
RELEASE_HASHES: tuple[tuple[str, str], ...] = (
    ("MD5Sum", "md5"),
    ("SHA1", "sha1"),
    ("SHA256", "sha256"),
)

# C-locale names, spelled out rather than delegated to strftime: the Release
# date must be RFC 2822 regardless of the server's locale, and %a/%b are
# locale-dependent.
_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)  # fmt: skip

GZIP_LEVEL = 9
XZ_PRESET = 6


class Signer(Protocol):
    """The two signatures a Release needs (4.1).

    A protocol rather than a concrete GnuPG dependency: this module stays
    testable without a keyring, and the signing implementation stays swappable.
    """

    def clearsign(self, data: bytes) -> bytes: ...

    def detach_sign(self, data: bytes) -> bytes: ...


@dataclass(frozen=True)
class DistributionPlan:
    """Everything needed to write one ``dists/<codename>`` tree."""

    codename: str
    suite: str
    architectures: tuple[str, ...]
    components: tuple[str, ...]
    description: str | None = None
    # component name -> the packages published in it
    stanzas: Mapping[str, Sequence[Mapping[str, str]]] = field(default_factory=dict)

    def for_architecture(self, component: str, architecture: str) -> list[Mapping[str, str]]:
        """The stanzas that belong in ``<component>/binary-<architecture>/Packages``.

        Architecture-independent packages are folded in here rather than left in
        a ``binary-all`` directory of their own, because apt only fetches the
        indices for architectures it is configured to use.
        """
        published = self.stanzas.get(component, ())
        selected = [
            stanza
            for stanza in published
            if stanza.get("Architecture") == architecture
            or (architecture != ARCH_ALL and stanza.get("Architecture") == ARCH_ALL)
        ]
        return sorted(
            selected,
            key=lambda s: (s.get("Package", ""), s.get("Version", ""), s.get("Architecture", "")),
        )


@dataclass(frozen=True)
class RepositoryPlan:
    """A whole APT repository, as the generator sees it."""

    origin: str
    label: str
    distributions: tuple[DistributionPlan, ...] = ()


@dataclass(frozen=True)
class IndexFile:
    """One generated file, and the digests Release must record for it."""

    relative_path: str
    size: int
    md5: str
    sha1: str
    sha256: str


def render_field(name: str, value: str) -> str:
    """Render one RFC822 field, folding a multi-line value correctly.

    Continuation lines must begin with whitespace, and a genuinely blank line
    inside a description is written as a lone ``.`` -- otherwise it would end
    the stanza.
    """
    lines = value.split("\n")
    rendered = [f"{name}: {lines[0].rstrip()}"]
    for line in lines[1:]:
        stripped = line.strip()
        rendered.append(f" {stripped}" if stripped else " .")
    return "\n".join(rendered)


def render_stanza(fields: Mapping[str, str], order: Sequence[str] = PACKAGES_FIELD_ORDER) -> str:
    ordered = [name for name in order if fields.get(name)]
    extra = sorted(set(fields) - set(order))
    return "\n".join(
        render_field(name, fields[name]) for name in [*ordered, *extra] if fields.get(name)
    )


def render_packages(stanzas: Iterable[Mapping[str, str]]) -> bytes:
    """A complete ``Packages`` file.

    An empty index is an empty file, which is valid: a repository with no
    packages yet is still one apt can add without erroring (4.3).
    """
    body = "\n\n".join(render_stanza(stanza) for stanza in stanzas)
    return f"{body}\n".encode() if body else b""


def format_release_date(moment: dt.datetime) -> str:
    """RFC 2822 in UTC, as apt expects (4.1)."""
    utc = moment.astimezone(dt.UTC)
    return (
        f"{_DAYS[utc.weekday()]}, {utc.day:02d} {_MONTHS[utc.month - 1]} {utc.year} "
        f"{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d} UTC"
    )


def compress_gzip(data: bytes) -> bytes:
    # mtime=0: the timestamp gzip would otherwise embed makes every regeneration
    # produce different bytes for identical content.
    return gzip.compress(data, compresslevel=GZIP_LEVEL, mtime=0)


def compress_xz(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ, preset=XZ_PRESET)


def digest_bytes(relative_path: str, data: bytes) -> IndexFile:
    return IndexFile(
        relative_path=relative_path,
        size=len(data),
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def render_binary_release(
    *, origin: str, label: str, suite: str, codename: str, component: str, architecture: str
) -> str:
    """The small ``Release`` inside each ``binary-<arch>`` directory.

    apt uses it to confirm that an index it fetched belongs to the suite and
    component it asked for, which is what stops a mirror from serving one
    component's packages in another's place.
    """
    return (
        "\n".join(
            [
                f"Archive: {suite}",
                f"Origin: {origin}",
                f"Label: {label}",
                f"Codename: {codename}",
                f"Component: {component}",
                f"Architecture: {architecture}",
            ]
        )
        + "\n"
    )


def render_release(
    plan: DistributionPlan,
    *,
    origin: str,
    label: str,
    files: Sequence[IndexFile],
    moment: dt.datetime,
) -> str:
    """The signed ``Release`` for one distribution.

    ``Valid-Until`` is deliberately absent (AD-15): an expiry turns an idle but
    perfectly good repository into a hard apt failure, and the only fix is a
    re-sign nobody scheduled.
    """
    fields: dict[str, str] = {
        "Origin": origin,
        "Label": label,
        "Suite": plan.suite,
        "Codename": plan.codename,
        "Date": format_release_date(moment),
        "Architectures": " ".join(plan.architectures),
        "Components": " ".join(plan.components),
    }
    if plan.description:
        fields["Description"] = plan.description

    lines = [render_stanza(fields, RELEASE_FIELD_ORDER)]
    ordered = sorted(files, key=lambda entry: entry.relative_path)
    for heading, attribute in RELEASE_HASHES:
        lines.append(f"{heading}:")
        lines.extend(
            f" {getattr(entry, attribute)} {entry.size:>16} {entry.relative_path}"
            for entry in ordered
        )
    return "\n".join(lines) + "\n"


def _write_index(
    directory: Path, relative_prefix: str, name: str, data: bytes, collected: list[IndexFile]
) -> None:
    atomic_write_bytes(directory / name, data)
    collected.append(digest_bytes(f"{relative_prefix}/{name}", data))


def build_distribution(
    target: Path,
    plan: DistributionPlan,
    *,
    origin: str,
    label: str,
    signer: Signer,
    moment: dt.datetime,
) -> list[IndexFile]:
    """Write a complete ``dists/<codename>`` tree into ``target``.

    ``target`` is expected to be a fresh empty directory; the caller swaps it
    into place once it is complete, so a reader never sees a partial tree (5.4).
    """
    ensure_directory(target)
    files: list[IndexFile] = []

    for component in plan.components:
        for architecture in plan.architectures:
            relative_prefix = f"{component}/binary-{architecture}"
            directory = ensure_directory(target / component / f"binary-{architecture}")

            packages = render_packages(plan.for_architecture(component, architecture))
            _write_index(directory, relative_prefix, "Packages", packages, files)
            _write_index(directory, relative_prefix, "Packages.gz", compress_gzip(packages), files)
            _write_index(directory, relative_prefix, "Packages.xz", compress_xz(packages), files)

            binary_release = render_binary_release(
                origin=origin,
                label=label,
                suite=plan.suite,
                codename=plan.codename,
                component=component,
                architecture=architecture,
            ).encode("utf-8")
            _write_index(directory, relative_prefix, "Release", binary_release, files)

    release = render_release(plan, origin=origin, label=label, files=files, moment=moment).encode(
        "utf-8"
    )
    atomic_write_bytes(target / "Release", release)

    # Both forms, because clients differ: modern apt prefers the inline
    # InRelease, older tooling and some mirrors still fetch Release + Release.gpg.
    atomic_write_bytes(target / "InRelease", signer.clearsign(release))
    atomic_write_bytes(target / "Release.gpg", signer.detach_sign(release))
    return files


def generate_distribution(
    root: Path,
    plan: DistributionPlan,
    *,
    origin: str,
    label: str,
    signer: Signer,
    moment: dt.datetime | None = None,
) -> list[IndexFile]:
    """Regenerate one distribution and swap it into place atomically."""
    dists = ensure_directory(root / "dists")
    staging = dists / f".tmp.{plan.codename}.{os.getpid()}"
    if staging.exists():  # a previous run died between building and swapping
        force_remove_tree(staging)

    files = build_distribution(
        staging,
        plan,
        origin=origin,
        label=label,
        signer=signer,
        moment=moment or dt.datetime.now(dt.UTC),
    )
    atomic_replace_tree(staging, dists / plan.codename)
    return files


def generate(
    root: Path,
    plan: RepositoryPlan,
    *,
    signer: Signer,
    moment: dt.datetime | None = None,
) -> dict[str, list[IndexFile]]:
    """Regenerate every distribution in the repository."""
    stamp = moment or dt.datetime.now(dt.UTC)
    return {
        distribution.codename: generate_distribution(
            root,
            distribution,
            origin=plan.origin,
            label=plan.label,
            signer=signer,
            moment=stamp,
        )
        for distribution in plan.distributions
    }


def create_skeleton(root: Path, plan: RepositoryPlan) -> None:
    """Create the directory tree a new APT repository needs (4.3)."""
    ensure_directory(root)
    ensure_directory(root / "dists")
    ensure_directory(root / "pool")
    for distribution in plan.distributions:
        for component in distribution.components:
            ensure_directory(root / "pool" / component)
