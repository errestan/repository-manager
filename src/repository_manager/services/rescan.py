"""Reconciling the database against the filesystem (specification.md 5.4).

A rescan answers one question: does what this application believes it is
publishing match what is actually on disk?  The two can part company — someone
copies a package in by hand, a backup restores an old tree, a filesystem loses
a file — and none of that is visible from the interface, because every page is
rendered from the database.

**It reports and changes nothing.**  That is the whole design.  Each kind of
drift has two opposite right answers depending on how it happened: a file on
disk with no row is either a package someone meant to add or litter from a
half-finished restore, and a row with no file is either a deletion to
acknowledge or a failure to recover from.  Guessing would risk deleting a
package nobody asked to lose, so the job says what it found and leaves the
decision to a person.

It runs as a job because the honest check is a full re-hash of every published
file, which is bounded by the size of the repository rather than by anyone's
patience — and because the queue already serialises it against the regeneration
it must not race.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from repository_manager.config import Settings
from repository_manager.jobs.queue import JobContext, JobQueue
from repository_manager.logging import get_logger
from repository_manager.metadata.digests import digest_file
from repository_manager.models import JobType, Package, Repository
from repository_manager.security.paths import resolve_within_roots
from repository_manager.services.packages import INCOMING_DIRNAME
from repository_manager.services.publishing import load_for_publish

log = get_logger(__name__)

#: What counts as a package file when walking the tree.  Generated metadata --
#: indices, ``repomd.xml``, signatures, the exported public key -- is this
#: application's own output and is rebuilt on demand, so it is not drift.
PACKAGE_SUFFIXES = frozenset({".deb", ".rpm"})

#: Directory names skipped entirely.  ``.incoming`` holds part-received uploads
#: whose whole purpose is to be transient (5.1).
SKIPPED_DIRNAMES = frozenset({INCOMING_DIRNAME})

#: How many entries of each kind the job log names individually before it stops
#: listing and reports a count.  A restore gone wrong can produce thousands,
#: and a log excerpt that is all one list is a log nobody reads.
LISTED_LIMIT = 25


@dataclass(frozen=True)
class Difference:
    """One thing that does not match, in words a person can act on."""

    path: str
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.path} — {self.detail}" if self.detail else self.path


@dataclass
class DriftReport:
    """What a rescan found."""

    checked_files: int = 0
    checked_rows: int = 0
    #: A row whose file is not on disk: clients are being offered a 404.
    missing: list[Difference] = field(default_factory=list)
    #: A file whose bytes are not the bytes that were published.
    modified: list[Difference] = field(default_factory=list)
    #: A package file with no row: served by the web server, in no index.
    untracked: list[Difference] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.missing or self.modified or self.untracked)

    @property
    def total(self) -> int:
        return len(self.missing) + len(self.modified) + len(self.untracked)

    def lines(self) -> list[str]:
        """The report as the job log renders it."""
        written = [
            f"Checked {self.checked_rows} published package(s) "
            f"against {self.checked_files} file(s) on disk."
        ]
        if self.clean:
            written.append("No drift found: the database and the filesystem agree.")
            return written

        for heading, entries in (
            ("published but missing from disk", self.missing),
            ("on disk but not the bytes that were published", self.modified),
            ("on disk but not published by this application", self.untracked),
        ):
            if not entries:
                continue
            written.append(f"{len(entries)} package file(s) {heading}:")
            written.extend(f"  - {entry}" for entry in entries[:LISTED_LIMIT])
            if len(entries) > LISTED_LIMIT:
                written.append(f"  … and {len(entries) - LISTED_LIMIT} more.")
        written.append(
            "Nothing was changed. Re-upload what is missing, or remove what should not "
            "be there, then regenerate the metadata."
        )
        return written

    @property
    def summary(self) -> str:
        if self.clean:
            return "No drift found."
        return (
            f"{len(self.missing)} missing, {len(self.modified)} modified, "
            f"{len(self.untracked)} untracked."
        )


def walk_packages(root: Path) -> Iterator[Path]:
    """Every package file under ``root``, staging directories excluded."""
    for candidate in sorted(root.rglob("*")):
        if candidate.suffix.lower() not in PACKAGE_SUFFIXES:
            continue
        if not candidate.is_file():
            continue
        if SKIPPED_DIRNAMES.intersection(candidate.relative_to(root).parts):
            continue
        yield candidate


def compare(root: Path, rows: Sequence[tuple[str, int, str]]) -> DriftReport:
    """Compare recorded ``(relative_path, size, sha256)`` against the tree.

    Synchronous and pure so it can be driven straight from a thread: hashing a
    repository is the expensive part, and it has no business on the event loop.
    """
    report = DriftReport(checked_rows=len(rows))
    on_disk = {str(path.relative_to(root)).replace("\\", "/"): path for path in walk_packages(root)}
    report.checked_files = len(on_disk)

    for relative_path, size, sha256 in rows:
        found = on_disk.pop(relative_path, None)
        if found is None:
            report.missing.append(
                Difference(relative_path, "the file is not there; clients get a 404")
            )
            continue
        digests = digest_file(found)
        if digests.sha256 != sha256:
            report.modified.append(
                Difference(
                    relative_path,
                    f"recorded {sha256[:12]}… but the file hashes to {digests.sha256[:12]}…",
                )
            )
        elif digests.size != size:  # pragma: no cover - a size change changes the hash
            report.modified.append(
                Difference(relative_path, f"recorded {size} bytes, found {digests.size}")
            )

    for relative_path in sorted(on_disk):
        report.untracked.append(Difference(relative_path, "no database row; it is in no index"))
    return report


async def scan(session: AsyncSession, settings: Settings, repository: Repository) -> DriftReport:
    """Compare one repository's rows against its tree."""
    rows = [
        (path, size, sha256)
        for path, size, sha256 in (
            await session.execute(
                select(Package.relative_path, Package.size, Package.sha256)
                .where(Package.repository_id == repository.id)
                .order_by(Package.relative_path)
            )
        ).all()
    ]
    # Re-checked rather than trusted from the row: the allowed roots may have
    # been narrowed since the repository was created (10.4).
    root = resolve_within_roots(Path(repository.root_path), settings.allowed_roots)
    return await asyncio.to_thread(compare, root, rows)


async def rescan_repository(context: JobContext) -> None:
    """Job handler for :data:`JobType.RESCAN`.

    Drift is reported through the job's log and its *success*, not through a
    failure: the job did what it was asked to do.  A failed job would mean the
    check could not be run, which is a different thing an operator would chase
    differently.
    """
    if context.repository_id is None:
        raise ValueError("A rescan job must name a repository.")

    async with context.sessionmaker() as session:
        repository = await load_for_publish(session, context.repository_id)
        slug = repository.slug
        await context.log(f"Rescanning {slug}.")
        await context.set_progress(10)
        report = await scan(session, context.settings, repository)

    await context.set_progress(90)
    for line in report.lines():
        await context.log(line)
    await context.set_progress(100)
    log.info(
        "repository rescanned",
        repository=slug,
        clean=report.clean,
        missing=len(report.missing),
        modified=len(report.modified),
        untracked=len(report.untracked),
    )


def register_handlers(queue: JobQueue) -> None:
    queue.register(JobType.RESCAN, rescan_repository)
