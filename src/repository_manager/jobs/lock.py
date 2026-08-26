"""An on-disk exclusive lock per repository (specification.md 5.4).

The queue already serialises jobs per repository within one process.  This lock
covers the case that cannot: two application instances sharing a filesystem,
or an administrator running a CLI regeneration while the service is up.  Two
processes rewriting one ``dists`` tree at the same time would interleave their
index files and produce hashes that match neither.

``flock`` is used rather than a lockfile-with-a-PID because the kernel releases
it when the holder dies, so a process killed mid-regeneration does not leave a
repository permanently locked.
"""

from __future__ import annotations

import errno
import fcntl
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# Dot-prefixed so it stays out of the directory listings a web server generates
# for the repository root, and so apt never tries to interpret it.
LOCKFILE_NAME = ".repoman.lock"

POLL_INTERVAL_SECONDS = 0.05


class RepositoryLockError(Exception):
    """Another process holds the repository lock."""


@contextmanager
def repository_lock(root: Path, *, timeout: float = 30.0) -> Iterator[Path]:
    """Hold an exclusive lock on ``root`` for the duration of the block.

    Raises :class:`RepositoryLockError` rather than blocking forever, so a stuck
    peer surfaces as a failed job with a clear reason instead of a worker that
    never returns.
    """
    root.mkdir(parents=True, exist_ok=True)
    path = root / LOCKFILE_NAME
    handle = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:  # pragma: no cover
                    raise
                if time.monotonic() >= deadline:
                    raise RepositoryLockError(
                        f"another process has been regenerating {root} for more than "
                        f"{timeout:g}s; not starting a second regeneration"
                    ) from exc
                time.sleep(POLL_INTERVAL_SECONDS)
        try:
            yield path
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        os.close(handle)
