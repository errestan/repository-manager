"""File hashing shared by both package formats (specification.md 4.1, 4.2).

Lifted out of :mod:`repository_manager.metadata.deb` when RPM support arrived:
the digests an upload needs are a property of the *file*, not of the format
inside it, and an ``rpm`` module importing from a ``deb`` one to hash bytes
would misdescribe the dependency.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

# Read in chunks so a 2 GiB upload is hashed without being held in memory.
HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class FileDigests:
    size: int
    md5: str
    sha1: str
    sha256: str


def digest_file(path: Path) -> FileDigests:
    """MD5, SHA1 and SHA256 in a single pass over the file.

    MD5 and SHA1 are here because the ``Packages`` and ``Release`` formats
    require them, not because they are trusted: SHA256 is the one that carries
    the integrity guarantee.
    """
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(HASH_CHUNK_BYTES):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return FileDigests(
        size=size, md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest()
    )
