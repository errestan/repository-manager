"""Filesystem containment and durable writes (specification.md 10.4).

Two rules, applied everywhere the application touches a repository tree:

* every path is proved to sit inside a configured allowed root **after**
  resolution, so a symlink cannot walk out of the sandbox; and
* every file is written to a temporary neighbour and renamed into place, so a
  reader never observes a half-written index.

The checks are cheap and are deliberately re-applied on each write rather than
cached, because the filesystem can change underneath us between one call and
the next.
"""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath

# Repository trees are served by a web server running as another user, so
# directories are traversable and files readable, but nothing is group-writable.
DIR_MODE = 0o755
FILE_MODE = 0o644

# Key material and passphrases: owner only, no exceptions (10.5).
PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


class PathError(Exception):
    """A path is outside the sandbox, malformed, or otherwise refused."""


def _resolved_roots(allowed_roots: Iterable[Path]) -> tuple[Path, ...]:
    """Allowed roots, symlinks followed.

    Resolving the roots as well as the candidate matters: if ``/srv/repos`` is
    itself a symlink to ``/mnt/data/repos``, comparing a resolved candidate
    against an unresolved root would reject every legitimate path.
    """
    return tuple(Path(root).resolve() for root in allowed_roots)


def resolve_within_roots(candidate: Path | str, allowed_roots: Iterable[Path]) -> Path:
    """Resolve ``candidate`` and prove it lies inside one of ``allowed_roots``.

    The path need not exist yet -- creation is the main caller -- so resolution
    is non-strict.  What must already be true is that no *existing* component of
    the path is a symlink pointing out of the sandbox, which non-strict
    ``resolve()`` still follows and therefore still catches.
    """
    path = Path(candidate)
    if not path.is_absolute():
        raise PathError(f"{path} is not an absolute path")
    if ".." in path.parts:
        raise PathError(f"{path} contains a '..' component")

    resolved = path.resolve()
    roots = _resolved_roots(allowed_roots)
    if not roots:
        raise PathError("no allowed roots are configured")
    for root in roots:
        if resolved == root or resolved.is_relative_to(root):
            return resolved

    permitted = ", ".join(str(root) for root in roots)
    raise PathError(
        f"{path} resolves to {resolved}, which is not inside a permitted root ({permitted}). "
        "Add it to REPOMAN_ALLOWED_ROOTS or choose a different location."
    )


def relative_within(root: Path, relative: str) -> Path:
    """Join a repository-relative path to its root, refusing to escape it.

    ``relative`` comes from the database, not directly from a request, but it
    was *derived* from parsed package metadata, so it is still checked here --
    a validation gap upstream should fail closed rather than write outside the
    tree.
    """
    pure = PurePosixPath(relative)
    if pure.is_absolute():
        raise PathError(f"{relative!r} must be relative to the repository root")
    if ".." in pure.parts:
        raise PathError(f"{relative!r} contains a '..' component")

    joined = root.joinpath(*pure.parts)
    resolved_root = root.resolve()
    # The file itself may be absent; resolve the deepest existing ancestor so a
    # symlinked *directory* in the middle of the path is still caught.
    probe = joined
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    if not probe.resolve().is_relative_to(resolved_root) and probe.resolve() != resolved_root:
        raise PathError(f"{relative!r} escapes the repository root via a symlink")
    return joined


def ensure_directory(path: Path, *, mode: int = DIR_MODE) -> Path:
    """Create ``path`` and its parents, and make sure the mode really is ``mode``.

    ``mkdir`` applies the process umask, so a directory created with 0o755 on a
    system with ``umask 077`` comes out 0o700 and the web server cannot read the
    tree.  The explicit ``chmod`` is what makes the mode mean what it says.
    """
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    return path


def is_empty_directory(path: Path) -> bool:
    return path.is_dir() and next(path.iterdir(), None) is None


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = FILE_MODE) -> None:
    """Write ``data`` to ``path`` via a temporary file in the same directory.

    Same directory, therefore same filesystem, therefore ``os.replace`` is a
    real atomic rename rather than a copy.  The temporary file is fsynced before
    the rename so a crash cannot leave a correctly-named but empty index.
    """
    ensure_directory(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(mode)
        tmp_path.replace(path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def atomic_write_text(path: Path, text: str, *, mode: int = FILE_MODE) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def atomic_replace_tree(new_tree: Path, destination: Path) -> None:
    """Swap a freshly built directory into place, then delete the old one.

    ``os.replace`` refuses to overwrite a non-empty directory, so this is two
    renames with a brief window in which ``destination`` does not exist.  That
    window is microseconds and both renames are atomic, which is as close to an
    atomic directory swap as POSIX offers without ``renameat2`` (5.4).  A client
    that reads during the window retries; a client that reads either side sees a
    wholly consistent tree, which is the property that actually matters.
    """
    ensure_directory(destination.parent)
    retired = destination.with_name(f".{destination.name}.retiring.{os.getpid()}")
    force_remove_tree(retired)

    had_previous = destination.exists()
    if had_previous:
        destination.replace(retired)
    try:
        new_tree.replace(destination)
    except BaseException:
        if had_previous:
            retired.replace(destination)
        raise
    force_remove_tree(retired)


def force_remove_tree(path: Path) -> None:
    """Recursively delete ``path`` with **no** containment check.

    Only for paths this application created itself -- staging directories,
    retired index trees.  Anything derived from user input must go through
    :func:`remove_tree`, which proves the path is inside the sandbox first.
    """
    if not path.exists():
        return
    for child in sorted(path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if child.is_dir() and not child.is_symlink():
            child.rmdir()
        else:
            child.unlink()
    path.rmdir()


def remove_tree(path: Path, allowed_roots: Iterable[Path]) -> None:
    """Recursively delete ``path``, but only after proving it is in the sandbox."""
    resolve_within_roots(path, allowed_roots)
    force_remove_tree(path)


def open_exclusive(path: Path, *, mode: int = FILE_MODE) -> int:
    """Create a file that must not already exist, refusing to follow a symlink.

    ``O_EXCL`` alone already fails on an existing symlink, but ``O_NOFOLLOW``
    states the intent and covers platforms where that is not guaranteed (10.4).
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags, mode)


def harden_private_directory(path: Path) -> Path:
    """Create or tighten a directory that holds secrets, and verify the result."""
    ensure_directory(path, mode=PRIVATE_DIR_MODE)
    current = stat.S_IMODE(path.stat().st_mode)
    if current & 0o077:
        raise PathError(
            f"{path} is mode {current:04o}; it holds key material and must not be "
            "readable by group or other"
        )
    return path


def describe_roots(allowed_roots: Sequence[Path]) -> str:
    return ", ".join(str(root) for root in allowed_roots) or "(none)"
