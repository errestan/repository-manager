"""Filesystem containment and durable writes (specification.md 10.4)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from repository_manager.security.paths import (
    PathError,
    atomic_replace_tree,
    atomic_write_bytes,
    ensure_directory,
    harden_private_directory,
    is_empty_directory,
    open_exclusive,
    relative_within,
    remove_tree,
    resolve_within_roots,
)


@pytest.fixture
def allowed(tmp_path: Path) -> Path:
    root = tmp_path / "srv"
    root.mkdir()
    return root


# ------------------------------------------------------------------ containment


def test_a_path_inside_an_allowed_root_is_accepted(allowed: Path) -> None:
    assert resolve_within_roots(allowed / "repo", [allowed]) == allowed / "repo"


def test_the_root_itself_is_inside_itself(allowed: Path) -> None:
    assert resolve_within_roots(allowed, [allowed]) == allowed


def test_a_path_outside_every_root_is_refused(allowed: Path, tmp_path: Path) -> None:
    with pytest.raises(PathError, match="not inside a permitted root"):
        resolve_within_roots(tmp_path / "elsewhere", [allowed])


def test_a_relative_path_is_refused(allowed: Path) -> None:
    with pytest.raises(PathError, match="absolute"):
        resolve_within_roots(Path("repo"), [allowed])


def test_a_dotdot_component_is_refused(allowed: Path) -> None:
    with pytest.raises(PathError, match=r"'\.\.'"):
        resolve_within_roots(allowed / ".." / "escape", [allowed])


def test_a_symlink_out_of_the_sandbox_is_refused(allowed: Path, tmp_path: Path) -> None:
    """The check is applied after resolution, which is the whole point (10.4)."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (allowed / "sneaky").symlink_to(outside)
    with pytest.raises(PathError, match="not inside a permitted root"):
        resolve_within_roots(allowed / "sneaky", [allowed])


def test_a_symlinked_root_is_resolved_on_both_sides(tmp_path: Path) -> None:
    """A root that is itself a symlink must still admit paths under it."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    assert resolve_within_roots(real / "repo", [link]) == real / "repo"


def test_no_configured_roots_means_nothing_is_permitted() -> None:
    with pytest.raises(PathError, match="no allowed roots"):
        resolve_within_roots(Path("/srv/repo"), [])


def test_a_prefix_match_is_not_enough(tmp_path: Path) -> None:
    """`/srv/repos-evil` must not pass because it starts with `/srv/repos`."""
    allowed = tmp_path / "repos"
    allowed.mkdir()
    (tmp_path / "repos-evil").mkdir()
    with pytest.raises(PathError):
        resolve_within_roots(tmp_path / "repos-evil" / "x", [allowed])


# ------------------------------------------------------------------ relative joins


def test_relative_within_joins_under_the_root(allowed: Path) -> None:
    assert relative_within(allowed, "pool/main/a/alpha.deb") == allowed / "pool/main/a/alpha.deb"


def test_relative_within_refuses_an_absolute_path(allowed: Path) -> None:
    with pytest.raises(PathError, match="relative"):
        relative_within(allowed, "/etc/passwd")


def test_relative_within_refuses_traversal(allowed: Path) -> None:
    with pytest.raises(PathError, match=r"'\.\.'"):
        relative_within(allowed, "pool/../../etc/passwd")


def test_relative_within_refuses_a_symlinked_directory(allowed: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (allowed / "pool").symlink_to(outside)
    with pytest.raises(PathError, match="escapes"):
        relative_within(allowed, "pool/main/a.deb")


# ------------------------------------------------------------------ writes


def test_atomic_write_creates_the_file_with_the_requested_mode(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "Packages"
    atomic_write_bytes(target, b"Package: alpha\n")
    assert target.read_bytes() == b"Package: alpha\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_atomic_write_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    atomic_write_bytes(tmp_path / "Release", b"x")
    assert [p.name for p in tmp_path.iterdir()] == ["Release"]


def test_a_failed_atomic_write_removes_its_temporary_file(tmp_path: Path) -> None:
    class Exploding(bytes):
        pass

    target = tmp_path / "Release"
    atomic_write_bytes(target, b"original")
    with pytest.raises(TypeError):
        atomic_write_bytes(target, "not bytes")  # type: ignore[arg-type]
    assert target.read_bytes() == b"original"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Release"]


def test_ensure_directory_overrides_the_umask(tmp_path: Path) -> None:
    """mkdir applies the umask; a 0755 tree the web server cannot read is useless."""
    previous = os.umask(0o077)
    try:
        created = ensure_directory(tmp_path / "pool")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(created.stat().st_mode) == 0o755


def test_open_exclusive_refuses_an_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "passphrase"
    target.write_text("first")
    with pytest.raises(FileExistsError):
        open_exclusive(target)


def test_harden_private_directory_creates_it_at_0700(tmp_path: Path) -> None:
    home = harden_private_directory(tmp_path / "gnupg")
    assert stat.S_IMODE(home.stat().st_mode) == 0o700


def test_harden_private_directory_tightens_a_world_readable_one(tmp_path: Path) -> None:
    """An existing keyring left group- or world-readable is fixed, not accepted."""
    home = tmp_path / "gnupg"
    home.mkdir()
    home.chmod(0o755)
    assert stat.S_IMODE(harden_private_directory(home).stat().st_mode) == 0o700


# ------------------------------------------------------------------ tree swaps


def test_atomic_replace_tree_swaps_a_complete_directory(tmp_path: Path) -> None:
    destination = tmp_path / "bookworm"
    ensure_directory(destination)
    (destination / "Release").write_text("old")

    staging = tmp_path / ".tmp.bookworm"
    ensure_directory(staging / "main")
    (staging / "Release").write_text("new")
    (staging / "main" / "Packages").write_text("stanza")

    atomic_replace_tree(staging, destination)
    assert (destination / "Release").read_text() == "new"
    assert (destination / "main" / "Packages").read_text() == "stanza"
    assert not staging.exists()


def test_atomic_replace_tree_works_when_there_is_no_previous_tree(tmp_path: Path) -> None:
    staging = ensure_directory(tmp_path / "staging")
    (staging / "Release").write_text("first")
    atomic_replace_tree(staging, tmp_path / "bookworm")
    assert (tmp_path / "bookworm" / "Release").read_text() == "first"


def test_remove_tree_refuses_a_path_outside_the_sandbox(allowed: Path, tmp_path: Path) -> None:
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "file").write_text("keep me")
    with pytest.raises(PathError):
        remove_tree(outside, [allowed])
    assert (outside / "file").exists()


def test_is_empty_directory(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert is_empty_directory(empty)
    (empty / "file").write_text("x")
    assert not is_empty_directory(empty)
