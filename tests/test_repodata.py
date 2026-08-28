"""Driving ``createrepo_c`` and signing what it produces (specification.md 4.2).

These tests run against the stand-in binary from ``conftest``, not the real
tool.  What is under test here is this application's half of the arrangement --
the arguments, the working directory, the failure handling and the signature.
Whether ``createrepo_c`` emits valid metadata is proved against the real binary
and a real ``dnf`` in ``tests/integration/test_dnf_client.py``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from repository_manager.metadata import repodata
from tests.conftest import FakeCreaterepo
from tests.support.rpms import build_simple


class RecordingSigner:
    """A signer that records what it was asked to sign."""

    def __init__(self, *, fail: bool = False) -> None:
        self.payloads: list[bytes] = []
        self.fail = fail

    def detach_sign(self, data: bytes) -> bytes:
        self.payloads.append(data)
        if self.fail:
            raise RuntimeError("the agent is not running")
        return b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n"


EL9 = repodata.VariantPlan(name="el9", arch="x86_64")


# ------------------------------------------------------------------ validation


@pytest.mark.parametrize(
    "name",
    ["..", ".", "", "el9/x86_64", "el9\\x86_64", "../../etc", "-leading", "with space"],
)
def test_a_variant_name_that_could_leave_the_root_is_refused(name: str) -> None:
    """These become directory names, so the grammar is narrow on purpose (10.4)."""
    with pytest.raises(repodata.RepodataError):
        repodata.VariantPlan(name=name, arch="x86_64")


@pytest.mark.parametrize("arch", ["..", "", "x86_64/../.."])
def test_a_variant_architecture_is_validated_the_same_way(arch: str) -> None:
    with pytest.raises(repodata.RepodataError):
        repodata.VariantPlan(name="el9", arch=arch)


def test_a_variant_knows_its_own_path_and_directories(tmp_path: Path) -> None:
    assert EL9.path == "el9/x86_64"
    assert EL9.directory(tmp_path) == tmp_path / "el9" / "x86_64"
    assert EL9.packages_directory(tmp_path) == tmp_path / "el9" / "x86_64" / "Packages"


def test_the_public_key_uses_the_name_every_distribution_expects() -> None:
    """``gpgkey=`` lines in the wild all point at this filename (4.2)."""
    assert repodata.public_key_filename("internal") == "RPM-GPG-KEY-internal"


def test_a_missing_binary_names_the_package_to_install(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator can act on this; a FileNotFoundError in a job log they cannot."""
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(repodata.RepodataError, match="createrepo-c"):
        repodata.resolve_binary()


def test_an_absolute_binary_path_that_does_not_exist_is_reported(tmp_path: Path) -> None:
    with pytest.raises(repodata.RepodataError, match="does not exist"):
        repodata.resolve_binary(str(tmp_path / "nowhere" / "createrepo_c"))


# ------------------------------------------------------------------- skeleton


def test_the_skeleton_creates_a_packages_directory_per_variant(tmp_path: Path) -> None:
    plan = repodata.RepositoryPlan(variants=(EL9, repodata.VariantPlan(name="el8", arch="aarch64")))
    repodata.create_skeleton(tmp_path, plan)

    assert (tmp_path / "el9" / "x86_64" / "Packages").is_dir()
    assert (tmp_path / "el8" / "aarch64" / "Packages").is_dir()


# ----------------------------------------------------------------- generation


def test_a_variant_is_indexed_in_place_and_its_repomd_signed(
    tmp_path: Path, fake_createrepo: FakeCreaterepo
) -> None:
    repodata.create_skeleton(tmp_path, repodata.RepositoryPlan(variants=(EL9,)))
    build_simple(tmp_path / "el9" / "x86_64" / "Packages" / "example-1.0-1.el9.x86_64.rpm")
    signer = RecordingSigner()

    result = repodata.generate_variant(tmp_path, EL9, signer=signer)

    assert result == repodata.VariantResult(variant="el9/x86_64", packages=1, signed=True)
    signature = tmp_path / "el9" / "x86_64" / "repodata" / "repomd.xml.asc"
    assert signature.is_file()
    assert signature.read_bytes().startswith(b"-----BEGIN PGP SIGNATURE-----")


def test_the_signature_is_over_the_repomd_that_was_actually_written(
    tmp_path: Path, fake_createrepo: FakeCreaterepo
) -> None:
    """Signing anything else would produce a signature clients read as tampering."""
    repodata.create_skeleton(tmp_path, repodata.RepositoryPlan(variants=(EL9,)))
    signer = RecordingSigner()

    repodata.generate_variant(tmp_path, EL9, signer=signer)

    repomd = (tmp_path / "el9" / "x86_64" / "repodata" / "repomd.xml").read_bytes()
    assert repomd in signer.payloads


def test_createrepo_is_invoked_in_the_variant_directory_with_pinned_options(
    tmp_path: Path, fake_createrepo: FakeCreaterepo
) -> None:
    """The on-disk layout in 4.2 is a contract, so the compression is not left to a default."""
    repodata.create_skeleton(tmp_path, repodata.RepositoryPlan(variants=(EL9,)))

    repodata.generate_variant(tmp_path, EL9, signer=RecordingSigner())

    (invocation,) = fake_createrepo.invocations
    assert invocation[-1] == str(tmp_path / "el9" / "x86_64")
    assert "--update" in invocation
    assert "--no-database" in invocation
    assert "--general-compress-type=gz" in invocation


def test_a_failing_createrepo_reports_its_own_words(
    tmp_path: Path, failing_createrepo: FakeCreaterepo
) -> None:
    """A job log saying "exit 1" helps nobody; the tool's stderr does."""
    directory = EL9.directory(tmp_path)
    directory.mkdir(parents=True)

    with pytest.raises(repodata.RepodataError, match="refusing, as this test asked it to"):
        repodata.run_createrepo(directory)


def test_a_broken_signer_stops_before_createrepo_runs(
    tmp_path: Path, fake_createrepo: FakeCreaterepo
) -> None:
    """The one ordering that matters (4.2).

    If createrepo_c ran first, a signing failure would leave fresh metadata
    under the previous signature -- which every client reads as tampering, and
    which no later run can undo because the old metadata is gone.  Failing on a
    throwaway signature first turns that into a job that failed having touched
    nothing.
    """
    repodata.create_skeleton(tmp_path, repodata.RepositoryPlan(variants=(EL9,)))

    with pytest.raises(RuntimeError, match="agent is not running"):
        repodata.generate_variant(tmp_path, EL9, signer=RecordingSigner(fail=True))

    assert fake_createrepo.invocations == []
    assert not (tmp_path / "el9" / "x86_64" / "repodata").exists()


def test_a_missing_repomd_is_reported_rather_than_signed(tmp_path: Path) -> None:
    EL9.directory(tmp_path).mkdir(parents=True)
    with pytest.raises(repodata.RepodataError, match="nothing to sign"):
        repodata.sign_repomd(tmp_path, EL9, RecordingSigner())


def test_every_variant_is_regenerated_and_reported_separately(
    tmp_path: Path, fake_createrepo: FakeCreaterepo
) -> None:
    el8 = repodata.VariantPlan(name="el8", arch="aarch64")
    plan = repodata.RepositoryPlan(variants=(EL9, el8))
    repodata.create_skeleton(tmp_path, plan)
    build_simple(tmp_path / "el9" / "x86_64" / "Packages" / "a-1.0-1.el9.x86_64.rpm")

    results = repodata.generate(tmp_path, plan, signer=RecordingSigner())

    assert set(results) == {"el9/x86_64", "el8/aarch64"}
    assert results["el9/x86_64"].packages == 1
    assert results["el8/aarch64"].packages == 0
    # One invocation per variant: they are independent trees with independent
    # repodata, and a rebuild of one is never a rebuild of the other.
    assert len(fake_createrepo.invocations) == 2


def test_an_empty_variant_still_gets_signed_metadata(
    tmp_path: Path, fake_createrepo: FakeCreaterepo
) -> None:
    """A new repository must be addable before anything is uploaded (4.3)."""
    plan = repodata.RepositoryPlan(variants=(EL9,))
    repodata.create_skeleton(tmp_path, plan)

    repodata.generate(tmp_path, plan, signer=RecordingSigner())

    assert (tmp_path / "el9" / "x86_64" / "repodata" / "repomd.xml").is_file()
    assert (tmp_path / "el9" / "x86_64" / "repodata" / "repomd.xml.asc").is_file()


def test_only_rpm_files_are_counted(tmp_path: Path, fake_createrepo: FakeCreaterepo) -> None:
    packages = EL9.packages_directory(tmp_path)
    packages.mkdir(parents=True)
    build_simple(packages / "a-1.0-1.el9.x86_64.rpm")
    (packages / "README.txt").write_text("not a package\n")

    assert repodata.count_packages(EL9.directory(tmp_path)) == 1


def test_an_absolute_binary_path_is_used_as_given(
    tmp_path: Path, fake_createrepo: FakeCreaterepo
) -> None:
    """An operator who keeps the tool outside PATH is not forced to symlink it."""
    assert repodata.resolve_binary(str(fake_createrepo.binary)) == str(fake_createrepo.binary)


def test_a_variant_with_no_packages_directory_counts_nothing(tmp_path: Path) -> None:
    assert repodata.count_packages(tmp_path / "el9" / "x86_64") == 0


def test_a_wedged_createrepo_is_killed_rather_than_waited_on_forever(
    tmp_path: Path, fake_createrepo: FakeCreaterepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A subprocess that never returns would hold the repository lock for good (5.4)."""
    import subprocess

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="createrepo_c", timeout=1.0)

    monkeypatch.setattr(subprocess, "run", timeout)
    directory = EL9.directory(tmp_path)
    directory.mkdir(parents=True)

    with pytest.raises(repodata.RepodataError, match="did not finish within"):
        repodata.run_createrepo(directory)


def test_a_configured_binary_that_cannot_be_executed_is_reported(
    tmp_path: Path, fake_createrepo: FakeCreaterepo
) -> None:
    """A path given outright is only checked for existence, so exec can still fail.

    ``shutil.which`` refuses a file with no execute bit and reports it as not
    installed, which is fair enough; an absolute path skips that lookup, so this
    is the route by which a lost execute bit actually reaches ``subprocess``.
    """
    fake_createrepo.binary.chmod(0o644)
    directory = EL9.directory(tmp_path)
    directory.mkdir(parents=True)

    with pytest.raises(repodata.RepodataError, match="could not be run"):
        repodata.run_createrepo(directory, binary=str(fake_createrepo.binary))
