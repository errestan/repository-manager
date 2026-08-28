"""Drive a real ``dnf`` against a generated repository.

Everything dnf touches is redirected inside a temporary directory: its cache,
its configuration, and the installroot holding the rpm database it imports keys
into.  ``file://`` is used rather than an HTTP server, exactly as the apt client
does -- it exercises the same verification path without a socket to manage.

Two flavours of dnf are in circulation and this has to work with both: dnf4
(Python, ``libdnf``) and dnf5 (C++, ``libdnf5``).  Where they differ, the
options chosen here are the ones both accept.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DNF = shutil.which("dnf5") or shutil.which("dnf")
RPMBUILD = shutil.which("rpmbuild")
CREATEREPO = shutil.which("createrepo_c")

#: dnf refuses to run without one, and the repositories under test are not
#: keyed to a release, so any value will do as long as it is stable.
RELEASEVER = "9"


@dataclass(frozen=True)
class DnfResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return f"{self.stdout}\n{self.stderr}"


class IsolatedDnf:
    """A dnf configuration rooted entirely inside ``base``."""

    def __init__(self, base: Path, repository_root: Path, key_file: Path) -> None:
        self.base = base
        self.repository_root = repository_root
        self.key_file = key_file
        self.config = base / "dnf.conf"
        self.repos = base / "repos.d"
        self.installroot = base / "installroot"

    def configure(self, repo_id: str, variant: str, *, repo_gpgcheck: bool = True) -> None:
        """Write the ``.repo`` file a user would be given (4.4).

        ``gpgcheck=0`` while ``repo_gpgcheck`` stays on, because these fixtures
        are built by ``rpmbuild`` and are deliberately unsigned: the signature
        this application produces is the one over ``repomd.xml``, and that is
        what the test is here to verify.  Turning package signing on as well
        would prove something about ``rpmbuild``.
        """
        for directory in (self.repos, self.installroot, self.base / "cache"):
            directory.mkdir(parents=True, exist_ok=True)
        self.config.write_text(
            "[main]\n"
            "gpgcheck=0\n"
            "installonly_limit=0\n"
            "assumeyes=1\n"
            "plugins=0\n"
            f"cachedir={self.base / 'cache'}\n"
            f"reposdir={self.repos}\n"
        )
        (self.repos / f"{repo_id}.repo").write_text(
            f"[{repo_id}]\n"
            f"name={repo_id}\n"
            f"baseurl=file://{self.repository_root}/{variant}\n"
            "enabled=1\n"
            "gpgcheck=0\n"
            f"repo_gpgcheck={1 if repo_gpgcheck else 0}\n"
            f"gpgkey=file://{self.key_file}\n"
        )

    def _options(self) -> list[str]:
        return [
            f"--config={self.config}",
            f"--setopt=reposdir={self.repos}",
            f"--setopt=cachedir={self.base / 'cache'}",
            f"--installroot={self.installroot}",
            f"--releasever={RELEASEVER}",
            "--assumeyes",
            "--quiet",
        ]

    def _run(self, *arguments: str) -> DnfResult:
        assert DNF is not None
        completed = subprocess.run(
            [DNF, *self._options(), *arguments],
            capture_output=True,
            text=True,
            check=False,
            cwd=self.base,
        )
        return DnfResult(completed.returncode, completed.stdout, completed.stderr)

    def makecache(self) -> DnfResult:
        """Fetch and verify the repository's metadata.

        The cache is cleared first so every call re-verifies from scratch
        rather than reporting a cached success.
        """
        shutil.rmtree(self.base / "cache", ignore_errors=True)
        (self.base / "cache").mkdir(parents=True)
        return self._run("makecache", "--refresh")

    def repoquery(self, *arguments: str) -> DnfResult:
        return self._run("repoquery", *arguments)


def run_createrepo(directory: Path, *arguments: str) -> DnfResult:
    """Invoke the real ``createrepo_c``, for tests that need a control case."""
    assert CREATEREPO is not None
    completed = subprocess.run(
        [CREATEREPO, *arguments, str(directory)], capture_output=True, text=True, check=False
    )
    return DnfResult(completed.returncode, completed.stdout, completed.stderr)


SPEC_TEMPLATE = """\
Name:           {name}
Version:        {version}
Release:        {release}
Summary:        {summary}
License:        {license}
URL:            https://example.test/{name}
BuildArch:      {arch}
{extra}
%description
A package built by the integration suite to be indexed and installed.

%install
mkdir -p %{{buildroot}}/usr/share/{name}
echo "{name} {version}-{release}" > %{{buildroot}}/usr/share/{name}/README

%files
%dir /usr/share/{name}
/usr/share/{name}/README

%changelog
* Mon Jan 01 2024 Integration Suite <suite@example.test> - {version}-{release}
- Built for a test.
"""


def build_rpm(
    workspace: Path,
    *,
    name: str,
    version: str,
    release: str,
    arch: str = "x86_64",
    epoch: int | None = None,
    summary: str = "A package for the integration suite",
    licence: str = "GPL-3.0-or-later",
) -> Path:
    """Build a real ``.rpm`` with ``rpmbuild`` and return its path.

    The unit suite builds its own RPMs in pure Python
    (:mod:`tests.support.rpms`), which is right for testing the *reader* and
    wrong here.  A generated index is only worth as much as the packages behind
    it, and packages produced by the same project that is being tested would
    make this a test of self-consistency rather than of format correctness.
    """
    assert RPMBUILD is not None
    extra = f"Epoch:          {epoch}\n" if epoch is not None else ""
    spec = workspace / "SPECS" / f"{name}.spec"
    spec.parent.mkdir(parents=True, exist_ok=True)
    spec.write_text(
        SPEC_TEMPLATE.format(
            name=name,
            version=version,
            release=release,
            arch=arch,
            summary=summary,
            license=licence,
            extra=extra,
        )
    )

    command = [RPMBUILD, "-bb", f"--define=_topdir {workspace}"]
    if arch != "noarch":
        # The build target defaults to the host's architecture, which would
        # silently retag an aarch64 fixture as x86_64 on CI.  `noarch` is left
        # alone: `BuildArch` already settles it, and naming it as a target is
        # not something every rpm release accepts.
        command.append(f"--target={arch}")
    command.append(str(spec))

    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(f"rpmbuild failed:\n{completed.stdout}\n{completed.stderr}")

    built = sorted((workspace / "RPMS").rglob(f"{name}-{version}-{release}.{arch}.rpm"))
    if not built:
        raise AssertionError(
            f"rpmbuild produced no {name}-{version}-{release}.{arch}.rpm:\n{completed.stdout}"
        )
    return built[0]
