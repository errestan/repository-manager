"""Drive a real ``apt-get`` against a generated repository.

Everything apt touches is redirected into a temporary directory, so the test
never reads or writes the host's own apt state.  ``file://`` is used rather than
an HTTP server: it exercises exactly the same verification path -- signature
check, then hash check against Release -- without a socket to manage.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

APT_GET = shutil.which("apt-get")
APT_CACHE = shutil.which("apt-cache")


@dataclass(frozen=True)
class AptResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return f"{self.stdout}\n{self.stderr}"


class IsolatedApt:
    """An apt configuration rooted entirely inside ``base``."""

    def __init__(self, base: Path, repository_root: Path, key_file: Path) -> None:
        self.base = base
        self.repository_root = repository_root
        self.key_file = key_file
        self.sources = base / "etc" / "sources.list"

    def configure(self, codename: str, components: str, architecture: str = "amd64") -> None:
        """Write the sources.list line a user would be given (4.4)."""
        for directory in ("lists/partial", "cache/archives/partial", "etc"):
            (self.base / directory).mkdir(parents=True, exist_ok=True)
        (self.base / "status").write_text("")
        self.sources.write_text(
            f"deb [signed-by={self.key_file} arch={architecture}] "
            f"file://{self.repository_root} {codename} {components}\n"
        )

    def _options(self) -> list[str]:
        return [
            "-o", f"Dir::Etc::sourcelist={self.sources}",
            # /dev/null rather than a directory: the host's own sources must
            # never be pulled into the test.
            "-o", "Dir::Etc::sourceparts=/dev/null",
            "-o", "Dir::Etc::trustedparts=/dev/null",
            "-o", f"Dir::State={self.base}",
            "-o", f"Dir::State::lists={self.base}/lists",
            "-o", f"Dir::State::status={self.base}/status",
            "-o", f"Dir::Cache={self.base}/cache",
            "-o", f"Dir::Cache::archives={self.base}/cache/archives",
            "-o", "APT::Architecture=amd64",
            "-o", "Acquire::Languages=none",
        ]  # fmt: skip

    def _run(self, binary: str, *arguments: str) -> AptResult:
        # cwd is the isolated base, not wherever pytest was started: `apt-get
        # download` writes the .deb into the working directory, and a test has
        # no business leaving files in the checkout.
        completed = subprocess.run(
            [binary, *self._options(), *arguments],
            capture_output=True,
            text=True,
            check=False,
            cwd=self.base,
        )
        return AptResult(completed.returncode, completed.stdout, completed.stderr)

    def update(self) -> AptResult:
        """Fetch and verify the repository's metadata.

        The lists are cleared first so every call re-verifies from scratch
        rather than reporting a cached success.
        """
        assert APT_GET is not None
        shutil.rmtree(self.base / "lists", ignore_errors=True)
        (self.base / "lists" / "partial").mkdir(parents=True)
        return self._run(APT_GET, "update")

    def policy(self, package: str) -> AptResult:
        assert APT_CACHE is not None
        return self._run(APT_CACHE, "policy", package)

    def show(self, package: str) -> AptResult:
        assert APT_CACHE is not None
        return self._run(APT_CACHE, "show", package)

    def download(self, package: str) -> AptResult:
        """Fetch the .deb itself, which checks its hash against the index."""
        assert APT_GET is not None
        return self._run(APT_GET, "download", package)

    def downloaded(self) -> list[Path]:
        """Packages `download` placed in the working directory."""
        return sorted(self.base.glob("*.deb"))
