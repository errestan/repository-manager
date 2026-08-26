"""Build ``.deb`` files in pure Python, for tests.

``dpkg-deb`` is deliberately not used here.  Unit tests must run on any machine
-- including the macOS and Fedora developer boxes that have no Debian tooling
-- and on this project's own CI, where the Debian tools are installed *only* in
the integration job.  Building the archive ourselves also removes a real
portability trap: dpkg on some distributions now compresses members with zstd,
which python-debian can only read by shelling out to ``unzstd``.

The format is three ar members in a fixed order (Debian Policy, deb(5)):
``debian-binary``, ``control.tar.gz``, ``data.tar.gz``.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

AR_MAGIC = b"!<arch>\n"
AR_HEADER_TERMINATOR = b"`\n"

# Fixed timestamp so a package built twice is byte-identical, which lets tests
# assert on digests without re-deriving them.
FIXED_MTIME = 1_700_000_000


def _ar_member(name: str, data: bytes, mtime: int = FIXED_MTIME) -> bytes:
    """One ar member: a 60-byte fixed-width header, the data, then even padding."""
    header = (
        f"{name:<16}"
        f"{mtime:<12}"
        f"{0:<6}"  # uid
        f"{0:<6}"  # gid
        f"{0o100644:<8o}"
        f"{len(data):<10}"
    ).encode("ascii") + AR_HEADER_TERMINATOR
    padding = b"\n" if len(data) % 2 else b""
    return header + data + padding


def _tar_gz(entries: Mapping[str, bytes], *, directories: tuple[str, ...] = ()) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name in directories:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = FIXED_MTIME
            archive.addfile(info)
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            info.mtime = FIXED_MTIME
            archive.addfile(info, io.BytesIO(content))
    return gzip.compress(raw.getvalue(), mtime=0)


@dataclass
class DebSpec:
    """The parts of a package a test actually cares about."""

    name: str = "example"
    version: str = "1.0-1"
    architecture: str = "amd64"
    maintainer: str = "Test Maintainer <maintainer@example.test>"
    description: str = "an example package\n A slightly longer description.\n .\n With a gap."
    section: str = "utils"
    priority: str = "optional"
    source: str | None = None
    depends: str | None = None
    homepage: str | None = None
    extra_control: Mapping[str, str] = field(default_factory=dict)
    # Payload contents, keyed by path inside the package.
    payload: Mapping[str, bytes] = field(default_factory=dict)
    # Replaces the generated control file wholesale, for tests that need a
    # malformed one.  Patching the built archive is not an option: the control
    # file lives inside a gzipped tar, so the fields are not present as plain
    # bytes to edit.
    control_override: str | None = None

    def control_text(self) -> str:
        if self.control_override is not None:
            return self.control_override
        return self._generated_control()

    def _generated_control(self) -> str:
        fields: dict[str, str] = {
            "Package": self.name,
            "Version": self.version,
            "Architecture": self.architecture,
            "Maintainer": self.maintainer,
            "Section": self.section,
            "Priority": self.priority,
        }
        if self.source:
            fields["Source"] = self.source
        if self.depends:
            fields["Depends"] = self.depends
        if self.homepage:
            fields["Homepage"] = self.homepage
        fields.update(self.extra_control)
        # Installed-Size is what apt uses to predict disk usage; a real package
        # always has one, so the fixtures do too.
        payload_bytes = sum(len(content) for content in self.effective_payload().values())
        fields["Installed-Size"] = str(max(1, payload_bytes // 1024))
        # Description last: it is the only multi-line field, and trailing fields
        # after a folded one are a common source of malformed control files.
        fields["Description"] = self.description
        return "".join(f"{key}: {value}\n" for key, value in fields.items())

    def effective_payload(self) -> Mapping[str, bytes]:
        if self.payload:
            return self.payload
        return {
            f"./usr/share/doc/{self.name}/README": (
                f"{self.name} {self.version} for {self.architecture}\n".encode()
            )
        }


def build_deb(spec: DebSpec, destination: Path) -> Path:
    """Write ``spec`` as a ``.deb`` at ``destination`` and return the path."""
    control = _tar_gz({"./control": spec.control_text().encode("utf-8")}, directories=("./",))
    data = _tar_gz(spec.effective_payload(), directories=("./",))

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(
        AR_MAGIC
        + _ar_member("debian-binary", b"2.0\n")
        + _ar_member("control.tar.gz", control)
        + _ar_member("data.tar.gz", data)
    )
    return destination


def build_simple(
    destination: Path,
    *,
    name: str = "example",
    version: str = "1.0-1",
    architecture: str = "amd64",
    **kwargs: object,
) -> Path:
    """Convenience wrapper for the common "one small package" case."""
    spec = DebSpec(name=name, version=version, architecture=architecture, **kwargs)  # type: ignore[arg-type]
    return build_deb(spec, destination)


def elapsed() -> float:  # pragma: no cover - used only when debugging slow tests
    return time.monotonic()
