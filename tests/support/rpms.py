"""Build ``.rpm`` files in pure Python, for unit tests.

``rpmbuild`` is deliberately not used here, for the same reason
:mod:`tests.support.debs` does not use ``dpkg-deb``: the unit suite has to run
on a developer's machine with no RPM tooling at all, and on this project's own
CI where the RPM tools are installed *only* in the integration job.

The scope of this builder is exactly what
:func:`repository_manager.metadata.rpm.read_rpm` needs -- a valid lead, a
signature header, a main header and a gzipped cpio payload.  It is a fixture,
not an implementation of ``rpmbuild``: nothing here computes real digests or
signatures, and the packages it produces are never fed to ``createrepo_c`` or
``dnf``.  Those get packages from a real ``rpmbuild`` in the integration job,
because proving that generated metadata is valid is worth nothing if the
packages behind it were hand-rolled by the same code under test.

Layout, per the RPM file format: a 96-byte lead, the signature header padded to
an eight-byte boundary, the main header, then the payload.
"""

from __future__ import annotations

import gzip
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

RPM_MAGIC = b"\xed\xab\xee\xdb"
HEADER_MAGIC = b"\x8e\xad\xe8"
HEADER_VERSION = 1

LEAD_STRUCT = struct.Struct("!4sBBhh66shh16s")
ENTRY_STRUCT = struct.Struct("!iiii")

LEAD_TYPE_BINARY = 0
LEAD_TYPE_SOURCE = 1
#: ``RPMSIGTYPE_HEADERSIG`` -- the only signature type in use since rpm 3.
LEAD_SIGNATURE_TYPE = 5
LEAD_OS_LINUX = 1

# Header entry types, from rpm's `rpmTagType`.
TYPE_INT16 = 3
TYPE_INT32 = 4
TYPE_STRING = 6
TYPE_BIN = 7
TYPE_STRING_ARRAY = 8
TYPE_I18NSTRING = 9

#: Integer entries are aligned in the data store; strings and blobs are not.
ALIGNMENT = {TYPE_INT16: 2, TYPE_INT32: 4}

#: The region tags that open each header.  A real header starts with one, and
#: writing them keeps these fixtures shaped like the thing they stand in for.
REGION_SIGNATURE = 62  # HEADER_SIGNATURES
REGION_IMMUTABLE = 63  # HEADERIMMUTABLE
REGION_TRAILER_SIZE = 16

# The main-header tags this builder can write, by name.
TAGS = {
    "name": 1000,
    "version": 1001,
    "release": 1002,
    "epoch": 1003,
    "summary": 1004,
    "description": 1005,
    "buildtime": 1006,
    "buildhost": 1007,
    "size": 1009,
    "license": 1014,
    "packager": 1015,
    "group": 1016,
    "url": 1020,
    "os": 1021,
    "arch": 1022,
    "sourcerpm": 1044,
    "archivesize": 1046,
    "sourcepackage": 1106,
    "archive_format": 1124,
    "archive_compression": 1125,
    "vendor": 1011,
    "rpmversion": 1064,
}

#: Fixed so a package built twice is byte-identical, which lets tests assert on
#: digests without re-deriving them.
FIXED_BUILDTIME = 1_700_000_000


@dataclass(frozen=True)
class Entry:
    tag: int
    type: int
    data: bytes
    count: int


def _string(tag: int, value: str, *, i18n: bool = False) -> Entry:
    encoded = value.encode("utf-8") + b"\x00"
    return Entry(tag=tag, type=TYPE_I18NSTRING if i18n else TYPE_STRING, data=encoded, count=1)


def _int32(tag: int, *values: int) -> Entry:
    return Entry(
        tag=tag,
        type=TYPE_INT32,
        data=struct.pack(f"!{len(values)}I", *values),
        count=len(values),
    )


def _binary(tag: int, value: bytes) -> Entry:
    return Entry(tag=tag, type=TYPE_BIN, data=value, count=len(value))


def _string_array(tag: int, values: Sequence[str]) -> Entry:
    data = b"".join(value.encode("utf-8") + b"\x00" for value in values)
    return Entry(tag=tag, type=TYPE_STRING_ARRAY, data=data, count=len(values))


def build_header(entries: Sequence[Entry], region_tag: int) -> bytes:
    """Encode one header structure: preamble, index entries, then the store.

    The region entry is index 0 and its 16-byte trailer sits at the end of the
    store, with a negative offset back to the start of the index -- which is
    how rpm marks where an immutable region begins and ends.
    """
    store = bytearray()
    index: list[tuple[int, int, int, int]] = []
    for entry in entries:
        alignment = ALIGNMENT.get(entry.type, 1)
        while len(store) % alignment:
            store.append(0)
        index.append((entry.tag, entry.type, len(store), entry.count))
        store.extend(entry.data)

    entry_count = len(index) + 1
    trailer_offset = len(store)
    store.extend(
        ENTRY_STRUCT.pack(
            region_tag, TYPE_BIN, -(entry_count * ENTRY_STRUCT.size), REGION_TRAILER_SIZE
        )
    )

    encoded_index = ENTRY_STRUCT.pack(region_tag, TYPE_BIN, trailer_offset, REGION_TRAILER_SIZE)
    encoded_index += b"".join(ENTRY_STRUCT.pack(*row) for row in index)

    return (
        HEADER_MAGIC
        + bytes([HEADER_VERSION])
        + b"\x00\x00\x00\x00"
        + struct.pack("!ii", entry_count, len(store))
        + encoded_index
        + bytes(store)
    )


def build_lead(label: str, *, package_type: int = LEAD_TYPE_BINARY) -> bytes:
    return LEAD_STRUCT.pack(
        RPM_MAGIC,
        3,  # major
        0,  # minor
        package_type,
        1,  # architecture number; advisory only, and ignored by every reader
        label.encode("utf-8")[:65].ljust(66, b"\x00"),
        LEAD_OS_LINUX,
        LEAD_SIGNATURE_TYPE,
        b"\x00" * 16,
    )


def _cpio_entry(name: str, data: bytes, *, mode: int = 0o100644) -> bytes:
    """One "new ASCII" (070701) cpio member, with its 4-byte padding."""
    encoded = name.encode("utf-8") + b"\x00"
    header = b"070701" + b"".join(
        f"{value:08X}".encode("ascii")
        for value in (
            0,  # inode
            mode,
            0,  # uid
            0,  # gid
            1,  # nlink
            FIXED_BUILDTIME,
            len(data),
            0,  # devmajor
            0,  # devminor
            0,  # rdevmajor
            0,  # rdevminor
            len(encoded),
            0,  # check
        )
    )
    member = header + encoded
    member += b"\x00" * (-len(member) % 4)
    member += data
    member += b"\x00" * (-len(member) % 4)
    return member


def build_payload(files: Mapping[str, bytes]) -> bytes:
    archive = b"".join(_cpio_entry(name, content) for name, content in files.items())
    archive += _cpio_entry("TRAILER!!!", b"", mode=0)
    # mtime=0 so the same inputs produce the same bytes.
    return gzip.compress(archive, mtime=0)


@dataclass
class RpmSpec:
    """The parts of a package a test actually cares about."""

    name: str = "example"
    version: str = "1.0"
    release: str = "1.el9"
    architecture: str = "x86_64"
    epoch: int | None = None
    summary: str = "An example package"
    description: str = "A slightly longer description of the example package."
    license: str = "GPL-3.0-or-later"
    url: str | None = "https://example.test/example"
    vendor: str | None = "Test Vendor"
    group: str = "Applications/System"
    #: ``None`` builds a source package -- no SOURCERPM tag and a source lead.
    source_rpm: str | None = ""
    payload: Mapping[str, bytes] = field(default_factory=dict)
    #: Replaces or adds raw entries, for tests that need a malformed header.
    extra_entries: Sequence[Entry] = ()
    #: Overrides the tags written from the fields above, by tag name.
    omit: frozenset[str] = frozenset()

    @property
    def is_source(self) -> bool:
        return self.source_rpm is None

    @property
    def label(self) -> str:
        return f"{self.name}-{self.version}-{self.release}"

    @property
    def filename(self) -> str:
        suffix = "src" if self.is_source else self.architecture
        return f"{self.label}.{suffix}.rpm"

    def effective_payload(self) -> Mapping[str, bytes]:
        if self.payload:
            return self.payload
        return {
            f"./usr/share/doc/{self.name}/README": (
                f"{self.name} {self.version}-{self.release} for {self.architecture}\n".encode()
            )
        }

    def entries(self) -> list[Entry]:
        payload = self.effective_payload()
        installed = sum(len(content) for content in payload.values())

        entries: list[Entry] = []

        def add(name: str, entry: Entry) -> None:
            if name not in self.omit:
                entries.append(entry)

        add("name", _string(TAGS["name"], self.name))
        add("version", _string(TAGS["version"], self.version))
        add("release", _string(TAGS["release"], self.release))
        add("arch", _string(TAGS["arch"], "src" if self.is_source else self.architecture))
        add("os", _string(TAGS["os"], "linux"))
        add("summary", _string(TAGS["summary"], self.summary, i18n=True))
        add("description", _string(TAGS["description"], self.description, i18n=True))
        add("license", _string(TAGS["license"], self.license))
        add("group", _string(TAGS["group"], self.group, i18n=True))
        add("rpmversion", _string(TAGS["rpmversion"], "4.19.1"))
        add("buildhost", _string(TAGS["buildhost"], "builder.example.test"))
        add("archive_format", _string(TAGS["archive_format"], "cpio"))
        add("archive_compression", _string(TAGS["archive_compression"], "gzip"))
        if self.url:
            add("url", _string(TAGS["url"], self.url))
        if self.vendor:
            add("vendor", _string(TAGS["vendor"], self.vendor))
        if self.epoch is not None:
            add("epoch", _int32(TAGS["epoch"], self.epoch))
        add("buildtime", _int32(TAGS["buildtime"], FIXED_BUILDTIME))
        add("size", _int32(TAGS["size"], installed))

        if self.is_source:
            # rpm marks a source package by the presence of this tag and the
            # absence of SOURCERPM; the value carried is irrelevant.
            add("sourcepackage", _int32(TAGS["sourcepackage"], 1))
        else:
            add(
                "sourcerpm",
                _string(TAGS["sourcerpm"], self.source_rpm or f"{self.label}.src.rpm"),
            )

        entries.extend(self.extra_entries)
        # rpm requires the index to be ordered by tag, and readers that binary
        # search it will silently miss entries that are not.
        return sorted(entries, key=lambda entry: entry.tag)


def build_rpm(spec: RpmSpec, destination: Path) -> Path:
    """Write ``spec`` as an ``.rpm`` at ``destination`` and return the path."""
    payload = build_payload(spec.effective_payload())
    header = build_header(spec.entries(), REGION_IMMUTABLE)

    # A real signature header carries the digests and signatures of everything
    # that follows.  These fixtures are never verified, so it holds only the
    # payload size -- but it has to be present and correctly padded, because
    # the main header's position is defined relative to its end.
    signature = build_header(
        [_binary(1000, struct.pack("!I", len(header) + len(payload)))], REGION_SIGNATURE
    )
    signature += b"\x00" * (-len(signature) % 8)

    lead_type = LEAD_TYPE_SOURCE if spec.is_source else LEAD_TYPE_BINARY
    destination.parent.mkdir(parents=True, exist_ok=True)
    lead = build_lead(spec.label, package_type=lead_type)
    destination.write_bytes(lead + signature + header + payload)
    return destination


def build_simple(
    destination: Path,
    *,
    name: str = "example",
    version: str = "1.0",
    release: str = "1.el9",
    architecture: str = "x86_64",
    **kwargs: object,
) -> Path:
    """Convenience wrapper for the common "one small package" case."""
    spec = RpmSpec(
        name=name,
        version=version,
        release=release,
        architecture=architecture,
        **kwargs,  # type: ignore[arg-type]
    )
    return build_rpm(spec, destination)
