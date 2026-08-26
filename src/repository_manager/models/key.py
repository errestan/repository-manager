"""Signing keys (specification.md 9, 10.5).

The database holds only what is safe to lose: a name, a fingerprint, and the
*public* half in armoured form.  Private key material lives in the app-managed
GnuPG home and is never written here, never exported through the UI, and never
included in a backup of this table.
"""

from __future__ import annotations

import datetime as dt
import enum
import re
from typing import TYPE_CHECKING

from sqlalchemy import Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from repository_manager.models.base import Base, UtcDateTime, utcnow

if TYPE_CHECKING:  # pragma: no cover - resolved by SQLAlchemy at mapper configuration
    from repository_manager.models.repository import Repository

# Keys are addressed by name in URLs and in the exported filename inside the
# repository root, so the same narrow shape as a repository slug applies (10.2).
KEY_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
KEY_NAME_MAX_LENGTH = 64

# OpenPGP v4 fingerprints are 40 hex characters.  Stored uppercase so lookups
# and comparisons never depend on how a particular gpg version formatted them.
FINGERPRINT_PATTERN = re.compile(r"^[0-9A-F]{40}$")


class KeyAlgorithm(enum.StrEnum):
    """Offered key types (4.3).  RSA 4096 is the default for compatibility."""

    RSA4096 = "rsa4096"
    RSA3072 = "rsa3072"
    ED25519 = "ed25519"

    @property
    def label(self) -> str:
        return {
            KeyAlgorithm.RSA4096: "RSA 4096",
            KeyAlgorithm.RSA3072: "RSA 3072",
            KeyAlgorithm.ED25519: "Ed25519",
        }[self]


class SigningKey(Base):
    __tablename__ = "signing_key"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(KEY_NAME_MAX_LENGTH), unique=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    algorithm: Mapped[KeyAlgorithm] = mapped_column(
        Enum(KeyAlgorithm, native_enum=False, length=16, validate_strings=True)
    )
    uid: Mapped[str] = mapped_column(Text)
    public_key_armored: Mapped[str] = mapped_column(Text)

    # A *reference* to the passphrase, resolved at signing time (10.5) -- never
    # the passphrase itself.  NULL means the key has no passphrase.
    passphrase_ref: Mapped[str | None] = mapped_column(Text, default=None)

    created_at: Mapped[dt.datetime] = mapped_column(UtcDateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(Text, default=None)
    expires_at: Mapped[dt.datetime | None] = mapped_column(UtcDateTime, default=None)

    repositories: Mapped[list[Repository]] = relationship(back_populates="signing_key")

    @validates("name")
    def _check_name(self, _key: str, value: str) -> str:
        if not KEY_NAME_PATTERN.match(value or ""):
            raise ValueError(
                f"key name {value!r} must be lowercase letters, digits and hyphens, "
                "starting and ending with a letter or digit"
            )
        if len(value) > KEY_NAME_MAX_LENGTH:
            raise ValueError(f"key name must be at most {KEY_NAME_MAX_LENGTH} characters")
        return value

    @validates("fingerprint")
    def _check_fingerprint(self, _key: str, value: str) -> str:
        normalised = (value or "").replace(" ", "").upper()
        if not FINGERPRINT_PATTERN.match(normalised):
            raise ValueError(f"{value!r} is not a 40-character OpenPGP fingerprint")
        return normalised

    @property
    def short_id(self) -> str:
        """The last 16 hex digits, which is how gpg refers to a key in output."""
        return self.fingerprint[-16:]

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= utcnow()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SigningKey {self.name!r} {self.short_id}>"
