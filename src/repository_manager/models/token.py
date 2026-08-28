"""API tokens (specification.md 7.4, 9).

A token is a credential a machine holds, which makes it a different problem
from a session cookie even though both are opaque strings.  Three properties
follow from that and shape this module.

**It is stored as a hash and found by a prefix.**  The first characters of the
token are copied into their own indexed column so a lookup is one indexed read
rather than a scan comparing every row -- and the comparison that actually
decides the outcome is against the SHA-256, in constant time.  The prefix is
not treated as unique: two tokens sharing twelve characters is vanishingly
unlikely but not impossible, and a uniqueness constraint would turn that into
a failed mint rather than a second row the lookup already handles.

**It cannot outlive its owner's access.**  The row records the scopes granted
at mint time; what the token may actually do is those scopes intersected with
the owner's *current* role, resolved at request time (7.4).  Nothing here
caches a role, because a stored role is a permission that keeps working after
the directory says otherwise.

**It always expires.**  ``expires_at`` is NOT NULL.  A token with no expiry is
a credential nobody will ever revisit, and the one thing worse than a leaked
token is a leaked token that still works in three years.
"""

from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from repository_manager.models.auth import DN_LENGTH
from repository_manager.models.base import Base, UtcDateTime, utcnow

#: ``rmt`` for "repository manager token".  A distinctive fixed prefix is what
#: lets a secret scanner recognise one of these in a pushed file or a CI log.
TOKEN_PREFIX = "rmt_"  # noqa: S105 - a format marker, not a secret

#: 32 random bytes, per 7.4.  base64url without padding renders them as 43
#: characters, so a whole token is 47.
TOKEN_BYTES = 32

#: How much of the token is copied into the indexed lookup column.  Long enough
#: that a realistic deployment never hashes more than one candidate, short
#: enough that the column is not a meaningful fraction of the secret: it leaks
#: 48 bits of the 256, leaving 208 to guess.
TOKEN_PREFIX_LENGTH = len(TOKEN_PREFIX) + 8

#: Separator for the two list-valued columns.  Neither scopes nor slugs may
#: contain a comma, so no escaping is needed and none is implemented.
LIST_SEPARATOR = ","


class TokenScope(enum.StrEnum):
    """What a token may ask for (7.4).

    Deliberately coarse.  Scopes name the two things the REST API does -- read
    package data, change it -- rather than mirroring the role matrix, because a
    scope that could grant more than its owner's role would be a permission
    that exists only on paper: the intersection in :meth:`ApiToken.permits`
    would drop it every time.
    """

    PACKAGE_READ = "package:read"
    PACKAGE_WRITE = "package:write"

    @property
    def label(self) -> str:
        return {
            TokenScope.PACKAGE_READ: "Read packages",
            TokenScope.PACKAGE_WRITE: "Upload and remove packages",
        }[self]

    @property
    def description(self) -> str:
        return {
            TokenScope.PACKAGE_READ: (
                "List repositories and their packages. Everything this grants is already "
                "readable without any token at all, so it is only useful for confirming a "
                "token works."
            ),
            TokenScope.PACKAGE_WRITE: (
                "Upload packages, remove them, and request metadata regeneration. Needs the "
                "maintainer role on the account that owns the token."
            ),
        }[self]


def encode_scopes(scopes: frozenset[TokenScope] | set[TokenScope]) -> str:
    """Canonical stored form: sorted, comma-joined.

    Sorted so two tokens granted the same scopes store the same string, which
    makes the column comparable and the audit entries diffable.
    """
    return LIST_SEPARATOR.join(sorted(scope.value for scope in scopes))


def decode_scopes(stored: str) -> frozenset[TokenScope]:
    """Parse the stored form, dropping anything this version no longer knows.

    Silently dropping is the safe direction: an unrecognised scope can only be
    one a newer version granted, and treating it as a grant would be inventing
    a permission from a string.
    """
    known = {member.value for member in TokenScope}
    return frozenset(
        TokenScope(part) for part in stored.split(LIST_SEPARATOR) if part.strip() and part in known
    )


class ApiToken(Base):
    """One minted token (9)."""

    __tablename__ = "api_token"
    __table_args__ = (
        # The authentication path's only query.
        Index("ix_api_token_prefix", "prefix"),
        # The tokens page: one owner's tokens, newest first.
        Index("ix_api_token_owner_created", "owner_dn", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    #: The distinguished name of the account that minted it.  A DN rather than a
    #: foreign key to a session, for the same reason the audit log uses one:
    #: sessions come and go and the token outlives them.
    owner_dn: Mapped[str] = mapped_column(String(DN_LENGTH), index=True)
    #: What the owner typed at login, so the tokens page can show a name a person
    #: recognises next to a DN only the directory does.
    owner_username: Mapped[str] = mapped_column(String(255))
    #: The owner's own description of what this token is for.
    label: Mapped[str] = mapped_column(String(120))

    prefix: Mapped[str] = mapped_column(String(32))
    #: SHA-256 of the whole token.  A plain digest rather than a password hash,
    #: for the same reason as a session cookie: the input is 256 bits of system
    #: randomness, so there is no dictionary for a KDF to slow down, and a
    #: per-request derivation would cost real latency on every API call.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)

    #: Comma-joined :class:`TokenScope` values; see :func:`encode_scopes`.
    scopes: Mapped[str] = mapped_column(String(120), default="")
    #: Comma-joined repository slugs, or NULL for "every repository".  Slugs
    #: rather than ids because the API addresses repositories by slug and the
    #: check is against the slug in the path -- storing ids would mean a join on
    #: the one request path that should stay a single indexed read.  NULL and
    #: the empty string are not the same thing, so the column is never written
    #: empty: see :meth:`repositories`.
    repository_scope: Mapped[str | None] = mapped_column(Text, default=None)

    created_at: Mapped[dt.datetime] = mapped_column(UtcDateTime, default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(UtcDateTime)
    #: Written back at most once a minute per token; see the token service.
    last_used_at: Mapped[dt.datetime | None] = mapped_column(UtcDateTime, default=None)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(UtcDateTime, default=None)
    revoked_by: Mapped[str | None] = mapped_column(String(DN_LENGTH), default=None)

    # -- derived ----------------------------------------------------------

    @property
    def granted(self) -> frozenset[TokenScope]:
        return decode_scopes(self.scopes)

    @property
    def repositories(self) -> tuple[str, ...]:
        """The allow-list, empty when the token is not restricted."""
        if not self.repository_scope:
            return ()
        return tuple(
            part.strip() for part in self.repository_scope.split(LIST_SEPARATOR) if part.strip()
        )

    @property
    def unrestricted(self) -> bool:
        """Whether this token may act on any repository."""
        return not self.repositories

    def covers(self, slug: str) -> bool:
        """Whether ``slug`` is inside this token's repository allow-list (7.4)."""
        return self.unrestricted or slug in self.repositories

    def is_expired(self, *, now: dt.datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None

    def is_usable(self, *, now: dt.datetime | None = None) -> bool:
        """Whether the row itself is still live.

        Revoked and expired are one answer here on purpose (7.4): telling a
        caller *which* it was would confirm that a token it holds is a real one
        that used to work.
        """
        return not self.revoked and not self.is_expired(now=now)

    @property
    def state(self) -> str:
        """A word for the tokens page.  Not a security decision; a label."""
        if self.revoked:
            return "Revoked"
        if self.is_expired():
            return "Expired"
        return "Active"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ApiToken {self.id} {self.prefix}... {self.state.lower()}>"
