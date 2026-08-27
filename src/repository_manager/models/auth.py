"""Sessions, roles and the audit trail (specification.md 3, 7.2, 9).

Two properties shape this module.

Sessions are *server-side*: the cookie is an opaque random string and every
fact about the session -- who it belongs to, what role it carries, when it
expires -- lives in a row, so revoking one is a database write rather than a
hope that a signed token expires soon.  The row stores a hash of the cookie,
not the cookie: a leaked database dump, a backup, or a stray ``SELECT *`` in a
log should not hand anyone a live session.

The audit log is *append-only*.  There is no update path and no delete path in
the application at all -- not a permission check that could be got around, an
absence of code.
"""

from __future__ import annotations

import datetime as dt
import enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from repository_manager.models.base import Base, UtcDateTime, utcnow

if TYPE_CHECKING:  # pragma: no cover - resolved by SQLAlchemy at mapper configuration
    from repository_manager.models.repository import Repository

# Long enough for any real distinguished name; PostgreSQL needs a length and
# SQLite ignores it.
DN_LENGTH = 512


class Role(enum.StrEnum):
    """What a signed-in user may do (3).

    Ordered deliberately: ``admin`` is a strict superset of ``maintainer``, so
    ``permits`` can be a comparison rather than a table anybody has to keep in
    step with the permission matrix.
    """

    MAINTAINER = "maintainer"
    ADMIN = "admin"

    @property
    def label(self) -> str:
        return self.value.capitalize()

    @property
    def _rank(self) -> int:
        return {Role.MAINTAINER: 1, Role.ADMIN: 2}[self]

    def permits(self, required: Role) -> bool:
        """Whether this role satisfies a requirement for ``required``."""
        return self._rank >= required._rank


class ActorType(enum.StrEnum):
    USER = "user"
    #: An API token acting on its owner's behalf (M5).  The literal is the name
    #: of a credential kind, not a credential.
    TOKEN = "token"  # noqa: S105
    #: The application acting on its own behalf, e.g. restart recovery re-queuing
    #: a job nobody asked for a second time.
    SYSTEM = "system"

    @property
    def label(self) -> str:
        return self.value.capitalize()


class AuditOutcome(enum.StrEnum):
    SUCCESS = "success"
    #: The action was attempted and did not work -- a bad password, a rejected
    #: upload.  Distinct from DENIED, which is a permission refusal.
    FAILURE = "failure"
    DENIED = "denied"

    @property
    def label(self) -> str:
        return self.value.capitalize()


class AuditAction(enum.StrEnum):
    """Every recordable action.

    A closed set rather than free text: the audit page filters on it, and a
    typo in a string literal would silently create a category nobody looks at.
    """

    LOGIN = "login"
    LOGOUT = "logout"
    SESSION_REVALIDATED = "session_revalidated"
    REPOSITORY_CREATE = "repository_create"
    DISTRIBUTION_ADD = "distribution_add"
    KEY_GENERATE = "key_generate"
    KEY_IMPORT = "key_import"
    KEY_DELETE = "key_delete"
    PACKAGE_UPLOAD = "package_upload"
    PACKAGE_REMOVE = "package_remove"
    REGENERATE = "regenerate"

    @property
    def label(self) -> str:
        return {
            AuditAction.LOGIN: "Sign in",
            AuditAction.LOGOUT: "Sign out",
            AuditAction.SESSION_REVALIDATED: "Session revalidated",
            AuditAction.REPOSITORY_CREATE: "Create repository",
            AuditAction.DISTRIBUTION_ADD: "Add distribution",
            AuditAction.KEY_GENERATE: "Generate signing key",
            AuditAction.KEY_IMPORT: "Import signing key",
            AuditAction.KEY_DELETE: "Delete signing key",
            AuditAction.PACKAGE_UPLOAD: "Upload package",
            AuditAction.PACKAGE_REMOVE: "Remove package",
            AuditAction.REGENERATE: "Regenerate metadata",
        }[self]


class UserSession(Base):
    """One signed-in browser session (7.2).

    Named ``UserSession`` rather than ``Session`` because the table is called
    ``session`` but the name ``Session`` already means a SQLAlchemy session
    everywhere else in this codebase, and confusing the two in a permission
    check is not a mistake worth leaving available.
    """

    __tablename__ = "session"
    __table_args__ = (
        # Expiry sweeps scan on this and nothing else.
        Index("ix_session_expires_at", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    #: SHA-256 of the cookie value.  The cookie itself is never stored, so this
    #: column cannot be replayed as a credential.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)

    user_dn: Mapped[str] = mapped_column(String(DN_LENGTH), index=True)
    #: The name typed at the login form, kept for the audit trail: it is what a
    #: person recognises, whereas the DN is what the directory recognises.
    username: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(
        Enum(Role, native_enum=False, length=16, validate_strings=True)
    )

    #: Per-session CSRF secret (7.3).  Unlike the session token this is meant to
    #: be readable by the server and echoed into forms, so it is stored as-is.
    csrf_secret: Mapped[str] = mapped_column(String(64))

    created_at: Mapped[dt.datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(UtcDateTime, default=utcnow)
    #: Absolute lifetime.  The idle timeout is applied against ``last_seen_at``
    #: at request time; this column is the ceiling neither can exceed.
    expires_at: Mapped[dt.datetime] = mapped_column(UtcDateTime)
    #: When group membership must next be re-checked against the directory, so
    #: revoked access takes effect without waiting for the session to expire.
    revalidate_after: Mapped[dt.datetime] = mapped_column(UtcDateTime)

    def is_expired(self, *, now: dt.datetime, idle_timeout: dt.timedelta) -> bool:
        return now >= self.expires_at or now - self.last_seen_at >= idle_timeout

    def needs_revalidation(self, *, now: dt.datetime) -> bool:
        return now >= self.revalidate_after

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<UserSession {self.id} {self.username} {self.role.value}>"


class AuditLog(Base):
    """An append-only record of every change (9).

    Deliberately denormalised: ``actor`` is the DN as a string rather than a
    foreign key to a session, and ``target`` names the affected object rather
    than pointing at it.  A repository that is later purged, or a session that
    has long since expired, must not take its history with it.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        # The audit page's two views: everything newest-first, and one actor's
        # own entries newest-first.
        Index("ix_audit_log_occurred_at", "occurred_at"),
        Index("ix_audit_log_actor_occurred", "actor", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[dt.datetime] = mapped_column(UtcDateTime, default=utcnow)

    actor: Mapped[str] = mapped_column(String(DN_LENGTH))
    actor_type: Mapped[ActorType] = mapped_column(
        Enum(ActorType, native_enum=False, length=16, validate_strings=True)
    )
    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction, native_enum=False, length=32, validate_strings=True)
    )
    outcome: Mapped[AuditOutcome] = mapped_column(
        Enum(AuditOutcome, native_enum=False, length=16, validate_strings=True)
    )

    #: SET NULL rather than CASCADE: purging a repository must not erase the
    #: record of who purged it.
    repository_id: Mapped[int | None] = mapped_column(
        ForeignKey("repository.id", ondelete="SET NULL"), index=True, default=None
    )
    #: Human-readable name of what was acted on, e.g. a package or key name.
    target: Mapped[str | None] = mapped_column(Text, default=None)
    details_json: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(postgresql.JSONB, "postgresql"), default=dict
    )
    source_ip: Mapped[str | None] = mapped_column(String(45), default=None)

    repository: Mapped[Repository | None] = relationship()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditLog {self.id} {self.action.value} {self.outcome.value}>"
