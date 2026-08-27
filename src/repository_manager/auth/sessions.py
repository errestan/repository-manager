"""Server-side session lifecycle (specification.md 7.2).

The cookie is an opaque 256-bit random string and nothing else -- it carries no
identity, no role and no expiry, so none of those can be tampered with, and
ending a session is a ``DELETE`` rather than a wait.

Only the SHA-256 of the cookie is stored.  Sessions are looked up by that hash,
so the table can be read, dumped or backed up without any of it being usable as
a credential.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from typing import Any, cast

from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from repository_manager.auth import csrf
from repository_manager.config import Settings
from repository_manager.models import Role, UserSession
from repository_manager.models.base import utcnow

#: Scoped to the mount path by ``Settings.cookie_path`` so two applications on
#: one hostname cannot see each other's sessions (13.5).
SESSION_COOKIE = "repoman_session"

#: 32 bytes, per 7.2.  ``token_urlsafe`` returns roughly 43 characters for this.
TOKEN_BYTES = 32


def hash_token(token: str) -> str:
    """The stored form of a session cookie.

    A plain SHA-256, not a password hash: the input is 256 bits of system
    randomness, so there is no dictionary to slow an attacker down with, and a
    per-request KDF would cost real latency for no gain.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def issue(
    session: AsyncSession,
    settings: Settings,
    *,
    user_dn: str,
    username: str,
    display_name: str,
    role: Role,
    now: dt.datetime | None = None,
) -> tuple[UserSession, str]:
    """Create a session row and return it with the cookie value to set.

    The raw token is returned rather than stored, and is the only time it
    exists outside the browser.
    """
    moment = now or utcnow()
    token = secrets.token_urlsafe(TOKEN_BYTES)
    record = UserSession(
        token_hash=hash_token(token),
        user_dn=user_dn,
        username=username,
        display_name=display_name,
        role=role,
        csrf_secret=csrf.new_secret(),
        created_at=moment,
        last_seen_at=moment,
        expires_at=moment + settings.session_absolute_lifetime,
        revalidate_after=moment + settings.session_revalidate_after,
    )
    session.add(record)
    await session.flush()
    return record, token


async def load(
    session: AsyncSession, settings: Settings, token: str | None, *, now: dt.datetime | None = None
) -> UserSession | None:
    """The live session for this cookie, or ``None``.

    An expired row is deleted on the way past rather than left to a sweep: the
    request that found it has already paid for the lookup, and a session that
    outlives its expiry in the table is a session an operator has to reason
    about.
    """
    if not token:
        return None
    moment = now or utcnow()
    record = await session.scalar(
        select(UserSession).where(UserSession.token_hash == hash_token(token))
    )
    if record is None:
        return None
    if record.is_expired(now=moment, idle_timeout=settings.session_idle_timeout):
        await session.delete(record)
        return None
    return record


def touch(record: UserSession, *, now: dt.datetime | None = None) -> None:
    """Push the idle timeout out, because the user is still here."""
    record.last_seen_at = now or utcnow()


def mark_revalidated(
    record: UserSession, settings: Settings, role: Role, *, now: dt.datetime | None = None
) -> None:
    """Record the outcome of a group re-check (7.2).

    The role is written back as well as the deadline: a demotion from admin to
    maintainer has to take effect on this session, not only on the next login.
    """
    record.role = role
    record.revalidate_after = (now or utcnow()) + settings.session_revalidate_after


async def destroy(session: AsyncSession, record: UserSession) -> None:
    await session.delete(record)


async def destroy_for_user(session: AsyncSession, user_dn: str) -> None:
    """End every session belonging to one user.

    Used when revalidation finds their access has been revoked: leaving their
    other browsers signed in would defeat the point of re-checking at all.
    """
    await session.execute(delete(UserSession).where(UserSession.user_dn == user_dn))


async def purge_expired(session: AsyncSession, *, now: dt.datetime | None = None) -> int:
    """Delete sessions past their absolute expiry, returning how many went.

    Only the absolute expiry is used, not the idle timeout: this runs without a
    request in hand, and a row whose idle timeout has passed is already
    unusable via :func:`load`.
    """
    # Cast because `execute` is typed as returning a generic Result, which has
    # no rowcount; a DELETE always yields a CursorResult, which does.
    result = cast(
        "CursorResult[Any]",
        await session.execute(
            delete(UserSession).where(UserSession.expires_at <= (now or utcnow()))
        ),
    )
    return int(result.rowcount or 0)
