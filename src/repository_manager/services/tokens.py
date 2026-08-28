"""Minting, presenting and revoking API tokens (specification.md 7.4).

The whole security argument for this module is in three functions, so they are
worth reading together.

:func:`mint` is the only place a token exists in plaintext.  It is returned to
the caller and never written down; the row gets a SHA-256 and a prefix.

:func:`authenticate` turns a presented string back into a row.  It looks up
candidates by the non-secret prefix and then decides with
``secrets.compare_digest``, so neither the number of rows examined nor the time
taken depends on how much of a guess was correct.  A token that is expired or
revoked fails in exactly the same way as one that never existed: the caller
learns "no", not "not any more".

:func:`effective_role` is the intersection rule.  A token's scopes are a
*ceiling*, not a grant -- what it may actually do is bounded by the role its
owner has in the directory right now.  Nothing here reads a stored role,
because a stored role is an access decision that keeps working after the
directory has said otherwise.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from repository_manager.config import Settings
from repository_manager.logging import get_logger
from repository_manager.models import (
    TOKEN_BYTES,
    TOKEN_PREFIX,
    TOKEN_PREFIX_LENGTH,
    ApiToken,
    Role,
    TokenScope,
    encode_scopes,
)
from repository_manager.models.base import utcnow
from repository_manager.models.token import LIST_SEPARATOR

log = get_logger(__name__)

LABEL_MAX_LENGTH = 120

#: How stale ``last_used_at`` may get before a request writes it back.  The
#: column exists so a person can tell a live token from a forgotten one, and a
#: minute of imprecision does not change that answer -- whereas a write on every
#: request would turn a read-only API call into a write transaction.
LAST_USED_INTERVAL = dt.timedelta(seconds=60)

#: What each scope needs from the owner's directory role (3, 7.4).  Reading is
#: unconditional for everyone (AD-16), so ``package:read`` needs nothing beyond
#: a live account; writing needs the maintainer role.
SCOPE_REQUIREMENTS: dict[TokenScope, Role | None] = {
    TokenScope.PACKAGE_READ: None,
    TokenScope.PACKAGE_WRITE: Role.MAINTAINER,
}


class TokenError(Exception):
    """A token could not be minted; the message is shown to a user.

    ``field`` names the input the message belongs against, so the form can put
    it where the person who typed it will see it rather than only in the summary
    at the top (11).
    """

    def __init__(self, message: str, *, field: str = "label") -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class MintedToken:
    """A new token and the one copy of its secret that will ever exist (7.4)."""

    record: ApiToken
    secret: str


def hash_token(presented: str) -> str:
    """The stored form of a token.

    A plain SHA-256 for the same reason session cookies use one: the input is
    256 bits of system randomness, so there is no dictionary a key-derivation
    function could slow an attacker down against, and paying for one on every
    API request would be latency spent on nothing.
    """
    return hashlib.sha256(presented.encode("utf-8")).hexdigest()


def generate() -> str:
    """A fresh token in the documented format, ``rmt_<base64url(32 bytes)>``."""
    return f"{TOKEN_PREFIX}{secrets.token_urlsafe(TOKEN_BYTES)}"


def prefix_of(presented: str) -> str:
    return presented[:TOKEN_PREFIX_LENGTH]


def _clean_label(label: str) -> str:
    cleaned = " ".join(label.split())
    if not cleaned:
        raise TokenError("Give the token a label, so you can tell it from your others later.")
    if len(cleaned) > LABEL_MAX_LENGTH:
        raise TokenError(f"The label must be {LABEL_MAX_LENGTH} characters or fewer.")
    return cleaned


def _clean_lifetime(days: int, settings: Settings) -> int:
    if days < 1:
        raise TokenError("A token must be valid for at least one day.", field="lifetime_days")
    if days > settings.token_max_lifetime_days:
        raise TokenError(
            f"This instance allows tokens to live at most {settings.token_max_lifetime_days} "
            "days (REPOMAN_TOKEN_MAX_LIFETIME_DAYS).",
            field="lifetime_days",
        )
    return days


def _clean_scopes(scopes: Iterable[TokenScope]) -> frozenset[TokenScope]:
    chosen = frozenset(scopes)
    if not chosen:
        raise TokenError("Choose at least one thing the token is allowed to do.", field="scopes")
    return chosen


def _clean_repositories(slugs: Sequence[str]) -> str | None:
    """Canonical stored form of the allow-list, or ``None`` for unrestricted.

    Empty and NULL mean different things in this column, so an empty selection
    becomes NULL rather than "": a token scoped to no repositories at all would
    be one that authenticates and can then do nothing, which is a confusing way
    to spell "revoked".
    """
    cleaned = sorted({slug.strip() for slug in slugs if slug.strip()})
    if not cleaned:
        return None
    return LIST_SEPARATOR.join(cleaned)


async def mint(
    session: AsyncSession,
    settings: Settings,
    *,
    owner_dn: str,
    owner_username: str,
    label: str,
    scopes: Iterable[TokenScope],
    repositories: Sequence[str] = (),
    lifetime_days: int | None = None,
    now: dt.datetime | None = None,
) -> MintedToken:
    """Create a token, returning its plaintext for the one time it is shown (7.4)."""
    moment = now or utcnow()
    cleaned_label = _clean_label(label)
    chosen = _clean_scopes(scopes)
    days = _clean_lifetime(
        settings.token_default_lifetime_days if lifetime_days is None else lifetime_days,
        settings,
    )

    secret = generate()
    record = ApiToken(
        owner_dn=owner_dn,
        owner_username=owner_username,
        label=cleaned_label,
        prefix=prefix_of(secret),
        token_hash=hash_token(secret),
        scopes=encode_scopes(chosen),
        repository_scope=_clean_repositories(repositories),
        created_at=moment,
        expires_at=moment + dt.timedelta(days=days),
    )
    session.add(record)
    await session.flush()
    log.info(
        "api token minted",
        token_id=record.id,
        owner_dn=owner_dn,
        scopes=record.scopes,
        repositories=record.repositories or "all",
        expires_at=record.expires_at.isoformat(),
    )
    return MintedToken(record=record, secret=secret)


def looks_like_a_token(presented: str) -> bool:
    """Cheap shape check, so a malformed header never reaches the database.

    Not a security boundary -- :func:`authenticate` decides -- but it keeps a
    stray ``Authorization: Bearer undefined`` from costing a query.
    """
    return presented.startswith(TOKEN_PREFIX) and len(presented) > TOKEN_PREFIX_LENGTH


async def authenticate(
    session: AsyncSession, presented: str, *, now: dt.datetime | None = None
) -> ApiToken | None:
    """The live token this string is, or ``None``.

    Candidates are fetched by prefix and then compared in constant time.  There
    may legitimately be more than one candidate -- twelve shared characters is
    improbable, not impossible -- so every match is compared rather than the
    first, and a token is never rejected for colliding with another.
    """
    if not looks_like_a_token(presented):
        return None
    moment = now or utcnow()
    digest = hash_token(presented)
    candidates = (
        await session.execute(select(ApiToken).where(ApiToken.prefix == prefix_of(presented)))
    ).scalars()

    matched: ApiToken | None = None
    for candidate in candidates:
        # Not short-circuited on the first match: comparing every candidate
        # costs one hash comparison each and keeps the work independent of
        # which row happened to be right.
        if secrets.compare_digest(candidate.token_hash, digest):
            matched = candidate
    if matched is None or not matched.is_usable(now=moment):
        return None
    return matched


def touch(token: ApiToken, *, now: dt.datetime | None = None) -> bool:
    """Record that the token was used, at most once a minute.  Returns whether it wrote."""
    moment = now or utcnow()
    if token.last_used_at is not None and moment - token.last_used_at < LAST_USED_INTERVAL:
        return False
    token.last_used_at = moment
    return True


def effective_scopes(granted: frozenset[TokenScope], role: Role) -> frozenset[TokenScope]:
    """Token scopes intersected with what the owner's current role allows (7.4).

    This is the rule that makes explicit revocation optional: an owner demoted
    out of the maintainer group keeps a token that authenticates and can no
    longer write anything.

    Takes the scope set rather than the row, because the request path holds a
    snapshot of the token and not the ORM instance -- see
    :class:`repository_manager.web.deps.TokenIdentity`.

    Worth being plain about what this can and cannot do *today*.  There are two
    roles, ``admin`` is a superset of ``maintainer``, and the only scope with a
    requirement asks for ``maintainer`` -- so with the current role set this
    function never narrows anything, and the enforcement that actually bites is
    the account losing every mapped group, which fails before it gets here.
    The rule is still written the way 7.4 states it rather than collapsed into
    that one case: a third role, or a scope that needs ``admin``, is a change to
    :data:`SCOPE_REQUIREMENTS` and nothing else, and the alternative is
    discovering at that point that the ceiling was never applied.
    """
    return frozenset(
        scope
        for scope in granted
        if (required := SCOPE_REQUIREMENTS[scope]) is None or role.permits(required)
    )


async def for_owner(session: AsyncSession, owner_dn: str) -> list[ApiToken]:
    statement = (
        select(ApiToken)
        .where(ApiToken.owner_dn == owner_dn)
        .order_by(ApiToken.created_at.desc(), ApiToken.id.desc())
    )
    return list((await session.execute(statement)).scalars().all())


async def all_tokens(session: AsyncSession) -> list[ApiToken]:
    """Every token, for an admin (3)."""
    statement = select(ApiToken).order_by(ApiToken.created_at.desc(), ApiToken.id.desc())
    return list((await session.execute(statement)).scalars().all())


async def load(session: AsyncSession, token_id: int) -> ApiToken | None:
    return await session.get(ApiToken, token_id)


async def revoke(
    session: AsyncSession, token: ApiToken, *, actor: str, now: dt.datetime | None = None
) -> None:
    """Mark a token unusable.  Idempotent: revoking twice is not an error (7.4)."""
    if token.revoked:
        return
    token.revoked_at = now or utcnow()
    token.revoked_by = actor
    await session.flush()
    log.info("api token revoked", token_id=token.id, owner_dn=token.owner_dn, revoked_by=actor)


def may_revoke(token: ApiToken, *, actor_dn: str, role: Role | None) -> bool:
    """The owner, or any admin (3)."""
    return token.owner_dn == actor_dn or (role is not None and role.permits(Role.ADMIN))
