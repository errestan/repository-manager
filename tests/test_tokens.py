"""API tokens: minting, presenting, revoking (specification.md 7.4)."""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.config import Settings
from repository_manager.models import (
    TOKEN_PREFIX,
    ApiToken,
    Role,
    TokenScope,
    decode_scopes,
    encode_scopes,
)
from repository_manager.models.base import utcnow
from repository_manager.services import tokens as token_service
from repository_manager.services.tokens import TokenError

Sessionmaker = async_sessionmaker[AsyncSession]

BOTH = (TokenScope.PACKAGE_READ, TokenScope.PACKAGE_WRITE)


async def _mint(
    session: AsyncSession, settings: Settings, **overrides: object
) -> token_service.MintedToken:
    arguments: dict[str, object] = {
        "owner_dn": "uid=mo,ou=people,dc=example,dc=test",
        "owner_username": "mo",
        "label": "build server",
        "scopes": BOTH,
    }
    arguments.update(overrides)
    return await token_service.mint(session, settings, **arguments)  # type: ignore[arg-type]


# ------------------------------------------------------------------ the format


def test_a_token_has_the_documented_shape() -> None:
    """`rmt_` plus 32 random bytes in base64url, per 7.4."""
    secret = token_service.generate()
    assert secret.startswith(TOKEN_PREFIX)
    body = secret.removeprefix(TOKEN_PREFIX)
    # base64url of 32 bytes, unpadded.
    assert len(body) == 43
    assert set(body) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def test_two_tokens_are_never_the_same() -> None:
    assert len({token_service.generate() for _ in range(200)}) == 200


def test_the_prefix_is_a_prefix_of_the_token() -> None:
    """The lookup column has to be derivable from what a client presents."""
    secret = token_service.generate()
    assert secret.startswith(token_service.prefix_of(secret))


def test_the_prefix_is_not_most_of_the_secret() -> None:
    """It is a lookup key, not the credential: the bulk must stay unstored."""
    secret = token_service.generate()
    assert len(token_service.prefix_of(secret)) < len(secret) / 3


# ------------------------------------------------------------------ scopes


def test_scopes_round_trip_through_their_stored_form() -> None:
    stored = encode_scopes(set(BOTH))
    assert decode_scopes(stored) == frozenset(BOTH)


def test_the_stored_form_is_canonical() -> None:
    """Two tokens granted the same scopes store the same string."""
    assert encode_scopes({TokenScope.PACKAGE_WRITE, TokenScope.PACKAGE_READ}) == encode_scopes(
        {TokenScope.PACKAGE_READ, TokenScope.PACKAGE_WRITE}
    )


def test_a_scope_this_version_does_not_know_is_not_a_grant() -> None:
    """A newer version's scope must never be read as a permission."""
    assert decode_scopes("package:read,package:everything") == {TokenScope.PACKAGE_READ}


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (Role.ADMIN, frozenset(BOTH)),
        (Role.MAINTAINER, frozenset(BOTH)),
    ],
)
def test_a_maintainer_keeps_both_scopes(role: Role, expected: frozenset[TokenScope]) -> None:
    assert token_service.effective_scopes(frozenset(BOTH), role) == expected


def test_write_is_the_scope_that_needs_a_role() -> None:
    """Reading is unconditional for everyone (AD-16); writing is not (3)."""
    assert token_service.SCOPE_REQUIREMENTS[TokenScope.PACKAGE_READ] is None
    assert token_service.SCOPE_REQUIREMENTS[TokenScope.PACKAGE_WRITE] is Role.MAINTAINER


# ------------------------------------------------------------------ minting


async def test_minting_returns_a_secret_that_is_not_stored(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    async with sessionmaker() as session:
        minted = await _mint(session, settings)
        await session.commit()
        stored = await session.scalar(select(ApiToken).where(ApiToken.id == minted.record.id))

    assert stored is not None
    assert minted.secret not in (stored.token_hash, stored.prefix)
    assert stored.token_hash == token_service.hash_token(minted.secret)


async def test_the_default_lifetime_comes_from_configuration(
    sessionmaker: Sessionmaker, make_settings: object
) -> None:
    settings = make_settings(token_default_lifetime_days=7)  # type: ignore[operator]
    async with sessionmaker() as session:
        minted = await _mint(session, settings)
    lifetime = minted.record.expires_at - minted.record.created_at
    assert lifetime == dt.timedelta(days=7)


async def test_a_lifetime_over_the_maximum_is_refused(
    sessionmaker: Sessionmaker, make_settings: object
) -> None:
    settings = make_settings(  # type: ignore[operator]
        token_max_lifetime_days=30, token_default_lifetime_days=30
    )
    async with sessionmaker() as session:
        with pytest.raises(TokenError, match="at most 30 days"):
            await _mint(session, settings, lifetime_days=31)


async def test_a_token_with_no_scopes_is_refused(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    """A credential that authenticates and can do nothing is a trap, not a token."""
    async with sessionmaker() as session:
        with pytest.raises(TokenError, match="at least one"):
            await _mint(session, settings, scopes=())


async def test_a_token_needs_a_label(sessionmaker: Sessionmaker, settings: Settings) -> None:
    async with sessionmaker() as session:
        with pytest.raises(TokenError, match="label"):
            await _mint(session, settings, label="   ")


async def test_no_repositories_chosen_means_every_repository(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    """NULL and "" are different things, and only one of them is honest."""
    async with sessionmaker() as session:
        minted = await _mint(session, settings, repositories=[])
    assert minted.record.repository_scope is None
    assert minted.record.unrestricted
    assert minted.record.covers("anything")


async def test_a_repository_allow_list_is_stored_sorted(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    async with sessionmaker() as session:
        minted = await _mint(session, settings, repositories=["zebra", "alpha"])
    assert minted.record.repositories == ("alpha", "zebra")
    assert minted.record.covers("alpha")
    assert not minted.record.covers("beta")


# ------------------------------------------------------------------ presenting


async def test_a_minted_token_authenticates(sessionmaker: Sessionmaker, settings: Settings) -> None:
    async with sessionmaker() as session:
        minted = await _mint(session, settings)
        await session.commit()
        found = await token_service.authenticate(session, minted.secret)
    assert found is not None
    assert found.id == minted.record.id


async def test_a_token_that_was_never_minted_does_not_authenticate(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    async with sessionmaker() as session:
        await _mint(session, settings)
        await session.commit()
        assert await token_service.authenticate(session, token_service.generate()) is None


@pytest.mark.parametrize(
    "presented",
    ["", "   ", "not-a-token", "rmt_", "rmt_short", "Bearer rmt_x", "rmt_" + "A" * 43],
)
async def test_a_malformed_credential_does_not_authenticate(
    sessionmaker: Sessionmaker, settings: Settings, presented: str
) -> None:
    async with sessionmaker() as session:
        await _mint(session, settings)
        await session.commit()
        assert await token_service.authenticate(session, presented) is None


async def test_the_right_prefix_with_the_wrong_body_is_refused(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    """The prefix is a lookup key; the hash comparison is what decides."""
    async with sessionmaker() as session:
        minted = await _mint(session, settings)
        await session.commit()
        forged = minted.record.prefix + "x" * (len(minted.secret) - len(minted.record.prefix))
        assert len(forged) == len(minted.secret)
        assert await token_service.authenticate(session, forged) is None


async def test_two_tokens_sharing_a_prefix_both_still_work(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    """A prefix collision is improbable, not impossible, so it must not break either token.

    Forced here by rewriting the second row to correspond to a secret that
    shares the first's twelve characters: the lookup fetches both candidates and
    the constant-time comparison is what picks between them.
    """
    async with sessionmaker() as session:
        first = await _mint(session, settings, label="first")
        second = await _mint(session, settings, label="second")
        collided = first.record.prefix + "Z" * (len(first.secret) - len(first.record.prefix))
        second.record.prefix = token_service.prefix_of(collided)
        second.record.token_hash = token_service.hash_token(collided)
        await session.commit()

        assert second.record.prefix == first.record.prefix
        found_first = await token_service.authenticate(session, first.secret)
        found_second = await token_service.authenticate(session, collided)

    assert found_first is not None
    assert found_first.label == "first"
    assert found_second is not None
    assert found_second.label == "second"


async def test_an_expired_token_does_not_authenticate(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    async with sessionmaker() as session:
        minted = await _mint(session, settings, lifetime_days=1)
        await session.commit()
        later = utcnow() + dt.timedelta(days=2)
        assert await token_service.authenticate(session, minted.secret, now=later) is None


async def test_a_revoked_token_does_not_authenticate(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    async with sessionmaker() as session:
        minted = await _mint(session, settings)
        await token_service.revoke(session, minted.record, actor="uid=ada")
        await session.commit()
        assert await token_service.authenticate(session, minted.secret) is None


async def test_revoking_twice_is_not_an_error(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    async with sessionmaker() as session:
        minted = await _mint(session, settings)
        await token_service.revoke(session, minted.record, actor="uid=ada")
        first = minted.record.revoked_at
        await token_service.revoke(session, minted.record, actor="uid=someone-else")
    assert minted.record.revoked_at == first
    assert minted.record.revoked_by == "uid=ada"


# ------------------------------------------------------------------ last used


async def test_use_is_recorded(sessionmaker: Sessionmaker, settings: Settings) -> None:
    async with sessionmaker() as session:
        minted = await _mint(session, settings)
    assert minted.record.last_used_at is None
    assert token_service.touch(minted.record) is True
    assert minted.record.last_used_at is not None


async def test_use_is_not_recorded_again_within_the_interval(
    sessionmaker: Sessionmaker, settings: Settings
) -> None:
    """A read-only API call must not become a write transaction every time."""
    async with sessionmaker() as session:
        minted = await _mint(session, settings)
    now = utcnow()
    token_service.touch(minted.record, now=now)
    assert token_service.touch(minted.record, now=now + dt.timedelta(seconds=5)) is False
    assert token_service.touch(minted.record, now=now + dt.timedelta(seconds=120)) is True


# ------------------------------------------------------------------ who may revoke


def _token(owner: str) -> ApiToken:
    return ApiToken(
        owner_dn=owner,
        owner_username="someone",
        label="x",
        prefix="rmt_abcdefgh",
        token_hash="0" * 64,
        scopes=encode_scopes({TokenScope.PACKAGE_READ}),
        expires_at=utcnow() + dt.timedelta(days=1),
    )


def test_an_owner_may_revoke_their_own() -> None:
    token = _token("uid=mo")
    assert token_service.may_revoke(token, actor_dn="uid=mo", role=Role.MAINTAINER)


def test_a_maintainer_may_not_revoke_someone_elses() -> None:
    token = _token("uid=someone-else")
    assert not token_service.may_revoke(token, actor_dn="uid=mo", role=Role.MAINTAINER)


def test_an_admin_may_revoke_anyones() -> None:
    token = _token("uid=someone-else")
    assert token_service.may_revoke(token, actor_dn="uid=ada", role=Role.ADMIN)


# ------------------------------------------------------------------ state


def test_revoked_and_expired_fail_the_same_way() -> None:
    """7.4: telling them apart would confirm that a held token was once real."""
    revoked = _token("uid=mo")
    revoked.revoked_at = utcnow()
    expired = _token("uid=mo")
    expired.expires_at = utcnow() - dt.timedelta(days=1)
    assert revoked.is_usable() == expired.is_usable() is False


def test_a_scope_the_owners_role_does_not_reach_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The intersection rule itself, exercised on a requirement that can narrow.

    Today's two roles cannot demonstrate this: ``admin`` is a superset of
    ``maintainer`` and the only scope with a requirement asks for
    ``maintainer``, so every real combination passes through unchanged. The
    requirement is patched here rather than the test skipped, because the rule
    in 7.4 is a ceiling and a ceiling nothing has ever pressed against is a
    ceiling nobody knows is there.
    """
    monkeypatch.setitem(token_service.SCOPE_REQUIREMENTS, TokenScope.PACKAGE_WRITE, Role.ADMIN)
    granted = frozenset(BOTH)
    assert token_service.effective_scopes(granted, Role.ADMIN) == granted
    assert token_service.effective_scopes(granted, Role.MAINTAINER) == {TokenScope.PACKAGE_READ}
