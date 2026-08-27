"""Session lifecycle and CSRF primitives (specification.md 7.2, 7.3)."""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.auth import csrf, sessions
from repository_manager.config import Settings
from repository_manager.models import Role, UserSession
from repository_manager.models.base import utcnow

DN = "uid=bob,ou=people,dc=example,dc=test"


async def _issue(
    factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    now: dt.datetime | None = None,
    role: Role = Role.MAINTAINER,
) -> tuple[int, str]:
    async with factory() as session:
        record, token = await sessions.issue(
            session,
            settings,
            user_dn=DN,
            username="bob",
            display_name="Bob Brown",
            role=role,
            now=now,
        )
        await session.commit()
        return record.id, token


# --------------------------------------------------------------------- issuing


async def test_the_cookie_is_never_stored(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """A database dump must not contain anything replayable as a session (7.2)."""
    _, token = await _issue(sessionmaker, settings)
    async with sessionmaker() as session:
        record = await session.scalar(select(UserSession))
        assert record is not None
        assert token not in record.token_hash
        assert record.token_hash == sessions.hash_token(token)


async def test_a_session_can_be_loaded_by_its_cookie(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    _, token = await _issue(sessionmaker, settings)
    async with sessionmaker() as session:
        record = await sessions.load(session, settings, token)
        assert record is not None
        assert record.user_dn == DN
        assert record.role is Role.MAINTAINER


async def test_an_unknown_cookie_loads_nothing(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    await _issue(sessionmaker, settings)
    async with sessionmaker() as session:
        assert await sessions.load(session, settings, "not-a-real-token") is None


async def test_no_cookie_loads_nothing(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    async with sessionmaker() as session:
        assert await sessions.load(session, settings, None) is None


async def test_two_sessions_get_different_tokens_and_secrets(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    _, first = await _issue(sessionmaker, settings)
    _, second = await _issue(sessionmaker, settings)
    assert first != second
    async with sessionmaker() as session:
        secrets_used = {
            record.csrf_secret for record in (await session.execute(select(UserSession))).scalars()
        }
    assert len(secrets_used) == 2


# --------------------------------------------------------------------- expiry


async def test_a_session_past_its_absolute_lifetime_is_rejected(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    issued = utcnow() - settings.session_absolute_lifetime - dt.timedelta(minutes=1)
    _, token = await _issue(sessionmaker, settings, now=issued)
    async with sessionmaker() as session:
        assert await sessions.load(session, settings, token) is None


async def test_an_idle_session_is_rejected_before_its_absolute_expiry(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """Eight hours idle inside a twenty-four hour lifetime still ends it (7.2)."""
    issued = utcnow() - settings.session_idle_timeout - dt.timedelta(minutes=1)
    _, token = await _issue(sessionmaker, settings, now=issued)
    async with sessionmaker() as session:
        assert await sessions.load(session, settings, token) is None


async def test_an_expired_session_is_deleted_on_the_way_past(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    issued = utcnow() - settings.session_absolute_lifetime - dt.timedelta(minutes=1)
    _, token = await _issue(sessionmaker, settings, now=issued)
    async with sessionmaker() as session:
        await sessions.load(session, settings, token)
        await session.commit()
    async with sessionmaker() as session:
        assert await session.scalar(select(UserSession)) is None


async def test_activity_pushes_the_idle_timeout_out(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    issued = utcnow() - settings.session_idle_timeout + dt.timedelta(minutes=5)
    _, token = await _issue(sessionmaker, settings, now=issued)
    async with sessionmaker() as session:
        record = await sessions.load(session, settings, token)
        assert record is not None
        sessions.touch(record)
        await session.commit()
    async with sessionmaker() as session:
        assert await sessions.load(session, settings, token) is not None


async def test_touching_cannot_outlive_the_absolute_lifetime(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """Activity extends the idle window; it must not extend the ceiling (7.2).

    Set up by moving the ceiling rather than the issue time: a session issued
    long enough ago to be near its absolute expiry would already have tripped
    the idle timeout, which is the other rule and not the one under test.
    """
    _, token = await _issue(sessionmaker, settings)
    async with sessionmaker() as session:
        record = await sessions.load(session, settings, token)
        assert record is not None
        record.expires_at = utcnow() + dt.timedelta(minutes=1)
        sessions.touch(record)
        await session.commit()
    async with sessionmaker() as session:
        beyond = utcnow() + dt.timedelta(minutes=2)
        assert await sessions.load(session, settings, token, now=beyond) is None


# --------------------------------------------------------------------- revalidation


async def test_a_new_session_is_not_due_for_revalidation(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    _, token = await _issue(sessionmaker, settings)
    async with sessionmaker() as session:
        record = await sessions.load(session, settings, token)
        assert record is not None
        assert not record.needs_revalidation(now=utcnow())


async def test_revalidation_falls_due_after_the_configured_interval(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    _, token = await _issue(sessionmaker, settings)
    later = utcnow() + settings.session_revalidate_after + dt.timedelta(seconds=1)
    async with sessionmaker() as session:
        record = await sessions.load(session, settings, token, now=utcnow())
        assert record is not None
        assert record.needs_revalidation(now=later)


async def test_revalidation_writes_back_a_changed_role(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """A demotion has to take effect on the open session, not only the next one."""
    _, token = await _issue(sessionmaker, settings, role=Role.ADMIN)
    async with sessionmaker() as session:
        record = await sessions.load(session, settings, token)
        assert record is not None
        sessions.mark_revalidated(record, settings, Role.MAINTAINER)
        await session.commit()
    async with sessionmaker() as session:
        record = await sessions.load(session, settings, token)
        assert record is not None
        assert record.role is Role.MAINTAINER
        assert not record.needs_revalidation(now=utcnow())


# --------------------------------------------------------------------- ending


async def test_destroying_a_session_makes_its_cookie_useless(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    _, token = await _issue(sessionmaker, settings)
    async with sessionmaker() as session:
        record = await sessions.load(session, settings, token)
        assert record is not None
        await sessions.destroy(session, record)
        await session.commit()
    async with sessionmaker() as session:
        assert await sessions.load(session, settings, token) is None


async def test_every_session_for_one_user_can_be_ended_at_once(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """Revoked access must not leave their other browsers signed in (7.2)."""
    _, first = await _issue(sessionmaker, settings)
    _, second = await _issue(sessionmaker, settings)
    async with sessionmaker() as session:
        await sessions.destroy_for_user(session, DN)
        await session.commit()
    async with sessionmaker() as session:
        assert await sessions.load(session, settings, first) is None
        assert await sessions.load(session, settings, second) is None


async def test_purging_removes_only_expired_sessions(
    sessionmaker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    stale = utcnow() - settings.session_absolute_lifetime - dt.timedelta(minutes=1)
    await _issue(sessionmaker, settings, now=stale)
    _, live = await _issue(sessionmaker, settings)
    async with sessionmaker() as session:
        assert await sessions.purge_expired(session) == 1
        await session.commit()
    async with sessionmaker() as session:
        assert await sessions.load(session, settings, live) is not None


# --------------------------------------------------------------------- CSRF tokens


def test_a_matching_token_verifies() -> None:
    secret = csrf.new_secret()
    assert csrf.verify(secret, secret)


@pytest.mark.parametrize("presented", [None, "", "wrong", "x"])
def test_a_wrong_or_missing_token_does_not_verify(presented: str | None) -> None:
    assert not csrf.verify(csrf.new_secret(), presented)


def test_an_empty_expected_token_never_verifies() -> None:
    """An anonymous identity carries no secret, and must not match one either."""
    assert not csrf.verify("", "")
    assert not csrf.verify("", "anything")


def test_secrets_are_unpredictable() -> None:
    assert len({csrf.new_secret() for _ in range(50)}) == 50


# --------------------------------------------------------------------- origin checks

EXPECTED = "https://packages.example.test"


@pytest.mark.parametrize(
    ("origin", "referer", "allowed"),
    [
        (EXPECTED, None, True),
        (None, f"{EXPECTED}/repositories/x", True),
        ("https://evil.example", None, False),
        ("null", None, False),
        (None, "https://evil.example/page", False),
        # Origin wins when both are present, so a matching Referer cannot rescue
        # a cross-site Origin.
        ("https://evil.example", f"{EXPECTED}/", False),
        # A different port or scheme is a different origin.
        ("http://packages.example.test", None, False),
        ("https://packages.example.test:8443", None, False),
    ],
)
def test_origin_decisions(origin: str | None, referer: str | None, allowed: bool) -> None:
    assert (
        csrf.origin_is_allowed(
            origin=origin, referer=referer, expected=EXPECTED, ambient_credentials=True
        )
        is allowed
    )


def test_a_request_with_neither_header_is_refused_when_it_carries_a_cookie() -> None:
    """An ambient credential has to prove where it came from (7.3)."""
    assert not csrf.origin_is_allowed(
        origin=None, referer=None, expected=EXPECTED, ambient_credentials=True
    )


def test_a_request_with_neither_header_is_allowed_when_it_carries_none() -> None:
    """A scripted anonymous POST has no ambient authority to abuse."""
    assert csrf.origin_is_allowed(
        origin=None, referer=None, expected=EXPECTED, ambient_credentials=False
    )
