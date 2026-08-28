"""The token owner's role cache (specification.md 7.4).

The cache exists so that a pipeline uploading twenty packages does not make
twenty LDAP round trips, and it is worth testing on its own because the two
interesting cases are both about being *wrong* in a controlled way: a revoked
account that keeps working for up to one interval, and a directory outage that
must not stop a build.
"""

from __future__ import annotations

import datetime as dt

import pytest

from repository_manager.auth.ldap import DirectoryUnavailableError, NoRoleAssignedError
from repository_manager.auth.roles import RoleCache
from repository_manager.models import Role
from repository_manager.models.base import utcnow
from tests.support import directory as fake_directory
from tests.support.directory import FakeDirectory

TTL = dt.timedelta(minutes=15)
MO = fake_directory.dn_for(fake_directory.MAINTAINER_USERNAME)


@pytest.fixture
def cache() -> RoleCache:
    return RoleCache(TTL)


@pytest.fixture
def directory() -> FakeDirectory:
    return fake_directory.populated()


async def test_a_role_is_resolved_from_the_directory(
    cache: RoleCache, directory: FakeDirectory
) -> None:
    assert await cache.resolve(directory, MO) is Role.MAINTAINER
    assert directory.role_lookups == 1


async def test_a_fresh_answer_is_reused(cache: RoleCache, directory: FakeDirectory) -> None:
    now = utcnow()
    await cache.resolve(directory, MO, now=now)
    await cache.resolve(directory, MO, now=now + TTL - dt.timedelta(seconds=1))
    assert directory.role_lookups == 1


async def test_a_stale_answer_is_re_checked(cache: RoleCache, directory: FakeDirectory) -> None:
    now = utcnow()
    await cache.resolve(directory, MO, now=now)
    await cache.resolve(directory, MO, now=now + TTL)
    assert directory.role_lookups == 2


async def test_a_promotion_takes_effect_within_one_interval(
    cache: RoleCache, directory: FakeDirectory
) -> None:
    now = utcnow()
    assert await cache.resolve(directory, MO, now=now) is Role.MAINTAINER
    directory.users[fake_directory.MAINTAINER_USERNAME].role = Role.ADMIN
    assert await cache.resolve(directory, MO, now=now + TTL) is Role.ADMIN


async def test_losing_every_group_is_reported(cache: RoleCache, directory: FakeDirectory) -> None:
    directory.users[fake_directory.MAINTAINER_USERNAME].role = None
    with pytest.raises(NoRoleAssignedError):
        await cache.resolve(directory, MO)


async def test_a_definite_refusal_is_not_undone_by_the_remembered_answer(
    cache: RoleCache, directory: FakeDirectory
) -> None:
    """The entry is dropped on a "no", so the next request does not read it back."""
    now = utcnow()
    await cache.resolve(directory, MO, now=now)
    directory.users[fake_directory.MAINTAINER_USERNAME].role = None

    with pytest.raises(NoRoleAssignedError):
        await cache.resolve(directory, MO, now=now + TTL)
    # Still refused inside what would have been the next fresh window.
    with pytest.raises(NoRoleAssignedError):
        await cache.resolve(directory, MO, now=now + TTL + dt.timedelta(seconds=1))


async def test_an_outage_falls_back_to_the_remembered_answer(
    cache: RoleCache, directory: FakeDirectory
) -> None:
    """A directory that cannot be reached has not revoked anything (7.2, 7.4)."""
    now = utcnow()
    await cache.resolve(directory, MO, now=now)
    directory.unavailable = True
    assert await cache.resolve(directory, MO, now=now + TTL) is Role.MAINTAINER


async def test_an_outage_with_nothing_remembered_fails(
    cache: RoleCache, directory: FakeDirectory
) -> None:
    """There is no honest answer to give, and guessing would be inventing access."""
    directory.unavailable = True
    with pytest.raises(DirectoryUnavailableError):
        await cache.resolve(directory, MO)


async def test_forgetting_forces_the_next_lookup(
    cache: RoleCache, directory: FakeDirectory
) -> None:
    now = utcnow()
    await cache.resolve(directory, MO, now=now)
    cache.forget(MO)
    await cache.resolve(directory, MO, now=now)
    assert directory.role_lookups == 2


async def test_owners_are_cached_separately(cache: RoleCache, directory: FakeDirectory) -> None:
    ada = fake_directory.dn_for(fake_directory.ADMIN_USERNAME)
    assert await cache.resolve(directory, MO) is Role.MAINTAINER
    assert await cache.resolve(directory, ada) is Role.ADMIN
