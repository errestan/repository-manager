"""Owner-role lookups for token authentication (specification.md 7.4).

A token's effective permission is its scopes intersected with its owner's
*current* directory role, so every API write has to know that role.  Asking the
directory on each request would put an LDAP round trip in front of every upload
in a CI pipeline, and a directory outage would then stop publishing entirely.

So the answer is cached for the same interval a browser session waits before
revalidating (``REPOMAN_SESSION_REVALIDATE_MINUTES``).  That is the same
promise sessions already make -- revoked access takes effect within one
interval rather than instantly -- applied to the other kind of credential, and
it is worth being plain that it is an interval and not an instant: an urgent
removal is done by revoking the token or deregistering the account, both of
which take effect on the next request.

A directory that is merely unreachable does not revoke anything.  When a
lookup fails and a previous answer is on hand, the stale answer is used and the
failure logged, matching how :func:`repository_manager.web.deps._revalidate`
treats the same outage for sessions.  With nothing cached there is no honest
answer to give, so the request fails.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from starlette.concurrency import run_in_threadpool

from repository_manager.auth.ldap import Authenticator, LdapError, NoRoleAssignedError
from repository_manager.logging import get_logger
from repository_manager.models import Role
from repository_manager.models.base import utcnow

log = get_logger(__name__)


@dataclass(frozen=True)
class _Entry:
    role: Role
    resolved_at: dt.datetime


class RoleCache:
    """Directory roles by DN, remembered for ``ttl``.

    Unbounded by design, and safely so: an entry is only ever created for a DN
    that already owns a token in this instance's database, so the key space is
    the number of token owners rather than anything a caller can inflate.
    """

    def __init__(self, ttl: dt.timedelta) -> None:
        self._ttl = ttl
        self._entries: dict[str, _Entry] = {}

    async def resolve(
        self, authenticator: Authenticator, user_dn: str, *, now: dt.datetime | None = None
    ) -> Role:
        """The owner's role, from cache when fresh.

        The directory is passed in rather than held, so the cache cannot end up
        querying a different one from the rest of the application: tests and a
        future alternative backend replace ``app.state.authenticator`` after the
        application is built, and a captured reference would quietly outlive
        that swap.

        Raises :class:`NoRoleAssignedError` when the directory says the account
        is in no mapped group, and :class:`LdapError` when it cannot be asked
        and nothing is remembered.
        """
        moment = now or utcnow()
        cached = self._entries.get(user_dn)
        if cached is not None and moment - cached.resolved_at < self._ttl:
            return cached.role

        try:
            role = await run_in_threadpool(authenticator.resolve_role, user_dn)
        except NoRoleAssignedError:
            # A definite "no". Forget the entry so the refusal is not undone by
            # a stale answer on the next request.
            self._entries.pop(user_dn, None)
            log.info("token owner has no mapped group", user_dn=user_dn)
            raise
        except LdapError as exc:
            if cached is None:
                log.warning("token owner role unresolvable", user_dn=user_dn, error=str(exc))
                raise
            log.warning(
                "token owner role served from a stale answer",
                user_dn=user_dn,
                error=str(exc),
                age_seconds=round((moment - cached.resolved_at).total_seconds()),
            )
            return cached.role

        self._entries[user_dn] = _Entry(role=role, resolved_at=moment)
        return role

    def forget(self, user_dn: str) -> None:
        """Drop a remembered answer, so the next request asks again."""
        self._entries.pop(user_dn, None)

    def clear(self) -> None:
        self._entries.clear()
