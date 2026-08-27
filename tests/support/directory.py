"""An in-memory directory, for tests that need a login but not a server.

Implements the same :class:`~repository_manager.auth.ldap.Authenticator`
protocol the real client does, so everything above it -- sessions, CSRF, the
role gate, the audit trail -- is exercised exactly as in production.  The LDAP
protocol handling itself is tested separately against ``ldap3``'s mock server
in ``tests/test_ldap.py`` and against a real OpenLDAP in the integration suite.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from repository_manager.auth.ldap import (
    DirectoryUnavailableError,
    InvalidCredentialsError,
    LdapIdentity,
    NoRoleAssignedError,
)
from repository_manager.models import Role

ADMIN_USERNAME = "ada"
ADMIN_PASSWORD = "ada-password"
MAINTAINER_USERNAME = "mo"
MAINTAINER_PASSWORD = "mo-password"

BASE_DN = "ou=people,dc=example,dc=test"


def dn_for(username: str) -> str:
    return f"uid={username},{BASE_DN}"


@dataclass
class DirectoryUser:
    username: str
    password: str
    role: Role | None
    display_name: str = ""

    @property
    def dn(self) -> str:
        return dn_for(self.username)


@dataclass
class FakeDirectory:
    """A directory whose contents a test can change between requests.

    Mutability is the point: revalidation (7.2) is only meaningfully tested by
    revoking someone's access while their session is open.
    """

    users: dict[str, DirectoryUser] = field(default_factory=dict)
    #: Set to make every call fail the way an unreachable server would.
    unavailable: bool = False
    #: Counts calls, so a test can prove revalidation did or did not happen.
    role_lookups: int = 0

    def add(
        self, username: str, password: str, role: Role | None, display_name: str = ""
    ) -> DirectoryUser:
        user = DirectoryUser(
            username=username,
            password=password,
            role=role,
            display_name=display_name or username.title(),
        )
        self.users[username] = user
        return user

    def _by_dn(self, dn: str) -> DirectoryUser | None:
        return next((user for user in self.users.values() if user.dn == dn), None)

    # -- Authenticator ---------------------------------------------------

    def authenticate(self, username: str, password: str) -> LdapIdentity:
        self._check_available()
        user = self.users.get(username.strip())
        if user is None or not password or password != user.password:
            raise InvalidCredentialsError("no")
        if user.role is None:
            raise NoRoleAssignedError(user.dn)
        return LdapIdentity(
            dn=user.dn,
            username=user.username,
            display_name=user.display_name,
            role=user.role,
        )

    def resolve_role(self, dn: str) -> Role:
        self.role_lookups += 1
        self._check_available()
        user = self._by_dn(dn)
        if user is None or user.role is None:
            raise NoRoleAssignedError(dn)
        return user.role

    def _check_available(self) -> None:
        if self.unavailable:
            raise DirectoryUnavailableError("simulated outage")


def populated() -> FakeDirectory:
    """The two accounts the web tests sign in as, plus one with no role."""
    directory = FakeDirectory()
    directory.add(ADMIN_USERNAME, ADMIN_PASSWORD, Role.ADMIN, "Ada Admin")
    directory.add(MAINTAINER_USERNAME, MAINTAINER_PASSWORD, Role.MAINTAINER, "Mo Maintainer")
    directory.add("unmapped", "unmapped-password", None, "No Role")
    return directory
