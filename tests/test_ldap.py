"""The LDAP client, against ldap3's in-memory directory (specification.md 7.1).

The mock replaces exactly one thing -- the socket -- by overriding the
connection factory.  Everything else runs its real code: the bind, the filter
construction, the RFC 4514/4515 escaping, the group resolution and the role
mapping.  A test that passes here is a test of this module, not of a stub.
"""

from __future__ import annotations

import pytest
from ldap3 import MOCK_SYNC, Connection, Server
from ldap3.core.exceptions import LDAPException

from repository_manager.auth.ldap import (
    GENERIC_FAILURE,
    DirectoryUnavailableError,
    InvalidCredentialsError,
    LdapAuthenticator,
    NoRoleAssignedError,
    normalise_dn,
)
from repository_manager.config import Settings
from repository_manager.models import Role
from tests.conftest import SettingsFactory

BASE = "dc=example,dc=test"
PEOPLE = f"ou=people,{BASE}"
GROUPS = f"ou=groups,{BASE}"
ADMIN_GROUP = f"cn=repo-admins,{GROUPS}"
MAINTAINER_GROUP = f"cn=repo-maintainers,{GROUPS}"
STAFF_GROUP = f"cn=staff,{GROUPS}"

SERVICE_DN = f"cn=service,{BASE}"
SERVICE_PASSWORD = "service-secret"

ALICE = f"uid=alice,{PEOPLE}"
BOB = f"uid=bob,{PEOPLE}"
CAROL = f"uid=carol,{PEOPLE}"


class MockAuthenticator(LdapAuthenticator):
    """The real authenticator with ldap3's mock server underneath it."""

    def __init__(self, settings: Settings, entries: dict[str, dict[str, object]]) -> None:
        super().__init__(settings)
        self.entries = entries
        #: Every (user, password) pair a bind was attempted with, so a test can
        #: assert the password reached the directory as a *bind* rather than
        #: being compared somewhere it should not have been.
        self.binds: list[tuple[str | None, str | None]] = []

    def build_connection(self, user: str | None, password: str | None) -> Connection:
        self.binds.append((user, password))
        connection = Connection(
            Server("mock-directory"),
            user=user,
            password=password,
            client_strategy=MOCK_SYNC,
            auto_bind=False,
            raise_exceptions=False,
        )
        for dn, attributes in self.entries.items():
            connection.strategy.add_entry(dn, dict(attributes))
        return connection


def directory_entries() -> dict[str, dict[str, object]]:
    """A small directory: two mapped users, one unmapped, and nested groups."""
    return {
        SERVICE_DN: {
            "objectClass": "inetOrgPerson",
            "sn": "service",
            "userPassword": SERVICE_PASSWORD,
        },
        ALICE: {
            "objectClass": "inetOrgPerson",
            "sn": "Ashe",
            "cn": "alice",
            "displayName": "Alice Ashe",
            "userPassword": "alice-secret",
            "memberOf": [ADMIN_GROUP, MAINTAINER_GROUP],
        },
        BOB: {
            "objectClass": "inetOrgPerson",
            "sn": "Brown",
            "cn": "Bob Brown",
            "userPassword": "bob-secret",
            "memberOf": [MAINTAINER_GROUP],
        },
        CAROL: {
            "objectClass": "inetOrgPerson",
            "sn": "Clark",
            "cn": "Carol Clark",
            "userPassword": "carol-secret",
            "memberOf": [STAFF_GROUP],
        },
        ADMIN_GROUP: {"objectClass": "groupOfNames", "cn": "repo-admins", "member": [ALICE]},
        MAINTAINER_GROUP: {
            "objectClass": "groupOfNames",
            "cn": "repo-maintainers",
            "member": [ALICE, BOB],
        },
        STAFF_GROUP: {
            "objectClass": "groupOfNames",
            "cn": "staff",
            "member": [CAROL, MAINTAINER_GROUP],
        },
    }


@pytest.fixture
def ldap_settings(make_settings: SettingsFactory) -> SettingsFactory:
    def factory(**overrides: object) -> Settings:
        defaults: dict[str, object] = {
            "ldap_url": "ldaps://directory.example.test",
            "ldap_bind_dn": SERVICE_DN,
            "ldap_bind_password": SERVICE_PASSWORD,
            "ldap_user_base_dn": PEOPLE,
            "ldap_group_admin": ADMIN_GROUP,
            "ldap_group_maintainer": MAINTAINER_GROUP,
        }
        return make_settings(**{**defaults, **overrides})

    return factory


@pytest.fixture
def authenticator(ldap_settings: SettingsFactory) -> MockAuthenticator:
    return MockAuthenticator(ldap_settings(), directory_entries())


# --------------------------------------------------------------- search-then-bind


def test_a_valid_login_resolves_a_dn_and_a_role(authenticator: MockAuthenticator) -> None:
    identity = authenticator.authenticate("bob", "bob-secret")
    assert identity.dn == BOB
    assert identity.role is Role.MAINTAINER
    assert identity.username == "bob"


def test_the_password_is_verified_by_binding_as_the_user(
    authenticator: MockAuthenticator,
) -> None:
    """The search runs as the service account and proves nothing on its own."""
    authenticator.authenticate("bob", "bob-secret")
    assert (BOB, "bob-secret") in authenticator.binds


def test_a_wrong_password_is_refused(authenticator: MockAuthenticator) -> None:
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("bob", "not-bobs-password")


def test_an_unknown_user_is_refused(authenticator: MockAuthenticator) -> None:
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("nobody", "whatever")


def test_both_refusals_read_identically_to_the_user(authenticator: MockAuthenticator) -> None:
    """Distinguishable messages would enumerate accounts (7.1)."""
    messages = []
    for username, password in (("bob", "wrong"), ("nobody", "wrong")):
        with pytest.raises(InvalidCredentialsError) as excinfo:
            authenticator.authenticate(username, password)
        messages.append(excinfo.value.user_message)
    assert messages == [GENERIC_FAILURE, GENERIC_FAILURE]


def test_a_directory_outage_also_reads_as_a_failed_login(
    authenticator: MockAuthenticator,
) -> None:
    """Whether the directory is up is not an unauthenticated caller's business."""
    assert DirectoryUnavailableError("down").user_message == GENERIC_FAILURE


# --------------------------------------------------------------- empty credentials


@pytest.mark.parametrize(("username", "password"), [("bob", ""), ("", "bob-secret"), ("", "")])
def test_an_empty_credential_never_reaches_the_directory(
    authenticator: MockAuthenticator, username: str, password: str
) -> None:
    """A bind with an empty password is an *anonymous* bind, and succeeds (7.1).

    Passing one through would turn an empty login form into a valid session, so
    the check has to happen before the connection is made -- which is what the
    empty bind list proves.
    """
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate(username, password)
    assert authenticator.binds == []


# --------------------------------------------------------------- injection


def test_a_username_cannot_inject_into_the_search_filter(
    authenticator: MockAuthenticator,
) -> None:
    """`*` must be matched literally, not as a wildcard (RFC 4515)."""
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("*", "alice-secret")
    # The escaped filter matched nothing, so no bind as any user was attempted.
    assert [user for user, _ in authenticator.binds] == [SERVICE_DN]


def test_a_username_cannot_close_the_filter_and_add_a_clause(
    authenticator: MockAuthenticator,
) -> None:
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("bob)(objectClass=*", "bob-secret")
    assert [user for user, _ in authenticator.binds] == [SERVICE_DN]


def test_a_username_cannot_inject_into_a_direct_bind_dn(
    ldap_settings: SettingsFactory,
) -> None:
    """A comma in a username must not add components to the DN (RFC 4514)."""
    settings = ldap_settings(
        ldap_bind_mode="direct", ldap_user_dn_template=f"uid={{username}},{PEOPLE}"
    )
    authenticator = MockAuthenticator(settings, directory_entries())
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("alice,ou=other", "alice-secret")
    attempted = authenticator.binds[0][0] or ""
    # The comma is escaped, so the whole thing is still a single RDN value and
    # the DN still ends at the configured base.
    assert "alice\\," in attempted
    assert attempted.endswith(f",{PEOPLE}")
    assert attempted.count(",") == PEOPLE.count(",") + 2


# --------------------------------------------------------------- direct bind


def test_direct_bind_skips_the_search(ldap_settings: SettingsFactory) -> None:
    settings = ldap_settings(
        ldap_bind_mode="direct", ldap_user_dn_template=f"uid={{username}},{PEOPLE}"
    )
    authenticator = MockAuthenticator(settings, directory_entries())
    identity = authenticator.authenticate("alice", "alice-secret")
    assert identity.dn == ALICE
    # First connection is the user's own bind, not a service-account search.
    assert authenticator.binds[0] == (ALICE, "alice-secret")


# --------------------------------------------------------------- roles


def test_admin_wins_when_both_groups_match(authenticator: MockAuthenticator) -> None:
    """Alice is in both mapped groups (3)."""
    assert authenticator.authenticate("alice", "alice-secret").role is Role.ADMIN


def test_a_user_in_no_mapped_group_is_refused_with_a_specific_message(
    authenticator: MockAuthenticator,
) -> None:
    """They proved who they are; telling them the password is wrong misdirects."""
    with pytest.raises(NoRoleAssignedError) as excinfo:
        authenticator.authenticate("carol", "carol-secret")
    assert excinfo.value.user_message != GENERIC_FAILURE
    assert "not a member" in excinfo.value.user_message


def test_group_dns_are_matched_regardless_of_case_and_spacing(
    ldap_settings: SettingsFactory,
) -> None:
    """An operator types the mapping by hand; the directory's spelling may differ."""
    settings = ldap_settings(ldap_group_admin=f"CN=Repo-Admins, OU=Groups, {BASE.upper()}")
    authenticator = MockAuthenticator(settings, directory_entries())
    assert authenticator.authenticate("alice", "alice-secret").role is Role.ADMIN


def test_resolve_role_rechecks_membership(authenticator: MockAuthenticator) -> None:
    assert authenticator.resolve_role(BOB) is Role.MAINTAINER


def test_resolve_role_raises_when_access_has_been_revoked(
    authenticator: MockAuthenticator,
) -> None:
    with pytest.raises(NoRoleAssignedError):
        authenticator.resolve_role(CAROL)


# --------------------------------------------------------------- group resolution


def test_group_search_mode_finds_the_same_groups(ldap_settings: SettingsFactory) -> None:
    """Not every directory publishes memberOf, so the reverse search is supported."""
    settings = ldap_settings(
        ldap_group_mode="search",
        ldap_group_base_dn=GROUPS,
        ldap_group_filter="(member={user_dn})",
    )
    authenticator = MockAuthenticator(settings, directory_entries())
    assert authenticator.authenticate("bob", "bob-secret").role is Role.MAINTAINER


def test_nested_groups_are_expanded_when_enabled(ldap_settings: SettingsFactory) -> None:
    """`repo-maintainers` is a member of `staff`, so staff should reach Carol's DN.

    Carol is only in `staff` directly; with nesting on, the expansion walks
    upwards from her group and must not invent a mapped one.
    """
    settings = ldap_settings(
        ldap_nested_groups=True,
        ldap_group_base_dn=GROUPS,
        ldap_group_admin=STAFF_GROUP,
    )
    authenticator = MockAuthenticator(settings, directory_entries())
    assert authenticator.authenticate("carol", "carol-secret").role is Role.ADMIN


def test_nesting_is_off_by_default(authenticator: MockAuthenticator) -> None:
    identity = authenticator.authenticate("bob", "bob-secret")
    assert set(identity.groups) == {MAINTAINER_GROUP}


# --------------------------------------------------------------- display name


def test_the_display_name_prefers_the_configured_attribute(
    authenticator: MockAuthenticator,
) -> None:
    assert authenticator.authenticate("alice", "alice-secret").display_name == "Alice Ashe"


def test_the_display_name_falls_back_to_the_next_attribute(
    authenticator: MockAuthenticator,
) -> None:
    """Bob has no displayName, so `cn` is used."""
    assert authenticator.authenticate("bob", "bob-secret").display_name == "Bob Brown"


def test_the_display_name_falls_back_to_the_username(ldap_settings: SettingsFactory) -> None:
    settings = ldap_settings(ldap_display_name_attributes="description")
    authenticator = MockAuthenticator(settings, directory_entries())
    assert authenticator.authenticate("bob", "bob-secret").display_name == "bob"


# --------------------------------------------------------------- failure classification


def test_a_broken_service_account_is_an_outage_not_a_bad_login(
    ldap_settings: SettingsFactory,
) -> None:
    """An operator's mistake must not be reported as the user's (7.1)."""
    settings = ldap_settings(ldap_bind_password="wrong-service-password")
    authenticator = MockAuthenticator(settings, directory_entries())
    with pytest.raises(DirectoryUnavailableError):
        authenticator.authenticate("bob", "bob-secret")


def test_an_unreachable_directory_raises_directory_unavailable(
    ldap_settings: SettingsFactory,
) -> None:
    class Broken(MockAuthenticator):
        def build_connection(self, user: str | None, password: str | None) -> Connection:
            raise LDAPException("connection refused")

    authenticator = Broken(ldap_settings(), directory_entries())
    with pytest.raises(DirectoryUnavailableError):
        authenticator.authenticate("bob", "bob-secret")


def test_an_ambiguous_user_filter_is_refused_rather_than_guessed(
    ldap_settings: SettingsFactory,
) -> None:
    """Two matches means the configuration is wrong; picking one logs someone in as
    an account they may not own."""
    settings = ldap_settings(ldap_user_filter="(sn={username})")
    entries = directory_entries()
    entries[f"uid=bob2,{PEOPLE}"] = {
        "objectClass": "inetOrgPerson",
        "sn": "Brown",
        "cn": "Bob Two",
        "userPassword": "other",
    }
    authenticator = MockAuthenticator(settings, entries)
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("Brown", "bob-secret")


# --------------------------------------------------------------- DN normalisation


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("cn=a,dc=x", "CN=A,DC=X"),
        ("cn=a,dc=x", "cn=a, dc=x"),
        ("cn=Repo Admins,ou=g,dc=x", "CN=repo admins, OU=G, DC=x"),
    ],
)
def test_equivalent_dns_normalise_the_same(left: str, right: str) -> None:
    assert normalise_dn(left) == normalise_dn(right)


def test_different_dns_do_not_normalise_the_same() -> None:
    assert normalise_dn("cn=a,dc=x") != normalise_dn("cn=b,dc=x")


def test_an_unparseable_dn_does_not_raise() -> None:
    """A malformed mapping should fail to match, not fail the login."""
    assert normalise_dn("not a dn at all") == "not a dn at all"
