"""Authentication against a real OpenLDAP (specification.md 7.1).

The unit suite drives ``ldap3``'s in-memory mock, which is fast and exact but
agrees with whatever this code believes about the protocol.  These tests point
the same authenticator at a real directory, so a misunderstanding about how a
bind, a filter or a group search actually behaves shows up here.

The directory's layout is discovered rather than assumed.  Where a container
image puts its users -- ``cn=`` or ``uid=``, under which ``ou`` -- is that
image's business and changes between versions; hard-coding it would produce
failures that say nothing about this code.  The fixtures below find the
accounts and the group first, and skip with a clear message if the directory
does not look the way the CI job promises.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from ldap3 import Connection, Server

from repository_manager.auth.ldap import (
    GENERIC_FAILURE,
    DirectoryUnavailableError,
    InvalidCredentialsError,
    LdapAuthenticator,
    NoRoleAssignedError,
)
from repository_manager.config import Settings
from repository_manager.models import Role
from repository_manager.web.app import create_app
from tests.conftest import SettingsFactory, browser

LDAP_URL = os.environ.get("REPOMAN_LDAP_URL", "")
BIND_DN = os.environ.get("REPOMAN_LDAP_BIND_DN", "")
BIND_PASSWORD = os.environ.get("REPOMAN_LDAP_BIND_PASSWORD", "")
USER_BASE = os.environ.get("REPOMAN_LDAP_USER_BASE_DN", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (LDAP_URL and BIND_DN and USER_BASE),
        reason="a real directory is required; see the integration job in ci.yml",
    ),
]

MAINTAINER_GROUP = f"cn=repo-maintainers,{USER_BASE}"

#: Matches whichever naming attribute the directory used for its user entries.
USER_FILTER = "(|(uid={username})(cn={username}))"


@dataclass(frozen=True)
class Fixture:
    """The DNs this particular directory actually uses."""

    alice: str
    bob: str
    admin_group: str


@pytest.fixture(scope="module")
def admin_connection() -> Iterator[Connection]:
    connection = Connection(Server(LDAP_URL), user=BIND_DN, password=BIND_PASSWORD, auto_bind=True)
    try:
        yield connection
    finally:
        connection.unbind()


def _one_dn(connection: Connection, base: str, search_filter: str) -> str:
    connection.search(base, search_filter, attributes=["cn"])
    entries = [
        entry for entry in connection.response or [] if entry.get("type") == "searchResEntry"
    ]
    if len(entries) != 1:
        pytest.skip(f"expected one entry for {search_filter}, found {len(entries)}")
    return str(entries[0]["dn"])


@pytest.fixture(scope="module")
def fixture(admin_connection: Connection) -> Iterator[Fixture]:
    """Find the seeded accounts, and add a second group to map to maintainer.

    The container fixture creates one group holding both accounts, which can
    neither distinguish the two roles nor show that ``admin`` wins a tie (3).
    """
    found = Fixture(
        alice=_one_dn(admin_connection, USER_BASE, USER_FILTER.format(username="alice")),
        bob=_one_dn(admin_connection, USER_BASE, USER_FILTER.format(username="bob")),
        admin_group=_one_dn(admin_connection, USER_BASE, "(cn=repo-admins)"),
    )
    admin_connection.add(
        MAINTAINER_GROUP,
        "groupOfNames",
        {"cn": "repo-maintainers", "member": [found.bob, found.alice]},
    )
    try:
        yield found
    finally:
        admin_connection.delete(MAINTAINER_GROUP)


@pytest.fixture
def directory_settings(make_settings: SettingsFactory, fixture: Fixture) -> SettingsFactory:
    def factory(**overrides: object) -> Settings:
        defaults: dict[str, object] = {
            "env": "development",
            "ldap_url": LDAP_URL,
            "ldap_allow_insecure": True,
            "ldap_bind_dn": BIND_DN,
            "ldap_bind_password": BIND_PASSWORD,
            "ldap_user_base_dn": USER_BASE,
            "ldap_user_filter": USER_FILTER,
            # The container's OpenLDAP carries no memberOf overlay, which is
            # exactly why the reverse group search exists (7.1).
            "ldap_group_mode": "search",
            "ldap_group_base_dn": USER_BASE,
            "ldap_group_filter": "(member={user_dn})",
            "ldap_group_admin": fixture.admin_group,
            "ldap_group_maintainer": MAINTAINER_GROUP,
        }
        return make_settings(**{**defaults, **overrides})

    return factory


@pytest.fixture
def authenticator(directory_settings: SettingsFactory) -> LdapAuthenticator:
    return LdapAuthenticator(directory_settings())


# --------------------------------------------------------------- authentication


def test_a_real_login_succeeds(authenticator: LdapAuthenticator, fixture: Fixture) -> None:
    identity = authenticator.authenticate("alice", "alicepass")
    assert identity.dn.lower() == fixture.alice.lower()


def test_a_wrong_password_is_refused(authenticator: LdapAuthenticator) -> None:
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("alice", "not-alices-password")


def test_an_unknown_user_is_refused(authenticator: LdapAuthenticator) -> None:
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("mallory", "anything")


def test_an_empty_password_is_refused_before_a_bind_is_attempted(
    authenticator: LdapAuthenticator,
) -> None:
    """An empty password is an *unauthenticated bind* request in LDAP terms.

    Whether a given server honours one is its own configuration, which is
    precisely why the client must not depend on the answer: the check happens
    before a connection is made, so a blank form field cannot become a session
    on any directory (7.1).
    """
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("alice", "")


def test_a_wildcard_username_is_escaped_not_interpreted(
    authenticator: LdapAuthenticator,
) -> None:
    """`(cn=*)` would match every entry if the filter were built by concatenation."""
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("*", "alicepass")


def test_a_filter_fragment_in_a_username_is_escaped(authenticator: LdapAuthenticator) -> None:
    with pytest.raises(InvalidCredentialsError):
        authenticator.authenticate("alice)(objectClass=*", "alicepass")


def test_direct_bind_works_against_a_real_server(
    directory_settings: SettingsFactory, fixture: Fixture
) -> None:
    """The template is built from the DN the directory actually gave Bob."""
    attribute, _, remainder = fixture.bob.partition("=")
    _, _, base = remainder.partition(",")
    settings = directory_settings(
        ldap_bind_mode="direct", ldap_user_dn_template=f"{attribute}={{username}},{base}"
    )
    identity = LdapAuthenticator(settings).authenticate("bob", "bobpass")
    assert identity.dn.lower() == fixture.bob.lower()


# --------------------------------------------------------------- roles


def test_group_membership_maps_to_a_role(authenticator: LdapAuthenticator) -> None:
    assert authenticator.authenticate("bob", "bobpass").role in {Role.ADMIN, Role.MAINTAINER}


def test_admin_wins_when_a_user_is_in_both_groups(authenticator: LdapAuthenticator) -> None:
    """Alice is in the container's group and in the one added above (3)."""
    assert authenticator.authenticate("alice", "alicepass").role is Role.ADMIN


def test_a_user_in_no_mapped_group_is_refused(directory_settings: SettingsFactory) -> None:
    settings = directory_settings(
        ldap_group_admin=f"cn=nobody-is-in-this,{USER_BASE}",
        ldap_group_maintainer=f"cn=nor-this,{USER_BASE}",
    )
    with pytest.raises(NoRoleAssignedError):
        LdapAuthenticator(settings).authenticate("alice", "alicepass")


def test_resolve_role_rechecks_against_the_live_directory(
    authenticator: LdapAuthenticator, fixture: Fixture
) -> None:
    assert authenticator.resolve_role(fixture.alice) is Role.ADMIN


# --------------------------------------------------------------- failure modes


def test_an_unreachable_directory_is_reported_as_an_outage(
    directory_settings: SettingsFactory,
) -> None:
    settings = directory_settings(ldap_url="ldap://127.0.0.1:1", ldap_timeout_seconds=2)
    with pytest.raises(DirectoryUnavailableError):
        LdapAuthenticator(settings).authenticate("alice", "alicepass")


def test_a_bad_service_account_is_an_outage_not_a_bad_login(
    directory_settings: SettingsFactory,
) -> None:
    """An operator's mistake must not be reported as the user's (7.1)."""
    settings = directory_settings(ldap_bind_password="not-the-service-password")
    with pytest.raises(DirectoryUnavailableError):
        LdapAuthenticator(settings).authenticate("alice", "alicepass")


# --------------------------------------------------------------- through the web


def test_signing_in_through_the_web_form_against_a_real_directory(
    directory_settings: SettingsFactory,
) -> None:
    """The whole stack: form post, bind, group search, session row, cookie."""
    app = create_app(directory_settings(), configure_logs=False)
    with browser(app) as client:
        response = client.post(
            "/login",
            data={"username": "alice", "password": "alicepass"},
            follow_redirects=False,
        )
        assert response.status_code == 303, response.text
        body = client.get("/").text
    assert "Signed in as" in body
    assert "Admin" in body


def test_a_rejected_web_login_says_nothing_about_why(
    directory_settings: SettingsFactory,
) -> None:
    """A real bad password and a real unknown user produce the same message (7.1)."""
    app = create_app(directory_settings(), configure_logs=False)
    with browser(app) as client:
        wrong_password = client.post("/login", data={"username": "alice", "password": "wrong"})
        unknown_user = client.post("/login", data={"username": "mallory", "password": "wrong"})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert GENERIC_FAILURE in wrong_password.text
    assert GENERIC_FAILURE in unknown_user.text
