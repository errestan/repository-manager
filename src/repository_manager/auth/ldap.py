"""LDAP authentication and group-to-role mapping (specification.md 7.1, 3).

``ldap3`` is a synchronous library, so everything here is synchronous and the
web layer runs it in a worker thread.  Keeping the blocking code honest about
being blocking is better than wrapping it in an async signature that lies.

Three rules run through the whole module:

* **Nothing user-supplied is interpolated raw.**  A username reaches a filter
  through :func:`ldap3.utils.conv.escape_filter_chars` and a DN through
  :func:`ldap3.utils.dn.escape_rdn` (RFC 4515 and RFC 4514 respectively).
* **The user-facing message never varies.**  "Bad password", "no such user" and
  "the directory is down" are all reported to the browser identically; the real
  reason goes to the log.  Anything else is an account-enumeration oracle.
* **An empty password is a failed login, never a bind attempt.**  LDAP treats a
  bind with an empty password as a request for an *anonymous* session, which
  succeeds -- so passing one through would turn a blank form into a valid login.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from ldap3 import Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn, parse_dn

from repository_manager.config import Settings
from repository_manager.logging import get_logger
from repository_manager.models import Role

log = get_logger(__name__)

#: Shown to whoever failed to log in, whatever the actual reason was (7.1).
GENERIC_FAILURE = "That username and password were not accepted."

#: Shown when the credentials were right but no mapped group matched (3).  This
#: one *is* specific: the person has proved who they are, and telling them their
#: password is wrong would send them to reset a password that works fine.
NO_ROLE_MESSAGE = (
    "Your account is not a member of any group permitted to make changes here. "
    "Ask an administrator to add you to the maintainer or administrator group."
)

_WHITESPACE_AFTER_COMMA = re.compile(r",\s+")


class LdapError(Exception):
    """Base class: carries the message the browser is allowed to see."""

    user_message = GENERIC_FAILURE


class InvalidCredentialsError(LdapError):
    """The username or password did not check out."""


class DirectoryUnavailableError(LdapError):
    """The directory could not be reached, or answered with an error.

    Deliberately reported to the user as an ordinary failed login: whether the
    directory is up is not information an unauthenticated caller needs, and a
    distinguishable message is a probe.
    """


class NoRoleAssignedError(LdapError):
    """Authentication succeeded but no mapped group matched (3)."""

    user_message = NO_ROLE_MESSAGE


@dataclass(frozen=True)
class LdapIdentity:
    """Who logged in, and what they may do."""

    dn: str
    username: str
    display_name: str
    role: Role
    groups: tuple[str, ...] = field(default_factory=tuple)


def normalise_dn(value: str) -> str:
    """A DN in a form two spellings of the same DN both reduce to.

    Directories are inconsistent about attribute-name case and about spaces
    after the commas, and a group mapping typed by hand will not match the
    directory's own spelling byte for byte.  Comparing the parsed form instead
    means ``CN=Repo Admins, OU=Groups, DC=example, DC=test`` and
    ``cn=repo admins,ou=groups,dc=example,dc=test`` are recognised as the same
    group, which is what an operator expects.

    Falls back to a lowercased, whitespace-collapsed string for anything
    ``ldap3`` cannot parse, so a malformed value simply fails to match rather
    than raising during a login.
    """
    collapsed = _WHITESPACE_AFTER_COMMA.sub(",", value.strip())
    try:
        components = parse_dn(collapsed, escape=True)
    except LDAPException:
        return collapsed.lower()
    return ",".join(f"{name.lower()}={value.strip().lower()}" for name, value, _ in components)


class Authenticator(Protocol):
    """What the web layer needs from a directory.

    A Protocol rather than the concrete class so a test -- or a future
    alternative backend -- can supply its own without subclassing ldap3.
    """

    def authenticate(self, username: str, password: str) -> LdapIdentity:
        """Verify credentials and resolve a role, or raise :class:`LdapError`."""
        ...  # pragma: no cover - structural

    def resolve_role(self, dn: str) -> Role:
        """Re-check an already-authenticated user's groups (7.2 revalidation)."""
        ...  # pragma: no cover - structural


class LdapAuthenticator:
    """Search-then-bind or direct-bind authentication against one directory."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._admin_group = normalise_dn(settings.ldap_group_admin)
        self._maintainer_group = normalise_dn(settings.ldap_group_maintainer)

    # -- connections ----------------------------------------------------

    def _server(self) -> Server:
        return Server(
            self.settings.ldap_url,
            connect_timeout=self.settings.ldap_timeout_seconds,
            # Validation is the TLS library's job and is on by default; naming
            # it here documents that it has not been turned off.
            tls=Tls() if self.settings.ldap_uses_tls else None,
            get_info=None,
        )

    def build_connection(self, user: str | None, password: str | None) -> Connection:
        """An unbound connection to the configured directory.

        Factored out as the single place a socket is created, so a test can
        substitute ``ldap3``'s in-memory mock server and still exercise every
        line of bind handling, search building and escaping below it.

        The default synchronous strategy is used, and each connection is created,
        used and unbound inside a single call, so it is never shared between
        threads.
        """
        return Connection(
            self._server(),
            user=user,
            password=password,
            auto_bind=False,
            raise_exceptions=False,
            receive_timeout=self.settings.ldap_timeout_seconds,
        )

    def _connect(self, user: str | None, password: str | None) -> Connection:
        """Bind, raising the right exception for the two failure kinds."""
        try:
            # Construction is inside the try as well as the bind: resolving the
            # server address happens here, so an unreachable or misspelled host
            # raises before a single byte is sent.
            connection = self.build_connection(user, password)
            # `open()` returns None and signals failure by raising, so there is
            # no return value to test here -- only the exception to catch.
            connection.open()
            if self.settings.ldap_start_tls and not connection.start_tls():
                raise DirectoryUnavailableError("StartTLS was refused")
            bound = connection.bind()
        except LDAPException as exc:
            raise DirectoryUnavailableError(str(exc)) from exc
        if not bound:
            raise InvalidCredentialsError(str(connection.result))
        return connection

    def _service_connection(self) -> Connection:
        """Bind as the configured service account, or anonymously if none is set."""
        password = (
            self.settings.ldap_bind_password.get_secret_value()
            if self.settings.ldap_bind_password is not None
            else None
        )
        try:
            return self._connect(self.settings.ldap_bind_dn, password)
        except InvalidCredentialsError as exc:
            # The service account's own password being wrong is an operator
            # problem, not an end-user one; re-classify so it is not reported as
            # the user's failed login.
            raise DirectoryUnavailableError(f"service account bind failed: {exc}") from exc

    @staticmethod
    def _search(
        connection: Connection, base: str, filter_: str, attributes: Sequence[str]
    ) -> list[dict[str, Any]]:
        try:
            connection.search(
                search_base=base,
                search_filter=filter_,
                attributes=list(attributes),
            )
        except LDAPException as exc:
            raise DirectoryUnavailableError(str(exc)) from exc
        # A search response carries referrals alongside real entries; only the
        # latter have a dn and attributes, and only they are entries.
        return [
            entry for entry in (connection.response or []) if entry.get("type") == "searchResEntry"
        ]

    # -- authentication --------------------------------------------------

    def authenticate(self, username: str, password: str) -> LdapIdentity:
        name = username.strip()
        if not name or not password:
            # Never reaches the directory: see the module docstring on empty
            # passwords and anonymous binds.
            raise InvalidCredentialsError("empty username or password")

        if self.settings.ldap_bind_mode == "direct":
            dn, attributes = self._direct_bind(name, password)
        else:
            dn, attributes = self._search_then_bind(name, password)

        groups = self._groups_for(dn)
        role = self._role_from_groups(groups)
        if role is None:
            log.info("login refused: no mapped group", username=name, dn=dn, groups=len(groups))
            raise NoRoleAssignedError(f"{dn} is in no mapped group")

        return LdapIdentity(
            dn=dn,
            username=name,
            display_name=self._display_name(name, attributes),
            role=role,
            groups=groups,
        )

    def _direct_bind(self, username: str, password: str) -> tuple[str, dict[str, Any]]:
        """Format the DN from the template and bind as it.

        ``escape_rdn`` is what stops a username containing a comma from adding
        components to the DN it is being substituted into.
        """
        template = self.settings.ldap_user_dn_template or ""
        dn = template.format(username=escape_rdn(username))
        connection = self._connect(dn, password)
        try:
            entries = self._search(
                connection, dn, "(objectClass=*)", self.settings.ldap_display_name_attributes
            )
        finally:
            connection.unbind()
        attributes = entries[0]["attributes"] if entries else {}
        return dn, dict(attributes)

    def _search_then_bind(self, username: str, password: str) -> tuple[str, dict[str, Any]]:
        """Find the user's DN with the service account, then bind as the user."""
        search_filter = self.settings.ldap_user_filter.format(
            username=escape_filter_chars(username)
        )
        service = self._service_connection()
        try:
            entries = self._search(
                service,
                self.settings.ldap_user_base_dn or "",
                search_filter,
                self.settings.ldap_display_name_attributes,
            )
        finally:
            service.unbind()

        if not entries:
            log.info("login refused: no such user", username=username)
            raise InvalidCredentialsError("no matching entry")
        if len(entries) > 1:
            # An ambiguous filter is a configuration error, and guessing which
            # entry was meant would be a way to log in as the wrong person.
            log.warning(
                "login refused: user filter is ambiguous",
                username=username,
                matches=len(entries),
            )
            raise InvalidCredentialsError(f"{len(entries)} entries matched")

        dn = str(entries[0]["dn"])
        # The bind is what actually verifies the password; the search above ran
        # as the service account and proves nothing about the user.
        self._connect(dn, password).unbind()
        return dn, dict(entries[0]["attributes"])

    def _display_name(self, username: str, attributes: dict[str, Any]) -> str:
        for name in self.settings.ldap_display_name_attributes:
            value = attributes.get(name)
            if isinstance(value, list):
                value = value[0] if value else None
            if value:
                return str(value)
        return username

    # -- groups and roles -------------------------------------------------

    def resolve_role(self, dn: str) -> Role:
        """Re-check group membership for an existing session (7.2).

        Raises :class:`NoRoleAssignedError` when the user has lost every mapped
        group, which is how a revoked account's session is ended early.
        """
        role = self._role_from_groups(self._groups_for(dn))
        if role is None:
            raise NoRoleAssignedError(f"{dn} is in no mapped group")
        return role

    def _groups_for(self, dn: str) -> tuple[str, ...]:
        connection = self._service_connection()
        try:
            direct = (
                self._groups_by_search(connection, dn)
                if self.settings.ldap_group_mode == "search"
                else self._groups_by_attribute(connection, dn)
            )
            if not self.settings.ldap_nested_groups:
                return tuple(direct)
            return tuple(self._expand_nested(connection, direct))
        finally:
            connection.unbind()

    def _groups_by_attribute(self, connection: Connection, dn: str) -> list[str]:
        attribute = self.settings.ldap_group_member_attribute
        entries = self._search(connection, dn, "(objectClass=*)", [attribute])
        if not entries:
            return []
        raw = entries[0]["attributes"].get(attribute) or []
        if isinstance(raw, str):
            raw = [raw]
        return [str(value) for value in raw]

    def _groups_by_search(self, connection: Connection, dn: str) -> list[str]:
        search_filter = self.settings.ldap_group_filter.format(user_dn=escape_filter_chars(dn))
        entries = self._search(
            connection, self.settings.ldap_group_base_dn or "", search_filter, ["cn"]
        )
        return [str(entry["dn"]) for entry in entries]

    def _expand_nested(self, connection: Connection, direct: Iterable[str]) -> list[str]:
        """Walk upwards from the user's direct groups (7.1).

        Bounded by ``ldap_nested_group_depth`` and by a seen-set, because a
        directory is perfectly capable of containing a membership cycle and a
        login is not the place to discover that the hard way.
        """
        base = self.settings.ldap_group_base_dn or self.settings.ldap_user_base_dn or ""
        if not base:
            return list(direct)

        seen = {normalise_dn(group): group for group in direct}
        frontier = list(seen.values())
        for _ in range(self.settings.ldap_nested_group_depth):
            if not frontier:
                break
            found: list[str] = []
            for child in frontier:
                clause = f"(member={escape_filter_chars(child)})"
                for entry in self._search(connection, base, clause, ["cn"]):
                    parent = str(entry["dn"])
                    key = normalise_dn(parent)
                    if key not in seen:
                        seen[key] = parent
                        found.append(parent)
            frontier = found
        return list(seen.values())

    def _role_from_groups(self, groups: Sequence[str]) -> Role | None:
        """Map group membership to a role; ``admin`` wins a tie (3)."""
        normalised = {normalise_dn(group) for group in groups}
        if self._admin_group in normalised:
            return Role.ADMIN
        if self._maintainer_group in normalised:
            return Role.MAINTAINER
        return None
