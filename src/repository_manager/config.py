"""Application configuration (specification.md 12).

Settings come from four layers, highest priority first:

1. explicit keyword arguments (tests, embedding)
2. ``REPOMAN_*`` environment variables
3. ``REPOMAN_*_FILE`` variables naming a file whose contents are the value --
   the Docker/Kubernetes secret convention, so a passphrase never has to appear
   in a process environment
4. a TOML file at ``REPOMAN_CONFIG_FILE``

Everything is validated at startup: :func:`load_settings` turns a
``ValidationError`` into an actionable, human-readable message rather than a
stack trace, because the most common deployment failure is a typo in an
environment variable.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import tomllib
from collections.abc import Iterable
from functools import cached_property
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_core import ErrorDetails
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

ENV_PREFIX = "REPOMAN_"
CONFIG_FILE_ENV = f"{ENV_PREFIX}CONFIG_FILE"

# Colon-separated, like PATH -- chosen over comma because these are filesystem
# paths and a comma is a legal character in one.
ROOTS_SEPARATOR = ":"


class ConfigError(Exception):
    """Configuration is invalid; the message is intended for a terminal."""


class SecretFileSettingsSource(PydanticBaseSettingsSource):
    """Read ``REPOMAN_<FIELD>_FILE`` variables, using the file's contents as the value.

    Only fields that exist on the model are considered, so a stray ``*_FILE``
    variable cannot inject an unknown key.  A trailing newline is stripped,
    since ``echo secret > file`` is how these are usually produced.
    """

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        raise NotImplementedError  # pragma: no cover - not used; __call__ is overridden

    def __call__(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for field_name in self.settings_cls.model_fields:
            env_name = f"{ENV_PREFIX}{field_name.upper()}_FILE"
            raw = os.environ.get(env_name)
            if not raw:
                continue
            path = Path(raw)
            try:
                content = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise ConfigError(f"{env_name}: cannot read {path}: {exc}") from exc
            values[field_name] = content.rstrip("\n")
        return values


class TomlFileSettingsSource(PydanticBaseSettingsSource):
    """Read a TOML file named by ``REPOMAN_CONFIG_FILE``.

    Keys are matched to field names case-insensitively so the file can use the
    natural lower-case spelling.  Unknown keys are an error rather than a silent
    no-op -- a misspelled key in a config file is otherwise invisible.
    """

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        raise NotImplementedError  # pragma: no cover - not used; __call__ is overridden

    def __call__(self) -> dict[str, Any]:
        raw = os.environ.get(CONFIG_FILE_ENV)
        if not raw:
            return {}
        path = Path(raw)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ConfigError(f"{CONFIG_FILE_ENV}: cannot read {path}: {exc}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{CONFIG_FILE_ENV}: {path} is not valid TOML: {exc}") from exc

        known = {name.lower() for name in self.settings_cls.model_fields}
        values: dict[str, Any] = {}
        unknown: list[str] = []
        for key, value in data.items():
            if key.lower() in known:
                values[key.lower()] = value
            else:
                unknown.append(key)
        if unknown:
            raise ConfigError(
                f"{path}: unknown setting(s): {', '.join(sorted(unknown))}. "
                "Check the spelling against specification.md 12."
            )
        return values


class Settings(BaseSettings):
    """Validated application configuration."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        extra="ignore",
        frozen=True,
    )

    # -- storage ----------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./repoman.db"
    allowed_roots: Annotated[tuple[Path, ...], NoDecode]
    gnupghome: Path = Path("./gnupg")

    # -- signing -----------------------------------------------------------
    # The domain used in a generated key's UID (4.3).  Defaults to the public
    # URL's host, so a working key can be generated with no extra configuration.
    key_email_domain: str | None = None
    verify_upload_signatures: bool = False

    # -- external identity -------------------------------------------------
    public_url: str
    root_path: str = ""
    # Where the *repository trees* are served from (AD-3): the application only
    # manages their contents, a reverse proxy publishes them.  Client setup
    # snippets are built from this, so it has to be the URL apt will fetch, not
    # the URL of this application's own pages.
    repository_base_url: str | None = None
    trusted_proxies: Annotated[tuple[str, ...], NoDecode] = ()
    send_hsts: bool = True

    # -- secrets -----------------------------------------------------------
    secret_key: SecretStr

    # -- directory (7.1) ---------------------------------------------------
    # Required from M3: there is no local user store, so an instance with no
    # directory has no way for anyone to log in and no way to make a change.
    ldap_url: str
    # Refusing a plaintext bind is the default because the password crosses this
    # connection.  The escape hatch exists for a laptop running a throwaway
    # directory in a container, and is refused in production below.
    ldap_allow_insecure: bool = False
    ldap_start_tls: bool = False
    ldap_timeout_seconds: float = Field(default=10.0, gt=0)

    ldap_bind_mode: Literal["search", "direct"] = "search"
    ldap_bind_dn: str | None = None
    ldap_bind_password: SecretStr | None = None
    ldap_user_base_dn: str | None = None
    ldap_user_filter: str = "(uid={username})"
    ldap_user_dn_template: str | None = None
    # Tried in order; the first one the entry actually has becomes the display
    # name, and the username itself is the final fallback.
    ldap_display_name_attributes: Annotated[tuple[str, ...], NoDecode] = ("displayName", "cn")

    # `memberof` reads the attribute off the user entry; `search` asks the
    # directory which groups list the user.  Both are common and neither is
    # universal, so both are supported (7.1).
    ldap_group_mode: Literal["memberof", "search"] = "memberof"
    ldap_group_member_attribute: str = "memberOf"
    ldap_group_base_dn: str | None = None
    ldap_group_filter: str = "(member={user_dn})"
    ldap_nested_groups: bool = False
    ldap_nested_group_depth: int = Field(default=5, gt=0, le=20)

    ldap_group_admin: str
    ldap_group_maintainer: str

    # -- sessions (7.2) ----------------------------------------------------
    session_idle_timeout_minutes: int = Field(default=8 * 60, gt=0)
    session_absolute_lifetime_minutes: int = Field(default=24 * 60, gt=0)
    session_revalidate_minutes: int = Field(default=15, gt=0)

    # -- limits ------------------------------------------------------------
    max_upload_bytes: int = Field(default=2_147_483_648, gt=0)
    job_concurrency: int = Field(default=2, gt=0)
    token_max_lifetime_days: int = Field(default=365, gt=0)
    # What the token form offers when nobody chooses (7.4).  Ninety days is
    # short enough that a forgotten token stops working within a quarter and
    # long enough that renewing it is not a weekly chore.
    token_default_lifetime_days: int = Field(default=90, gt=0)

    # -- REST API (8.2) ----------------------------------------------------
    # The OpenAPI schema and the reference page it feeds.  Both are anonymous
    # reads describing endpoints that are themselves anonymous or token-gated,
    # so there is nothing here an attacker learns that `curl` would not tell
    # them -- but a deployment that would rather not publish its shape can turn
    # the pair off.
    api_docs_enabled: bool = True

    # -- behaviour ---------------------------------------------------------
    log_format: Literal["json", "console"] = "json"
    env: Literal["production", "development"] = "production"
    dev_insecure_cookies: bool = False

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            SecretFileSettingsSource(settings_cls),
            dotenv_settings,
            TomlFileSettingsSource(settings_cls),
        )

    # -- parsing -----------------------------------------------------------

    @field_validator("allowed_roots", "trusted_proxies", mode="before")
    @classmethod
    def _split_list(cls, value: Any) -> Any:
        """Accept a separator-joined string as well as a real sequence.

        ``NoDecode`` disables pydantic-settings' default JSON decoding, which
        would otherwise reject ``/srv/a:/srv/b``.
        """
        if isinstance(value, str):
            return tuple(part for part in value.split(ROOTS_SEPARATOR) if part.strip())
        return value

    @field_validator("ldap_display_name_attributes", mode="before")
    @classmethod
    def _split_attributes(cls, value: Any) -> Any:
        """Comma-separated, unlike the path lists: these are LDAP attribute names."""
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("allowed_roots")
    @classmethod
    def _roots_must_be_absolute(cls, value: tuple[Path, ...]) -> tuple[Path, ...]:
        if not value:
            raise ValueError("at least one allowed root is required")
        relative = [str(p) for p in value if not p.is_absolute()]
        if relative:
            raise ValueError(f"must be absolute paths: {', '.join(relative)}")
        return tuple(dict.fromkeys(value))

    @field_validator("trusted_proxies")
    @classmethod
    def _proxies_must_parse(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for entry in value:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"{entry!r} is not an IP address or CIDR: {exc}") from exc
        return value

    @field_validator("public_url")
    @classmethod
    def _public_url_is_absolute(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"}:
            raise ValueError("must start with http:// or https://")
        if not parts.netloc:
            raise ValueError("must include a host, e.g. https://packages.example.com")
        if parts.query or parts.fragment:
            raise ValueError("must not contain a query string or fragment")
        return value.rstrip("/")

    @field_validator("repository_base_url")
    @classmethod
    def _repository_base_is_absolute(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"}:
            raise ValueError("must start with http:// or https://")
        if not parts.netloc:
            raise ValueError("must include a host, e.g. https://packages.example.com/repos")
        return value.rstrip("/")

    @field_validator("root_path")
    @classmethod
    def _normalise_root_path(cls, value: str) -> str:
        """Normalise to '' or '/prefix' -- no trailing slash, exactly one leading."""
        trimmed = value.strip().strip("/")
        return f"/{trimmed}" if trimmed else ""

    # -- cross-field validation -------------------------------------------

    @model_validator(mode="after")
    def _root_path_matches_public_url(self) -> Settings:
        url_path = urlsplit(self.public_url).path.rstrip("/")
        if self.root_path and url_path != self.root_path:
            raise ValueError(
                f"root_path is {self.root_path!r} but public_url's path is {url_path or '/'!r}; "
                "they describe the same external prefix and must agree"
            )
        return self

    @model_validator(mode="after")
    def _ldap_transport_is_encrypted(self) -> Settings:
        """The user's password crosses this connection, so refuse plaintext (7.1)."""
        scheme = urlsplit(self.ldap_url).scheme.lower()
        if scheme not in {"ldap", "ldaps"}:
            raise ValueError(
                f"must start with ldaps:// or ldap://, not {scheme or self.ldap_url!r}"
            )
        if scheme == "ldaps" or self.ldap_start_tls:
            return self
        if not self.ldap_allow_insecure:
            raise ValueError(
                "ldap:// carries the bind password in clear text. Use ldaps://, or set "
                "REPOMAN_LDAP_START_TLS=true, or -- for a local development directory "
                "only -- REPOMAN_LDAP_ALLOW_INSECURE=true."
            )
        if self.env == "production":
            raise ValueError(
                "ldap_allow_insecure cannot be enabled when REPOMAN_ENV=production: it sends "
                "every user's password over an unencrypted connection."
            )
        return self

    @model_validator(mode="after")
    def _ldap_bind_mode_is_complete(self) -> Settings:
        """Each bind mode needs its own settings; a half-configured one fails at login."""
        if self.ldap_bind_mode == "search":
            if not self.ldap_user_base_dn:
                raise ValueError(
                    "search bind mode needs REPOMAN_LDAP_USER_BASE_DN, the subtree user "
                    "entries are searched under"
                )
            if "{username}" not in self.ldap_user_filter:
                raise ValueError("must contain the {username} placeholder")
        elif not self.ldap_user_dn_template:
            raise ValueError(
                "direct bind mode needs REPOMAN_LDAP_USER_DN_TEMPLATE, for example "
                "'uid={username},ou=people,dc=example,dc=com'"
            )
        elif "{username}" not in self.ldap_user_dn_template:
            raise ValueError("must contain the {username} placeholder")
        return self

    @model_validator(mode="after")
    def _ldap_group_resolution_is_complete(self) -> Settings:
        if self.ldap_group_mode != "search":
            return self
        if not self.ldap_group_base_dn:
            raise ValueError(
                "group search mode needs REPOMAN_LDAP_GROUP_BASE_DN, the subtree group "
                "entries are searched under"
            )
        if "{user_dn}" not in self.ldap_group_filter:
            raise ValueError("must contain the {user_dn} placeholder")
        return self

    @model_validator(mode="after")
    def _session_lifetimes_are_ordered(self) -> Settings:
        """An idle timeout longer than the absolute lifetime never fires (7.2)."""
        if self.session_idle_timeout_minutes > self.session_absolute_lifetime_minutes:
            raise ValueError(
                f"session_idle_timeout_minutes ({self.session_idle_timeout_minutes}) is longer "
                f"than session_absolute_lifetime_minutes "
                f"({self.session_absolute_lifetime_minutes}), so it could never take effect"
            )
        return self

    @model_validator(mode="after")
    def _token_lifetimes_are_ordered(self) -> Settings:
        """A default longer than the maximum would fail every mint (7.4)."""
        if self.token_default_lifetime_days > self.token_max_lifetime_days:
            raise ValueError(
                f"token_default_lifetime_days ({self.token_default_lifetime_days}) is longer "
                f"than token_max_lifetime_days ({self.token_max_lifetime_days}), so the "
                "default would be refused as soon as anyone accepted it"
            )
        return self

    @model_validator(mode="after")
    def _refuse_insecure_production(self) -> Settings:
        """Refuse to start in production with cookies that cannot be Secure (10.6)."""
        if (
            self.env == "production"
            and urlsplit(self.public_url).scheme == "http"
            and not self.dev_insecure_cookies
        ):
            raise ValueError(
                "public_url is http:// in a production environment, so session cookies "
                "could not be marked Secure. Use https:// (the reverse proxy terminates "
                "TLS), or set REPOMAN_DEV_INSECURE_COOKIES=true to accept the risk."
            )
        return self

    # -- derived values ----------------------------------------------------

    @cached_property
    def effective_root_path(self) -> str:
        """The mount prefix, taken from root_path or inferred from public_url."""
        if self.root_path:
            return self.root_path
        return urlsplit(self.public_url).path.rstrip("/")

    @cached_property
    def public_origin(self) -> str:
        """Scheme and authority of the external URL, with no path."""
        parts = urlsplit(self.public_url)
        return f"{parts.scheme}://{parts.netloc}"

    @cached_property
    def cookie_secure(self) -> bool:
        return urlsplit(self.public_url).scheme == "https"

    @cached_property
    def cookie_path(self) -> str:
        """Scope cookies to the mount point so co-hosted apps cannot read them (13.5)."""
        return self.effective_root_path or "/"

    @cached_property
    def repository_base(self) -> str:
        """Base URL of the served repository trees, for client snippets (4.4).

        Defaults to ``<public_url>/repos``, which is what the reference nginx
        configuration in the documentation maps to the repository roots.
        """
        if self.repository_base_url:
            return self.repository_base_url
        return f"{self.public_url}/repos"

    def repository_url(self, slug: str) -> str:
        return f"{self.repository_base}/{slug}"

    @cached_property
    def key_uid_domain(self) -> str:
        """Email domain for generated signing keys (4.3).

        Falls back to the public URL's hostname so a fresh deployment can
        generate a usable key without being told anything extra.
        """
        if self.key_email_domain:
            return self.key_email_domain
        return urlsplit(self.public_url).hostname or "localhost"

    @cached_property
    def ldap_uses_tls(self) -> bool:
        return urlsplit(self.ldap_url).scheme.lower() == "ldaps" or self.ldap_start_tls

    @cached_property
    def session_idle_timeout(self) -> dt.timedelta:
        return dt.timedelta(minutes=self.session_idle_timeout_minutes)

    @cached_property
    def session_absolute_lifetime(self) -> dt.timedelta:
        return dt.timedelta(minutes=self.session_absolute_lifetime_minutes)

    @cached_property
    def session_revalidate_after(self) -> dt.timedelta:
        return dt.timedelta(minutes=self.session_revalidate_minutes)

    @cached_property
    def trusted_proxy_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return tuple(ipaddress.ip_network(entry, strict=False) for entry in self.trusted_proxies)

    def is_trusted_proxy(self, client: str | None) -> bool:
        """Whether forwarded headers from this peer may be honoured (10.6)."""
        if not client or not self.trusted_proxy_networks:
            return False
        try:
            address = ipaddress.ip_address(client)
        except ValueError:
            return False
        return any(address in network for network in self.trusted_proxy_networks)


def _describe(error: ErrorDetails) -> str:
    location = ".".join(str(part) for part in error["loc"]) or "(model)"
    if location == "(model)":
        return f"  - {error['msg'].removeprefix('Value error, ')}"
    variable = f"{ENV_PREFIX}{location.upper()}"
    return f"  - {variable}: {error['msg'].removeprefix('Value error, ')}"


def load_settings(**overrides: Any) -> Settings:
    """Build :class:`Settings`, reporting problems as a readable message.

    Raises :class:`ConfigError` rather than ``ValidationError`` so callers can
    print the message directly; a stack trace helps nobody diagnose a missing
    environment variable.
    """
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        lines = "\n".join(_describe(error) for error in exc.errors())
        raise ConfigError(
            f"Configuration is invalid:\n{lines}\n\n"
            "See specification.md section 12 for the full list of settings."
        ) from exc


def required_variables() -> Iterable[str]:
    """Names of the settings with no default, for error messages and docs."""
    return sorted(
        f"{ENV_PREFIX}{name.upper()}"
        for name, field in Settings.model_fields.items()
        if field.is_required()
    )
