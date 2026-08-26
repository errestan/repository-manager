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

    # -- limits ------------------------------------------------------------
    max_upload_bytes: int = Field(default=2_147_483_648, gt=0)
    job_concurrency: int = Field(default=2, gt=0)
    token_max_lifetime_days: int = Field(default=365, gt=0)

    # -- behaviour ---------------------------------------------------------
    log_format: Literal["json", "console"] = "json"
    env: Literal["production", "development"] = "production"
    dev_insecure_cookies: bool = False

    # Temporary, and deliberately awkward to switch on.  M2 delivers the write
    # paths (create, upload, remove, regenerate) but M3 delivers the login that
    # is supposed to guard them (13.6).  Rather than ship endpoints that any
    # anonymous caller could drive, they are refused unless an operator opts in,
    # and the opt-in is rejected outright in production.  M3 removes this
    # setting along with the checks that read it.
    allow_unauthenticated_writes: bool = False

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
    def _refuse_open_writes_in_production(self) -> Settings:
        """Never allow the M2 interim write gate to be opened in production."""
        if self.allow_unauthenticated_writes and self.env == "production":
            raise ValueError(
                "allow_unauthenticated_writes cannot be enabled when REPOMAN_ENV=production: "
                "it disables the only thing standing in front of package upload and repository "
                "creation until LDAP authentication lands in M3."
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
