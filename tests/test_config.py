"""Configuration loading and validation (specification.md 12)."""

from __future__ import annotations

from pathlib import Path

import pytest

from repository_manager.config import ConfigError, load_settings, required_variables

# The directory settings became required in M3: with no directory there is no
# way to sign in, and therefore no way to change anything (12, 7.1).
LDAP: dict[str, object] = {
    "ldap_url": "ldaps://directory.example.test",
    "ldap_user_base_dn": "ou=people,dc=example,dc=test",
    "ldap_group_admin": "cn=repo-admins,ou=groups,dc=example,dc=test",
    "ldap_group_maintainer": "cn=repo-maintainers,ou=groups,dc=example,dc=test",
}

BASE: dict[str, object] = {
    "allowed_roots": "/srv/repositories",
    "public_url": "https://packages.example.test",
    "secret_key": "s" * 32,
    **LDAP,
}

REQUIRED = {
    "REPOMAN_ALLOWED_ROOTS",
    "REPOMAN_PUBLIC_URL",
    "REPOMAN_SECRET_KEY",
    "REPOMAN_LDAP_URL",
    "REPOMAN_LDAP_GROUP_ADMIN",
    "REPOMAN_LDAP_GROUP_MAINTAINER",
}


def test_required_variables_have_no_default() -> None:
    assert set(required_variables()) == REQUIRED


def test_load_settings_reports_every_missing_variable_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in REQUIRED:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    message = str(excinfo.value)
    for name in REQUIRED:
        assert name in message, name


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/srv/a", (Path("/srv/a"),)),
        ("/srv/a:/srv/b", (Path("/srv/a"), Path("/srv/b"))),
        ("/srv/a:/srv/a", (Path("/srv/a"),)),
        ("/srv/a::/srv/b", (Path("/srv/a"), Path("/srv/b"))),
    ],
)
def test_allowed_roots_is_colon_separated(raw: str, expected: tuple[Path, ...]) -> None:
    assert load_settings(**{**BASE, "allowed_roots": raw}).allowed_roots == expected


def test_allowed_roots_must_be_absolute() -> None:
    with pytest.raises(ConfigError, match="absolute"):
        load_settings(**{**BASE, "allowed_roots": "relative/path"})


def test_allowed_roots_must_not_be_empty() -> None:
    with pytest.raises(ConfigError, match="at least one"):
        load_settings(**{**BASE, "allowed_roots": ""})


@pytest.mark.parametrize("value", ["packages.example.test", "ftp://host", "://x"])
def test_public_url_must_have_a_supported_scheme(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(**{**BASE, "public_url": value})


def test_public_url_rejects_query_and_fragment() -> None:
    with pytest.raises(ConfigError, match="query string or fragment"):
        load_settings(**{**BASE, "public_url": "https://host/x?a=1"})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("", ""), ("/repoman", "/repoman"), ("repoman", "/repoman"), ("/repoman/", "/repoman")],
)
def test_root_path_is_normalised(raw: str, expected: str) -> None:
    settings = load_settings(**{**BASE, "public_url": f"https://host{expected}", "root_path": raw})
    assert settings.root_path == expected


def test_root_path_must_agree_with_public_url() -> None:
    with pytest.raises(ConfigError, match="must agree"):
        load_settings(**{**BASE, "public_url": "https://host/a", "root_path": "/b"})


def test_root_path_is_inferred_from_public_url_when_unset() -> None:
    settings = load_settings(**{**BASE, "public_url": "https://host/repoman"})
    assert settings.effective_root_path == "/repoman"


def test_production_refuses_plain_http() -> None:
    with pytest.raises(ConfigError, match="could not be marked Secure"):
        load_settings(**{**BASE, "public_url": "http://host", "env": "production"})


def test_plain_http_is_allowed_when_explicitly_accepted() -> None:
    settings = load_settings(
        **{**BASE, "public_url": "http://host", "env": "production", "dev_insecure_cookies": True}
    )
    assert settings.cookie_secure is False


def test_plain_http_is_allowed_in_development() -> None:
    assert load_settings(**{**BASE, "public_url": "http://host", "env": "development"})


def test_cookie_path_scopes_to_the_mount_point() -> None:
    at_root = load_settings(**BASE)
    at_prefix = load_settings(**{**BASE, "public_url": "https://host/repoman"})
    assert at_root.cookie_path == "/"
    assert at_prefix.cookie_path == "/repoman"


def test_public_origin_excludes_the_path() -> None:
    settings = load_settings(**{**BASE, "public_url": "https://host:8443/repoman"})
    assert settings.public_origin == "https://host:8443"


def test_trusted_proxies_reject_nonsense() -> None:
    with pytest.raises(ConfigError, match="not an IP address or CIDR"):
        load_settings(**{**BASE, "trusted_proxies": "not-an-ip"})


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [("10.1.2.3", True), ("127.0.0.1", True), ("203.0.113.1", False), (None, False), ("x", False)],
)
def test_is_trusted_proxy(candidate: str | None, expected: bool) -> None:
    settings = load_settings(**{**BASE, "trusted_proxies": "127.0.0.1:10.0.0.0/8"})
    assert settings.is_trusted_proxy(candidate) is expected


def test_no_proxies_configured_means_nothing_is_trusted() -> None:
    settings = load_settings(**BASE)
    assert settings.is_trusted_proxy("127.0.0.1") is False


def test_secret_key_is_not_exposed_by_repr() -> None:
    settings = load_settings(**BASE)
    assert "s" * 32 not in repr(settings)
    assert settings.secret_key.get_secret_value() == "s" * 32


def test_settings_from_a_toml_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "repoman.toml"
    config.write_text(
        'allowed_roots = "/srv/from-toml"\n'
        'public_url = "https://toml.example.test"\n'
        'secret_key = "k"\n'
        'ldap_url = "ldaps://directory.example.test"\n'
        'ldap_user_base_dn = "ou=people,dc=example,dc=test"\n'
        'ldap_group_admin = "cn=repo-admins,ou=groups,dc=example,dc=test"\n'
        'ldap_group_maintainer = "cn=repo-maintainers,ou=groups,dc=example,dc=test"\n'
        "job_concurrency = 7\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("REPOMAN_CONFIG_FILE", str(config))
    settings = load_settings()
    assert settings.allowed_roots == (Path("/srv/from-toml"),)
    assert settings.job_concurrency == 7


def test_environment_beats_the_toml_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "repoman.toml"
    config.write_text("job_concurrency = 7\n", encoding="utf-8")
    monkeypatch.setenv("REPOMAN_CONFIG_FILE", str(config))
    monkeypatch.setenv("REPOMAN_JOB_CONCURRENCY", "3")
    assert load_settings(**BASE).job_concurrency == 3


def test_unknown_toml_key_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "repoman.toml"
    config.write_text("job_concurency = 7\n", encoding="utf-8")  # codespell:ignore
    monkeypatch.setenv("REPOMAN_CONFIG_FILE", str(config))
    with pytest.raises(ConfigError, match="unknown setting"):
        load_settings(**BASE)


def test_secret_can_be_supplied_by_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "secret"
    secret.write_text("from-a-file\n", encoding="utf-8")
    monkeypatch.setenv("REPOMAN_SECRET_KEY_FILE", str(secret))
    settings = load_settings(allowed_roots="/srv/x", public_url="https://host", **LDAP)
    # The trailing newline that `echo secret > file` leaves behind is stripped.
    assert settings.secret_key.get_secret_value() == "from-a-file"


def test_missing_secret_file_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPOMAN_SECRET_KEY_FILE", str(tmp_path / "absent"))
    with pytest.raises(ConfigError, match="cannot read"):
        load_settings(allowed_roots="/srv/x", public_url="https://host", **LDAP)


# --------------------------------------------------------------- directory (7.1)


def test_ldaps_is_accepted() -> None:
    assert load_settings(**BASE).ldap_uses_tls is True


def test_plain_ldap_is_refused_by_default() -> None:
    """The bind password crosses this connection in clear text (7.1)."""
    with pytest.raises(ConfigError, match="clear text"):
        load_settings(**{**BASE, "ldap_url": "ldap://directory.example.test"})


def test_plain_ldap_is_accepted_with_start_tls() -> None:
    settings = load_settings(
        **{**BASE, "ldap_url": "ldap://directory.example.test", "ldap_start_tls": True}
    )
    assert settings.ldap_uses_tls is True


def test_plain_ldap_is_accepted_when_explicitly_allowed_outside_production() -> None:
    settings = load_settings(
        **{
            **BASE,
            "ldap_url": "ldap://directory.example.test",
            "ldap_allow_insecure": True,
            "env": "development",
        }
    )
    assert settings.ldap_uses_tls is False


def test_the_insecure_escape_hatch_is_refused_in_production() -> None:
    with pytest.raises(ConfigError, match="production"):
        load_settings(
            **{
                **BASE,
                "ldap_url": "ldap://directory.example.test",
                "ldap_allow_insecure": True,
                "env": "production",
            }
        )


@pytest.mark.parametrize("value", ["directory.example.test", "https://directory", "ldapi://x"])
def test_the_ldap_url_must_be_an_ldap_url(value: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(**{**BASE, "ldap_url": value})


def test_search_bind_mode_needs_a_user_base() -> None:
    with pytest.raises(ConfigError, match="USER_BASE_DN"):
        load_settings(**{**BASE, "ldap_user_base_dn": None})


def test_the_user_filter_must_name_the_username() -> None:
    with pytest.raises(ConfigError, match="username"):
        load_settings(**{**BASE, "ldap_user_filter": "(uid=fixed)"})


def test_direct_bind_mode_needs_a_dn_template() -> None:
    with pytest.raises(ConfigError, match="USER_DN_TEMPLATE"):
        load_settings(**{**BASE, "ldap_bind_mode": "direct"})


def test_the_dn_template_must_name_the_username() -> None:
    with pytest.raises(ConfigError, match="username"):
        load_settings(
            **{
                **BASE,
                "ldap_bind_mode": "direct",
                "ldap_user_dn_template": "uid=fixed,ou=people,dc=example,dc=test",
            }
        )


def test_group_search_mode_needs_a_group_base() -> None:
    with pytest.raises(ConfigError, match="GROUP_BASE_DN"):
        load_settings(**{**BASE, "ldap_group_mode": "search"})


def test_the_group_filter_must_name_the_user_dn() -> None:
    with pytest.raises(ConfigError, match="user_dn"):
        load_settings(
            **{
                **BASE,
                "ldap_group_mode": "search",
                "ldap_group_base_dn": "ou=groups,dc=example,dc=test",
                "ldap_group_filter": "(objectClass=groupOfNames)",
            }
        )


def test_display_name_attributes_are_comma_separated() -> None:
    settings = load_settings(**{**BASE, "ldap_display_name_attributes": "gecos, cn"})
    assert settings.ldap_display_name_attributes == ("gecos", "cn")


# --------------------------------------------------------------- sessions (7.2)


def test_session_lifetimes_have_the_specified_defaults() -> None:
    settings = load_settings(**BASE)
    assert settings.session_idle_timeout.total_seconds() == 8 * 3600
    assert settings.session_absolute_lifetime.total_seconds() == 24 * 3600
    assert settings.session_revalidate_after.total_seconds() == 15 * 60


def test_an_idle_timeout_longer_than_the_lifetime_is_refused() -> None:
    """It could never fire, so accepting it would silently mean something else."""
    with pytest.raises(ConfigError, match="never take effect"):
        load_settings(
            **{
                **BASE,
                "session_idle_timeout_minutes": 2880,
                "session_absolute_lifetime_minutes": 1440,
            }
        )


@pytest.mark.parametrize(
    "field",
    [
        "session_idle_timeout_minutes",
        "session_absolute_lifetime_minutes",
        "session_revalidate_minutes",
    ],
)
def test_session_durations_must_be_positive(field: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(**{**BASE, field: 0})


# --------------------------------------------------------------- API tokens (7.4)


def test_token_lifetimes_have_the_specified_defaults() -> None:
    settings = load_settings(**BASE)
    assert settings.token_default_lifetime_days == 90
    assert settings.token_max_lifetime_days == 365


def test_a_default_token_lifetime_over_the_maximum_is_refused() -> None:
    """Every mint would be refused as soon as anyone accepted the default."""
    with pytest.raises(ConfigError, match="longer than token_max_lifetime_days"):
        load_settings(
            **{**BASE, "token_default_lifetime_days": 400, "token_max_lifetime_days": 365}
        )


@pytest.mark.parametrize("field", ["token_default_lifetime_days", "token_max_lifetime_days"])
def test_token_lifetimes_must_be_positive(field: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(**{**BASE, field: 0})


def test_the_api_documentation_is_served_by_default() -> None:
    """It describes endpoints that are anonymous or refuse without a token (8.2)."""
    assert load_settings(**BASE).api_docs_enabled is True


def test_the_api_documentation_can_be_switched_off() -> None:
    assert load_settings(**BASE, api_docs_enabled=False).api_docs_enabled is False
