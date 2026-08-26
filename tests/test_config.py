"""Configuration loading and validation (specification.md 12)."""

from __future__ import annotations

from pathlib import Path

import pytest

from repository_manager.config import ConfigError, load_settings, required_variables

BASE: dict[str, object] = {
    "allowed_roots": "/srv/repositories",
    "public_url": "https://packages.example.test",
    "secret_key": "s" * 32,
}


def test_required_variables_are_the_three_with_no_default() -> None:
    assert set(required_variables()) == {
        "REPOMAN_ALLOWED_ROOTS",
        "REPOMAN_PUBLIC_URL",
        "REPOMAN_SECRET_KEY",
    }


def test_load_settings_reports_every_missing_variable_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("REPOMAN_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("REPOMAN_PUBLIC_URL", raising=False)
    monkeypatch.delenv("REPOMAN_SECRET_KEY", raising=False)
    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    message = str(excinfo.value)
    assert "REPOMAN_ALLOWED_ROOTS" in message
    assert "REPOMAN_PUBLIC_URL" in message
    assert "REPOMAN_SECRET_KEY" in message


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
    settings = load_settings(allowed_roots="/srv/x", public_url="https://host")
    # The trailing newline that `echo secret > file` leaves behind is stripped.
    assert settings.secret_key.get_secret_value() == "from-a-file"


def test_missing_secret_file_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPOMAN_SECRET_KEY_FILE", str(tmp_path / "absent"))
    with pytest.raises(ConfigError, match="cannot read"):
        load_settings(allowed_roots="/srv/x", public_url="https://host")
