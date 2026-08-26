"""Log redaction and request identity (specification.md 10.7, 13.3)."""

from __future__ import annotations

from typing import Literal

import pytest

from repository_manager.logging import (
    REDACTED,
    add_request_id,
    configure_logging,
    get_logger,
    redact_secrets,
    request_id_var,
)


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "PASSWORD",
        "ldap_bind_password",
        "passphrase",
        "secret_key",
        "api_token",
        "cookie",
        "authorization",
        "csrf_secret",
        "session_id",
    ],
)
def test_sensitive_keys_are_redacted(key: str) -> None:
    assert redact_secrets(None, "info", {key: "value"})[key] == REDACTED


@pytest.mark.parametrize("key", ["repository", "slug", "count", "user_dn", "path"])
def test_ordinary_keys_are_untouched(key: str) -> None:
    assert redact_secrets(None, "info", {key: "value"})[key] == "value"


def test_redaction_reaches_into_nested_structures() -> None:
    event = {
        "outer": {"token": "abc", "safe": 1, "deeper": {"password": "p"}},
        "items": [{"api_key": "k"}, {"name": "fine"}],
    }
    result = redact_secrets(None, "info", event)
    assert result["outer"]["token"] == REDACTED
    assert result["outer"]["safe"] == 1
    assert result["outer"]["deeper"]["password"] == REDACTED
    assert result["items"][0]["api_key"] == REDACTED
    assert result["items"][1]["name"] == "fine"


def test_request_id_is_added_when_set() -> None:
    token = request_id_var.set("abc123")
    try:
        assert add_request_id(None, "info", {})["request_id"] == "abc123"
    finally:
        request_id_var.reset(token)


def test_request_id_is_absent_outside_a_request() -> None:
    token = request_id_var.set(None)
    try:
        assert "request_id" not in add_request_id(None, "info", {})
    finally:
        request_id_var.reset(token)


@pytest.mark.parametrize("log_format", ["json", "console"])
def test_configure_logging_accepts_both_formats(log_format: Literal["json", "console"]) -> None:
    """Both renderers must construct; startup must not depend on which is chosen."""
    configure_logging(log_format)
    assert get_logger("test") is not None
