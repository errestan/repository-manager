"""Proxy trust, request identity and security headers (specification.md 10.1, 10.6)."""

from __future__ import annotations

import re

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from repository_manager.models import Repository
from tests.conftest import AppFactory, issue_token

PROXY = ("127.0.0.1", 5555)
STRANGER = ("203.0.113.99", 5555)


def _with_probe(app: FastAPI) -> FastAPI:
    @app.get("/whoami")
    async def whoami(request: Request) -> dict[str, str | None]:
        return {
            "ip": request.scope.get("client_ip"),
            "root_path": request.scope.get("root_path"),
            "scheme": request.scope.get("scheme"),
        }

    return app


def _paths(html: str) -> set[str]:
    return {
        re.sub(r"^https?://[^/]+", "", url)
        for url in re.findall(r'(?:href|action)="([^"#]+)"', html)
        if "testserver" in url
    }


# --------------------------------------------------------------- security headers


def test_security_headers_are_present(client: TestClient) -> None:
    headers = client.get("/").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert headers["x-frame-options"] == "DENY"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert "camera=()" in headers["permissions-policy"]


def test_csp_has_a_nonce_and_no_unsafe_inline(client: TestClient) -> None:
    csp = client.get("/").headers["content-security-policy"]
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert re.search(r"script-src 'self' 'nonce-[\w-]+'", csp)
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'none'" in csp


def test_csp_nonce_changes_between_responses(client: TestClient) -> None:
    first = client.get("/").headers["content-security-policy"]
    second = client.get("/").headers["content-security-policy"]
    assert first != second


def test_hsts_is_absent_over_plain_http(app: FastAPI) -> None:
    """A client reaching the app over http gets no HSTS, whatever the config says.

    Built with its own http client rather than the shared fixture: that one
    addresses the https public URL, because session cookies are Secure and would
    otherwise never be sent (see tests/conftest.py).
    """
    with TestClient(app) as plain:
        assert "strict-transport-security" not in plain.get("/").headers


def test_hsts_is_sent_over_https_via_a_trusted_proxy(make_app: AppFactory) -> None:
    app = make_app(trusted_proxies="127.0.0.1")
    with TestClient(app, client=PROXY) as client:
        response = client.get("/", headers={"X-Forwarded-Proto": "https"})
    assert response.headers["strict-transport-security"].startswith("max-age=")


def test_hsts_can_be_suppressed_when_the_proxy_sends_it(make_app: AppFactory) -> None:
    app = make_app(trusted_proxies="127.0.0.1", send_hsts=False)
    with TestClient(app, client=PROXY) as client:
        response = client.get("/", headers={"X-Forwarded-Proto": "https"})
    assert "strict-transport-security" not in response.headers


# --------------------------------------------------------------- request identity


def test_every_response_carries_a_request_id(client: TestClient) -> None:
    assert client.get("/").headers["x-request-id"]


def test_request_ids_are_unique(client: TestClient) -> None:
    first = client.get("/").headers["x-request-id"]
    second = client.get("/").headers["x-request-id"]
    assert first != second


# --------------------------------------------------------------- forwarded-for


@pytest.mark.parametrize(
    ("forwarded_for", "expected"),
    [
        ("203.0.113.7", "203.0.113.7"),
        # The right-most entry that is not itself a trusted proxy wins.
        ("203.0.113.7, 10.0.0.5", "203.0.113.7"),
        ("9.9.9.9, 203.0.113.7, 10.0.0.5", "203.0.113.7"),
        # A chain that is entirely trusted leaves only the peer to believe.
        ("10.0.0.9, 10.0.0.5", "127.0.0.1"),
    ],
)
def test_client_ip_from_trusted_proxy(
    make_app: AppFactory, forwarded_for: str, expected: str
) -> None:
    app = _with_probe(make_app(trusted_proxies="127.0.0.1:10.0.0.0/8"))
    with TestClient(app, client=PROXY) as client:
        body = client.get("/whoami", headers={"X-Forwarded-For": forwarded_for}).json()
    assert body["ip"] == expected


def test_untrusted_peer_cannot_spoof_its_address(make_app: AppFactory) -> None:
    """Without a trusted-proxy list, X-Forwarded-For is ignored entirely (10.6).

    Otherwise any client could escape login rate limiting and poison the audit
    log by inventing a source address.
    """
    app = _with_probe(make_app())
    with TestClient(app, client=STRANGER) as client:
        body = client.get("/whoami", headers={"X-Forwarded-For": "1.2.3.4"}).json()
    assert body["ip"] == "203.0.113.99"


def test_peer_address_is_used_when_no_header_is_sent(make_app: AppFactory) -> None:
    app = _with_probe(make_app(trusted_proxies="127.0.0.1"))
    with TestClient(app, client=PROXY) as client:
        assert client.get("/whoami").json()["ip"] == "127.0.0.1"


def test_untrusted_peer_cannot_force_https_scheme(make_app: AppFactory) -> None:
    app = _with_probe(make_app())
    with TestClient(app, client=STRANGER) as client:
        response = client.get("/whoami", headers={"X-Forwarded-Proto": "https"})
    assert response.json()["scheme"] == "http"
    assert "strict-transport-security" not in response.headers


# --------------------------------------------------------------- sub-path (AD-14)


def test_untrusted_peer_cannot_inject_a_prefix(make_app: AppFactory) -> None:
    app = _with_probe(make_app())
    with TestClient(app, client=STRANGER) as client:
        body = client.get("/whoami", headers={"X-Forwarded-Prefix": "/evil"}).json()
    assert body["root_path"] == ""


def test_trusted_proxy_may_set_the_prefix(make_app: AppFactory) -> None:
    app = _with_probe(make_app(trusted_proxies="127.0.0.1"))
    with TestClient(app, client=PROXY) as client:
        body = client.get("/whoami", headers={"X-Forwarded-Prefix": "/repoman"}).json()
    assert body["root_path"] == "/repoman"


def test_configured_prefix_serves_when_the_proxy_passes_it_through(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    """`proxy_pass` that keeps the prefix in the path (13.5)."""
    app = make_app(public_url="https://packages.example.test/repoman", root_path="/repoman")
    with TestClient(app) as client:
        for path in (
            "/repoman/",
            "/repoman/healthz",
            "/repoman/readyz",
            "/repoman/repositories/internal",
            "/repoman/static/css/app.css",
        ):
            assert client.get(path).status_code == 200, path


def test_prefix_applies_when_the_proxy_strips_it(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    """A proxy that strips the prefix and sends X-Forwarded-Prefix (13.5)."""
    app = make_app(trusted_proxies="127.0.0.1")
    headers = {"X-Forwarded-Prefix": "/repoman"}
    with TestClient(app, client=PROXY) as client:
        for path in ("/", "/repositories/internal", "/static/css/app.css"):
            assert client.get(path, headers=headers).status_code == 200, path
        links = _paths(client.get("/", headers=headers).text)
    assert links, "expected in-app links"
    assert all(link.startswith("/repoman/") for link in links), links


def test_every_generated_link_carries_the_prefix(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    app = make_app(public_url="https://packages.example.test/repoman", root_path="/repoman")
    with TestClient(app) as client:
        links = _paths(client.get("/repoman/").text)
    assert links
    assert all(link.startswith("/repoman/") for link in links), links


def test_no_prefix_appears_when_mounted_at_the_root(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    app = make_app()
    with TestClient(app) as client:
        links = _paths(client.get("/").text)
    assert links
    assert not any(link.startswith("/repoman") for link in links), links


def test_the_current_page_is_marked_under_a_prefix(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    """`aria-current="page"` has to survive a sub-path deployment (11, 13.5).

    The prefix appears in ``scope["path"]`` and again in ``root_path``, so a
    page that recombined the two compared ``/repoman/repoman/`` against
    ``/repoman/`` and marked nothing at all.
    """
    app = make_app(public_url="https://packages.example.test/repoman", root_path="/repoman")
    with TestClient(app) as client:
        at_root = client.get("/repoman/").text
        at_keys = client.get("/repoman/keys").text
    assert 'aria-current="page"' in at_root
    assert 'aria-current="page"' in at_keys


def test_the_api_is_recognised_under_a_prefix(
    make_app: AppFactory, sync_session: Session, apt_repository: Repository
) -> None:
    """The token gate keys on the routed path, not the raw one (7.4, 13.5).

    Getting this wrong would not be a 404: the request would fall through to
    the session-authenticated branch, which is a security boundary in the wrong
    place.
    """
    app = make_app(public_url="https://packages.example.test/repoman", root_path="/repoman")
    token = issue_token(sync_session)
    with TestClient(app, base_url="https://packages.example.test") as client:
        response = client.post(
            "/repoman/api/v1/repositories/internal/regenerate", headers=token.header
        )
    assert response.status_code == 202


def test_a_probe_is_not_logged_under_a_prefix(
    make_app: AppFactory, caplog: pytest.LogCaptureFixture
) -> None:
    """Health checks run once a second; the log filter has to see through the prefix."""
    app = make_app(public_url="https://packages.example.test/repoman", root_path="/repoman")
    with TestClient(app) as client, caplog.at_level("INFO"):
        client.get("/repoman/healthz")
    assert not [record for record in caplog.records if record.msg == "request"]
