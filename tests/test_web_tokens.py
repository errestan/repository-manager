"""The tokens page (specification.md 7.4, 8.1, 11).

Driven through the forms a browser submits, with no JavaScript, because that is
the contract the interface makes.
"""

from __future__ import annotations

import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.orm import Session

from repository_manager.models import TOKEN_PREFIX, ApiToken, Repository
from tests.conftest import AppFactory, IssuedToken, browser, issue_token, sign_in
from tests.support import directory as fake_directory


def errors_in(response: object) -> list[str]:
    body = getattr(response, "text", "")
    return [text.strip() for text in re.findall(r'<a href="#field-[^"]+">([^<]+)</a>', body)]


def secret_in(body: str) -> str:
    match = re.search(rf'<code class="token-secret">({TOKEN_PREFIX}[A-Za-z0-9_-]+)</code>', body)
    assert match, "no token rendered"
    return match.group(1)


def _mint(client: TestClient, **overrides: str | list[str]) -> Response:
    data: dict[str, str | list[str]] = {
        "label": "build server",
        "scopes": ["package:read", "package:write"],
        "lifetime_days": "30",
    }
    data.update(overrides)
    # Bound to a typed local first: TestClient.post is annotated loosely enough
    # that returning it directly is returning Any.
    response: Response = client.post("/tokens", data=data)
    return response


# ------------------------------------------------------------------ minting


def test_a_token_is_minted_and_shown_once(maintainer_client: TestClient) -> None:
    response = _mint(maintainer_client)
    assert response.status_code == 200, errors_in(response)
    secret = secret_in(response.text)

    # Shown on the response to the POST and never again: the page it renders is
    # the only copy, which is why this route does not redirect.
    assert secret not in maintainer_client.get("/tokens").text


def test_the_minted_token_actually_works(
    manageable_app: FastAPI, apt_repository: Repository
) -> None:
    """The one test that ties the page to the API it exists to serve."""
    with browser(manageable_app) as client:
        sign_in(client, fake_directory.MAINTAINER_USERNAME, fake_directory.MAINTAINER_PASSWORD)
        secret = secret_in(_mint(client).text)

    with browser(manageable_app) as api:
        response = api.post(
            "/api/v1/repositories/internal/regenerate",
            headers={"authorization": f"Bearer {secret}"},
        )
    assert response.status_code == 202


def test_a_new_token_appears_in_the_list_by_its_prefix(maintainer_client: TestClient) -> None:
    secret = secret_in(_mint(maintainer_client).text)
    listing = maintainer_client.get("/tokens").text
    assert "build server" in listing
    assert secret[:12] in listing


def test_a_token_with_no_permissions_is_refused(maintainer_client: TestClient) -> None:
    response = _mint(maintainer_client, scopes=[])
    assert response.status_code == 400
    assert any("at least one" in message for message in errors_in(response))


def test_a_token_with_no_label_is_refused(maintainer_client: TestClient) -> None:
    response = _mint(maintainer_client, label="")
    assert response.status_code == 400
    assert any("label" in message.lower() for message in errors_in(response))


def test_a_lifetime_over_the_maximum_is_refused_on_the_form(
    make_app: AppFactory, apt_repository: Repository
) -> None:
    app = make_app(token_max_lifetime_days=30, token_default_lifetime_days=30)
    with browser(app) as client:
        sign_in(client, fake_directory.MAINTAINER_USERNAME, fake_directory.MAINTAINER_PASSWORD)
        response = _mint(client, lifetime_days="365")
    assert response.status_code == 400
    assert any("at most 30 days" in message for message in errors_in(response))


def test_a_rejected_form_keeps_the_boxes_that_were_ticked(
    maintainer_client: TestClient, apt_repository: Repository
) -> None:
    """Nothing typed is lost when the server says no (11)."""
    response = _mint(
        maintainer_client, label="", scopes=["package:write"], repositories=["internal"]
    )
    body = response.text
    assert re.search(r'value="package:write"[^>]*checked', body, re.DOTALL)
    assert re.search(r'value="internal"[^>]*checked', body, re.DOTALL)
    assert not re.search(r'value="package:read"[^>]*checked', body, re.DOTALL)


def test_a_repository_that_does_not_exist_cannot_be_scoped_to(
    maintainer_client: TestClient, apt_repository: Repository
) -> None:
    response = _mint(maintainer_client, repositories=["not-a-repository"])
    assert response.status_code == 400
    assert any("No such repository" in message for message in errors_in(response))


def test_scoping_to_a_repository_is_recorded(
    maintainer_client: TestClient, sync_session: Session, apt_repository: Repository
) -> None:
    _mint(maintainer_client, repositories=["internal"])
    stored = sync_session.query(ApiToken).one()
    assert stored.repositories == ("internal",)


def test_ticking_nothing_means_every_repository(
    maintainer_client: TestClient, sync_session: Session, apt_repository: Repository
) -> None:
    _mint(maintainer_client)
    stored = sync_session.query(ApiToken).one()
    assert stored.repository_scope is None
    assert stored.unrestricted


# ------------------------------------------------------------------ visibility


def test_a_maintainer_sees_only_their_own(
    maintainer_client: TestClient, sync_session: Session
) -> None:
    issue_token(sync_session, owner=fake_directory.ADMIN_USERNAME, label="ada token")
    _mint(maintainer_client, label="mine")
    listing = maintainer_client.get("/tokens").text
    assert "mine" in listing
    assert "ada token" not in listing


def test_an_admin_sees_everyones(admin_client: TestClient, sync_session: Session) -> None:
    issue_token(sync_session, label="mo token")
    listing = admin_client.get("/tokens").text
    assert "mo token" in listing
    assert fake_directory.MAINTAINER_USERNAME in listing


# ------------------------------------------------------------------ revocation


def test_an_owner_may_revoke_their_own(
    maintainer_client: TestClient, sync_session: Session, write_token: IssuedToken
) -> None:
    response = maintainer_client.post(
        f"/tokens/{write_token.record_id}/revoke", follow_redirects=False
    )
    assert response.status_code == 303
    sync_session.expire_all()
    stored = sync_session.get(ApiToken, write_token.record_id)
    assert stored is not None
    assert stored.revoked


def test_a_revoked_token_stops_working_immediately(
    manageable_app: FastAPI, sync_session: Session, apt_repository: Repository
) -> None:
    token = issue_token(sync_session)
    with browser(manageable_app) as api:
        api.headers.update(token.header)
        assert api.post("/api/v1/repositories/internal/regenerate").status_code == 202

        with browser(manageable_app) as owner:
            sign_in(owner, fake_directory.MAINTAINER_USERNAME, fake_directory.MAINTAINER_PASSWORD)
            owner.post(f"/tokens/{token.record_id}/revoke")

        assert api.post("/api/v1/repositories/internal/regenerate").status_code == 401


def test_a_maintainer_may_not_revoke_someone_elses(
    maintainer_client: TestClient, sync_session: Session
) -> None:
    """Answered as "no such token": which ids exist is not theirs to learn."""
    other = issue_token(sync_session, owner=fake_directory.ADMIN_USERNAME)
    response = maintainer_client.post(f"/tokens/{other.record_id}/revoke", follow_redirects=False)
    assert response.status_code == 404


def test_an_admin_may_revoke_anyones(admin_client: TestClient, sync_session: Session) -> None:
    other = issue_token(sync_session)
    response = admin_client.post(f"/tokens/{other.record_id}/revoke", follow_redirects=False)
    assert response.status_code == 303


def test_revoking_a_token_that_is_not_there_is_a_404(admin_client: TestClient) -> None:
    assert admin_client.post("/tokens/9999/revoke", follow_redirects=False).status_code == 404


# ------------------------------------------------------------------ the audit trail


@pytest.mark.parametrize(
    ("action", "expected"),
    [("mint", "Create API token"), ("revoke", "Revoke API token")],
)
def test_token_actions_are_audited(
    admin_client: TestClient, sync_session: Session, action: str, expected: str
) -> None:
    if action == "mint":
        _mint(admin_client, label="audited")
    else:
        token = issue_token(sync_session, label="audited")
        admin_client.post(f"/tokens/{token.record_id}/revoke")
    assert expected in admin_client.get("/audit").text


def test_the_audit_entry_never_holds_the_token(
    admin_client: TestClient, sync_session: Session
) -> None:
    secret = secret_in(_mint(admin_client).text)
    from repository_manager.models import AuditLog

    entries = sync_session.query(AuditLog).all()
    assert entries
    for entry in entries:
        assert secret not in str(entry.details_json)


def test_a_permission_this_instance_does_not_offer_is_refused(
    maintainer_client: TestClient,
) -> None:
    """The page and the server disagreeing is worth saying, not quietly narrowing."""
    response = _mint(maintainer_client, scopes=["package:read", "package:everything"])
    assert response.status_code == 400
    assert any("not a permission" in message for message in errors_in(response))


def test_a_lifetime_that_is_not_a_number_is_refused(maintainer_client: TestClient) -> None:
    response = _mint(maintainer_client, lifetime_days="soon")
    assert response.status_code == 400
    assert any("whole number" in message for message in errors_in(response))


def test_an_expired_token_is_labelled_as_such(
    maintainer_client: TestClient, sync_session: Session
) -> None:
    """Revoked and expired fail identically to a caller, but a person sees which."""
    issue_token(sync_session, label="stale", expires_in_days=-1)
    assert "Expired" in maintainer_client.get("/tokens").text
