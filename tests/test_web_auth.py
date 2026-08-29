"""Signing in and out, and what the audit trail records (7.1, 7.2, 9)."""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from repository_manager.auth import sessions
from repository_manager.auth.ldap import GENERIC_FAILURE
from repository_manager.models import (
    AuditAction,
    AuditLog,
    AuditOutcome,
    Repository,
    Role,
    UserSession,
)
from repository_manager.models.base import utcnow
from tests.conftest import PUBLIC_URL, AppFactory, browser, sign_in
from tests.support.directory import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    MAINTAINER_PASSWORD,
    MAINTAINER_USERNAME,
    FakeDirectory,
    dn_for,
)


@pytest.fixture
def visitor(manageable_app: FastAPI) -> Iterator[TestClient]:
    with browser(manageable_app) as client:
        yield client


def audit_entries(session: Session, action: AuditAction | None = None) -> list[AuditLog]:
    statement = select(AuditLog).order_by(AuditLog.id)
    if action is not None:
        statement = statement.where(AuditLog.action == action)
    return list(session.execute(statement).scalars())


# --------------------------------------------------------------------- signing in


def test_a_valid_login_starts_a_session(visitor: TestClient) -> None:
    response = visitor.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert sessions.SESSION_COOKIE in response.cookies
    assert "Signed in as" in visitor.get("/").text


def test_the_session_cookie_is_httponly_and_samesite_lax(visitor: TestClient) -> None:
    response = visitor.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    header = response.headers["set-cookie"]
    assert "HttpOnly" in header
    assert "SameSite=lax" in header.lower().replace("samesite=lax", "SameSite=lax")
    assert "Secure" in header


def test_the_cookie_is_scoped_to_the_mount_point(make_app: object) -> None:
    """Two applications on one hostname must not read each other's sessions (13.5)."""
    app = make_app(  # type: ignore[operator]
        public_url="https://packages.example.test/repoman", root_path="/repoman"
    )
    with TestClient(
        app,
        base_url="https://packages.example.test",
        headers={"origin": "https://packages.example.test"},
    ) as client:
        response = client.post(
            "/repoman/login",
            data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            follow_redirects=False,
        )
    assert "Path=/repoman" in response.headers["set-cookie"]


@pytest.mark.parametrize(
    ("username", "password"),
    [
        (ADMIN_USERNAME, "wrong-password"),
        ("no-such-person", "any-password"),
        (ADMIN_USERNAME, ""),
        ("", ""),
    ],
)
def test_a_failed_login_is_refused_uniformly(
    visitor: TestClient, username: str, password: str
) -> None:
    """Every rejection reads the same, so none of them enumerates accounts (7.1)."""
    response = visitor.post("/login", data={"username": username, "password": password})
    assert response.status_code == 401
    assert GENERIC_FAILURE in response.text


def test_a_failed_login_does_not_start_a_session(
    visitor: TestClient, sync_session: Session
) -> None:
    visitor.post("/login", data={"username": ADMIN_USERNAME, "password": "wrong"})
    assert sync_session.scalar(select(UserSession)) is None


def test_a_user_with_no_mapped_group_is_told_why(visitor: TestClient) -> None:
    """They authenticated; a wrong-password message would send them to reset it (3)."""
    response = visitor.post(
        "/login", data={"username": "unmapped", "password": "unmapped-password"}
    )
    assert response.status_code == 401
    assert "not a member of any group" in response.text
    assert GENERIC_FAILURE not in response.text


def test_a_directory_outage_reads_as_an_ordinary_failure(
    visitor: TestClient, directory: FakeDirectory
) -> None:
    directory.unavailable = True
    response = visitor.post("/login", data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert response.status_code == 401
    assert GENERIC_FAILURE in response.text


def test_the_password_is_never_echoed_back(visitor: TestClient) -> None:
    secret = "a-very-distinctive-password"
    response = visitor.post("/login", data={"username": ADMIN_USERNAME, "password": secret})
    assert secret not in response.text


def test_the_username_is_kept_so_it_need_not_be_retyped(visitor: TestClient) -> None:
    response = visitor.post("/login", data={"username": ADMIN_USERNAME, "password": "wrong"})
    assert f'value="{ADMIN_USERNAME}"' in response.text


# --------------------------------------------------------------------- fixation


def test_the_session_is_replaced_on_login(visitor: TestClient, sync_session: Session) -> None:
    """A token planted before login must be worthless after it (7.2)."""
    sign_in(visitor, MAINTAINER_USERNAME, MAINTAINER_PASSWORD)
    first = visitor.cookies[sessions.SESSION_COOKIE]

    visitor.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    second = visitor.cookies[sessions.SESSION_COOKIE]

    assert first != second
    stored = list(sync_session.execute(select(UserSession)).scalars())
    assert [record.token_hash for record in stored] == [sessions.hash_token(second)]


def test_signing_out_destroys_the_session(visitor: TestClient, sync_session: Session) -> None:
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    token = visitor.cookies[sessions.SESSION_COOKIE]
    visitor.post("/logout", follow_redirects=False)
    assert sync_session.scalar(select(UserSession)) is None
    # Replaying the cookie afterwards must not resurrect anything.
    visitor.cookies.set(sessions.SESSION_COOKIE, token)
    assert "Signed in as" not in visitor.get("/").text


def test_signing_out_clears_the_cookie(visitor: TestClient) -> None:
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    response = visitor.post("/logout", follow_redirects=False)
    assert 'repoman_session=""' in response.headers["set-cookie"] or (
        "repoman_session=;" in response.headers["set-cookie"]
    )


# --------------------------------------------------------------------- redirects


@pytest.mark.parametrize(
    "hostile",
    [
        "https://evil.example/steal",
        "//evil.example",
        "javascript:alert(1)",
        "/\\evil.example",
    ],
)
def test_the_post_login_redirect_cannot_leave_the_application(
    visitor: TestClient, hostile: str
) -> None:
    """An open redirect on a login page is worth more than on any other (7.2)."""
    response = visitor.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD, "next": hostile},
        follow_redirects=False,
    )
    location = str(response.headers["location"])
    assert "evil.example" not in location
    assert not location.startswith("javascript:")


def test_an_absolute_url_to_our_own_origin_is_accepted(visitor: TestClient) -> None:
    response = visitor.post(
        "/login",
        data={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD,
            "next": f"{PUBLIC_URL}/keys",
        },
        follow_redirects=False,
    )
    assert str(response.headers["location"]).endswith("/keys")


def test_visiting_the_login_page_while_signed_in_redirects_away(visitor: TestClient) -> None:
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    response = visitor.get("/login", follow_redirects=False)
    assert response.status_code == 303


# --------------------------------------------------------------------- revalidation


def _make_due(sync_session: Session) -> None:
    """Bring the revalidation deadline forward so the next request re-checks."""
    record = sync_session.scalar(select(UserSession))
    assert record is not None
    record.revalidate_after = utcnow() - dt.timedelta(seconds=1)
    sync_session.commit()


def test_a_session_is_not_revalidated_before_its_interval(
    visitor: TestClient, directory: FakeDirectory
) -> None:
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    before = directory.role_lookups
    visitor.get("/")
    visitor.get("/keys")
    assert directory.role_lookups == before


def test_revocation_ends_the_session_at_the_next_revalidation(
    visitor: TestClient, sync_session: Session, directory: FakeDirectory
) -> None:
    """Losing the group must not wait for the session to expire (7.2)."""
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    directory.users[ADMIN_USERNAME].role = None
    _make_due(sync_session)

    body = visitor.get("/").text
    assert "Signed in as" not in body
    assert sync_session.scalar(select(UserSession)) is None


def test_a_demotion_takes_effect_on_the_open_session(
    visitor: TestClient, sync_session: Session, directory: FakeDirectory
) -> None:
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert visitor.get("/repositories/new", follow_redirects=False).status_code == 200

    directory.users[ADMIN_USERNAME].role = Role.MAINTAINER
    _make_due(sync_session)

    assert visitor.get("/repositories/new", follow_redirects=False).status_code == 403


def test_a_directory_outage_does_not_sign_everybody_out(
    visitor: TestClient, sync_session: Session, directory: FakeDirectory
) -> None:
    """An outage would otherwise lock the team out of a system whose data is local."""
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    directory.unavailable = True
    _make_due(sync_session)

    assert "Signed in as" in visitor.get("/").text
    assert sync_session.scalar(select(UserSession)) is not None


def test_a_deferred_revalidation_is_retried_on_the_next_request(
    visitor: TestClient, sync_session: Session, directory: FakeDirectory
) -> None:
    """The deadline is left alone on an error, so recovery needs no extra trigger."""
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    directory.unavailable = True
    _make_due(sync_session)
    visitor.get("/")

    before = directory.role_lookups
    visitor.get("/")
    assert directory.role_lookups > before


# --------------------------------------------------------------------- audit trail


def test_a_successful_login_is_recorded(visitor: TestClient, sync_session: Session) -> None:
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    entries = audit_entries(sync_session, AuditAction.LOGIN)
    assert len(entries) == 1
    assert entries[0].outcome is AuditOutcome.SUCCESS
    assert entries[0].actor == dn_for(ADMIN_USERNAME)


def test_a_failed_login_is_recorded_without_naming_an_actor(
    visitor: TestClient, sync_session: Session
) -> None:
    """There is no verified identity to attribute it to, so the typed name is a detail."""
    visitor.post("/login", data={"username": ADMIN_USERNAME, "password": "wrong"})
    entry = audit_entries(sync_session, AuditAction.LOGIN)[0]
    assert entry.outcome is AuditOutcome.FAILURE
    assert entry.actor == "anonymous"
    assert entry.details_json["username"] == ADMIN_USERNAME


def test_a_login_refused_for_want_of_a_role_is_recorded_as_denied(
    visitor: TestClient, sync_session: Session
) -> None:
    visitor.post("/login", data={"username": "unmapped", "password": "unmapped-password"})
    entry = audit_entries(sync_session, AuditAction.LOGIN)[0]
    assert entry.outcome is AuditOutcome.DENIED


def test_the_password_never_reaches_the_audit_log(
    visitor: TestClient, sync_session: Session
) -> None:
    secret = "another-distinctive-password"
    visitor.post("/login", data={"username": ADMIN_USERNAME, "password": secret})
    entry = audit_entries(sync_session, AuditAction.LOGIN)[0]
    assert secret not in repr(entry.details_json)


def test_signing_out_is_recorded(visitor: TestClient, sync_session: Session) -> None:
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    visitor.post("/logout", follow_redirects=False)
    assert len(audit_entries(sync_session, AuditAction.LOGOUT)) == 1


def test_a_regeneration_is_recorded_against_its_repository(
    maintainer_client: TestClient, sync_session: Session, apt_repository: Repository
) -> None:
    maintainer_client.post("/repositories/internal/regenerate", follow_redirects=False)
    entry = audit_entries(sync_session, AuditAction.REGENERATE)[0]
    assert entry.repository_id == apt_repository.id
    assert entry.actor == dn_for(MAINTAINER_USERNAME)
    assert entry.target == "internal"


def test_the_source_address_is_recorded(visitor: TestClient, sync_session: Session) -> None:
    sign_in(visitor, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert audit_entries(sync_session, AuditAction.LOGIN)[0].source_ip == "testclient"


# --------------------------------------------------------------------- the audit page


def test_an_admin_sees_every_account(
    admin_client: TestClient, manageable_app: FastAPI, sync_session: Session
) -> None:
    with browser(manageable_app) as other:
        sign_in(other, MAINTAINER_USERNAME, MAINTAINER_PASSWORD)
    body = admin_client.get("/audit").text
    assert dn_for(MAINTAINER_USERNAME) in body
    assert dn_for(ADMIN_USERNAME) in body


def test_a_maintainer_sees_only_their_own(
    maintainer_client: TestClient, manageable_app: FastAPI
) -> None:
    """Scoped in the query, so the other rows never reach the response (3)."""
    with browser(manageable_app) as other:
        sign_in(other, ADMIN_USERNAME, ADMIN_PASSWORD)
    body = maintainer_client.get("/audit").text
    assert dn_for(MAINTAINER_USERNAME) in body
    assert dn_for(ADMIN_USERNAME) not in body


def test_the_audit_page_can_be_filtered_by_action(admin_client: TestClient) -> None:
    admin_client.post("/keys/test-key/delete", follow_redirects=False)
    body = admin_client.get("/audit", params={"action": AuditAction.LOGIN.value}).text
    assert "Sign in" in body
    assert "Delete signing key" not in _rows(body)


def test_an_unknown_action_filter_is_ignored_rather_than_erroring(
    admin_client: TestClient,
) -> None:
    assert admin_client.get("/audit", params={"action": "nonsense"}).status_code == 200


def _rows(body: str) -> str:
    match = re.search(r"<tbody>(.*?)</tbody>", body, flags=re.DOTALL)
    return match.group(1) if match else ""


# ------------------------------------------------------------------ rate limiting (10.3)


def test_repeated_wrong_passwords_are_slowed_down(make_app: AppFactory) -> None:
    """Backoff before the directory is contacted, so guessing costs us nothing."""
    app = make_app(login_max_attempts=3, login_lockout_seconds=60)
    with browser(app) as client:
        for _ in range(3):
            refused = client.post("/login", data={"username": ADMIN_USERNAME, "password": "wrong"})
            assert refused.status_code == 401

        throttled = client.post("/login", data={"username": ADMIN_USERNAME, "password": "wrong"})
    assert throttled.status_code == 429
    assert "Too many failed sign-in attempts" in throttled.text


def test_a_lockout_refuses_the_correct_password_too(
    make_app: AppFactory, directory: FakeDirectory
) -> None:
    """Otherwise it would confirm the password by answering differently."""
    app = make_app(login_max_attempts=2, login_lockout_seconds=60)
    with browser(app) as client:
        for _ in range(2):
            client.post("/login", data={"username": ADMIN_USERNAME, "password": "wrong"})
        response = client.post(
            "/login", data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        )
    assert response.status_code == 429
    # The directory was never asked about the last attempt.
    assert directory.role_lookups == 0


def test_a_throttled_attempt_is_audited(make_app: AppFactory, sync_session: Session) -> None:
    """Read from the table rather than the page: signing in to look would need
    an account this instance has just locked out by address."""
    app = make_app(login_max_attempts=1, login_lockout_seconds=60)
    with browser(app) as client:
        client.post("/login", data={"username": ADMIN_USERNAME, "password": "wrong"})
        refused = client.post("/login", data={"username": ADMIN_USERNAME, "password": "wrong"})
    assert refused.status_code == 429

    entries = sync_session.scalars(
        select(AuditLog).where(AuditLog.action == AuditAction.LOGIN)
    ).all()
    denied = [entry for entry in entries if entry.outcome is AuditOutcome.DENIED]
    assert denied
    assert denied[-1].details_json["reason"] == "rate_limited"


def test_signing_in_correctly_clears_the_backoff(make_app: AppFactory) -> None:
    app = make_app(login_max_attempts=5)
    with browser(app) as client:
        for _ in range(2):
            client.post("/login", data={"username": ADMIN_USERNAME, "password": "wrong"})
        # Within the backoff delay the next attempt would be refused, so this
        # proves the reset happens on success rather than merely on time.
        assert sign_in(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert (
            client.post(
                "/login",
                data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
                follow_redirects=False,
            ).status_code
            == 303
        )


def test_another_account_is_unaffected_by_someone_elses_failures(
    make_app: AppFactory,
) -> None:
    app = make_app(login_max_attempts=2, login_lockout_seconds=60)
    with browser(app) as attacker:
        for _ in range(3):
            attacker.post("/login", data={"username": "unmapped", "password": "wrong"})
    # A different client, so a different address is not what makes this pass --
    # the TestClient uses one. The username key is what differs.
    with browser(app) as victim:
        response = victim.post(
            "/login",
            data={"username": MAINTAINER_USERNAME, "password": MAINTAINER_PASSWORD},
            follow_redirects=False,
        )
    assert response.status_code == 429


def test_the_limiter_can_be_switched_off(make_app: AppFactory) -> None:
    app = make_app(rate_limit_enabled=False, login_max_attempts=1)
    with browser(app) as client:
        for _ in range(5):
            assert (
                client.post(
                    "/login", data={"username": ADMIN_USERNAME, "password": "wrong"}
                ).status_code
                == 401
            )
