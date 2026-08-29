"""The optional Prometheus endpoint (specification.md 13.3, 8.1)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from repository_manager.config import ConfigError
from repository_manager.models import JobState, JobType, Repository, SigningKey
from repository_manager.web import metrics as metrics_module
from tests.conftest import AppFactory, Keyring, browser, issue_token, sign_in
from tests.support import directory as fake_directory
from tests.support.debs import DebSpec, build_deb


@pytest.fixture
def observed(make_app: AppFactory) -> FastAPI:
    return make_app(metrics_enabled=True)


def scrape(app: FastAPI) -> str:
    with browser(app) as client:
        response = client.get("/metrics")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/plain")
    body: str = response.text
    return body


# ------------------------------------------------------------------ the switch


def test_metrics_are_off_by_default(client: TestClient) -> None:
    """The endpoint is unauthenticated, so publishing it is a deliberate act."""
    assert client.get("/metrics").status_code == 404


def test_turning_them_on_serves_the_exposition(
    observed: FastAPI, apt_repository: Repository
) -> None:
    body = scrape(observed)
    assert "# HELP repoman_requests_total" in body
    assert "# TYPE repoman_request_duration_seconds histogram" in body


def test_asking_for_metrics_without_the_library_fails_at_startup(
    make_app: AppFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A monitoring endpoint that silently does nothing is worse than none."""

    def refuse() -> object:
        raise ConfigError(metrics_module.MISSING_DEPENDENCY)

    monkeypatch.setattr(metrics_module, "require_client", refuse)
    with pytest.raises(ConfigError, match="prometheus-client"):
        make_app(metrics_enabled=True)


# ------------------------------------------------------------------ what it counts


def test_requests_are_counted_by_matched_route(
    observed: FastAPI, apt_repository: Repository
) -> None:
    """Labelled by template, not path: a thousand bad slugs must not mint a
    thousand time series."""
    with browser(observed) as client:
        client.get("/repositories/internal")
        client.get("/repositories/nope")
        body = client.get("/metrics").text

    assert 'endpoint="/repositories/{slug}"' in body
    assert "internal" not in body.split("repoman_packages")[0]


def test_an_unrouted_request_is_bucketed_together(observed: FastAPI) -> None:
    with browser(observed) as client:
        client.get("/no-such-page")
        body = client.get("/metrics").text
    assert 'endpoint="<unmatched>"' in body


def test_repository_and_package_counts_come_from_the_database(
    observed: FastAPI, apt_repository: Repository, rpm_repository: Repository
) -> None:
    body = scrape(observed)
    assert 'repoman_repositories{type="apt"} 1.0' in body
    assert 'repoman_repositories{type="rpm"} 1.0' in body
    assert 'repoman_packages{repository="internal"} 0.0' in body


def test_every_job_state_is_emitted_even_at_zero(
    observed: FastAPI, apt_repository: Repository
) -> None:
    """A series that appears only on failure cannot be alerted on in advance."""
    body = scrape(observed)
    for state in JobState:
        assert f'repoman_jobs{{state="{state.value}"}}' in body


def test_live_tokens_are_counted(
    observed: FastAPI, sync_session: Session, apt_repository: Repository
) -> None:
    issue_token(sync_session)
    issue_token(sync_session, revoked=True, label="dead")
    issue_token(sync_session, expires_in_days=-1, label="stale")
    body = scrape(observed)
    assert "repoman_api_tokens_live 1.0" in body


def test_job_outcomes_are_recorded_as_they_finish(observed: FastAPI) -> None:
    """Recorded in-process via the queue's observer, not read back from rows."""
    instruments = observed.state.metrics
    instruments.record_job(JobType.REGENERATE_METADATA, JobState.SUCCEEDED, 1.5)
    instruments.record_job(JobType.RESCAN, JobState.FAILED, 0.25)
    body = scrape(observed)

    assert 'repoman_job_outcomes_total{state="succeeded",type="regenerate_metadata"} 1.0' in body
    assert 'repoman_job_outcomes_total{state="failed",type="rescan"} 1.0' in body
    assert 'repoman_job_duration_seconds_count{type="regenerate_metadata"} 1.0' in body


def test_a_job_that_never_started_records_no_duration(observed: FastAPI) -> None:
    instruments = observed.state.metrics
    instruments.record_job(JobType.RESCAN, JobState.CANCELLED, None)
    body = scrape(observed)
    assert 'repoman_job_outcomes_total{state="cancelled",type="rescan"} 1.0' in body
    assert 'repoman_job_duration_seconds_count{type="rescan"}' not in body


def test_upload_bytes_are_counted(
    make_app: AppFactory,
    scratch_keyring: Keyring,
    signing_key: SigningKey,
    repository_root: Path,
    sync_session: Session,
    tmp_path: Path,
) -> None:
    """Through a real upload, so the counter cannot be defined and never called."""
    app = make_app(metrics_enabled=True, gnupghome=str(scratch_keyring.home))
    token = issue_token(sync_session)
    deb = build_deb(DebSpec(name="alpha", version="1.0-1"), tmp_path / "alpha.deb")

    with browser(app) as admin:
        sign_in(admin, fake_directory.ADMIN_USERNAME, fake_directory.ADMIN_PASSWORD)
        created = admin.post(
            "/repositories/new",
            data={
                "name": "Counted",
                "root_path": str(repository_root / "counted"),
                "signing_key_id": str(signing_key.id),
                "retention": "all",
                "format": "apt",
                "codename": "bookworm",
                "components": "main",
                "architectures": "amd64",
            },
            follow_redirects=False,
        )
        slug = str(created.headers["location"]).rsplit("/", 1)[-1]

    with browser(app) as pipeline:
        pipeline.headers.update(token.header)
        published = pipeline.post(
            f"/api/v1/repositories/{slug}/packages",
            data={"distribution": "bookworm", "component": "main"},
            files={"file": ("alpha.deb", deb.read_bytes())},
        )
    assert published.status_code == 201, published.text

    body = scrape(app)
    assert f"repoman_upload_bytes_total {float(deb.stat().st_size)}" in body


def test_the_queue_reports_finished_jobs_to_the_exporter(
    make_app: AppFactory, scratch_keyring: Keyring
) -> None:
    """The wiring, not the instrument: an observer nobody installed counts nothing."""
    app = make_app(metrics_enabled=True, gnupghome=str(scratch_keyring.home))
    with browser(app):
        assert app.state.queue.observer == app.state.metrics.record_job


def test_no_observer_is_installed_when_metrics_are_off(app: FastAPI) -> None:
    with browser(app):
        assert app.state.queue.observer is None


def test_two_applications_do_not_collide_on_metric_names(make_app: AppFactory) -> None:
    """Each has its own registry; the library's global default is never used."""
    first = make_app(metrics_enabled=True)
    second = make_app(metrics_enabled=True)
    assert first.state.metrics.registry is not second.state.metrics.registry
