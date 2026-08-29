"""Optional Prometheus metrics (specification.md 13.3, 8.1).

Off unless ``REPOMAN_METRICS_ENABLED=true``, and when off the route does not
exist at all rather than answering 404 from a check somebody could get wrong.
The endpoint is unauthenticated when it is on — a scraper is not a user and has
no session — so turning it on is a deployment decision about who can reach the
port, which the deployment documentation spells out.

``prometheus-client`` is an optional dependency.  Asking for metrics without it
installed is a startup failure with an actionable message, not a route that
quietly serves nothing: a monitoring endpoint that silently does not work is
worse than one that is absent, because somebody will build an alert on it.

Two kinds of number live here, and the difference is worth knowing when reading
a dashboard.  Requests, upload bytes and job durations are **counted in this
process**, so they reset when it restarts and are per replica.  Repository,
package and job-queue counts are **read from the database at scrape time**, so
they are the same from every replica and survive a restart.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from repository_manager.config import ConfigError
from repository_manager.models import (
    ApiToken,
    Job,
    JobState,
    JobType,
    Package,
    Repository,
)

if TYPE_CHECKING:  # pragma: no cover - imported for typing only
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

MISSING_DEPENDENCY = (
    "REPOMAN_METRICS_ENABLED is true but prometheus-client is not installed. "
    "Install the metrics extra: pip install 'repository-manager[metrics]'."
)

#: Request durations, in seconds.  Chosen around what this application actually
#: does: a page render is milliseconds, an upload is bounded by the network, and
#: anything past ten seconds is worth seeing as its own bucket.
DURATION_BUCKETS = (0.005, 0.025, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)

#: Job durations run much longer: a `createrepo_c` pass over a large repository
#: is minutes, not milliseconds.
JOB_BUCKETS = (0.1, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0)


def require_client() -> Any:
    """Import ``prometheus_client``, or explain what to install."""
    try:
        import prometheus_client
    except ImportError as exc:  # pragma: no cover - exercised by the config test
        raise ConfigError(MISSING_DEPENDENCY) from exc
    return prometheus_client


class Metrics:
    """Every instrument this application exports.

    Built with its own registry rather than the library's global default, so
    two applications in one process (which is exactly what the test suite is)
    do not collide on metric names.
    """

    def __init__(self) -> None:
        client = require_client()
        self.client = client
        self.registry = client.CollectorRegistry()

        self.requests = client.Counter(
            "repoman_requests_total",
            "HTTP requests served.",
            ["method", "endpoint", "status"],
            registry=self.registry,
        )
        self.request_duration = client.Histogram(
            "repoman_request_duration_seconds",
            "Time to serve an HTTP request.",
            ["method", "endpoint"],
            buckets=DURATION_BUCKETS,
            registry=self.registry,
        )
        self.upload_bytes = client.Counter(
            "repoman_upload_bytes_total",
            "Bytes accepted from package uploads.",
            registry=self.registry,
        )
        self.job_duration = client.Histogram(
            "repoman_job_duration_seconds",
            "Time a background job took to run.",
            ["type"],
            buckets=JOB_BUCKETS,
            registry=self.registry,
        )
        self.job_outcomes = client.Counter(
            "repoman_job_outcomes_total",
            "Background jobs by how they ended.",
            ["type", "state"],
            registry=self.registry,
        )

        # Read from the database on each scrape; see the module docstring.
        self.repositories = client.Gauge(
            "repoman_repositories",
            "Repositories registered, by type.",
            ["type"],
            registry=self.registry,
        )
        self.packages = client.Gauge(
            "repoman_packages",
            "Packages stored, by repository.",
            ["repository"],
            registry=self.registry,
        )
        self.jobs = client.Gauge(
            "repoman_jobs",
            "Jobs in the queue, by state.",
            ["state"],
            registry=self.registry,
        )
        self.tokens = client.Gauge(
            "repoman_api_tokens_live",
            "API tokens that are neither expired nor revoked.",
            registry=self.registry,
        )

    # -- recorded in this process -----------------------------------------

    def record_request(self, method: str, endpoint: str, status: int, seconds: float) -> None:
        self.requests.labels(method=method, endpoint=endpoint, status=str(status)).inc()
        self.request_duration.labels(method=method, endpoint=endpoint).observe(seconds)

    def record_upload(self, size: int) -> None:
        self.upload_bytes.inc(max(0, size))

    def record_job(self, job_type: JobType, state: JobState, seconds: float | None) -> None:
        self.job_outcomes.labels(type=job_type.value, state=state.value).inc()
        if seconds is not None:
            self.job_duration.labels(type=job_type.value).observe(max(0.0, seconds))

    # -- read at scrape time ----------------------------------------------

    async def refresh(self, session: AsyncSession) -> None:
        """Fill the database-backed gauges.

        Deliberately a handful of aggregate queries rather than a walk of the
        rows: a scrape happens every fifteen seconds forever, and a metrics
        endpoint that gets slower as the repository grows is a metrics endpoint
        that eventually takes the application down with it.
        """
        self.repositories.clear()
        for repository_type, count in (
            await session.execute(
                select(Repository.type, func.count(Repository.id))
                .where(Repository.deregistered_at.is_(None))
                .group_by(Repository.type)
            )
        ).all():
            self.repositories.labels(type=repository_type.value).set(count)

        self.packages.clear()
        for slug, count in (
            await session.execute(
                select(Repository.slug, func.count(Package.id))
                .select_from(Repository)
                .outerjoin(Package, Package.repository_id == Repository.id)
                .where(Repository.deregistered_at.is_(None))
                .group_by(Repository.slug)
            )
        ).all():
            self.packages.labels(repository=slug).set(count)

        # Seeded with every state at zero: a series that appears only once
        # something fails is a series no alert can be written against ahead of
        # time.
        counts: dict[JobState, int] = dict.fromkeys(JobState, 0)
        for state, total in (
            await session.execute(select(Job.state, func.count(Job.id)).group_by(Job.state))
        ).all():
            counts[state] = total
        for state, total in counts.items():
            self.jobs.labels(state=state.value).set(total)

        live = await session.scalar(
            select(func.count(ApiToken.id)).where(
                ApiToken.revoked_at.is_(None), ApiToken.expires_at > func.now()
            )
        )
        self.tokens.set(int(live or 0))

    def render(self) -> tuple[bytes, str]:
        return self.client.generate_latest(self.registry), self.client.CONTENT_TYPE_LATEST


def endpoint_of(scope: Scope) -> str:
    """A low-cardinality label for the route that served this request.

    The *template* rather than the path: labelling by
    ``/repositories/internal`` would mint a new time series per repository, and
    a caller asking for a thousand nonexistent slugs would mint a thousand more.
    Anything that did not match a route is bucketed together as ``<unmatched>``
    for the same reason.
    """
    route = scope.get("route")
    path = getattr(route, "path", None)
    return str(path) if path else "<unmatched>"


class MetricsMiddleware:
    """Count and time every request, labelled by matched route.

    Added only when metrics are enabled, so an instance that does not export
    them does not pay for them either.
    """

    def __init__(self, app: ASGIApp, metrics: Metrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # Read after the call: routing is what sets `route` on the scope,
            # so asking before would label everything `<unmatched>`.
            self.metrics.record_request(
                str(scope.get("method", "")),
                endpoint_of(scope),
                status_code,
                time.perf_counter() - started,
            )


async def snapshot(
    metrics: Metrics, sessionmaker: async_sessionmaker[AsyncSession]
) -> tuple[bytes, str]:
    async with sessionmaker() as session:
        await metrics.refresh(session)
    return metrics.render()
