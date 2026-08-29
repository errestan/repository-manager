"""An asyncio worker pool backed by the ``job`` table (specification.md 6).

The database is the queue, not a convenience mirror of one held in memory.
That choice buys three properties the specification asks for:

* a job survives a restart, so an interrupted regeneration can be re-queued
  rather than silently lost;
* claiming is a conditional ``UPDATE``, so two workers -- or two processes --
  cannot run the same job; and
* "one job at a time per repository" is expressed in the claim query itself,
  so no worker is ever blocked holding a slot while it waits for a lock.

CPU-bound and subprocess work belongs in ``asyncio.to_thread``; a handler that
blocks the loop stalls every other job and the web application with it.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import CursorResult, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.config import Settings
from repository_manager.logging import get_logger
from repository_manager.models import Job, JobState, JobType
from repository_manager.models.base import utcnow

log = get_logger(__name__)

# How long a worker waits before looking for work again when the queue is
# empty.  Enqueue wakes workers immediately, so this only bounds how quickly a
# *second* process notices work -- it is not the normal path.
POLL_INTERVAL_SECONDS = 1.0

# Message recorded against jobs that were running when the process stopped.
RESTART_REASON = (
    "The application restarted while this job was running, so its result is unknown. "
    "Metadata regeneration has been re-queued."
)


@dataclass
class JobContext:
    """What a handler is given, and the only way it should report progress."""

    job_id: int
    repository_id: int | None
    settings: Settings
    sessionmaker: async_sessionmaker[AsyncSession]

    async def log(self, message: str) -> None:
        """Append a line to the job's log excerpt, visible in the UI."""
        async with self.sessionmaker() as session, session.begin():
            job = await session.get(Job, self.job_id)
            if job is not None:
                job.append_log(message)

    async def set_progress(self, percent: int) -> None:
        """Record progress as a number, which the UI renders as text (11)."""
        bounded = max(0, min(100, percent))
        async with self.sessionmaker() as session, session.begin():
            job = await session.get(Job, self.job_id)
            if job is not None:
                job.progress = bounded


JobHandler = Callable[[JobContext], Awaitable[None]]

#: Called as each job reaches a terminal state, with its type, that state and
#: how long it ran (``None`` if it never started).  Exists so metrics can be
#: recorded without this module knowing anything about metrics (13.3); a queue
#: that imported the exporter would be a queue that could not run without it.
JobObserver = Callable[[JobType, JobState, float | None], None]


class JobQueue:
    """A pool of workers draining the ``job`` table."""

    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        settings: Settings,
        handlers: Mapping[JobType, JobHandler] | None = None,
        *,
        poll_interval: float = POLL_INTERVAL_SECONDS,
        observer: JobObserver | None = None,
    ) -> None:
        self.sessionmaker = sessionmaker
        self.settings = settings
        self.handlers: dict[JobType, JobHandler] = dict(handlers or {})
        self.poll_interval = poll_interval
        self.observer = observer

        self._workers: list[asyncio.Task[None]] = []
        self._stopping = asyncio.Event()
        self._wakeup = asyncio.Event()
        # Claiming reads then writes; without this two workers in the same
        # process can interleave between the two and both see the same row.
        self._claim_lock = asyncio.Lock()
        self._active = 0

    def register(self, job_type: JobType, handler: JobHandler) -> None:
        self.handlers[job_type] = handler

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self._workers:  # pragma: no cover - defensive
            return
        self._stopping.clear()
        recovered = await self.recover()
        if recovered:
            log.warning("recovered interrupted jobs", count=recovered)
        self._workers = [
            asyncio.create_task(self._worker(index), name=f"repoman-job-worker-{index}")
            for index in range(self.settings.job_concurrency)
        ]
        log.info("job queue started", workers=len(self._workers))

    async def stop(self) -> None:
        self._stopping.set()
        self._wakeup.set()
        for worker in self._workers:
            worker.cancel()
        for worker in self._workers:
            with contextlib.suppress(asyncio.CancelledError):
                await worker
        self._workers = []
        log.info("job queue stopped")

    async def recover(self) -> int:
        """Fail jobs left ``running`` by an unclean shutdown, and re-queue (6)."""
        async with self.sessionmaker() as session, session.begin():
            stranded = list(
                (await session.execute(select(Job).where(Job.state == JobState.RUNNING))).scalars()
            )
            repositories: set[int] = set()
            for job in stranded:
                job.state = JobState.FAILED
                job.error = RESTART_REASON
                job.finished_at = utcnow()
                job.append_log(RESTART_REASON)
                if job.repository_id is not None:
                    repositories.add(job.repository_id)

            for repository_id in sorted(repositories):
                session.add(
                    Job(
                        type=JobType.REGENERATE_METADATA,
                        repository_id=repository_id,
                        state=JobState.QUEUED,
                        actor="system (restart recovery)",
                    )
                )
        if stranded:
            self.wake()
        return len(stranded)

    # -- producing ---------------------------------------------------------

    def wake(self) -> None:
        """Tell an idle worker to look again.

        Called *after* the caller commits.  Waking earlier would have workers
        querying for a row that is not visible to them yet, and they would then
        sleep for a whole poll interval before finding it.
        """
        self._wakeup.set()

    async def enqueue(
        self,
        session: AsyncSession,
        job_type: JobType,
        *,
        repository_id: int | None = None,
        actor: str | None = None,
    ) -> int:
        """Queue a job **in the caller's transaction**, coalescing where possible.

        Taking the caller's session rather than opening one is not a
        convenience: on SQLite a second connection writing while the request's
        own transaction is still open blocks until ``busy_timeout`` expires and
        then fails.  Sharing the transaction also makes the enqueue atomic with
        the change that motivated it -- an upload that rolls back cannot leave a
        rebuild queued for a package that was never stored.

        Coalescing matters because uploading fifty packages would otherwise
        queue fifty identical rebuilds of one tree; the last alone produces the
        same result (5.4).
        """
        existing = await session.scalar(
            select(Job.id)
            .where(
                Job.type == job_type,
                Job.repository_id == repository_id,
                Job.state == JobState.QUEUED,
            )
            .order_by(Job.id)
            .limit(1)
        )
        if existing is not None:
            return int(existing)

        job = Job(type=job_type, repository_id=repository_id, actor=actor)
        session.add(job)
        await session.flush()
        return job.id

    # -- consuming ---------------------------------------------------------

    async def _claim(self) -> int | None:
        """Atomically take the oldest runnable job, or return ``None``."""
        async with self._claim_lock, self.sessionmaker() as session, session.begin():
            busy = (
                select(Job.repository_id)
                .where(Job.state == JobState.RUNNING, Job.repository_id.is_not(None))
                .scalar_subquery()
            )
            candidate = await session.scalar(
                select(Job.id)
                .where(Job.state == JobState.QUEUED)
                # A repository already being rebuilt is skipped rather than
                # waited on, so the worker moves to another repository's work.
                .where(or_(Job.repository_id.is_(None), Job.repository_id.not_in(busy)))
                .order_by(Job.id)
                .limit(1)
            )
            if candidate is None:
                return None

            # `execute` is typed as returning Result; an UPDATE really returns a
            # CursorResult, and rowcount is the whole point of the call.
            result = cast(
                "CursorResult[Any]",
                await session.execute(
                    update(Job)
                    .where(Job.id == candidate, Job.state == JobState.QUEUED)
                    .values(state=JobState.RUNNING, started_at=utcnow())
                ),
            )
            # Lost the race to another worker or another process; try again later.
            return int(candidate) if result.rowcount == 1 else None

    async def _worker(self, index: int) -> None:
        while not self._stopping.is_set():
            try:
                job_id = await self._claim()
            except Exception:  # pragma: no cover - a claim failure must not kill the pool
                log.exception("job claim failed", worker=index)
                job_id = None

            if job_id is None:
                await self._idle_wait()
                continue

            self._active += 1
            try:
                await self._execute(job_id)
            finally:
                self._active -= 1

    async def _idle_wait(self) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._wakeup.wait(), timeout=self.poll_interval)
        self._wakeup.clear()

    async def _execute(self, job_id: int) -> None:
        async with self.sessionmaker() as session:
            job = await session.get(Job, job_id)
            if job is None:  # pragma: no cover - deleted between claim and run
                return
            job_type, repository_id = job.type, job.repository_id

        handler = self.handlers.get(job_type)
        context = JobContext(
            job_id=job_id,
            repository_id=repository_id,
            settings=self.settings,
            sessionmaker=self.sessionmaker,
        )

        if handler is None:
            await self._finish(
                job_id,
                JobState.FAILED,
                error=f"No handler is registered for job type {job_type.value!r}.",
            )
            return

        log.info("job started", job_id=job_id, type=job_type.value, repository_id=repository_id)
        try:
            await handler(context)
        except asyncio.CancelledError:
            # Shutdown, not failure: leave it queued so recovery picks it up.
            await self._finish(job_id, JobState.QUEUED, error=None, reset=True)
            raise
        except Exception as exc:
            log.exception("job failed", job_id=job_id, type=job_type.value)
            await self._finish(job_id, JobState.FAILED, error=str(exc))
        else:
            await self._finish(job_id, JobState.SUCCEEDED, error=None)
            log.info("job succeeded", job_id=job_id, type=job_type.value)

    async def _finish(
        self, job_id: int, state: JobState, *, error: str | None, reset: bool = False
    ) -> None:
        observed: tuple[JobType, float | None] | None = None
        async with self.sessionmaker() as session, session.begin():
            job = await session.get(Job, job_id)
            if job is None:  # pragma: no cover
                return
            job.state = state
            job.error = error
            if reset:
                job.started_at = None
                job.finished_at = None
                job.progress = 0
            else:
                job.finished_at = utcnow()
                if state == JobState.SUCCEEDED:
                    job.progress = 100
                observed = (job.type, job.duration_seconds)

        # Outside the transaction, and never allowed to affect it: a failure in
        # an observer is a monitoring problem, not a reason to lose the record
        # of a job that really did finish.
        if observed is not None and self.observer is not None:
            job_type, seconds = observed
            try:
                self.observer(job_type, state, seconds)
            except Exception:  # pragma: no cover - defensive
                log.exception("job observer failed", job_id=job_id)

    # -- test and shutdown support ----------------------------------------

    async def pending_count(self) -> int:
        async with self.sessionmaker() as session:
            total = await session.scalar(
                select(func.count(Job.id)).where(Job.state.in_([JobState.QUEUED, JobState.RUNNING]))
            )
        return int(total or 0)

    async def drain(self, timeout: float = 30.0) -> None:
        """Wait until nothing is queued, running, or mid-handler.

        Used by tests and by the shutdown path.  It checks the in-memory
        ``_active`` counter as well as the table, because a handler that has
        finished its database work but not yet returned would otherwise look
        idle.
        """
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            if await self.pending_count() == 0 and self._active == 0:
                return
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError(f"jobs did not finish within {timeout:g}s")
            await asyncio.sleep(0.02)
