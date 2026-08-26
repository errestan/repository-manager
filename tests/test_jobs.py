"""The background worker pool (specification.md 6, 5.4)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from repository_manager.config import Settings
from repository_manager.jobs.lock import RepositoryLockError, repository_lock
from repository_manager.jobs.queue import JobContext, JobQueue
from repository_manager.models import Job, JobState, JobType, Repository, RepositoryType

# Short enough that a test never waits on the poll, long enough not to spin.
POLL = 0.01


@pytest.fixture
def queue(sessionmaker: async_sessionmaker[AsyncSession], settings: Settings) -> JobQueue:
    return JobQueue(sessionmaker, settings, poll_interval=POLL)


async def add_repository(
    sessionmaker: async_sessionmaker[AsyncSession], slug: str = "internal"
) -> int:
    async with sessionmaker() as session, session.begin():
        repository = Repository(
            slug=slug, name=slug, type=RepositoryType.APT, root_path=f"/srv/{slug}"
        )
        session.add(repository)
        await session.flush()
        return repository.id


async def enqueue(queue: JobQueue, repository_id: int | None, actor: str | None = None) -> int:
    """Enqueue and commit, the way a route does."""
    async with queue.sessionmaker() as session:
        job_id = await queue.enqueue(
            session, JobType.REGENERATE_METADATA, repository_id=repository_id, actor=actor
        )
        await session.commit()
    queue.wake()
    return job_id


async def load(sessionmaker: async_sessionmaker[AsyncSession], job_id: int) -> Job:
    async with sessionmaker() as session:
        job = await session.get(Job, job_id)
        assert job is not None
        await session.refresh(job)
        return job


# ------------------------------------------------------------------ enqueueing


async def test_enqueue_creates_a_queued_job(
    queue: JobQueue, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    repository_id = await add_repository(sessionmaker)
    job_id = await enqueue(queue, repository_id, actor="tester")
    job = await load(sessionmaker, job_id)
    assert job.state is JobState.QUEUED
    assert job.actor == "tester"


async def test_repeated_requests_collapse_into_one_pending_job(
    queue: JobQueue, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """Fifty uploads must not queue fifty identical rebuilds (5.4)."""
    repository_id = await add_repository(sessionmaker)
    ids = [await enqueue(queue, repository_id) for _ in range(5)]
    assert len(set(ids)) == 1

    async with sessionmaker() as session:
        total = len((await session.execute(select(Job))).scalars().all())
    assert total == 1


async def test_different_repositories_get_their_own_jobs(
    queue: JobQueue, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    first = await add_repository(sessionmaker, "one")
    second = await add_repository(sessionmaker, "two")
    assert await enqueue(queue, first) != await enqueue(queue, second)


# ------------------------------------------------------------------ execution


async def test_a_queued_job_runs_and_succeeds(
    queue: JobQueue, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    ran = asyncio.Event()

    async def handler(context: JobContext) -> None:
        await context.log("did the work")
        await context.set_progress(50)
        ran.set()

    queue.register(JobType.REGENERATE_METADATA, handler)
    repository_id = await add_repository(sessionmaker)
    await queue.start()
    try:
        job_id = await enqueue(queue, repository_id)
        await asyncio.wait_for(ran.wait(), timeout=5)
        await queue.drain(timeout=5)
    finally:
        await queue.stop()

    job = await load(sessionmaker, job_id)
    assert job.state is JobState.SUCCEEDED
    assert job.progress == 100
    assert "did the work" in job.log
    assert job.started_at is not None
    assert job.finished_at is not None


async def test_a_failing_handler_records_the_reason(
    queue: JobQueue, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    async def handler(_context: JobContext) -> None:
        raise RuntimeError("the signing key is unavailable")

    queue.register(JobType.REGENERATE_METADATA, handler)
    repository_id = await add_repository(sessionmaker)
    await queue.start()
    try:
        job_id = await enqueue(queue, repository_id)
        await queue.drain(timeout=5)
    finally:
        await queue.stop()

    job = await load(sessionmaker, job_id)
    assert job.state is JobState.FAILED
    assert job.error is not None
    assert "signing key is unavailable" in job.error


async def test_a_job_with_no_handler_fails_rather_than_hanging(
    queue: JobQueue, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    repository_id = await add_repository(sessionmaker)
    await queue.start()
    try:
        job_id = await enqueue(queue, repository_id)
        await queue.drain(timeout=5)
    finally:
        await queue.stop()

    job = await load(sessionmaker, job_id)
    assert job.state is JobState.FAILED
    assert job.error is not None
    assert "No handler" in job.error


async def test_one_repository_is_never_rebuilt_twice_at_once(
    sessionmaker: async_sessionmaker[AsyncSession], make_settings: Callable[..., Settings]
) -> None:
    """Two workers interleaving on one dists tree would corrupt it (5.4)."""
    settings = make_settings(job_concurrency=4)
    queue = JobQueue(sessionmaker, settings, poll_interval=POLL)

    concurrent = 0
    peak = 0

    async def handler(_context: JobContext) -> None:
        nonlocal concurrent, peak
        concurrent += 1
        peak = max(peak, concurrent)
        await asyncio.sleep(0.05)
        concurrent -= 1

    queue.register(JobType.REGENERATE_METADATA, handler)
    repository_id = await add_repository(sessionmaker)

    # Three separate jobs for one repository: coalescing only merges *queued*
    # jobs, so these are created directly to guarantee three distinct rows.
    async with sessionmaker() as session, session.begin():
        for _ in range(3):
            session.add(Job(type=JobType.REGENERATE_METADATA, repository_id=repository_id))

    await queue.start()
    try:
        await queue.drain(timeout=10)
    finally:
        await queue.stop()

    assert peak == 1


async def test_separate_repositories_rebuild_concurrently(
    sessionmaker: async_sessionmaker[AsyncSession], make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings(job_concurrency=2)
    queue = JobQueue(sessionmaker, settings, poll_interval=POLL)

    started = asyncio.Semaphore(0)
    release = asyncio.Event()

    async def handler(_context: JobContext) -> None:
        started.release()
        await asyncio.wait_for(release.wait(), timeout=5)

    queue.register(JobType.REGENERATE_METADATA, handler)
    first = await add_repository(sessionmaker, "one")
    second = await add_repository(sessionmaker, "two")

    await queue.start()
    try:
        await enqueue(queue, first)
        await enqueue(queue, second)
        # Both handlers must be inside the body at the same time.
        await asyncio.wait_for(started.acquire(), timeout=5)
        await asyncio.wait_for(started.acquire(), timeout=5)
        release.set()
        await queue.drain(timeout=5)
    finally:
        release.set()
        await queue.stop()


# ------------------------------------------------------------------ recovery


async def test_startup_fails_interrupted_jobs_and_requeues_the_repository(
    queue: JobQueue, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """A job left running by an unclean shutdown must not stay running (6)."""
    repository_id = await add_repository(sessionmaker)
    async with sessionmaker() as session, session.begin():
        stranded = Job(
            type=JobType.REGENERATE_METADATA,
            repository_id=repository_id,
            state=JobState.RUNNING,
        )
        session.add(stranded)
        await session.flush()
        stranded_id = stranded.id

    recovered = await queue.recover()
    assert recovered == 1

    job = await load(sessionmaker, stranded_id)
    assert job.state is JobState.FAILED
    assert job.error is not None
    assert "restarted" in job.error

    async with sessionmaker() as session:
        queued = (
            (await session.execute(select(Job).where(Job.state == JobState.QUEUED))).scalars().all()
        )
    assert len(queued) == 1
    assert queued[0].repository_id == repository_id


async def test_recovery_is_a_no_op_when_nothing_was_interrupted(queue: JobQueue) -> None:
    assert await queue.recover() == 0


# ------------------------------------------------------------------ logging


async def test_the_log_excerpt_keeps_the_most_recent_output() -> None:
    """A job that dies late must not have its failure truncated away."""
    job = Job(type=JobType.REGENERATE_METADATA)
    for index in range(4000):
        job.append_log(f"line {index}")
    assert "earlier output truncated" in job.log
    assert "line 3999" in job.log
    assert "line 0\n" not in job.log


# ------------------------------------------------------------------ on-disk lock


def test_the_repository_lock_excludes_a_second_holder(tmp_path: Path) -> None:
    """Covers a second *process*, which the in-process queue cannot (5.4)."""
    root = tmp_path / "repo"
    with repository_lock(root, timeout=0.1):
        assert (root / ".repoman.lock").exists()
        with pytest.raises(RepositoryLockError, match="regenerating"):
            _hold_from_another_process(root)


def _hold_from_another_process(root: Path) -> None:
    """Take the lock through a separate file descriptor.

    flock is per open-file-description, so a fresh ``open`` in the same process
    contends exactly as another process would.
    """
    with repository_lock(root, timeout=0.1):  # pragma: no cover - must not be reached
        pass


def test_the_lock_is_released_when_the_block_ends(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    with repository_lock(root, timeout=0.1):
        pass
    with repository_lock(root, timeout=0.1):
        pass


def test_the_lockfile_is_hidden_from_directory_listings(tmp_path: Path) -> None:
    """Dot-prefixed so a web server's autoindex does not advertise it."""
    root = tmp_path / "repo"
    with repository_lock(root, timeout=0.1):
        assert next(root.iterdir()).name.startswith(".")
