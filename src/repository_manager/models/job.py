"""Background job records (specification.md 6, 9).

Jobs are rows first and tasks second: the row is written before the worker
picks it up and updated as it runs, so a restart mid-job leaves evidence rather
than a silently lost operation.
"""

from __future__ import annotations

import datetime as dt
import enum
from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from repository_manager.models.base import Base, UtcDateTime, utcnow

if TYPE_CHECKING:  # pragma: no cover - resolved by SQLAlchemy at mapper configuration
    from repository_manager.models.repository import Repository

# A job log is a diagnostic excerpt, not an archive.  Capping it here keeps a
# pathological subprocess from turning one bad upload into an unbounded row.
LOG_EXCERPT_LIMIT = 16_384


class JobType(enum.StrEnum):
    REGENERATE_METADATA = "regenerate_metadata"

    @property
    def label(self) -> str:
        return {JobType.REGENERATE_METADATA: "Regenerate metadata"}[self]


class JobState(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in {JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED}

    @property
    def label(self) -> str:
        return self.value.capitalize()


class Job(Base):
    __tablename__ = "job"
    __table_args__ = (
        # Both the worker's claim query and the coalescing check filter on
        # exactly this pair, and they run on every upload.
        Index("ix_job_state_repository", "state", "repository_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[JobType] = mapped_column(
        Enum(JobType, native_enum=False, length=32, validate_strings=True)
    )
    repository_id: Mapped[int | None] = mapped_column(
        ForeignKey("repository.id", ondelete="CASCADE"), index=True, default=None
    )
    state: Mapped[JobState] = mapped_column(
        Enum(JobState, native_enum=False, length=16, validate_strings=True),
        default=JobState.QUEUED,
    )

    progress: Mapped[int] = mapped_column(Integer, default=0)
    log: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, default=None)
    actor: Mapped[str | None] = mapped_column(Text, default=None)

    created_at: Mapped[dt.datetime] = mapped_column(UtcDateTime, default=utcnow)
    started_at: Mapped[dt.datetime | None] = mapped_column(UtcDateTime, default=None)
    finished_at: Mapped[dt.datetime | None] = mapped_column(UtcDateTime, default=None)

    repository: Mapped[Repository | None] = relationship(back_populates="jobs")

    def append_log(self, message: str) -> None:
        """Add a line, keeping the *most recent* text when the excerpt overflows.

        Truncating the tail would throw away the failure and keep the setup,
        which is precisely backwards for diagnosing a job that died late.
        """
        combined = f"{self.log}{message}\n" if self.log else f"{message}\n"
        if len(combined) > LOG_EXCERPT_LIMIT:
            combined = "[earlier output truncated]\n" + combined[-LOG_EXCERPT_LIMIT:]
        self.log = combined

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None:
            return None
        end = self.finished_at or utcnow()
        return (end - self.started_at).total_seconds()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Job {self.id} {self.type.value} {self.state.value}>"
