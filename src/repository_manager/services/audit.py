"""Writing the audit trail (specification.md 9).

One function, deliberately.  Every call site records the same shape -- who,
what, to which thing, from where, and whether it worked -- so the audit page can
present a uniform table and nobody has to remember a per-action convention.

Entries join the caller's transaction rather than opening one.  That is what
makes the record atomic with the change it describes: an upload that rolls back
leaves no audit entry claiming it happened, and one that commits cannot commit
without its entry.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from repository_manager.models import (
    ActorType,
    AuditAction,
    AuditLog,
    AuditOutcome,
)

#: Recorded as the actor when the attempt had no identity to name -- a failed
#: login, most often, where the typed username is the only thing known and goes
#: into ``details`` rather than being trusted as an actor.
ANONYMOUS_ACTOR = "anonymous"


async def record(
    session: AsyncSession,
    *,
    action: AuditAction,
    actor: str,
    actor_type: ActorType = ActorType.USER,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    repository_id: int | None = None,
    target: str | None = None,
    source_ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        action=action,
        actor=actor or ANONYMOUS_ACTOR,
        actor_type=actor_type,
        outcome=outcome,
        repository_id=repository_id,
        target=target,
        source_ip=source_ip,
        details_json=details or {},
    )
    session.add(entry)
    return entry
