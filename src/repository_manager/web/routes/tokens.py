"""API token management (specification.md 7.4, 8.1).

One page, and one deliberate departure from how every other form in this
application behaves: minting does **not** redirect.

Everywhere else a successful POST answers 303 and the browser re-fetches the
page, which is what stops a refresh repeating the action.  A new token cannot
work that way, because the secret exists exactly once and the only place to put
it in a redirect is the query string -- where it would land in the browser's
history, in the proxy's access log, and in the ``Referer`` of the next request
the page makes.  So the token is rendered straight into the response to the
POST, and refreshing that page re-submits the form, which mints a second token:
harmless, visible in the list, and revocable, which is the right trade against
writing a live credential into three logs.

Who may see what follows section 3: an owner sees their own tokens, an admin
sees everyone's and may revoke any of them.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse, Response

from repository_manager.models import (
    ApiToken,
    AuditAction,
    Repository,
    Role,
    TokenScope,
)
from repository_manager.services import audit
from repository_manager.services import tokens as token_service
from repository_manager.services.tokens import MintedToken, TokenError
from repository_manager.web.deps import (
    Identity,
    db_session,
    get_settings,
    get_templates,
    require_authenticated,
)
from repository_manager.web.forms import FormState
from repository_manager.web.middleware import client_ip
from repository_manager.web.templating import render

router = APIRouter(tags=["tokens"])


async def _visible(session: AsyncSession, identity: Identity) -> list[ApiToken]:
    """An admin sees every token; anyone else sees their own (3).

    Scoped in the query rather than in the template, for the same reason the
    audit page is: rows that must not be shown are better never fetched.
    """
    if identity.role is Role.ADMIN:
        return await token_service.all_tokens(session)
    return await token_service.for_owner(session, identity.user_dn)


async def _repository_slugs(session: AsyncSession) -> list[str]:
    statement = (
        select(Repository.slug)
        .where(Repository.deregistered_at.is_(None))
        .order_by(Repository.slug)
    )
    return list((await session.execute(statement)).scalars().all())


async def _context(
    request: Request,
    session: AsyncSession,
    identity: Identity,
    form: FormState,
    *,
    minted: MintedToken | None = None,
) -> dict[str, Any]:
    settings = get_settings(request)
    return {
        "tokens": await _visible(session, identity),
        "repository_options": [(slug, slug, None) for slug in await _repository_slugs(session)],
        "scopes": [(scope.value, scope.label, scope.description) for scope in TokenScope],
        "form": form,
        "minted": minted,
        "shows_every_owner": identity.role is Role.ADMIN,
        "default_days": settings.token_default_lifetime_days,
        "max_days": settings.token_max_lifetime_days,
    }


async def _page(
    request: Request,
    session: AsyncSession,
    identity: Identity,
    form: FormState,
    *,
    minted: MintedToken | None = None,
    status_code: int = 200,
) -> Response:
    return render(
        get_templates(request),
        request,
        "tokens/list.html.j2",
        await _context(request, session, identity, form, minted=minted),
        status_code=status_code,
    )


@router.get(
    "/tokens",
    include_in_schema=False,
    name="token_list",
)
async def token_list(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
    identity: Annotated[Identity, Depends(require_authenticated)],
) -> Response:
    form = FormState(
        values={"lifetime_days": str(get_settings(request).token_default_lifetime_days)}
    )
    return await _page(request, session, identity, form)


def _chosen_scopes(form: FormState, raw: list[str]) -> set[TokenScope]:
    known = {scope.value: scope for scope in TokenScope}
    unknown = [value for value in raw if value not in known]
    if unknown:
        # Not merely dropped: a scope this version does not know about arriving
        # in a form means the page and the server disagree, and silently minting
        # a token with less power than the person ticked is worse than saying so.
        form.add("scopes", "That is not a permission this instance offers.")
    return {known[value] for value in raw if value in known}


def _chosen_repositories(form: FormState, raw: list[str], available: list[str]) -> list[str]:
    unknown = sorted(set(raw) - set(available))
    if unknown:
        form.add("repositories", f"No such repository: {', '.join(unknown)}.")
    return [slug for slug in raw if slug in set(available)]


def _lifetime(form: FormState, raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        form.add("lifetime_days", "Give the number of days as a whole number.")
        return 0


@router.post(
    "/tokens",
    include_in_schema=False,
    name="token_create",
)
async def token_create(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
    identity: Annotated[Identity, Depends(require_authenticated)],
) -> Response:
    """Mint a token for the signed-in user, and show it once (7.4).

    A token is always minted for its own creator.  There is no field for an
    owner and no admin override, because a credential nobody chose to hold is
    one nobody will think to revoke -- and its actions would appear in the audit
    log under their name.
    """
    settings = get_settings(request)
    submitted = await request.form()
    label = str(submitted.get("label") or "")
    raw_days = str(submitted.get("lifetime_days") or settings.token_default_lifetime_days)

    raw_scopes = [str(value) for value in submitted.getlist("scopes")]
    raw_repositories = [str(value) for value in submitted.getlist("repositories")]
    # The tick-box selections go into `values` as lists rather than strings, so
    # a rejected form comes back with the same boxes ticked.
    form = FormState(
        values={
            "label": label,
            "lifetime_days": raw_days,
            "scopes": raw_scopes,
            "repositories": raw_repositories,
        }
    )
    available = await _repository_slugs(session)
    scopes = _chosen_scopes(form, raw_scopes)
    repositories = _chosen_repositories(form, raw_repositories, available)
    days = _lifetime(form, raw_days)

    if not form.ok:
        return await _page(request, session, identity, form, status_code=400)

    try:
        minted = await token_service.mint(
            session,
            settings,
            owner_dn=identity.user_dn,
            owner_username=identity.username,
            label=label,
            scopes=scopes,
            repositories=repositories,
            lifetime_days=days,
        )
    except TokenError as exc:
        form.add(exc.field, str(exc))
        return await _page(request, session, identity, form, status_code=400)

    await audit.record(
        session,
        action=AuditAction.TOKEN_MINT,
        actor=identity.user_dn,
        target=minted.record.label,
        source_ip=client_ip(request.scope),
        # The prefix, never the token: this row is readable by every admin and
        # outlives the credential itself.
        details={
            "token_id": minted.record.id,
            "token_prefix": minted.record.prefix,
            "scopes": minted.record.scopes,
            "repositories": list(minted.record.repositories) or "all",
            "expires_at": minted.record.expires_at.isoformat(),
        },
    )
    await session.commit()
    return await _page(request, session, identity, FormState(), minted=minted)


@router.post(
    "/tokens/{token_id}/revoke",
    include_in_schema=False,
    name="token_revoke",
)
async def token_revoke(
    request: Request,
    token_id: int,
    session: Annotated[AsyncSession, Depends(db_session)],
    identity: Annotated[Identity, Depends(require_authenticated)],
) -> Response:
    """Revoke a token: the owner's, or any of them for an admin (3, 7.4)."""
    token = await token_service.load(session, token_id)
    if token is None or not token_service.may_revoke(
        token, actor_dn=identity.user_dn, role=identity.role
    ):
        # One answer for "no such token" and "not yours": whether a token id
        # exists is not something one user should learn about another's.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such token")

    label = token.label
    await token_service.revoke(session, token, actor=identity.user_dn)
    await audit.record(
        session,
        action=AuditAction.TOKEN_REVOKE,
        actor=identity.user_dn,
        target=label,
        source_ip=client_ip(request.scope),
        details={
            "token_id": token.id,
            "token_prefix": token.prefix,
            "owner_dn": token.owner_dn,
            "own_token": token.owner_dn == identity.user_dn,
        },
    )
    return RedirectResponse(
        request.url_for("token_list").include_query_params(revoked=label),
        status_code=status.HTTP_303_SEE_OTHER,
    )
