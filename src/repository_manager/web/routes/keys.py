"""Signing key management (specification.md 8.1, 4.3, 10.5).

Public keys are downloadable by anyone -- clients need them to verify the
repository.  Private keys have no route at all: there is no export endpoint to
guard, because the capability is absent from the GnuPG wrapper itself.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.responses import RedirectResponse, Response

from repository_manager.models import KEY_NAME_PATTERN, KeyAlgorithm, SigningKey
from repository_manager.services import keys as key_service
from repository_manager.services.keys import KeyServiceError
from repository_manager.web.deps import (
    db_session,
    get_settings,
    get_templates,
    require_write_access,
    writes_enabled,
)
from repository_manager.web.forms import FormState, required
from repository_manager.web.templating import render

router = APIRouter(tags=["keys"])

GENERATE = "generate"
IMPORT = "import"


async def _all_keys(session: AsyncSession) -> list[SigningKey]:
    statement = (
        select(SigningKey).options(selectinload(SigningKey.repositories)).order_by(SigningKey.name)
    )
    return list((await session.execute(statement)).scalars().all())


def _page(
    request: Request, keys: list[SigningKey], form: FormState, status_code: int = 200
) -> Response:
    return render(
        get_templates(request),
        request,
        "keys/list.html.j2",
        {
            "keys": keys,
            "form": form,
            "algorithms": [(member.value, member.label) for member in KeyAlgorithm],
            "writes_enabled": writes_enabled(request),
        },
        status_code=status_code,
    )


@router.get("/keys", include_in_schema=False, name="key_list")
async def key_list(
    request: Request, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    return _page(request, await _all_keys(session), FormState())


@router.post(
    "/keys",
    include_in_schema=False,
    name="key_create",
    dependencies=[Depends(require_write_access)],
)
async def key_create(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
    action: Annotated[str, Form()],
    name: Annotated[str, Form()] = "",
    display_name: Annotated[str, Form()] = "",
    algorithm: Annotated[str, Form()] = KeyAlgorithm.RSA4096.value,
    armored: Annotated[str, Form()] = "",
    passphrase: Annotated[str, Form()] = "",
) -> Response:
    settings = get_settings(request)
    form = FormState(
        values={
            "action": action,
            "name": name,
            "display_name": display_name,
            "algorithm": algorithm,
            # The pasted key and its passphrase are deliberately NOT echoed back
            # into the re-rendered form: private key material should not make a
            # second trip through the browser (10.5).
        }
    )

    display = ""
    cleaned_name = required(form, "name", name, "Key name")
    if cleaned_name and not KEY_NAME_PATTERN.match(cleaned_name):
        form.add(
            "name",
            "Use lowercase letters, digits and hyphens only, starting and ending with "
            "a letter or digit.",
        )

    if action == GENERATE:
        display = required(form, "display_name", display_name, "Owner or repository name")
        if algorithm not in {member.value for member in KeyAlgorithm}:
            form.add("algorithm", "Choose one of the offered key types.")
    elif action == IMPORT:
        required(form, "armored", armored, "Armoured private key")
    else:
        form.add("action", "Choose whether to generate a new key or import an existing one.")

    if not form.ok:
        return _page(request, await _all_keys(session), form, status_code=400)

    try:
        if action == GENERATE:
            await key_service.generate_key(
                session,
                settings,
                name=cleaned_name,
                display_name=display,
                algorithm=KeyAlgorithm(algorithm),
            )
        else:
            await key_service.import_key(
                session,
                settings,
                name=cleaned_name,
                armored=armored,
                passphrase=passphrase or None,
            )
    except KeyServiceError as exc:
        form.add("name" if action == GENERATE else "armored", str(exc))
        return _page(request, await _all_keys(session), form, status_code=400)

    return RedirectResponse(
        request.url_for("key_list").include_query_params(created=cleaned_name),
        status_code=status.HTTP_303_SEE_OTHER,
    )


async def _load_key(session: AsyncSession, name: str) -> SigningKey:
    if not KEY_NAME_PATTERN.match(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such key")
    key = await session.scalar(
        select(SigningKey)
        .where(SigningKey.name == name)
        .options(selectinload(SigningKey.repositories))
    )
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such key")
    return key


@router.get("/keys/{name}/public.asc", include_in_schema=False, name="key_public")
async def key_public(
    request: Request, name: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    """The armoured public key, for `signed-by=` and `gpgkey=` client setup (4.4)."""
    key = await _load_key(session, name)
    return Response(
        content=key.public_key_armored,
        media_type="application/pgp-keys",
        headers={"content-disposition": f'attachment; filename="{key.name}.asc"'},
    )


@router.post(
    "/keys/{name}/delete",
    include_in_schema=False,
    name="key_delete",
    dependencies=[Depends(require_write_access)],
)
async def key_delete(
    request: Request, name: str, session: Annotated[AsyncSession, Depends(db_session)]
) -> Response:
    key = await _load_key(session, name)
    try:
        await key_service.delete_key(session, get_settings(request), key)
    except KeyServiceError as exc:
        form = FormState()
        form.add("name", str(exc))
        return _page(request, await _all_keys(session), form, status_code=409)

    return RedirectResponse(
        request.url_for("key_list").include_query_params(deleted=name),
        status_code=status.HTTP_303_SEE_OTHER,
    )
