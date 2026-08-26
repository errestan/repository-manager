"""Signing key management (specification.md 4.3, 10.5)."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from repository_manager.config import Settings
from repository_manager.logging import get_logger
from repository_manager.models import KeyAlgorithm, Repository, SigningKey
from repository_manager.security.gpg import GnuPG, GnuPGError, KeyInfo
from repository_manager.security.passphrase import PassphraseStore, generate_passphrase

log = get_logger(__name__)


class KeyServiceError(Exception):
    """A key operation was refused; the message is shown to the user."""


def build_gnupg(settings: Settings) -> GnuPG:
    return GnuPG(settings.gnupghome)


def build_passphrase_store(settings: Settings) -> PassphraseStore:
    return PassphraseStore(settings.gnupghome)


@dataclass(frozen=True)
class GnuPGSigner:
    """Adapts a keyring and a key to the ``Signer`` protocol the generator wants.

    The passphrase is resolved by the caller and held only for as long as the
    signing operation takes; nothing here writes it anywhere.
    """

    gpg: GnuPG
    fingerprint: str
    passphrase: str | None

    def clearsign(self, data: bytes) -> bytes:
        return self.gpg.clearsign(data, self.fingerprint, passphrase=self.passphrase)

    def detach_sign(self, data: bytes) -> bytes:
        return self.gpg.detach_sign(data, self.fingerprint, passphrase=self.passphrase)


def build_signer(settings: Settings, key: SigningKey) -> GnuPGSigner:
    """A signer for ``key``, resolving its passphrase at the last moment.

    Note the cost: signing with a passphrase-protected key measures at roughly
    0.5s per signature here, against about 4ms for an unprotected one, so a
    rebuild spends about a second per distribution in gpg alone.  That is
    accepted rather than optimised around -- regeneration is a background job,
    and the alternative is keeping unlocked key material resident for longer.
    """
    store = build_passphrase_store(settings)
    return GnuPGSigner(
        gpg=build_gnupg(settings),
        fingerprint=key.fingerprint,
        passphrase=store.resolve(key.passphrase_ref),
    )


def default_uid(display_name: str, key_name: str, settings: Settings) -> str:
    """The UID for a generated key (4.3)."""
    return f"{display_name} repository signing key <{key_name}@{settings.key_uid_domain}>"


async def _reject_duplicate(session: AsyncSession, *, name: str, fingerprint: str | None) -> None:
    clash = await session.scalar(select(SigningKey).where(SigningKey.name == name))
    if clash is not None:
        raise KeyServiceError(f"A key named {name!r} already exists.")
    if fingerprint is not None:
        existing = await session.scalar(
            select(SigningKey).where(SigningKey.fingerprint == fingerprint)
        )
        if existing is not None:
            raise KeyServiceError(
                f"That key is already registered as {existing.name!r} "
                f"(fingerprint {existing.short_id})."
            )


def _record(
    info: KeyInfo, *, name: str, armored: str, ref: str | None, actor: str | None
) -> SigningKey:
    return SigningKey(
        name=name,
        fingerprint=info.fingerprint,
        algorithm=info.algorithm,
        uid=info.uid,
        public_key_armored=armored,
        passphrase_ref=ref,
        created_by=actor,
        expires_at=info.expires_at,
    )


async def generate_key(
    session: AsyncSession,
    settings: Settings,
    *,
    name: str,
    display_name: str,
    algorithm: KeyAlgorithm = KeyAlgorithm.RSA4096,
    actor: str | None = None,
) -> SigningKey:
    """Create a new signing key with a generated passphrase.

    The passphrase is generated rather than requested: nobody has to type it
    again, it is never weak, and it lives only in the 0700 keyring directory
    beside the key it protects (10.5).
    """
    await _reject_duplicate(session, name=name, fingerprint=None)

    gpg = build_gnupg(settings)
    store = build_passphrase_store(settings)
    passphrase = generate_passphrase()
    store.store(name, passphrase)

    try:
        uid = default_uid(display_name, name, settings)
        info = gpg.generate_key(uid, algorithm, passphrase=passphrase)
    except GnuPGError as exc:
        # Roll the passphrase back, or the reference is left pointing at a key
        # that does not exist and the name can never be reused.
        store.forget(name)
        raise KeyServiceError(f"The signing key could not be generated: {exc}") from exc

    await _reject_duplicate(session, name=name, fingerprint=info.fingerprint)
    key = _record(
        info,
        name=name,
        armored=gpg.export_public(info.fingerprint),
        ref=name,
        actor=actor,
    )
    session.add(key)
    await session.flush()
    log.info(
        "signing key generated",
        key=name,
        fingerprint=info.fingerprint,
        algorithm=algorithm.value,
    )
    return key


async def import_key(
    session: AsyncSession,
    settings: Settings,
    *,
    name: str,
    armored: str,
    passphrase: str | None = None,
    actor: str | None = None,
) -> SigningKey:
    """Import an existing private key into the app-managed keyring."""
    await _reject_duplicate(session, name=name, fingerprint=None)

    gpg = build_gnupg(settings)
    try:
        info = gpg.import_key(armored)
    except GnuPGError as exc:
        raise KeyServiceError(str(exc)) from exc

    await _reject_duplicate(session, name=name, fingerprint=info.fingerprint)

    ref: str | None = None
    if passphrase:
        store = build_passphrase_store(settings)
        store.store(name, passphrase)
        ref = name

    key = _record(
        info,
        name=name,
        armored=gpg.export_public(info.fingerprint),
        ref=ref,
        actor=actor,
    )
    session.add(key)
    await session.flush()
    log.info("signing key imported", key=name, fingerprint=info.fingerprint)
    return key


async def delete_key(session: AsyncSession, settings: Settings, key: SigningKey) -> None:
    """Remove a key, refusing while any repository still signs with it (10.5)."""
    users = await session.scalar(
        select(func.count(Repository.id)).where(Repository.signing_key_id == key.id)
    )
    if users:
        raise KeyServiceError(
            f"{key.name!r} still signs {users} "
            f"{'repository' if users == 1 else 'repositories'}. "
            "Move them to another key first; deleting this one would leave their metadata "
            "unverifiable."
        )

    gpg = build_gnupg(settings)
    try:
        gpg.delete_key(key.fingerprint)
    except GnuPGError as exc:  # pragma: no cover - keyring already missing the key
        log.warning("key absent from keyring at delete", key=key.name, error=str(exc))

    if key.passphrase_ref:
        build_passphrase_store(settings).forget(key.passphrase_ref)
    await session.delete(key)
    log.info("signing key deleted", key=key.name)


async def verify_usable(settings: Settings, key: SigningKey) -> None:
    """Confirm a key can actually sign, before a repository depends on it.

    Catching this at creation time turns "the keyring lost its private half"
    into an immediate, fixable error rather than a failed job days later.
    """
    gpg = build_gnupg(settings)
    if not gpg.has_secret_key(key.fingerprint):
        raise KeyServiceError(
            f"The private half of {key.name!r} is not in the keyring at {settings.gnupghome}, "
            "so it cannot sign repository metadata."
        )
    try:
        build_signer(settings, key).detach_sign(b"repository-manager signing probe\n")
    except Exception as exc:
        raise KeyServiceError(f"{key.name!r} could not produce a signature: {exc}") from exc
