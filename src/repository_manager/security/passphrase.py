"""Resolving signing-key passphrases (specification.md 10.5).

The database stores a *reference*, never a passphrase.  A reference resolves in
two places, in this order:

1. an environment variable ``REPOMAN_KEY_PASSPHRASE_<REF>`` -- the hook for
   Kubernetes secrets, Vault agents and anything else that injects at runtime;
2. a file in ``<GNUPGHOME>/passphrases/<ref>``, mode 0600 -- what the
   application writes for a key it generated itself, so that a single-host
   deployment works with no external secret store.

Resolution happens at signing time rather than at startup so that rotating a
secret does not require a restart, and so that a passphrase is held only for
as long as one signature takes.
"""

from __future__ import annotations

import re
import secrets
from pathlib import Path

from repository_manager.security.paths import (
    PRIVATE_FILE_MODE,
    harden_private_directory,
    open_exclusive,
)

ENV_PREFIX = "REPOMAN_KEY_PASSPHRASE_"
PASSPHRASE_DIRNAME = "passphrases"  # noqa: S105 - a directory name, not a secret

# References become part of an environment variable name and a filename, so the
# same narrow alphabet as a key name applies.
REF_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

# 32 bytes of urlsafe base64.  The passphrase protects a key at rest on a host
# where the application can already read it, so length costs nothing and there
# is no reason to be modest.
GENERATED_PASSPHRASE_BYTES = 32


class PassphraseError(Exception):
    """A passphrase reference could not be resolved."""


def generate_passphrase() -> str:
    return secrets.token_urlsafe(GENERATED_PASSPHRASE_BYTES)


def environment_variable(ref: str) -> str:
    return f"{ENV_PREFIX}{ref.replace('-', '_').upper()}"


class PassphraseStore:
    """Passphrase lookup rooted at one GnuPG home."""

    def __init__(self, gnupghome: Path, environ: dict[str, str] | None = None) -> None:
        import os

        self.gnupghome = Path(gnupghome)
        self.environ = os.environ if environ is None else environ

    @property
    def directory(self) -> Path:
        return self.gnupghome / PASSPHRASE_DIRNAME

    @staticmethod
    def _check_ref(ref: str) -> str:
        if not REF_PATTERN.match(ref or ""):
            raise PassphraseError(
                f"{ref!r} is not a valid passphrase reference; use lowercase letters, "
                "digits and hyphens"
            )
        return ref

    def store(self, ref: str, passphrase: str) -> str:
        """Persist a passphrase for a key this application generated.

        Written with ``O_EXCL`` so an existing reference is never silently
        overwritten -- that would strand the key it belonged to, which is
        unrecoverable.
        """
        self._check_ref(ref)
        directory = harden_private_directory(self.directory)
        path = directory / ref
        try:
            fd = open_exclusive(path, mode=PRIVATE_FILE_MODE)
        except FileExistsError as exc:
            raise PassphraseError(
                f"a passphrase for {ref!r} already exists at {path}; refusing to overwrite it"
            ) from exc
        # `Path.open` cannot adopt an existing descriptor, and the descriptor is
        # the whole point: it came from an O_EXCL|O_NOFOLLOW create.
        with open(fd, "w", encoding="utf-8") as handle:  # noqa: PTH123
            handle.write(passphrase)
        return ref

    def resolve(self, ref: str | None) -> str | None:
        """The passphrase for ``ref``, or ``None`` when the key has none."""
        if ref is None:
            return None
        self._check_ref(ref)

        from_env = self.environ.get(environment_variable(ref))
        if from_env:
            return from_env

        path = self.directory / ref
        try:
            return path.read_text(encoding="utf-8").rstrip("\n")
        except FileNotFoundError as exc:
            raise PassphraseError(
                f"No passphrase found for key {ref!r}. Set {environment_variable(ref)} "
                f"or place the passphrase in {path} (mode 0600)."
            ) from exc
        except OSError as exc:
            raise PassphraseError(f"cannot read the passphrase for {ref!r}: {exc}") from exc

    def forget(self, ref: str) -> None:
        self._check_ref(ref)
        (self.directory / ref).unlink(missing_ok=True)
