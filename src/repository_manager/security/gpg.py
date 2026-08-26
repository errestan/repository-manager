"""A thin, auditable wrapper around the ``gpg`` binary (specification.md 10.5).

Design constraints, all of them security rather than convenience:

* the passphrase is written to a pipe and handed over as a file descriptor, so
  it never appears in ``argv`` (world-readable via ``/proc``) nor in the
  environment;
* ``--pinentry-mode loopback`` is always set, so a server process can never
  block waiting for a pinentry dialogue that nobody will ever see;
* the homedir is app-managed and mode 0700, verified on every construction;
* nothing here can export a private key -- there is deliberately no method for
  it, because "the UI must never offer it" is easier to guarantee when the
  capability does not exist.

The ``gpg`` binary is used rather than a Python OpenPGP library because it is
what the rest of the ecosystem trusts, and because key storage, agent handling
and algorithm support then remain the distribution's problem rather than ours.
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from repository_manager.models.key import KeyAlgorithm
from repository_manager.security.paths import harden_private_directory

STATUS_PREFIX = "[GNUPG:] "

# Record type in gpg's colon-separated listing format that carries a fingerprint.
FINGERPRINT_RECORD = "fpr"

# SHA-1 signatures are rejected by modern apt; be explicit rather than relying
# on whatever the local gpg happens to default to.
DIGEST_ALGO = "SHA256"

# gpg's numeric public-key algorithm identifiers (RFC 4880 section 9.1).
_RSA = 1
_EDDSA = 22

_ALGORITHM_SPECS: dict[KeyAlgorithm, str] = {
    KeyAlgorithm.RSA4096: "rsa4096",
    KeyAlgorithm.RSA3072: "rsa3072",
    KeyAlgorithm.ED25519: "ed25519",
}


class GnuPGError(Exception):
    """A gpg invocation failed, with its stderr attached."""


@dataclass(frozen=True)
class KeyInfo:
    """What the application needs to know about a key in the keyring."""

    fingerprint: str
    uid: str
    algorithm: KeyAlgorithm
    created_at: dt.datetime
    expires_at: dt.datetime | None
    has_secret: bool


@dataclass(frozen=True)
class _Result:
    returncode: int
    stdout: bytes
    stderr: str

    @property
    def status_lines(self) -> list[str]:
        return [
            line[len(STATUS_PREFIX) :]
            for line in self.stderr.splitlines()
            if line.startswith(STATUS_PREFIX)
        ]

    @property
    def message(self) -> str:
        """stderr with the machine-readable status chatter removed."""
        return "\n".join(
            line for line in self.stderr.splitlines() if not line.startswith(STATUS_PREFIX)
        ).strip()


def _timestamp(raw: str) -> dt.datetime | None:
    """Parse a gpg colon-format timestamp: seconds since the epoch, or empty."""
    if not raw or raw == "0":
        return None
    if "T" in raw:  # gpg can emit ISO basic form for far-future dates
        return dt.datetime.strptime(raw, "%Y%m%dT%H%M%S").replace(tzinfo=dt.UTC)
    return dt.datetime.fromtimestamp(int(raw), tz=dt.UTC)


def _algorithm(algo: str, length: str) -> KeyAlgorithm:
    code = int(algo or 0)
    if code == _EDDSA:
        return KeyAlgorithm.ED25519
    if code == _RSA and length == "3072":
        return KeyAlgorithm.RSA3072
    return KeyAlgorithm.RSA4096


class GnuPG:
    """Operations against one app-managed keyring."""

    def __init__(self, home: Path, *, binary: str | None = None) -> None:
        resolved = binary or shutil.which("gpg")
        if resolved is None:
            raise GnuPGError(
                "gpg was not found on PATH. Install GnuPG (Debian/Ubuntu: 'apt install gnupg', "
                "Fedora/RHEL: 'dnf install gnupg2') -- repository metadata cannot be signed "
                "without it."
            )
        self.binary = resolved
        self.home = harden_private_directory(Path(home))

    # -- process plumbing --------------------------------------------------

    def _base_args(self) -> list[str]:
        return [
            self.binary,
            "--homedir",
            str(self.home),
            "--batch",
            "--yes",
            "--no-tty",
            # Never prompt: on a server there is nobody to answer.
            "--pinentry-mode",
            "loopback",
            # Machine-readable results on stderr, alongside human-readable ones.
            "--status-fd",
            "2",
        ]

    def _run(
        self,
        args: list[str],
        *,
        stdin: bytes | None = None,
        passphrase: str | None = None,
        check: bool = True,
    ) -> _Result:
        argv = self._base_args()
        read_fd: int | None = None
        pass_fds: tuple[int, ...] = ()

        if passphrase is not None:
            # The passphrase crosses the process boundary through a pipe, so it
            # is visible only to this process and gpg -- not in argv, not in the
            # environment, not on disk.
            read_fd, write_fd = os.pipe()
            os.set_inheritable(read_fd, True)
            with os.fdopen(write_fd, "wb") as sink:
                sink.write(passphrase.encode("utf-8"))
            argv += ["--passphrase-fd", str(read_fd)]
            pass_fds = (read_fd,)

        argv += args
        try:
            completed = subprocess.run(  # noqa: S603 - argv is built here, never shell-parsed
                argv,
                input=stdin,
                capture_output=True,
                pass_fds=pass_fds,
                check=False,
            )
        finally:
            if read_fd is not None:
                os.close(read_fd)

        result = _Result(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr.decode("utf-8", errors="replace"),
        )
        if check and result.returncode != 0:
            raise GnuPGError(result.message or f"gpg exited {result.returncode}")
        return result

    def shutdown(self) -> None:
        """Stop the gpg-agent bound to this homedir.

        gpg 2 starts an agent per homedir and leaves it running.  Tests create
        many short-lived homedirs, and a long-running deployment that reloads
        configuration should not accumulate agents either.
        """
        gpgconf = shutil.which("gpgconf")
        if gpgconf is None:  # pragma: no cover - gpgconf ships with gpg
            return
        subprocess.run(  # noqa: S603 - fixed argv, no user input
            [gpgconf, "--homedir", str(self.home), "--kill", "gpg-agent"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    # -- inspection --------------------------------------------------------

    def _secret_fingerprints(self) -> set[str]:
        result = self._run(["--list-secret-keys", "--with-colons"], check=False)
        found: set[str] = set()
        in_secret = False
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            fields = line.split(":")
            if fields[0] in {"sec", "ssb"}:
                in_secret = fields[0] == "sec"
            # The fingerprint record follows the key record it belongs to.
            elif fields[0] == FINGERPRINT_RECORD and in_secret:
                found.add(fields[9].upper())
                in_secret = False
        return found

    def list_keys(self) -> list[KeyInfo]:
        """Every public key in the keyring, newest primary key data only."""
        result = self._run(["--list-keys", "--with-colons"], check=False)
        secrets = self._secret_fingerprints()

        keys: list[KeyInfo] = []
        pending: tuple[KeyAlgorithm, dt.datetime | None, dt.datetime | None] | None = None
        fingerprint: str | None = None

        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            fields = line.split(":")
            record = fields[0]
            if record == "pub":
                pending = (
                    _algorithm(fields[3], fields[2]),
                    _timestamp(fields[5]),
                    _timestamp(fields[6]),
                )
                fingerprint = None
            elif record == FINGERPRINT_RECORD and pending is not None and fingerprint is None:
                fingerprint = fields[9].upper()
            elif record == "uid" and pending is not None and fingerprint is not None:
                algorithm, created, expires = pending
                keys.append(
                    KeyInfo(
                        fingerprint=fingerprint,
                        uid=fields[9],
                        algorithm=algorithm,
                        created_at=created or dt.datetime.now(dt.UTC),
                        expires_at=expires,
                        has_secret=fingerprint in secrets,
                    )
                )
                pending = None
                fingerprint = None
        return keys

    def find_key(self, fingerprint: str) -> KeyInfo | None:
        wanted = fingerprint.replace(" ", "").upper()
        return next((key for key in self.list_keys() if key.fingerprint == wanted), None)

    def has_secret_key(self, fingerprint: str) -> bool:
        return fingerprint.replace(" ", "").upper() in self._secret_fingerprints()

    # -- key lifecycle -----------------------------------------------------

    def generate_key(
        self,
        uid: str,
        algorithm: KeyAlgorithm = KeyAlgorithm.RSA4096,
        *,
        passphrase: str | None = None,
    ) -> KeyInfo:
        """Create a signing key that never expires (4.3, AD-15).

        No expiry is deliberate: an expired signing key silently breaks every
        client that already trusts it, and the failure surfaces as an
        unhelpful apt error long after anyone remembers creating the key.
        """
        spec = _ALGORITHM_SPECS[algorithm]
        # Always take the descriptor path, even for an unprotected key: with no
        # --passphrase-fd at all, gpg decides it needs to prompt and then fails
        # with "we are in batchmode - can't get input".  An empty passphrase on
        # the descriptor is how you say "no passphrase" without a terminal.
        result = self._run(
            ["--quick-generate-key", uid, spec, "sign", "never"],
            passphrase=passphrase if passphrase is not None else "",
        )
        fingerprint = self._created_fingerprint(result)
        key = self.find_key(fingerprint)
        if key is None:  # pragma: no cover - gpg reported a key it did not store
            raise GnuPGError(f"gpg created {fingerprint} but it is not in the keyring")
        return key

    @staticmethod
    def _created_fingerprint(result: _Result) -> str:
        for status in result.status_lines:
            parts = status.split()
            if parts and parts[0] == "KEY_CREATED" and len(parts) >= 3:
                return parts[2].upper()
        raise GnuPGError(
            "gpg did not report a created key. Output was:\n" + (result.message or "(silent)")
        )

    def import_key(self, armored: str) -> KeyInfo:
        """Import an existing key, requiring the private half to be present.

        A public key alone cannot sign anything, so importing one would create a
        repository that appears configured and then fails at its first publish.
        Rejecting it here turns that into an immediate, explainable error.
        """
        # check=False: gpg exits non-zero for "that was not a key", and its own
        # message ("no valid OpenPGP data found") says nothing about what to do.
        # The actionable wording below should always be the one the user sees.
        result = self._run(["--import"], stdin=armored.encode("utf-8"), check=False)
        fingerprints = [
            parts[2].upper()
            for status in result.status_lines
            if (parts := status.split()) and parts[0] == "IMPORT_OK" and len(parts) >= 3
        ]
        if not fingerprints:
            raise GnuPGError(
                "No OpenPGP key was found in that text. Paste the full ASCII-armoured "
                "private key block, as produced by 'gpg --armor --export-secret-keys'."
            )

        fingerprint = fingerprints[0]
        if not self.has_secret_key(fingerprint):
            raise GnuPGError(
                f"Key {fingerprint[-16:]} was imported without its private half, so it cannot "
                "sign repository metadata. Export it with 'gpg --armor --export-secret-keys'."
            )
        key = self.find_key(fingerprint)
        if key is None:  # pragma: no cover - imported but not listed
            raise GnuPGError(f"gpg imported {fingerprint} but it is not in the keyring")
        return key

    def export_public(self, fingerprint: str) -> str:
        """The armoured *public* key, for clients to trust.

        There is no private counterpart to this method, by design (10.5).
        """
        result = self._run(["--armor", "--export", fingerprint])
        armored = result.stdout.decode("ascii", errors="replace")
        if "BEGIN PGP PUBLIC KEY BLOCK" not in armored:
            raise GnuPGError(f"no public key for {fingerprint} in this keyring")
        return armored

    def delete_key(self, fingerprint: str) -> None:
        """Remove both halves.  Callers must check for referencing repositories first."""
        self._run(["--delete-secret-and-public-key", fingerprint])

    # -- signing -----------------------------------------------------------

    def clearsign(self, data: bytes, fingerprint: str, *, passphrase: str | None = None) -> bytes:
        """Inline signature, as apt expects in ``InRelease`` (4.1)."""
        result = self._run(
            [
                "--armor",
                "--digest-algo",
                DIGEST_ALGO,
                "--local-user",
                fingerprint,
                "--clearsign",
            ],
            stdin=data,
            passphrase=passphrase,
        )
        return result.stdout

    def detach_sign(self, data: bytes, fingerprint: str, *, passphrase: str | None = None) -> bytes:
        """Detached armoured signature, as apt expects in ``Release.gpg`` (4.1)."""
        result = self._run(
            [
                "--armor",
                "--digest-algo",
                DIGEST_ALGO,
                "--local-user",
                fingerprint,
                "--detach-sign",
            ],
            stdin=data,
            passphrase=passphrase,
        )
        return result.stdout

    # -- verification (used by tests and the rescan path) ------------------

    def verify_detached(self, data: bytes, signature: bytes) -> bool:
        signature_file = self.home / ".verify.sig"
        try:
            signature_file.write_bytes(signature)
            result = self._run(["--verify", str(signature_file), "-"], stdin=data, check=False)
        finally:
            signature_file.unlink(missing_ok=True)
        return result.returncode == 0

    def verify_clearsigned(self, signed: bytes) -> bytes | None:
        """Return the signed payload if the signature is good, else ``None``."""
        result = self._run(["--decrypt"], stdin=signed, check=False)
        if result.returncode != 0:
            return None
        return result.stdout
