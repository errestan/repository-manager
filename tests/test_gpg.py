"""The GnuPG wrapper, against a real gpg (specification.md 10.5)."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from repository_manager.models import KeyAlgorithm
from repository_manager.security.gpg import GnuPG, GnuPGError
from repository_manager.security.passphrase import (
    PassphraseError,
    PassphraseStore,
    environment_variable,
    generate_passphrase,
)
from tests.conftest import Keyring

RELEASE = b"Origin: Example\nCodename: bookworm\n"


@pytest.fixture
def gpg(scratch_keyring: Keyring) -> GnuPG:
    return GnuPG(scratch_keyring.home)


# ------------------------------------------------------------------ inspection


def test_the_fixture_key_is_present_with_its_private_half(
    gpg: GnuPG, scratch_keyring: Keyring
) -> None:
    key = gpg.find_key(scratch_keyring.fingerprint)
    assert key is not None
    assert key.has_secret
    assert key.algorithm is KeyAlgorithm.ED25519


def test_a_signing_key_never_expires(gpg: GnuPG, scratch_keyring: Keyring) -> None:
    """An expired key breaks every client that already trusts it (AD-15)."""
    key = gpg.find_key(scratch_keyring.fingerprint)
    assert key is not None
    assert key.expires_at is None


def test_an_unknown_fingerprint_is_not_found(gpg: GnuPG) -> None:
    assert gpg.find_key("0" * 40) is None
    assert not gpg.has_secret_key("0" * 40)


def test_the_keyring_directory_is_private(scratch_keyring: Keyring) -> None:
    assert stat.S_IMODE(scratch_keyring.home.stat().st_mode) == 0o700


def test_a_missing_gpg_binary_is_reported_clearly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The most likely deployment failure deserves an actionable message."""
    monkeypatch.setattr("repository_manager.security.gpg.shutil.which", lambda _name: None)
    with pytest.raises(GnuPGError, match="Install GnuPG"):
        GnuPG(tmp_path / "home")


# ------------------------------------------------------------------ signing


def test_clearsign_produces_an_inline_signature(gpg: GnuPG, scratch_keyring: Keyring) -> None:
    signed = gpg.clearsign(RELEASE, scratch_keyring.fingerprint)
    assert signed.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----")
    assert gpg.verify_clearsigned(signed) == RELEASE


def test_detached_signatures_verify(gpg: GnuPG, scratch_keyring: Keyring) -> None:
    signature = gpg.detach_sign(RELEASE, scratch_keyring.fingerprint)
    assert signature.startswith(b"-----BEGIN PGP SIGNATURE-----")
    assert gpg.verify_detached(RELEASE, signature)


def test_a_detached_signature_does_not_verify_altered_content(
    gpg: GnuPG, scratch_keyring: Keyring
) -> None:
    signature = gpg.detach_sign(RELEASE, scratch_keyring.fingerprint)
    assert not gpg.verify_detached(RELEASE + b"Suite: evil\n", signature)


def test_an_altered_clearsigned_document_is_rejected(gpg: GnuPG, scratch_keyring: Keyring) -> None:
    signed = gpg.clearsign(RELEASE, scratch_keyring.fingerprint)
    assert gpg.verify_clearsigned(signed.replace(b"Example", b"Evil123")) is None


def test_signing_with_an_absent_key_fails(gpg: GnuPG) -> None:
    with pytest.raises(GnuPGError):
        gpg.detach_sign(RELEASE, "0" * 40)


# ------------------------------------------------------------------ export


def test_only_the_public_key_can_be_exported(gpg: GnuPG, scratch_keyring: Keyring) -> None:
    """There is deliberately no private export method to guard (10.5)."""
    armored = gpg.export_public(scratch_keyring.fingerprint)
    assert "BEGIN PGP PUBLIC KEY BLOCK" in armored
    assert "PRIVATE KEY" not in armored
    assert not hasattr(gpg, "export_private")
    assert not hasattr(gpg, "export_secret")


def test_exporting_an_unknown_key_fails(gpg: GnuPG) -> None:
    with pytest.raises(GnuPGError, match="no public key"):
        gpg.export_public("0" * 40)


# ------------------------------------------------------------------ import


def test_importing_a_public_key_alone_is_refused(gpg: GnuPG, tmp_path: Path) -> None:
    """A public key cannot sign, so accepting it would defer the failure (10.5)."""
    other = GnuPG(tmp_path / "other")
    try:
        info = other.generate_key("Other <other@example.test>", KeyAlgorithm.ED25519)
        public_only = other.export_public(info.fingerprint)
    finally:
        other.shutdown()

    with pytest.raises(GnuPGError, match="without its private half"):
        gpg.import_key(public_only)


def test_importing_nonsense_is_refused(gpg: GnuPG) -> None:
    with pytest.raises(GnuPGError, match="No OpenPGP key"):
        gpg.import_key("this is not a key at all")


# ------------------------------------------------------------------ generation


def test_generating_a_key_with_a_passphrase_round_trips(tmp_path: Path) -> None:
    gpg = GnuPG(tmp_path / "protected")
    try:
        info = gpg.generate_key(
            "Protected <p@example.test>", KeyAlgorithm.ED25519, passphrase="correct horse"
        )
        # The wrong passphrase is tried FIRST, deliberately.  gpg-agent caches
        # the unlocked key once a correct passphrase has been supplied, and from
        # then on it signs regardless of what is passed -- so asserting the
        # rejection after a success would test the agent's cache, not the key.
        with pytest.raises(GnuPGError, match=r"[Bb]ad passphrase"):
            gpg.detach_sign(RELEASE, info.fingerprint, passphrase="wrong")

        signature = gpg.detach_sign(RELEASE, info.fingerprint, passphrase="correct horse")
        assert gpg.verify_detached(RELEASE, signature)
    finally:
        gpg.shutdown()


def test_deleting_a_key_removes_both_halves(gpg: GnuPG, scratch_keyring: Keyring) -> None:
    gpg.delete_key(scratch_keyring.fingerprint)
    assert gpg.find_key(scratch_keyring.fingerprint) is None
    assert not gpg.has_secret_key(scratch_keyring.fingerprint)


# ------------------------------------------------------------------ passphrases


def test_a_stored_passphrase_round_trips(tmp_path: Path) -> None:
    store = PassphraseStore(tmp_path / "gnupg", environ={})
    secret = generate_passphrase()
    store.store("internal", secret)
    assert store.resolve("internal") == secret


def test_a_stored_passphrase_is_owner_only(tmp_path: Path) -> None:
    store = PassphraseStore(tmp_path / "gnupg", environ={})
    store.store("internal", "s3cret")
    mode = stat.S_IMODE((store.directory / "internal").stat().st_mode)
    assert mode == 0o600


def test_the_environment_takes_priority_over_the_file(tmp_path: Path) -> None:
    """The hook for Vault, Kubernetes secrets and anything else at runtime (10.5)."""
    store = PassphraseStore(
        tmp_path / "gnupg", environ={environment_variable("internal"): "from-the-environment"}
    )
    store.store("internal", "from-the-file")
    assert store.resolve("internal") == "from-the-environment"


def test_an_unknown_reference_says_where_to_put_it(tmp_path: Path) -> None:
    store = PassphraseStore(tmp_path / "gnupg", environ={})
    with pytest.raises(PassphraseError, match="REPOMAN_KEY_PASSPHRASE_INTERNAL"):
        store.resolve("internal")


def test_storing_twice_refuses_rather_than_stranding_the_key(tmp_path: Path) -> None:
    store = PassphraseStore(tmp_path / "gnupg", environ={})
    store.store("internal", "first")
    with pytest.raises(PassphraseError, match="already exists"):
        store.store("internal", "second")
    assert store.resolve("internal") == "first"


def test_no_reference_means_no_passphrase(tmp_path: Path) -> None:
    assert PassphraseStore(tmp_path / "gnupg", environ={}).resolve(None) is None


def test_a_hostile_reference_is_refused(tmp_path: Path) -> None:
    store = PassphraseStore(tmp_path / "gnupg", environ={})
    for hostile in ("../../etc/passwd", "Internal", "with space", ""):
        with pytest.raises(PassphraseError, match="not a valid passphrase reference"):
            store.resolve(hostile)


def test_generated_passphrases_are_long_and_distinct() -> None:
    first, second = generate_passphrase(), generate_passphrase()
    assert first != second
    assert len(first) >= 40
