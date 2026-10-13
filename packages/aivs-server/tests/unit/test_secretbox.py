"""Envelope encryption for the reversible secrets.

The round trip is the least interesting property here. What these assert is that
a sealed value is *not portable*: it cannot be moved to another row, or reused
for another purpose, or opened by a different deployment's key. Those are the
properties that make the AAD worth carrying, and without tests they are the ones
that would be quietly dropped by a refactor that "simplified" the signature.
"""

from __future__ import annotations

import base64
import logging
import os
import uuid

import pytest
from pydantic import ValidationError

from aivs_server.auth.secretbox import (
    ALGORITHM_NAMES,
    DEFAULT_ALGORITHM_NAME,
    SecretBox,
    SecretPurpose,
    algorithm_by_name,
)
from aivs_server.config import Settings
from tests.conftest import (
    TEST_CA_CERT_FILE,
    TEST_DATABASE_URL,
    TEST_PROXY_SECRET,
    TEST_SECRET_KEY,
    TEST_SESSION_SECRET,
)

KEY_BYTES = algorithm_by_name(DEFAULT_ALGORITHM_NAME).key_bytes
KEY_A = os.urandom(KEY_BYTES)
KEY_B = os.urandom(KEY_BYTES)


@pytest.fixture(params=ALGORITHM_NAMES)
def box(request) -> SecretBox:
    """Every property below is asserted for every registered algorithm.

    Agility that is only exercised for the default is agility nobody has tried.
    """
    return SecretBox(active=KEY_A, algorithm=algorithm_by_name(request.param))


def test_a_sealed_secret_round_trips(box):
    subject = uuid.uuid4()
    sealed = box.seal("JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=subject)

    assert sealed != b"JBSWY3DPEHPK3PXP"
    assert b"JBSWY3DPEHPK3PXP" not in sealed
    assert box.unseal(sealed, purpose=SecretPurpose.TOTP, subject=subject) == "JBSWY3DPEHPK3PXP"


def test_sealing_twice_produces_different_ciphertext(box):
    """A fresh nonce each time, so equal secrets are not visibly equal.

    Without this, two operators who enrolled from the same seed -- or one
    operator's seed before and after a change -- would be recognisable as such
    from the column alone.
    """
    subject = uuid.uuid4()
    first = box.seal("same-secret", purpose=SecretPurpose.TOTP, subject=subject)
    second = box.seal("same-secret", purpose=SecretPurpose.TOTP, subject=subject)

    assert first != second


def test_a_seal_does_not_open_for_another_row(box):
    """The property the AAD exists for.

    Unbound, a sealed TOTP seed is a portable capability: anyone able to write
    one operator's column could paste in another operator's seed and inherit
    their second factor.
    """
    mine = uuid.uuid4()
    theirs = uuid.uuid4()
    sealed = box.seal("JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=mine)

    assert box.unseal(sealed, purpose=SecretPurpose.TOTP, subject=theirs) is None


def test_a_seal_does_not_open_for_another_purpose(box):
    subject = uuid.uuid4()
    sealed = box.seal("shared-value", purpose=SecretPurpose.TOTP, subject=subject)

    assert box.unseal(sealed, purpose=SecretPurpose.WEBHOOK_HMAC, subject=subject) is None


def test_a_tampered_ciphertext_does_not_open(box):
    subject = uuid.uuid4()
    sealed = bytearray(box.seal("JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=subject))
    sealed[-1] ^= 0x01

    assert box.unseal(bytes(sealed), purpose=SecretPurpose.TOTP, subject=subject) is None


def test_another_deployments_key_does_not_open_it(box):
    subject = uuid.uuid4()
    sealed = box.seal("JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=subject)

    assert (
        SecretBox(active=KEY_B).unseal(sealed, purpose=SecretPurpose.TOTP, subject=subject) is None
    )


def test_an_absent_value_is_not_an_error(box):
    """An operator who never enrolled has no seed, which is not a failure."""
    assert box.unseal(None, purpose=SecretPurpose.TOTP, subject=uuid.uuid4()) is None
    assert box.unseal(b"", purpose=SecretPurpose.TOTP, subject=uuid.uuid4()) is None


def test_a_legacy_base64_value_does_not_open_and_says_so(box, caplog):
    """The pre-migration format must fail loudly, not decode by accident."""
    legacy = base64.b64encode(b"JBSWY3DPEHPK3PXP")

    with caplog.at_level(logging.WARNING):
        assert box.unseal(legacy, purpose=SecretPurpose.TOTP, subject=uuid.uuid4()) is None

    assert "not in a recognised format" in caplog.text


def test_a_failure_never_logs_the_secret(box, caplog):
    subject = uuid.uuid4()
    sealed = box.seal("JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=subject)

    with caplog.at_level(logging.WARNING):
        box.unseal(sealed, purpose=SecretPurpose.TOTP, subject=uuid.uuid4())

    assert caplog.text  # it did complain
    assert "JBSWY3DPEHPK3PXP" not in caplog.text


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------
def test_the_previous_key_still_opens_existing_values():
    """During a rotation both keys open; only the new one seals."""
    subject = uuid.uuid4()
    old = SecretBox(active=KEY_A)
    sealed_before = old.seal("JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=subject)

    rotating = SecretBox(active=KEY_B, previous=KEY_A)

    assert rotating.unseal(sealed_before, purpose=SecretPurpose.TOTP, subject=subject) == (
        "JBSWY3DPEHPK3PXP"
    )
    assert rotating.needs_rewrap(sealed_before) is True

    resealed = rotating.seal("JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=subject)
    assert rotating.needs_rewrap(resealed) is False
    # And once re-sealed, dropping the previous key is safe.
    assert (
        SecretBox(active=KEY_B).unseal(resealed, purpose=SecretPurpose.TOTP, subject=subject)
        == "JBSWY3DPEHPK3PXP"
    )


def test_dropping_the_previous_key_too_early_is_visible():
    """`needs_rewrap` is the check an operator runs before dropping the old key."""
    subject = uuid.uuid4()
    sealed_before = SecretBox(active=KEY_A).seal(
        "JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=subject
    )
    dropped_early = SecretBox(active=KEY_B)

    assert dropped_early.needs_rewrap(sealed_before) is True
    assert dropped_early.unseal(sealed_before, purpose=SecretPurpose.TOTP, subject=subject) is None


def test_a_legacy_value_reports_as_needing_rewrap(box):
    assert box.needs_rewrap(base64.b64encode(b"JBSWY3DPEHPK3PXP")) is True


def test_an_absent_value_does_not_need_rewrap(box):
    assert box.needs_rewrap(None) is False


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def _settings(**overrides: object) -> Settings:
    base = {
        "environment": "test",
        "public_base_url": "https://aivs.test",
        "database_url": TEST_DATABASE_URL,
        "proxy_shared_secret": TEST_PROXY_SECRET,
        "session_secret": TEST_SESSION_SECRET,
        "secret_encryption_key": TEST_SECRET_KEY,
        "issuing_ca_certificate_file": TEST_CA_CERT_FILE,
    }
    return Settings(**(base | overrides))


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(base64.b64encode(b"too-short").decode(), id="wrong-length"),
        pytest.param("not-base64-at-all!!", id="not-base64"),
    ],
)
def test_an_unusable_key_refuses_to_start(value):
    """Caught at construction, not at the first login after a deployment."""
    with pytest.raises(ValidationError):
        _settings(secret_encryption_key=value)


def test_the_shipped_placeholder_is_refused_by_name():
    """`deploy/env.example` ships REPLACE_ME, and it must not start.

    Named explicitly rather than relying on the length check: the whole reason
    the placeholder rule exists is that an earlier set of placeholders happened
    to be long enough to pass validation.
    """
    with pytest.raises(ValidationError, match="REPLACE_ME"):
        _settings(secret_encryption_key="REPLACE_ME")


def test_settings_build_a_working_box():
    box = SecretBox.from_settings(_settings())
    subject = uuid.uuid4()
    sealed = box.seal("value", purpose=SecretPurpose.WEBHOOK_HMAC, subject=subject)

    assert box.unseal(sealed, purpose=SecretPurpose.WEBHOOK_HMAC, subject=subject) == "value"


def test_a_rotation_is_configurable_end_to_end():
    previous = base64.b64encode(KEY_A).decode()
    active = base64.b64encode(KEY_B).decode()
    box = SecretBox.from_settings(
        _settings(secret_encryption_key=active, secret_encryption_key_previous=previous)
    )
    subject = uuid.uuid4()

    sealed_under_old = SecretBox(active=KEY_A).seal(
        "value", purpose=SecretPurpose.TOTP, subject=subject
    )
    assert box.unseal(sealed_under_old, purpose=SecretPurpose.TOTP, subject=subject) == "value"


def test_an_empty_previous_key_means_not_rotating():
    """Compose writes `${VAR:-}` as an empty string when nothing is set.

    A deployment that is not mid-rotation must not be refused for a variable it
    never set -- but the leniency must not extend to the active key.
    """
    settings = _settings(secret_encryption_key_previous="")
    assert settings.secret_encryption_key_previous is None
    assert settings.secret_encryption_key_previous_bytes is None
    assert SecretBox.from_settings(settings) is not None


def test_an_empty_active_key_is_still_refused():
    with pytest.raises(ValidationError):
        _settings(secret_encryption_key="")


@pytest.mark.parametrize("length", [16, 31, 33, 64])
def test_a_key_of_the_wrong_length_is_refused_at_construction(length):
    """Belt to the config validator's braces: the box never stretches a key."""
    with pytest.raises(ValueError, match="exactly"):
        SecretBox(active=os.urandom(length))


def test_a_previous_key_of_the_wrong_length_is_refused_too():
    """Held to "a length some algorithm uses", not to the active algorithm's.

    The previous key exists to open values that may have been written under a
    different algorithm, so pinning it to the current one would refuse exactly
    the cross-algorithm migration this design is for.
    """
    with pytest.raises(ValueError, match="must be one of"):
        SecretBox(active=KEY_A, previous=os.urandom(16))


def test_the_active_fingerprint_is_stable_and_not_derived_from_the_key_directly():
    """Reported to operators during a rotation, so it must not leak material.

    The containment used to be written the other way round -- `KEY_A.hex() not
    in fingerprint` -- which can never fail, because the fingerprint is eight
    hex characters and the operands are 44 and 64. It passed with the
    fingerprint defined as `key[:4]`, i.e. with four bytes of the key printed
    verbatim. The assertion that matters is that no prefix of the key's own
    encodings appears in the fingerprint.
    """
    fingerprint = SecretBox(active=KEY_A).active_fingerprint

    assert fingerprint == SecretBox(active=KEY_A).active_fingerprint, "stable"
    assert fingerprint != SecretBox(active=KEY_B).active_fingerprint, "distinguishing"
    assert len(fingerprint) == 8

    # A truncation of the key, or of either of its usual encodings, would show
    # up here. `key[:4]` -- the mutation that slipped past the old form -- makes
    # the first of these fail.
    assert fingerprint != KEY_A[:4].hex()
    assert not KEY_A.hex().startswith(fingerprint)
    assert not base64.b64encode(KEY_A).decode().startswith(fingerprint)


# ---------------------------------------------------------------------------
# Algorithm agility
# ---------------------------------------------------------------------------
def test_more_than_one_algorithm_is_registered():
    """A registry with one entry has never had its indirection exercised."""
    assert len(ALGORITHM_NAMES) >= 2
    assert DEFAULT_ALGORITHM_NAME in ALGORITHM_NAMES


@pytest.mark.parametrize("name", ALGORITHM_NAMES)
def test_every_algorithm_names_itself_in_its_ciphertext(name):
    """The header, not the configuration, says how a value was written."""
    algorithm = algorithm_by_name(name)
    sealed = SecretBox(active=KEY_A, algorithm=algorithm).seal(
        "value", purpose=SecretPurpose.TOTP, subject=uuid.uuid4()
    )

    assert sealed[:4] == b"AIVS"
    assert sealed[4] == 1, "envelope version"
    assert sealed[5] == algorithm.id


def test_algorithm_ids_and_names_are_unique():
    """Ids are on disk in deployments we do not control; collisions are silent."""
    algorithms = [algorithm_by_name(n) for n in ALGORITHM_NAMES]
    assert len({a.id for a in algorithms}) == len(algorithms)
    assert len({a.name for a in algorithms}) == len(algorithms)


def test_a_value_keeps_opening_after_the_algorithm_changes():
    """The whole point: changing the algorithm does not strand existing data.

    Same key, different algorithm. The old value opens because it says what it
    was written with; the new value is written with the new one.
    """
    subject = uuid.uuid4()
    old = SecretBox(active=KEY_A, algorithm=algorithm_by_name("aes-256-gcm"))
    sealed_before = old.seal("JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=subject)

    switched = SecretBox(active=KEY_A, algorithm=algorithm_by_name("chacha20-poly1305"))

    assert (
        switched.unseal(sealed_before, purpose=SecretPurpose.TOTP, subject=subject)
        == "JBSWY3DPEHPK3PXP"
    )
    assert switched.needs_rewrap(sealed_before) is True, "reported for migration"

    resealed = switched.seal("JBSWY3DPEHPK3PXP", purpose=SecretPurpose.TOTP, subject=subject)
    assert switched.needs_rewrap(resealed) is False


def test_an_algorithm_and_key_change_together_is_still_readable():
    """The realistic combined move: new cipher, new key, old key retained."""
    subject = uuid.uuid4()
    sealed_before = SecretBox(active=KEY_A, algorithm=algorithm_by_name("aes-256-gcm")).seal(
        "value", purpose=SecretPurpose.TOTP, subject=subject
    )

    rotating = SecretBox(
        active=KEY_B, previous=KEY_A, algorithm=algorithm_by_name("chacha20-poly1305")
    )

    assert rotating.unseal(sealed_before, purpose=SecretPurpose.TOTP, subject=subject) == "value"
    assert rotating.needs_rewrap(sealed_before) is True


def test_a_value_from_an_unknown_algorithm_is_refused_not_guessed(box, caplog):
    """A rollback past an algorithm we no longer implement must say so."""
    subject = uuid.uuid4()
    sealed = bytearray(box.seal("value", purpose=SecretPurpose.TOTP, subject=subject))
    sealed[5] = 0xFE  # an id no build has ever assigned

    with caplog.at_level(logging.WARNING):
        assert box.unseal(bytes(sealed), purpose=SecretPurpose.TOTP, subject=subject) is None

    assert "algorithm this build does not know" in caplog.text
    assert box.needs_rewrap(bytes(sealed)) is True


def test_a_future_envelope_version_is_refused_not_guessed(box, caplog):
    """Mid-rollout, an older build must not misparse a newer layout."""
    subject = uuid.uuid4()
    sealed = bytearray(box.seal("value", purpose=SecretPurpose.TOTP, subject=subject))
    sealed[4] = 9

    with caplog.at_level(logging.WARNING):
        assert box.unseal(bytes(sealed), purpose=SecretPurpose.TOTP, subject=subject) is None

    assert "unsupported envelope version" in caplog.text


def test_a_truncated_value_is_refused(box):
    """Shorter than a nonce plus a tag cannot be a ciphertext for this algorithm."""
    subject = uuid.uuid4()
    sealed = box.seal("value", purpose=SecretPurpose.TOTP, subject=subject)

    assert box.unseal(sealed[:-8], purpose=SecretPurpose.TOTP, subject=subject) is None


def test_an_unknown_algorithm_name_refuses_to_start():
    with pytest.raises(ValidationError, match="supported"):
        _settings(secret_encryption_algorithm="aes-512-gcm")


def test_settings_select_the_algorithm_for_new_values():
    box = SecretBox.from_settings(_settings(secret_encryption_algorithm="chacha20-poly1305"))

    assert box.algorithm.name == "chacha20-poly1305"
    sealed = box.seal("value", purpose=SecretPurpose.TOTP, subject=uuid.uuid4())
    assert sealed[5] == algorithm_by_name("chacha20-poly1305").id


def test_the_default_algorithm_is_what_a_deployment_gets_unasked():
    assert SecretBox.from_settings(_settings()).algorithm.name == DEFAULT_ALGORITHM_NAME
