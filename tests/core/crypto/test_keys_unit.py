"""S-01 (BANK-SEC-01/02) -- `core.crypto.keys.SecretsBackedKeyProvider`:
proves it reads key material through `infra.secrets.SecretsProvider`
(substitution test, mirroring `tests/infra/secrets/test_db_consumer_
integration.py`'s own non-vacuous pattern -- never `os.environ` directly),
and fails closed on every missing/malformed-configuration case."""

from __future__ import annotations

import base64

import pytest
from core.crypto.errors import EncryptionKeyUnavailableError, UnknownKeyVersionError
from core.crypto.keys import SecretsBackedKeyProvider
from infra.secrets.provider import SecretsProvider

_VALID_KEY_B64 = base64.b64encode(b"0" * 32).decode()


class _FakeProvider(SecretsProvider):
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str | None:
        return self._values.get(name)


def test_current_key_version_comes_from_the_secrets_provider_not_os_environ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FIELD_ENCRYPTION_ACTIVE_KEY_VERSION", "from-os-environ")
    fake_provider = _FakeProvider({"FIELD_ENCRYPTION_ACTIVE_KEY_VERSION": "v1"})
    monkeypatch.setattr("core.crypto.keys.get_secrets_provider", lambda: fake_provider)

    assert SecretsBackedKeyProvider().current_key_version() == "v1"


def test_key_for_version_decodes_base64_to_raw_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_provider = _FakeProvider({"FIELD_ENCRYPTION_KEY_V1": _VALID_KEY_B64})
    monkeypatch.setattr("core.crypto.keys.get_secrets_provider", lambda: fake_provider)

    key = SecretsBackedKeyProvider().key_for_version("v1")

    assert key == b"0" * 32
    assert len(key) == 32


def test_key_for_version_is_case_insensitive_on_version_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_provider = _FakeProvider({"FIELD_ENCRYPTION_KEY_V1": _VALID_KEY_B64})
    monkeypatch.setattr("core.crypto.keys.get_secrets_provider", lambda: fake_provider)

    assert SecretsBackedKeyProvider().key_for_version("v1") == b"0" * 32


def test_missing_active_version_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("core.crypto.keys.get_secrets_provider", lambda: _FakeProvider({}))

    with pytest.raises(EncryptionKeyUnavailableError):
        SecretsBackedKeyProvider().current_key_version()


def test_missing_key_for_requested_version_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("core.crypto.keys.get_secrets_provider", lambda: _FakeProvider({}))

    with pytest.raises(UnknownKeyVersionError):
        SecretsBackedKeyProvider().key_for_version("v1")


def test_non_base64_key_material_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_provider = _FakeProvider({"FIELD_ENCRYPTION_KEY_V1": "not valid base64!!!"})
    monkeypatch.setattr("core.crypto.keys.get_secrets_provider", lambda: fake_provider)

    with pytest.raises(EncryptionKeyUnavailableError):
        SecretsBackedKeyProvider().key_for_version("v1")


def test_wrong_length_key_material_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    too_short = base64.b64encode(b"short").decode()
    fake_provider = _FakeProvider({"FIELD_ENCRYPTION_KEY_V1": too_short})
    monkeypatch.setattr("core.crypto.keys.get_secrets_provider", lambda: fake_provider)

    with pytest.raises(EncryptionKeyUnavailableError):
        SecretsBackedKeyProvider().key_for_version("v1")


def test_no_key_material_ever_appears_in_an_exception_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_looking_value = "super-secret-never-leak"  # pragma: allowlist secret
    fake_provider = _FakeProvider({"FIELD_ENCRYPTION_KEY_V1": secret_looking_value})
    monkeypatch.setattr("core.crypto.keys.get_secrets_provider", lambda: fake_provider)

    with pytest.raises(EncryptionKeyUnavailableError) as exc_info:
        SecretsBackedKeyProvider().key_for_version("v1")

    assert secret_looking_value not in str(exc_info.value)
    assert secret_looking_value not in repr(exc_info.value)


def test_a_future_key_version_is_structurally_representable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S-02 architectural prerequisite: `key_for_version()` takes an
    arbitrary version string -- nothing hard-codes a single permanent key
    identifier -- so a future `v2` (post-rotation) resolves the same way
    `v1` does, with no code change to this class."""
    fake_provider = _FakeProvider(
        {
            "FIELD_ENCRYPTION_KEY_V1": _VALID_KEY_B64,
            "FIELD_ENCRYPTION_KEY_V2": base64.b64encode(b"1" * 32).decode(),
        }
    )
    monkeypatch.setattr("core.crypto.keys.get_secrets_provider", lambda: fake_provider)

    provider = SecretsBackedKeyProvider()
    assert provider.key_for_version("v1") == b"0" * 32
    assert provider.key_for_version("v2") == b"1" * 32
