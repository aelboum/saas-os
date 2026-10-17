"""AI provider credential provisioning (`saas_os.control_plane.inference.credentials`).

Only a secret name the deployment lists in `AI_PROVIDER_CREDENTIALS` may be
used as an AI provider credential. A name that merely resolves, such as the
installation's own `DATABASE_URL`, is never eligible, and the secrets provider
is never asked for it. A malformed list provisions nothing.
"""

from __future__ import annotations

import pytest

from saas_os.control_plane.inference import service
from saas_os.control_plane.inference.credentials import (
    PROVISIONING_VARIABLE,
    AICredentialProvisioningError,
    is_provisioned,
    provisioned_credential_names,
    resolve_ai_credential,
)
from saas_os.infra.secrets import get_secrets_provider

_VALUE = "placeholder-credential-value-for-tests"  # pragma: allowlist secret


class _Recording:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.asked: list[str] = []

    def get(self, name: str) -> str | None:
        self.asked.append(name)
        return self.values.get(name)


def _env(value: str | None) -> dict[str, str]:
    return {} if value is None else {PROVISIONING_VARIABLE: value}


@pytest.mark.parametrize(
    ("raw", "names"),
    [
        (None, frozenset()),
        ("", frozenset()),
        ("   ", frozenset()),
        ("AI_KEY", frozenset({"AI_KEY"})),
        (" AI_KEY , OTHER_KEY ,AI_KEY", frozenset({"AI_KEY", "OTHER_KEY"})),
    ],
)
def test_the_provisioned_names(raw: str | None, names: frozenset[str]) -> None:
    assert provisioned_credential_names(_env(raw)) == names


@pytest.mark.parametrize("raw", ["AI_KEY,", ",AI_KEY", "AI_KEY,,B", "ai_key", "AI-KEY", "A B"])
def test_a_malformed_list_is_never_partly_applied(raw: str) -> None:
    with pytest.raises(AICredentialProvisioningError) as caught:
        provisioned_credential_names(_env(raw))
    assert str(caught.value) == f"{PROVISIONING_VARIABLE} is malformed"
    assert not is_provisioned("AI_KEY", _env(raw))


def test_an_unrelated_installation_secret_is_never_resolved() -> None:
    secrets = _Recording({"DATABASE_URL": "postgresql://u:p@db/x", "AI_KEY": _VALUE})
    env = _env("AI_KEY")
    assert resolve_ai_credential("DATABASE_URL", secrets=lambda: secrets, env=env) is None  # type: ignore[arg-type,return-value]
    assert secrets.asked == []
    assert resolve_ai_credential("AI_KEY", secrets=lambda: secrets, env=env) == _VALUE  # type: ignore[arg-type,return-value]
    assert secrets.asked == ["AI_KEY"]


@pytest.mark.parametrize(
    ("name", "raw", "values"),
    [
        ("AI_KEY", None, {"AI_KEY": _VALUE}),  # nothing provisioned
        ("AI_KEY", "AI_KEY,", {"AI_KEY": _VALUE}),  # malformed list
        ("AI_KEY", "AI_KEY", {}),  # provisioned but missing
        ("AI_KEY", "AI_KEY", {"AI_KEY": ""}),  # provisioned but empty
        ("ai_key", "AI_KEY", {"ai_key": _VALUE}),  # not a secret name
    ],
)
def test_every_other_case_resolves_nothing(
    name: str, raw: str | None, values: dict[str, str]
) -> None:
    secrets = _Recording(values)
    assert resolve_ai_credential(name, secrets=lambda: secrets, env=_env(raw)) is None  # type: ignore[arg-type,return-value]


def test_the_runtime_resolver_uses_only_provisioned_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The real secrets provider (`ENVIRONMENT=test`: the process environment).
    monkeypatch.setenv("AI_TEST_PROVIDER_KEY", _VALUE)
    monkeypatch.setenv("AI_TEST_UNRELATED_SECRET", _VALUE)
    monkeypatch.setenv(PROVISIONING_VARIABLE, "AI_TEST_PROVIDER_KEY")
    get_secrets_provider.cache_clear()
    try:
        credential = service._default_credential("AI_TEST_PROVIDER_KEY")  # pyright: ignore[reportPrivateUsage]
        assert credential is not None and credential.reveal() == _VALUE
        assert service._default_credential("AI_TEST_UNRELATED_SECRET") is None  # pyright: ignore[reportPrivateUsage]
        monkeypatch.delenv(PROVISIONING_VARIABLE)
        assert service._default_credential("AI_TEST_PROVIDER_KEY") is None  # pyright: ignore[reportPrivateUsage]
    finally:
        get_secrets_provider.cache_clear()
