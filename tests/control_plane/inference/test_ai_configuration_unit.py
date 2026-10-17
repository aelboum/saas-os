"""AI-C configuration -- hermetic checks (ADR-0054 Phase AI-C).

- The validation done before any transaction: base URLs, trust networks,
  capabilities, origins.
- The operator commands: parsing, input errors, no credential values.
- The support-access exclusion of the AI tenant actions, and that it does
  not make them authority-changing.
- The tenant AI permission vocabulary.
"""

from __future__ import annotations

import argparse

import pytest

from saas_os.control_plane.inference.capabilities import Capability
from saas_os.control_plane.inference.config import service
from saas_os.control_plane.inference.config.errors import AIConfigurationError
from saas_os.control_plane.inference.permissions import AI_PERMISSIONS
from saas_os.core.rbac import is_authority_changing
from saas_os.core.rbac.authorization import (
    _SUPPORT_ACCESS_EXCLUDED_ACTIONS,  # pyright: ignore[reportPrivateUsage]
    AI_SUPPORT_ACCESS_EXCLUDED_ACTIONS,
)
from saas_os.ops import ai_commands
from saas_os.ops.operator_cli import _build_parser  # pyright: ignore[reportPrivateUsage]

# --- base URLs ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://api.openai.com/v1",
        "https://api.anthropic.com",
        "https://llm.internal.example:8443/v1",
        "https://93.184.216.34/v1",
    ],
)
def test_valid_base_urls(url: str) -> None:
    service._validate_base_url(url)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://api.openai.com/v1", "base_url_must_be_https"),
        (
            "https://user:pw@api.openai.com/v1",  # pragma: allowlist secret
            "base_url_userinfo_not_allowed",
        ),
        ("https://user@api.openai.com/v1", "base_url_userinfo_not_allowed"),
        ("https://api.openai.com/v1?x=1", "base_url_query_not_allowed"),
        ("https://api.openai.com/v1#f", "base_url_query_not_allowed"),
        ("https://127.0.0.1/v1", "base_url_non_public_literal"),
        ("https://10.0.0.1/v1", "base_url_non_public_literal"),
        ("https://[::1]/v1", "base_url_non_public_literal"),
        ("https://169.254.169.254/latest", "base_url_non_public_literal"),
        ("https://api.openai.com:99999/v1", "invalid_base_url"),
        ("https://exämple.test/v1", "invalid_base_url"),
        ("https:///v1", "invalid_base_url"),
        ("https://bad_host.example/v1", "invalid_base_url"),
        ("https://" + "a" * 2050 + ".test/", "invalid_base_url"),
    ],
)
def test_invalid_base_urls_are_refused(url: str, reason: str) -> None:
    with pytest.raises(AIConfigurationError) as caught:
        service._validate_base_url(url)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == reason
    assert url not in str(caught.value)  # the reason code only


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://api.openai.com/v1", "https://api.openai.com:443"),
        ("https://api.openai.com:443/v2", "https://api.openai.com:443"),
        ("https://llm.example:8443/v1", "https://llm.example:8443"),
    ],
)
def test_endpoint_origin(url: str, origin: str) -> None:
    assert service.endpoint_origin(url) == origin


def test_a_path_change_keeps_the_origin_and_a_host_change_does_not() -> None:
    a = service.endpoint_origin("https://api.openai.com/v1")
    assert service.endpoint_origin("https://api.openai.com/v2") == a
    assert service.endpoint_origin("https://api.attacker.example/v1") != a
    assert service.endpoint_origin("https://api.openai.com:8443/v1") != a


# --- trust networks -------------------------------------------------------------------


def test_private_networks_are_accepted() -> None:
    networks = service._validate_trust_networks(["10.20.0.0/16", "fd12::/64"])  # pyright: ignore[reportPrivateUsage]
    assert networks == ["10.20.0.0/16", "fd12::/64"]


@pytest.mark.parametrize(
    ("networks", "reason"),
    [
        ([], "invalid_networks"),
        (["10.0.0.0/33"], "invalid_networks"),
        (["10.0.0.1/8"], "invalid_networks"),  # host bits set
        (["not-a-network"], "invalid_networks"),
        (["127.0.0.0/8"], "network_never_trusted"),
        (["169.254.169.254/32"], "network_never_trusted"),
        (["fe80::/10"], "network_never_trusted"),
        (["0.0.0.0/0"], "network_never_trusted"),
        (["8.8.8.0/24"], "network_is_public"),
        (["10.0.0.0/8"] * 17, "invalid_networks"),
    ],
)
def test_invalid_or_untrustable_networks_are_refused(networks: list[str], reason: str) -> None:
    with pytest.raises(AIConfigurationError) as caught:
        service._validate_trust_networks(networks)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == reason


# --- capabilities and keys -------------------------------------------------------------


def test_capabilities_are_the_closed_vocabulary_sorted_and_deduplicated() -> None:
    values = service._validate_capabilities(["text_output", "text_input", "text_input"])  # pyright: ignore[reportPrivateUsage]
    assert values == ["text_input", "text_output"]
    for bad in ([], ["vision"], ["text_input", "tools"]):
        with pytest.raises(AIConfigurationError):
            service._validate_capabilities(bad)  # pyright: ignore[reportPrivateUsage]
    assert {c.value for c in Capability} >= {"text_input", "text_output"}


@pytest.mark.parametrize("key", ["", "OpenAI", "-x", "a" * 65, "a b", "ä"])
def test_invalid_provider_keys(key: str) -> None:
    with pytest.raises(AIConfigurationError):
        service._validate_key(key)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("ref", ["", "openai_key", "1KEY", "KEY-1", "K" * 201])
def test_a_credential_ref_must_be_a_secret_name(ref: str) -> None:
    with pytest.raises(AIConfigurationError) as caught:
        service._validate_credential_ref(ref)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == "invalid_credential_ref"


def test_a_credential_ref_must_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Empty:
        def get(self, name: str) -> str | None:
            del name
            return None

    monkeypatch.setattr(service, "get_secrets_provider", lambda: _Empty())
    with pytest.raises(AIConfigurationError) as caught:
        service._validate_credential_ref("AI_TEST_MISSING_KEY")  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == "credential_ref_unresolved"


# --- support access and the tenant permission vocabulary -----------------------------


def test_support_access_never_satisfies_the_ai_tenant_actions() -> None:
    assert AI_SUPPORT_ACCESS_EXCLUDED_ACTIONS == {
        ("ai.inference", "run"),
        ("ai.policy", "manage"),
        ("ai.credential", "manage"),
    }
    # Reading the policy stays ordinarily reachable.
    assert ("ai.policy", "read") not in AI_SUPPORT_ACCESS_EXCLUDED_ACTIONS


def test_the_ai_exclusion_does_not_make_the_actions_authority_changing() -> None:
    """A support-access exclusion only: the API-key rule built on
    `is_authority_changing` is unchanged (ADR-0047)."""
    for resource, action in AI_SUPPORT_ACCESS_EXCLUDED_ACTIONS:
        assert not is_authority_changing(resource, action)
        assert (resource, action) not in _SUPPORT_ACCESS_EXCLUDED_ACTIONS


def test_the_tenant_ai_permissions() -> None:
    assert AI_PERMISSIONS == (
        ("ai.inference", "run"),
        ("ai.policy", "read"),
        ("ai.policy", "manage"),
        ("ai.credential", "manage"),
    )


# --- operator commands ------------------------------------------------------------------

_OPERATOR = "00000000-0000-4000-8000-000000000001"


def _parse(*argv: str) -> argparse.Namespace:
    return _build_parser().parse_args(list(argv))


def test_every_ai_command_is_registered() -> None:
    parser = _build_parser()
    subparsers = next(
        a
        for a in parser._actions  # pyright: ignore[reportPrivateUsage]
        if isinstance(a, argparse._SubParsersAction)  # pyright: ignore[reportPrivateUsage]
    )
    assert set(ai_commands.AI_COMMANDS) <= set(subparsers.choices)


def test_provider_create_takes_a_secret_name_and_no_value_option() -> None:
    base = [
        "ai-provider-create",
        "--key",
        "openai",
        "--protocol",
        "openai_chat_completions",
        "--base-url",
        "https://api.openai.com/v1",
    ]
    tail = ["--operator", _OPERATOR, "--reason", "TICKET-1"]
    args = _parse(*base, "--credential-ref", "OPENAI_API_KEY", *tail)
    assert args.credential_ref == "OPENAI_API_KEY"
    with pytest.raises(SystemExit):
        _parse(*base, "--credential", "not-a-real-value", *tail)


@pytest.mark.parametrize(
    "argv",
    [
        ("ai-alias-set", "--alias", "a", "--candidate", "no-colon", "--operator", _OPERATOR),
        ("ai-trust-revoke", "--entry", "not-a-uuid", "--operator", _OPERATOR),
        ("ai-show", "--operator", "not-a-uuid"),
        (
            "ai-trust-create",
            "--host",
            "h.example",
            "--port",
            "443",
            "--network",
            "10.0.0.0/8",
            "--expires-at",
            "2027-01-01T00:00:00",  # no UTC offset
            "--operator",
            _OPERATOR,
        ),
    ],
)
def test_input_errors_are_refused_before_any_core_call(
    argv: tuple[str, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[str] = []
    for name in ("read_ai_configuration", "set_alias", "create_trust_entry", "revoke_trust_entry"):
        monkeypatch.setattr(service, name, lambda *a, _n=name, **k: called.append(_n))
    extra = () if argv[0] == "ai-show" else ("--reason", "TICKET-1")
    args = _parse(*argv, *extra)
    with pytest.raises(ai_commands.AICommandInputError):
        ai_commands.AI_COMMANDS[args.command](args)
    assert called == []


@pytest.mark.parametrize("reason", ["", "   ", "x" * 501])
def test_a_reason_is_required_and_bounded(reason: str) -> None:
    args = _parse(
        "ai-provider-status",
        "--key",
        "k",
        "--status",
        "disabled",
        "--operator",
        _OPERATOR,
        "--reason",
        reason,
    )
    with pytest.raises(ai_commands.AICommandInputError):
        ai_commands.AI_COMMANDS[args.command](args)


def test_a_command_passes_a_user_caller_and_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake(**kwargs: object) -> str:
        seen.update(kwargs)
        return "ok"

    monkeypatch.setattr(service, "set_destination_policy", fake)
    args = _parse(
        "ai-destination-policy",
        "--provider",
        "openai",
        "--classification",
        "tenant_data",
        "--allowed",
        "no",
        "--operator",
        _OPERATOR,
        "--reason",
        " TICKET-9 ",
    )
    assert ai_commands.AI_COMMANDS[args.command](args) == "ok"
    caller = seen["caller"]
    assert type(caller).__name__ == "UserCaller"
    assert str(caller.user_id) == _OPERATOR  # type: ignore[attr-defined]
    assert seen["reason"] == "TICKET-9" and seen["allowed"] is False
