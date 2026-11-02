"""ADR-0050 -- `saas-os-operator`: argument guards and the exact Core call
each command makes. Core is replaced by recorders here; the commands
against a real database are in `test_operator_cli_integration.py`."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import types
import uuid
from typing import Any

import pytest

from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.ops import operator_cli as cli

_T = uuid.uuid4()
_U = uuid.uuid4()
_OP = uuid.uuid4()


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, tuple[Any, ...], dict[str, Any]]]:
    recorded: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def recorder(name: str, result: object):  # type: ignore[no-untyped-def]
        def call(*args: Any, **kwargs: Any) -> object:
            recorded.append((name, args, kwargs))
            return result

        return call

    tenant = types.SimpleNamespace(id=_T, status="deleted", parent_id=None)
    monkeypatch.setattr(cli, "transition_tenant_status", recorder("transition", tenant))
    monkeypatch.setattr(cli, "move_tenant", recorder("move", tenant))
    monkeypatch.setattr(cli, "purge_tenant", recorder("purge", {"tenant_id": _T}))
    monkeypatch.setattr(cli, "erase_user_identity", recorder("erase", {"user_id": _U}))
    monkeypatch.setattr(cli, "validate_application_role", lambda engine: None)
    monkeypatch.setattr(cli, "get_engine", lambda: object())
    monkeypatch.setattr(cli, "get_user", lambda user_id: object())
    monkeypatch.setenv("ENVIRONMENT", "test")
    return recorded


def test_delete_tenant_is_one_transition_by_the_named_operator(
    calls: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main(
        [
            "delete-tenant",
            "--tenant",
            str(_T),
            "--operator",
            str(_OP),
            "--reason",
            "T-1",
            "--confirm",
            str(_T),
        ]
    )
    assert code == 0
    [(name, args, kwargs)] = calls
    assert name == "transition"
    assert args[0] == _T and args[1].value == "deleted"
    assert kwargs == {"caller": UserCaller(_OP), "reason": "T-1"}
    assert json.loads(capsys.readouterr().out)["result"]["tenant_id"] == str(_T)


def test_purge_uses_the_one_purge_authority_and_names_the_actor(calls: list[Any]) -> None:
    code = cli.main(
        [
            "purge-tenant",
            "--tenant",
            str(_T),
            "--actor",
            str(_U),
            "--no-product-participants",
            "--confirm",
            str(_T),
        ]
    )
    assert code == 0
    [(name, args, kwargs)] = calls
    assert (name, args) == ("purge", (_T,))
    assert kwargs == {
        "caller": SystemCaller(SystemAuthority.TENANT_PURGE),
        "actor_user_id": _U,
        # Issue #95: the explicit override reaches the completion audit.
        "product_participants_skipped": True,
    }


def test_purge_runs_the_products_setup_first(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    ran: list[str] = []
    module = types.ModuleType("_operator_setup_probe")
    module.setup = lambda: ran.append("setup")  # type: ignore[attr-defined]
    # What the product's setup registers, as the purge sees it.
    monkeypatch.setattr(cli, "registered_purge_participant_names", lambda: tuple(ran))
    monkeypatch.setitem(__import__("sys").modules, "_operator_setup_probe", module)
    code = cli.main(
        [
            "purge-tenant",
            "--tenant",
            str(_T),
            "--actor",
            str(_U),
            "--setup",
            "_operator_setup_probe:setup",
            "--confirm",
            str(_T),
        ]
    )
    assert code == 0
    assert ran == ["setup"]
    assert calls[0][0] == "purge"
    # Issue #95: an ordinary --setup purge declares no skip.
    assert calls[0][2]["product_participants_skipped"] is False


def test_erase_names_the_tenants_and_the_actor(calls: list[Any]) -> None:
    other = uuid.uuid4()
    code = cli.main(
        [
            "erase-user",
            "--user",
            str(_U),
            "--tenant",
            str(_T),
            "--tenant",
            str(other),
            "--actor",
            str(_OP),
            "--confirm",
            str(_U),
        ]
    )
    assert code == 0
    [(name, args, kwargs)] = calls
    assert (name, args, kwargs) == ("erase", (_U, [_T, other]), {"actor_user_id": _OP})


def test_move_to_the_root(calls: list[Any]) -> None:
    code = cli.main(
        ["move-tenant", "--tenant", str(_T), "--root", "--operator", str(_OP), "--reason", "T-2"]
    )
    assert code == 0
    assert calls[0][1] == (_T, None)


@pytest.mark.parametrize(
    "argv",
    [
        # --confirm must repeat the target.
        [
            "delete-tenant",
            "--tenant",
            str(_T),
            "--operator",
            str(_OP),
            "--reason",
            "r",
            "--confirm",
            str(uuid.uuid4()),
        ],
        [
            "purge-tenant",
            "--tenant",
            str(_T),
            "--actor",
            str(_U),
            "--no-product-participants",
            "--confirm",
            "not-a-uuid",
        ],
        [
            "erase-user",
            "--user",
            str(_U),
            "--tenant",
            str(_T),
            "--actor",
            str(_OP),
            "--confirm",
            str(_T),
        ],
        # Purge must say how product data is handled, and not both ways.
        ["purge-tenant", "--tenant", str(_T), "--actor", str(_U), "--confirm", str(_T)],
        [
            "purge-tenant",
            "--tenant",
            str(_T),
            "--actor",
            str(_U),
            "--no-product-participants",
            "--setup",
            "x:y",
            "--confirm",
            str(_T),
        ],
        [
            "purge-tenant",
            "--tenant",
            str(_T),
            "--actor",
            str(_U),
            "--setup",
            "no_such_module:f",
            "--confirm",
            str(_T),
        ],
        # Erasure needs a tenant; a move exactly one destination.
        ["erase-user", "--user", str(_U), "--actor", str(_OP), "--confirm", str(_U)],
        ["move-tenant", "--tenant", str(_T), "--operator", str(_OP), "--reason", "r"],
        [
            "move-tenant",
            "--tenant",
            str(_T),
            "--root",
            "--new-parent",
            str(_U),
            "--operator",
            str(_OP),
            "--reason",
            "r",
        ],
        # A reason that is only whitespace.
        ["move-tenant", "--tenant", str(_T), "--root", "--operator", str(_OP), "--reason", "  "],
        [
            "delete-tenant",
            "--tenant",
            "x",
            "--operator",
            str(_OP),
            "--reason",
            "r",
            "--confirm",
            "x",
        ],
    ],
)
def test_invalid_input_is_refused_before_any_core_call(calls: list[Any], argv: list[str]) -> None:
    assert cli.main(argv) == 2
    assert calls == []


def test_production_requires_its_confirmation(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli, "get_settings", lambda: types.SimpleNamespace(environment="production")
    )
    argv = ["move-tenant", "--tenant", str(_T), "--root", "--operator", str(_OP), "--reason", "r"]
    assert cli.main(argv) == 2
    assert calls == []
    assert cli.main([*argv, "--confirm-production"]) == 0


def test_a_core_refusal_is_exit_1_with_only_its_type(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise PermissionError("tenant 1234 secret detail")

    monkeypatch.setattr(cli, "move_tenant", refuse)
    code = cli.main(
        ["move-tenant", "--tenant", str(_T), "--root", "--operator", str(_OP), "--reason", "r"]
    )
    assert code == 1
    err = capsys.readouterr().err
    assert "PermissionError" in err
    assert "secret detail" not in err


def test_the_runtime_role_is_checked_before_the_operation(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def superuser(engine: object) -> None:
        raise RuntimeError("superuser")

    monkeypatch.setattr(cli, "validate_application_role", superuser)
    code = cli.main(
        ["move-tenant", "--tenant", str(_T), "--root", "--operator", str(_OP), "--reason", "r"]
    )
    assert code == 1
    assert calls == []


def test_standard_output_is_exactly_one_json_document(
    calls: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing but the result reaches standard output, so a script can
    parse it."""
    for argv in (
        ["move-tenant", "--tenant", str(_T), "--root", "--operator", str(_OP), "--reason", "r"],
        [
            "erase-user",
            "--user",
            str(_U),
            "--tenant",
            str(_T),
            "--actor",
            str(_OP),
            "--confirm",
            str(_U),
        ],
    ):
        assert cli.main(argv) == 0
        out = capsys.readouterr().out
        assert len(out.strip().splitlines()) == 1
        json.loads(out)


def test_results_keep_sequence_order_and_sort_only_sets() -> None:
    import dataclasses

    @dataclasses.dataclass(frozen=True)
    class _Result:
        names: tuple[str, ...]
        ids: frozenset[uuid.UUID]
        counts: dict[str, int]

    first, second = uuid.UUID(int=2), uuid.UUID(int=1)
    out = cli._jsonable(_Result(("b", "a"), frozenset({first, second}), {"x": 1}))
    assert out == {"names": ["b", "a"], "ids": [str(second), str(first)], "counts": {"x": 1}}


def test_purge_refuses_an_actor_that_is_not_a_user(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "get_user", lambda user_id: None)
    code = cli.main(
        [
            "purge-tenant",
            "--tenant",
            str(_T),
            "--actor",
            str(_U),
            "--no-product-participants",
            "--confirm",
            str(_T),
        ]
    )
    assert code == 2
    assert calls == []


def test_purge_refuses_a_setup_that_registers_no_participant(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = types.ModuleType("_operator_empty_setup")
    module.setup = lambda: None  # type: ignore[attr-defined]
    monkeypatch.setitem(__import__("sys").modules, "_operator_empty_setup", module)
    monkeypatch.setattr(cli, "registered_purge_participant_names", lambda: ())
    code = cli.main(
        [
            "purge-tenant",
            "--tenant",
            str(_T),
            "--actor",
            str(_U),
            "--setup",
            "_operator_empty_setup:setup",
            "--confirm",
            str(_T),
        ]
    )
    assert code == 2
    assert calls == []


@pytest.mark.parametrize(
    "argv",
    [
        [
            "move-tenant",
            "--tenant",
            str(_T),
            "--root",
            "--operator",
            str(_OP),
            "--reason",
            "r" * 501,
        ],
        [
            "move-tenant",
            "--tenant",
            str(_T),
            "--new-parent",
            "nope",
            "--operator",
            str(_OP),
            "--reason",
            "r",
        ],
        ["move-tenant", "--tenant", str(_T), "--root", "--operator", "nope", "--reason", "r"],
        [
            "erase-user",
            "--user",
            str(_U),
            *[a for _ in range(1001) for a in ("--tenant", str(_T))],
            "--actor",
            str(_OP),
            "--confirm",
            str(_U),
        ],
    ],
)
def test_bounds_and_identifiers_are_checked(calls: list[Any], argv: list[str]) -> None:
    assert cli.main(argv) == 2
    assert calls == []


def test_a_padded_reason_within_bounds_is_accepted(calls: list[Any]) -> None:
    reason = "  " + "r" * 500 + "  "
    argv = [
        "move-tenant",
        "--tenant",
        str(_T),
        "--root",
        "--operator",
        str(_OP),
        "--reason",
        reason,
    ]
    assert cli.main(argv) == 0
    assert calls[0][2]["reason"] == "r" * 500


def test_a_fresh_operator_process_resolves_every_table_its_audit_writes_reference() -> None:
    """`saas-os-operator` runs in its own process. Every foreign key of every
    table its import loads must resolve there: `core.audit_log` references
    RBAC tables, and an unresolved one fails every audit write with
    `NoReferencedTableError` -- seen with `purge-tenant --setup
    my_product.purge:register_purge_participants`, a setup that does not build
    the application. No database is needed: SQLAlchemy resolves the keys from
    the table definitions alone."""
    probe = (
        "import saas_os.ops.operator_cli\n"
        "from sqlalchemy.exc import NoReferencedTableError\n"
        "from saas_os.infra.db.orm import Base\n"
        "missing = []\n"
        "for table in Base.metadata.tables.values():\n"
        "    for fk in table.foreign_keys:\n"
        "        try:\n"
        "            fk.column\n"
        "        except NoReferencedTableError:\n"
        "            missing.append(f'{table.fullname} -> {fk.target_fullname}')\n"
        "print(sorted(missing))\n"
    )
    env = {
        **os.environ,
        "ENVIRONMENT": os.environ.get("ENVIRONMENT", "test"),
        "REDIS_URL": os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    }
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "[]", result.stdout


@pytest.mark.parametrize(("argv", "apply"), [([], False), (["--apply"], True)])
def test_redact_webhook_errors_counts_unless_told_to_apply(
    calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    apply: bool,
) -> None:
    import saas_os.core.webhooks.stored_errors as stored_errors

    seen: list[bool] = []

    async def redact(*, apply: bool) -> object:
        seen.append(apply)
        return stored_errors.StoredWebhookErrorRedaction(
            applied=apply, outbox_events=2, dead_letter_entries=1
        )

    monkeypatch.setattr(stored_errors, "redact_stored_webhook_url_errors", redact)
    assert cli.main(["redact-webhook-errors", *argv]) == 0
    assert seen == [apply] and calls == []
    assert json.loads(capsys.readouterr().out)["result"] == {
        "applied": apply,
        "dead_letter_entries": 1,
        "outbox_events": 2,
    }


# --- replay-outbox-events (outbox decision brief Q2, 2A) ---------------------------


@pytest.mark.parametrize(("extra", "apply"), [([], False), (["--apply"], True)])
def test_replay_outbox_events_names_the_operator_and_counts_unless_told_to_apply(
    calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
    apply: bool,
) -> None:
    import saas_os.core.outbox.replay as replay

    seen: list[tuple[Any, dict[str, Any]]] = []

    def fake(tenant_id: uuid.UUID, **kwargs: Any) -> object:
        seen.append((tenant_id, kwargs))
        return replay.OutboxReplayResult(tenant_id, 2, 2 if apply else 0, applied=apply)

    monkeypatch.setattr(replay, "replay_dead_lettered_events", fake)
    event = uuid.uuid4()
    argv = ["replay-outbox-events", "--tenant", str(_T), "--operator", str(_OP)]
    argv += ["--event-id", str(event), "--reason", "T-3: quota raised", *extra]
    assert cli.main(argv) == 0
    ((tenant_id, kwargs),) = seen
    assert tenant_id == _T and kwargs["caller"] == UserCaller(_OP)
    assert kwargs["event_ids"] == [event] and kwargs["dead_lettered_since"] is None
    assert kwargs["apply"] is apply and kwargs["reason"] == "T-3: quota raised"
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["matched"] == 2 and result["applied"] is apply


def test_replay_outbox_events_reads_a_time_with_its_offset(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    import saas_os.core.outbox.replay as replay

    seen: list[dict[str, Any]] = []

    def fake(tenant_id: uuid.UUID, **kwargs: Any) -> object:
        seen.append(kwargs)
        return replay.OutboxReplayResult(tenant_id, 0, 0, applied=False)

    monkeypatch.setattr(replay, "replay_dead_lettered_events", fake)
    argv = ["replay-outbox-events", "--tenant", str(_T), "--operator", str(_OP), "--reason", "r"]
    assert cli.main([*argv, "--dead-lettered-since", "2030-01-01T00:00:00+00:00"]) == 0
    assert seen[0]["dead_lettered_since"].isoformat() == "2030-01-01T00:00:00+00:00"
    assert seen[0]["event_ids"] is None


@pytest.mark.parametrize(
    "selection",
    [
        [],
        ["--event-id", str(uuid.uuid4()), "--dead-lettered-since", "2030-01-01T00:00:00+00:00"],
        ["--dead-lettered-since", "2030-01-01T00:00:00"],  # no offset
        ["--dead-lettered-since", "yesterday"],
        ["--event-id", "not-a-uuid"],
    ],
)
def test_replay_outbox_events_refuses_a_bad_selection_before_any_core_call(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch, selection: list[str]
) -> None:
    import saas_os.core.outbox.replay as replay

    def never(*args: Any, **kwargs: Any) -> object:
        raise AssertionError("Core must not be called")

    monkeypatch.setattr(replay, "replay_dead_lettered_events", never)
    argv = ["replay-outbox-events", "--tenant", str(_T), "--operator", str(_OP), "--reason", "r"]
    assert cli.main([*argv, *selection]) == 2


# --- reencrypt-webhook-secrets (finding F7) ---------------------------------


@pytest.mark.parametrize(("extra", "apply"), [([], False), (["--apply"], True)])
def test_reencrypt_webhook_secrets_names_the_operator_and_counts_unless_told_to_apply(
    calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
    apply: bool,
) -> None:
    import saas_os.core.webhooks.reencryption as reencryption

    seen: list[tuple[Any, dict[str, Any]]] = []

    def fake(tenant_id: uuid.UUID, **kwargs: Any) -> object:
        seen.append((tenant_id, kwargs))
        return reencryption.WebhookSecretReencryptionResult(
            tenant_id, 3, 3 if apply else 0, applied=apply
        )

    monkeypatch.setattr(reencryption, "reencrypt_legacy_signing_secrets", fake)
    argv = ["reencrypt-webhook-secrets", "--tenant", str(_T), "--operator", str(_OP)]
    assert cli.main([*argv, "--reason", "T-4: F7", *extra]) == 0
    ((tenant_id, kwargs),) = seen
    assert tenant_id == _T and kwargs["caller"] == UserCaller(_OP)
    assert kwargs["apply"] is apply and kwargs["reason"] == "T-4: F7"
    result = json.loads(capsys.readouterr().out)["result"]
    assert result == {
        "tenant_id": str(_T),
        "matched": 3,
        "reencrypted": 3 if apply else 0,
        "applied": apply,
    }


def test_reencrypt_webhook_secrets_prints_only_the_error_type_on_failure(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A failure reaches the terminal as its type only: whatever an error
    message might hold never reaches the terminal."""
    import saas_os.core.webhooks.reencryption as reencryption

    def failing(tenant_id: uuid.UUID, **kwargs: Any) -> object:
        raise reencryption.WebhookSecretReencryptionKeyError("SENTINEL-NOT-PRINTED")

    monkeypatch.setattr(reencryption, "reencrypt_legacy_signing_secrets", failing)
    argv = ["reencrypt-webhook-secrets", "--tenant", str(_T), "--operator", str(_OP)]
    assert cli.main([*argv, "--reason", "r", "--apply"]) != 0
    captured = capsys.readouterr()
    assert "WebhookSecretReencryptionKeyError" in captured.err
    assert "SENTINEL-NOT-PRINTED" not in captured.err + captured.out


@pytest.mark.parametrize(
    "argv",
    [
        ["--tenant", "not-a-uuid", "--operator", str(_OP), "--reason", "r"],
        ["--tenant", str(_T), "--operator", "nobody", "--reason", "r"],
    ],
)
def test_reencrypt_webhook_secrets_refuses_bad_ids_before_any_core_call(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    import saas_os.core.webhooks.reencryption as reencryption

    def never(*args: Any, **kwargs: Any) -> object:
        raise AssertionError("Core must not be called")

    monkeypatch.setattr(reencryption, "reencrypt_legacy_signing_secrets", never)
    assert cli.main(["reencrypt-webhook-secrets", *argv]) == 2


# --- apply-permission-grants (ADR 0060, option C) ----------------------------------


def _declared_module(monkeypatch: pytest.MonkeyPatch, attribute: str) -> list[object]:
    declared: list[object] = [object()]
    module = types.ModuleType("grt_declared_grants")
    setattr(module, attribute, declared)
    monkeypatch.setitem(sys.modules, "grt_declared_grants", module)
    return declared


@pytest.mark.parametrize(
    ("scope", "apply"),
    [(["--tenant", str(_T)], False), (["--all-tenants"], False), (["--all-tenants"], True)],
)
def test_apply_permission_grants_names_the_operator_the_list_and_the_scope(
    calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    scope: list[str],
    apply: bool,
) -> None:
    import saas_os.core.permission_grants as grants

    declared = _declared_module(monkeypatch, "PERMISSION_GRANT_MIGRATIONS")
    seen: list[tuple[Any, dict[str, Any]]] = []
    run_id = uuid.uuid4() if apply else None

    def fake(migrations: object, **kwargs: Any) -> object:
        seen.append((migrations, kwargs))
        return grants.PermissionGrantRunResult(
            "crm_app",
            apply,
            run_id,
            (grants.TenantGrantResult(_T, grants.TENANT_CHANGED, 1, 0, 0, 2, 1),),
        )

    monkeypatch.setattr(grants, "apply_permission_grant_migrations", fake)
    argv = ["apply-permission-grants", "--operator", str(_OP), "--namespace", "crm_app"]
    argv += ["--module", "grt_declared_grants", "--reason", "T-4: reports", *scope]
    argv += ["--apply"] if apply else []
    assert cli.main(argv) == 0
    ((migrations, kwargs),) = seen
    assert migrations is declared
    assert kwargs["caller"] == UserCaller(_OP) and kwargs["namespace"] == "crm_app"
    assert kwargs["apply"] is apply and kwargs["reason"] == "T-4: reports"
    if "--all-tenants" in scope:
        assert kwargs["tenant_ids"] == [] and kwargs["all_tenants"] is True
    else:
        assert kwargs["tenant_ids"] == [_T] and kwargs["all_tenants"] is False
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["applied"] is apply and result["tenant_outcomes"] == {"changed": 1}
    assert result["run_id"] == (str(run_id) if apply else None)
    (tenant,) = result["tenants"]
    assert tenant["grants_added"] == 2 and tenant["grants_already_present"] == 1
    # Counts only: no role or permission name can appear in the output.
    assert set(tenant) == {
        "tenant_id",
        "outcome",
        "migrations_applied",
        "roles_missing",
        "migrations_already_applied",
        "grants_added",
        "grants_already_present",
        "error",
    }


def test_apply_permission_grants_reads_a_named_attribute(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    import saas_os.core.permission_grants as grants

    declared = _declared_module(monkeypatch, "RELEASE_4")
    seen: list[object] = []

    def fake(migrations: object, **kwargs: Any) -> object:
        seen.append(migrations)
        return grants.PermissionGrantRunResult("crm_app", False, None, ())

    monkeypatch.setattr(grants, "apply_permission_grant_migrations", fake)
    argv = ["apply-permission-grants", "--operator", str(_OP), "--namespace", "crm_app"]
    argv += ["--module", "grt_declared_grants:RELEASE_4", "--reason", "r", "--all-tenants"]
    assert cli.main(argv) == 0
    assert seen == [declared]


@pytest.mark.parametrize(
    "bad",
    [
        [],  # neither --tenant nor --all-tenants
        ["--tenant", str(_T), "--all-tenants"],
        ["--tenant", "not-a-uuid"],
        ["--all-tenants", "--module-override"],
    ],
)
def test_apply_permission_grants_refuses_an_unclear_scope_before_core(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch, bad: list[str]
) -> None:
    import saas_os.core.permission_grants as grants

    _declared_module(monkeypatch, "PERMISSION_GRANT_MIGRATIONS")
    monkeypatch.setattr(
        grants,
        "apply_permission_grant_migrations",
        lambda *a, **k: pytest.fail("Core must not be called"),
    )
    argv = ["apply-permission-grants", "--operator", str(_OP), "--namespace", "crm_app"]
    argv += ["--module", "grt_declared_grants", "--reason", "r", *bad]
    assert cli.main(argv) == 2


def test_apply_permission_grants_refuses_a_module_it_cannot_import(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    import saas_os.core.permission_grants as grants

    monkeypatch.setattr(
        grants,
        "apply_permission_grant_migrations",
        lambda *a, **k: pytest.fail("Core must not be called"),
    )
    argv = ["apply-permission-grants", "--operator", str(_OP), "--namespace", "crm_app"]
    argv += ["--module", "grt_no_such_module_here", "--reason", "r", "--all-tenants"]
    assert cli.main(argv) == 2


# --- permission grant ledger retention (owner policy of 2026-11-02) -------------


def _report(more: bool = False) -> object:
    from datetime import UTC, datetime

    import saas_os.core.permission_grants as grants

    purged = datetime(2024, 1, 1, tzinfo=UTC)
    return grants.LedgerRetentionReport(
        datetime(2026, 11, 2, tzinfo=UTC),
        (
            grants.TenantLedgerRetention(
                _T,
                grants.RetentionStatus.ELIGIBLE,
                3,
                0,
                purged,
                grants.retention_expires_at(purged),
            ),
        ),
        more,
    )


@pytest.mark.parametrize(
    "scope",
    [["--tenant", str(_T)], ["--all-purged"], ["--all-purged", "--after", str(_OP)]],
)
def test_ledger_retention_report_names_the_operator_and_the_scope(
    calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    scope: list[str],
) -> None:
    import saas_os.core.permission_grants as grants

    seen: list[dict[str, Any]] = []

    def fake(**kwargs: Any) -> object:
        seen.append(kwargs)
        return _report()

    monkeypatch.setattr(grants, "permission_grant_ledger_retention_report", fake)
    argv = ["permission-grant-ledger-retention", "--operator", str(_OP), "--reason", "T-6"]
    assert cli.main([*argv, *scope]) == 0
    (kwargs,) = seen
    assert kwargs["caller"] == UserCaller(_OP) and kwargs["reason"] == "T-6"
    # The command never overrides the database clock.
    assert "as_of" not in kwargs
    if "--tenant" in scope:
        assert kwargs["tenant_ids"] == [_T] and kwargs["all_purged"] is False
    else:
        assert kwargs["tenant_ids"] == [] and kwargs["all_purged"] is True
        assert kwargs["after"] == (_OP if "--after" in scope else None)
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["eligible_ledger_rows"] == 3 and result["status_counts"]["eligible"] == 1
    (tenant,) = result["tenants"]
    assert set(tenant) == {
        "tenant_id",
        "status",
        "ledger_rows",
        "active_holds",
        "purged_at",
        "expires_at",
    }
    assert tenant["purged_at"] == "2024-01-01T00:00:00+00:00"
    assert tenant["expires_at"] == "2026-01-01T00:00:00+00:00"


@pytest.mark.parametrize(
    "bad",
    [
        [],
        ["--tenant", str(_T), "--all-purged"],
        ["--tenant", "not-a-uuid"],
        ["--tenant", str(_T), "--after", str(_OP)],
        ["--all-purged", "--after", "nope"],
    ],
)
def test_ledger_retention_report_refuses_an_unclear_scope_before_core(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch, bad: list[str]
) -> None:
    import saas_os.core.permission_grants as grants

    monkeypatch.setattr(
        grants,
        "permission_grant_ledger_retention_report",
        lambda **k: pytest.fail("Core must not be called"),
    )
    argv = ["permission-grant-ledger-retention", "--operator", str(_OP), "--reason", "r"]
    assert cli.main([*argv, *bad]) == 2


def test_hold_and_release_name_the_operator_the_tenant_and_the_hold(
    calls: list[Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from datetime import UTC, datetime

    import saas_os.core.permission_grants as grants

    hold_id, audit_id = uuid.uuid4(), uuid.uuid4()
    placed = datetime(2026, 11, 2, tzinfo=UTC)
    seen: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def place(*args: Any, **kwargs: Any) -> object:
        seen.append(("place", args, kwargs))
        return grants.LedgerHoldResult(hold_id, _T, kwargs["reference"], placed, None, audit_id)

    def release(*args: Any, **kwargs: Any) -> object:
        seen.append(("release", args, kwargs))
        return grants.LedgerHoldResult(hold_id, _T, "LEGAL-1", placed, placed, audit_id)

    monkeypatch.setattr(grants, "place_permission_grant_ledger_hold", place)
    monkeypatch.setattr(grants, "release_permission_grant_ledger_hold", release)
    argv = ["hold-permission-grant-ledger", "--operator", str(_OP), "--tenant", str(_T)]
    assert cli.main([*argv, "--reference", "LEGAL-1", "--reason", "T-7"]) == 0
    out = json.loads(capsys.readouterr().out)["result"]
    assert out["hold_id"] == str(hold_id) and out["released_at"] is None
    argv = ["release-permission-grant-ledger-hold", "--operator", str(_OP), "--hold", str(hold_id)]
    assert cli.main([*argv, "--reason", "T-8"]) == 0
    out = json.loads(capsys.readouterr().out)["result"]
    assert out["released_at"] == "2026-11-02T00:00:00+00:00"
    assert seen == [
        (
            "place",
            (_T,),
            {"reference": "LEGAL-1", "caller": UserCaller(_OP), "reason": "T-7"},
        ),
        ("release", (hold_id,), {"caller": UserCaller(_OP), "reason": "T-8"}),
    ]


def test_no_operator_command_deletes_ledger_rows() -> None:
    """Owner policy of 2026-11-02: deletion of expired ledger rows is an
    open owner decision; no command performs it."""
    commands = set(cli._COMMANDS)
    assert {
        "permission-grant-ledger-retention",
        "hold-permission-grant-ledger",
        "release-permission-grant-ledger-hold",
    } <= commands
    assert not [c for c in commands if "ledger" in c and ("delete" in c or "expire" in c)]
