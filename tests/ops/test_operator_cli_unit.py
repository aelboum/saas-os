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
