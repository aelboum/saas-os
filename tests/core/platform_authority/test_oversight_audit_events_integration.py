"""The two audit events of an oversight read against a real PostgreSQL
(ADR-0045 sections 8 and 9d): the *attempt*, committed in a transaction of
its own before anything is read, and the *completion*, written in the read
transaction and carrying the attempt's id.

Every assertion about "committed" is made through a second connection (the
privileged test engine), which sees a row only once its transaction has
committed. Nothing here counts rows inside an open transaction.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from phase_c_helpers import REASON, P, Scene
from platform_helpers import PlatformWorld

import saas_os.core.billing.oversight as oversight
import saas_os.core.platform_authority as platform_package
import saas_os.core.platform_authority.audit as platform_audit
import saas_os.core.tenancy.registry as registry
from saas_os.core.authority import UserCaller
from saas_os.core.billing import commercial_overview
from saas_os.core.platform_authority import PlatformNotAuthorizedError, revoke_operator
from saas_os.core.tenancy import (
    TenantNotFoundError,
    list_tenant_registry,
    read_tenant_registry_entry,
)
from saas_os.infra.observability import bind_correlation_context

pytestmark = pytest.mark.integration

_READS = ("registry", "entry", "overview")
_ACTION = {
    "registry": "platform.tenant.read",
    "entry": "platform.tenant.read",
    "overview": "platform.billing.read",
}
_PERMISSION = {"registry": P.TENANT_READ, "entry": P.TENANT_READ, "overview": P.BILLING_READ}
# The module whose `session_scope` opens the read transaction.
_MODULE = {"registry": registry, "entry": registry, "overview": oversight}


def _call(read: str, reader: UserCaller, tenant: uuid.UUID) -> Any:
    if read == "registry":
        return list_tenant_registry(caller=reader, limit=3)
    if read == "entry":
        return read_tenant_registry_entry(tenant, caller=reader)
    return commercial_overview(caller=reader, limit=3)


def _returned(read: str, result: Any) -> int:
    return 1 if read == "entry" else len(result.tenants)


def _rows(platform: PlatformWorld, action: str) -> list[dict[str, Any]]:
    """Committed rows of `action`, with their ids (a second connection)."""
    return [
        {"id": row[0], "outcome": row[1], "metadata": row[2], "target_id": row[3], "actor": row[4]}
        for row in platform.execute(
            "SELECT id, outcome, metadata, target_id, actor_user_id "
            "FROM core.platform_audit_log WHERE action = :a ORDER BY created_at, id",
            {"a": action},
        )
    ]


def _attempts(platform: PlatformWorld, read: str) -> list[dict[str, Any]]:
    return _rows(platform, _ACTION[read] + "_attempt")


def _completions(platform: PlatformWorld, read: str) -> list[dict[str, Any]]:
    return [row for row in _rows(platform, _ACTION[read]) if row["outcome"] == "success"]


def _linked_pairs(
    platform: PlatformWorld, read: str
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Every (attempt, completion) pair joined by the completion's
    `attempt_id`. The check an auditor would run."""
    attempts = {str(row["id"]): row for row in _attempts(platform, read)}
    return [
        (attempts[row["metadata"]["attempt_id"]], row)
        for row in _completions(platform, read)
        if row["metadata"].get("attempt_id") in attempts
    ]


def _reader(platform: PlatformWorld, read: str) -> tuple[UserCaller, uuid.UUID]:
    reader, operator_id = platform.operator([_PERMISSION[read]])
    platform.clear_audit()
    return reader, operator_id


def _on_read_transaction(
    monkeypatch: pytest.MonkeyPatch,
    read: str,
    *,
    before: Callable[[], None] | None = None,
    fail_commit: bool = False,
) -> dict[str, int]:
    """Wrap the `session_scope` that opens the read transaction: run
    `before` just before it opens, and optionally make its commit fail
    (the body runs; the transaction is rolled back and an error raised in
    place of the commit)."""
    module = _MODULE[read]
    real = module.session_scope
    opened = {"n": 0}

    @contextmanager
    def scope() -> Iterator[Any]:
        if before is not None:
            before()
        opened["n"] += 1
        with real() as session:
            yield session
            if fail_commit:
                session.rollback()
                raise RuntimeError("forced commit failure")

    monkeypatch.setattr(module, "session_scope", scope)
    return opened


# --- success -----------------------------------------------------------------------


@pytest.mark.parametrize("read", _READS)
def test_a_read_leaves_one_attempt_and_one_completion_linked_with_the_count(
    scene: Scene, platform: PlatformWorld, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)

    result = _call(read, reader, tenant)

    attempts, completions = _attempts(platform, read), _completions(platform, read)
    assert len(attempts) == 1 and len(completions) == 1
    assert _linked_pairs(platform, read) == [(attempts[0], completions[0])]
    attempt, completion = attempts[0], completions[0]
    assert attempt["actor"] == completion["actor"] == reader.user_id
    assert attempt["outcome"] == "success"
    assert completion["metadata"] == {
        "attempt_id": str(attempt["id"]),
        "returned": _returned(read, result),
    }
    # The attempt records the request, and nothing that was read.
    if read == "entry":
        assert attempt["target_id"] == str(tenant) and attempt["metadata"] is None
    else:
        assert attempt["metadata"] == {"cursor": None, "page_size": 3}
        assert "returned" not in attempt["metadata"]
    assert platform.audit_count() == 2


@pytest.mark.parametrize("read", _READS)
def test_the_attempt_is_committed_before_the_read_transaction_opens(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)
    seen: dict[str, Any] = {}

    def observe() -> None:
        # A second connection: only committed rows are visible to it.
        seen["attempts"] = _attempts(platform, read)
        seen["completions"] = _completions(platform, read)

    opened = _on_read_transaction(monkeypatch, read, before=observe)
    _call(read, reader, tenant)

    assert opened["n"] == 1
    assert len(seen["attempts"]) == 1  # durable before the first protected statement
    assert seen["completions"] == []
    assert [row["id"] for row in _attempts(platform, read)] == [seen["attempts"][0]["id"]]


@pytest.mark.parametrize("read", _READS)
def test_the_link_is_the_attempt_id_and_correlation_id_keeps_its_meaning(
    scene: Scene, platform: PlatformWorld, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)

    def correlation_ids() -> list[str | None]:
        return [
            row[0]
            for row in platform.execute(
                "SELECT correlation_id FROM core.platform_audit_log ORDER BY created_at, id"
            )
        ]

    _call(read, reader, tenant)  # no request context: nothing to record
    assert correlation_ids() == [None, None]
    assert len(_linked_pairs(platform, read)) == 1  # linked all the same

    platform.clear_audit()
    with bind_correlation_context(request_id="req-phase-c-1"):
        _call(read, reader, tenant)
    # Both rows carry the ambient request id, as every platform row does;
    # it is not the attempt's id, and the link does not depend on it.
    assert correlation_ids() == ["req-phase-c-1", "req-phase-c-1"]
    ((attempt, completion),) = _linked_pairs(platform, read)
    assert completion["metadata"]["attempt_id"] == str(attempt["id"]) != "req-phase-c-1"


# --- the attempt fails: nothing is read ----------------------------------------------


@pytest.mark.parametrize("read", _READS)
def test_a_failed_attempt_insert_prevents_the_read(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("forced attempt failure")

    # The attempt writer's own insert; the read transaction is watched.
    monkeypatch.setattr(platform_audit, "record_platform_event_in_transaction", refuse)
    opened = _on_read_transaction(monkeypatch, read)

    with pytest.raises(RuntimeError, match="forced attempt failure"):
        _call(read, reader, tenant)
    assert opened["n"] == 0  # the read transaction never opened
    assert _attempts(platform, read) == [] and _completions(platform, read) == []
    assert platform.audit_count() == 0  # no row of any kind: nothing happened


@pytest.mark.parametrize("read", _READS)
def test_a_failed_attempt_commit_prevents_the_read(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)
    real = platform_audit.session_scope

    @contextmanager
    def uncommittable() -> Iterator[Any]:
        with real() as session:
            yield session
            session.rollback()
            raise RuntimeError("forced attempt commit failure")

    monkeypatch.setattr(platform_audit, "session_scope", uncommittable)
    opened = _on_read_transaction(monkeypatch, read)

    with pytest.raises(RuntimeError, match="forced attempt commit failure"):
        _call(read, reader, tenant)
    assert opened["n"] == 0
    assert _attempts(platform, read) == [] and _completions(platform, read) == []
    assert platform.audit_count() == 0


# --- the read fails: the attempt stays, no completion, no data --------------------------


@pytest.mark.parametrize("read", _READS)
def test_a_failed_read_leaves_the_attempt_and_no_completion(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("forced read failure")

    if read == "overview":
        monkeypatch.setattr(oversight, "_tenant_subscriptions", broken)
    else:
        monkeypatch.setattr(registry, "_entry", broken)

    result: Any = None
    with pytest.raises(RuntimeError, match="forced read failure"):
        result = _call(read, reader, tenant)
    assert result is None
    assert len(_attempts(platform, read)) == 1  # durable: it survived the rollback
    assert _completions(platform, read) == []


@pytest.mark.parametrize("read", _READS)
def test_a_failed_completion_insert_returns_nothing(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("forced completion failure")

    # The name the read looks up for its completion row. The attempt
    # writer holds its own reference and still works.
    if read == "overview":
        monkeypatch.setattr(oversight, "record_platform_event_in_transaction", refuse)
    else:
        monkeypatch.setattr(platform_package, "record_platform_event_in_transaction", refuse)

    result: Any = None
    with pytest.raises(RuntimeError, match="forced completion failure"):
        result = _call(read, reader, tenant)
    assert result is None
    assert len(_attempts(platform, read)) == 1
    assert _completions(platform, read) == []


@pytest.mark.parametrize("read", _READS)
def test_a_failed_completion_commit_returns_nothing(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)
    _on_read_transaction(monkeypatch, read, fail_commit=True)

    result: Any = None
    with pytest.raises(RuntimeError, match="forced commit failure"):
        result = _call(read, reader, tenant)
    assert result is None
    assert len(_attempts(platform, read)) == 1
    assert _completions(platform, read) == []  # written, then rolled back with the read


# --- authority lost between the two transactions -----------------------------------------


@pytest.mark.parametrize("read", _READS)
def test_authority_revoked_between_the_transactions_returns_nothing_and_is_denied(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    owner, _ = platform.owner()
    reader, operator_id = _reader(platform, read)

    def revoke() -> None:
        revoke_operator(operator_id, caller=owner, reason=REASON)

    _on_read_transaction(monkeypatch, read, before=revoke)

    result: Any = None
    with pytest.raises(PlatformNotAuthorizedError):
        result = _call(read, reader, tenant)
    assert result is None
    assert len(_attempts(platform, read)) == 1  # the attempt was authorized, and stays
    assert _completions(platform, read) == []
    denied = platform.audit(action=_ACTION[read], outcome="denied")
    assert len(denied) == 1
    assert denied[0]["actor_user_id"] == reader.user_id and denied[0]["reason"] == "not_authorized"


@pytest.mark.parametrize("read", _READS)
def test_an_unauthorized_caller_leaves_a_denial_and_no_attempt(
    scene: Scene, platform: PlatformWorld, read: str
) -> None:
    tenant = scene.tenant(active=True)
    stranger, _ = platform.operator([p for p in P if p is not _PERMISSION[read]])
    platform.clear_audit()

    with pytest.raises(PlatformNotAuthorizedError):
        _call(read, stranger, tenant)
    assert _attempts(platform, read) == [] and _completions(platform, read) == []
    assert len(platform.audit(action=_ACTION[read], outcome="denied")) == 1


# --- a tenant that does not exist ---------------------------------------------------------


def test_a_read_of_an_unknown_tenant_leaves_both_events_and_then_raises(
    scene: Scene, platform: PlatformWorld
) -> None:
    unknown = uuid.uuid4()
    reader, _ = _reader(platform, "entry")

    with pytest.raises(TenantNotFoundError):
        read_tenant_registry_entry(unknown, caller=reader)

    pairs = _linked_pairs(platform, "entry")
    assert len(pairs) == 1 and platform.audit_count() == 2
    attempt, completion = pairs[0]
    assert attempt["target_id"] == completion["target_id"] == str(unknown)
    assert completion["metadata"]["returned"] == 0
    assert (
        platform.scalar(
            "SELECT count(*) FROM core.platform_audit_log WHERE target_tenant_id IS NOT NULL"
        )
        == 0
    )


def test_an_unauthorized_read_is_answered_alike_for_a_real_and_an_unknown_tenant(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    stranger, _ = platform.operator([p for p in P if p is not P.TENANT_READ])
    platform.clear_audit()

    for target in (tenant, uuid.uuid4()):
        with pytest.raises(PlatformNotAuthorizedError):
            read_tenant_registry_entry(target, caller=stranger)
    rows = platform.audit()
    # Two denials, alike but for the id that was asked for; no attempt.
    assert [row["outcome"] for row in rows] == ["denied", "denied"]
    assert {row["action"] for row in rows} == {"platform.tenant.read"}
    assert {row["reason"] for row in rows} == {"not_authorized"}


# --- negative controls ---------------------------------------------------------------------
#
# Each removes one part of the model and shows the check above that would
# catch it failing: the read still returns data, and the evidence is short.


@pytest.mark.parametrize("read", _READS)
def test_without_the_attempt_writer_a_read_has_no_attempt(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)
    fake = lambda **kwargs: uuid.uuid4()  # noqa: E731 -- "recorded", but nothing was written
    monkeypatch.setattr(platform_package, "record_oversight_attempt", fake)
    monkeypatch.setattr(oversight, "record_oversight_attempt", fake)

    assert _call(read, reader, tenant) is not None
    assert _attempts(platform, read) == []
    assert len(_completions(platform, read)) == 1
    assert _linked_pairs(platform, read) == []  # a completion pointing at nothing


@pytest.mark.parametrize("read", _READS)
def test_without_the_completion_insert_a_read_has_only_its_attempt(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)
    skip = lambda *args, **kwargs: None  # noqa: E731
    monkeypatch.setattr(platform_package, "record_platform_event_in_transaction", skip)
    monkeypatch.setattr(oversight, "record_platform_event_in_transaction", skip)

    assert _call(read, reader, tenant) is not None  # read, and returned
    assert len(_attempts(platform, read)) == 1
    assert _completions(platform, read) == [] and _linked_pairs(platform, read) == []


@pytest.mark.parametrize("read", _READS)
def test_without_the_link_the_two_events_cannot_be_paired(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    tenant = scene.tenant(active=True)
    reader, _ = _reader(platform, read)
    real = platform_package.record_platform_event_in_transaction

    def unlinked(session: Any, **kwargs: Any) -> Any:
        kwargs["metadata"] = {k: v for k, v in kwargs["metadata"].items() if k != "attempt_id"}
        return real(session, **kwargs)

    monkeypatch.setattr(platform_package, "record_platform_event_in_transaction", unlinked)
    monkeypatch.setattr(oversight, "record_platform_event_in_transaction", unlinked)

    assert _call(read, reader, tenant) is not None
    assert len(_attempts(platform, read)) == 1 and len(_completions(platform, read)) == 1
    assert _linked_pairs(platform, read) == []
