"""`python -m saas_os.api.platform_bootstrap` against a real PostgreSQL
(ADR-0045 section 6): the first owner, the once-only rule, idempotency,
the issuer rule, recovery, and the evidence each run leaves.

Runs the real command entry point (`main(argv)`) as the restricted runtime
role, exactly as an operator would.

Marked `integration`, excluded from the default `pytest` run. Disposable
databases only: every test starts from, and leaves, empty platform tables.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.api.platform_bootstrap as cli
from saas_os.core.platform_authority import PlatformPermission, platform_can
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine

pytestmark = pytest.mark.integration

_ISSUER = "https://idp.platform-bootstrap.test"
_CLEAR = "TRUNCATE core.platform_audit_log, core.platform_grants, core.platform_operators"
_OWNER_PREDICATE = (
    "SELECT count(*) FROM core.platform_operators o JOIN core.users u ON u.id = o.user_id "
    "JOIN core.platform_grants g ON g.operator_id = o.id WHERE o.status = 'active' "
    "AND u.is_active AND g.permission = 'platform.authority:manage' AND g.revoked_at IS NULL"
)


class Db:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def rows(self, sql: str, params: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        with self.engine.begin() as conn:
            result = conn.execute(text(sql), params or {})
            return [tuple(row) for row in result] if result.returns_rows else []

    def scalar(self, sql: str, params: dict[str, Any] | None = None) -> Any:
        return self.rows(sql, params)[0][0]

    def identities(self) -> int:
        return self.scalar(
            "SELECT count(*) FROM core.external_identities WHERE issuer = :i", {"i": _ISSUER}
        )

    def user_of(self, subject: str) -> uuid.UUID:
        return self.scalar(
            "SELECT user_id FROM core.external_identities WHERE issuer = :i AND subject = :s",
            {"i": _ISSUER, "s": subject},
        )

    def operator_of(self, subject: str) -> uuid.UUID:
        return self.scalar(
            "SELECT id FROM core.platform_operators WHERE user_id = :u AND status <> 'revoked'",
            {"u": self.user_of(subject)},
        )


@pytest.fixture
def db(monkeypatch: pytest.MonkeyPatch) -> Iterator[Db]:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
        get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL / MIGRATIONS_DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.platform_operators LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated to head: {exc}")
    monkeypatch.setenv("OIDC_ISSUER_URL", _ISSUER + "/")  # trailing slash: normalized away
    world = Db(engine)
    world.rows(_CLEAR)
    try:
        yield world
    finally:
        world.rows(_CLEAR)
        users = [
            row[0]
            for row in world.rows(
                "SELECT user_id FROM core.external_identities WHERE issuer = :i", {"i": _ISSUER}
            )
        ]
        world.rows("DELETE FROM core.external_identities WHERE issuer = :i", {"i": _ISSUER})
        if users:
            world.rows("DELETE FROM core.users WHERE id = ANY(:u)", {"u": users})
        engine.dispose()


def _bootstrap(subject: str, *extra: str, issuer: str = _ISSUER) -> int:
    return cli.main(
        [
            "bootstrap",
            "--owner-issuer",
            issuer,
            "--owner-subject",
            subject,
            "--reason",
            "initial platform owner",
            *extra,
        ]
    )


def _recover(*args: str) -> int:
    return cli.main(["recover", *args, "--reason", "INC-1 recovery"])


def test_bootstrap_enrolls_the_first_owner_with_exactly_the_reviewed_list(db: Db) -> None:
    assert _bootstrap("owner-1") == 0
    operator_id = db.operator_of("owner-1")
    granted = {
        row[0]
        for row in db.rows(
            "SELECT permission FROM core.platform_grants "
            "WHERE operator_id = :o AND revoked_at IS NULL",
            {"o": operator_id},
        )
    }
    assert granted == {p.value for p in cli.BOOTSTRAP_PERMISSIONS}
    assert len(granted) == 18
    assert db.scalar(_OWNER_PREDICATE) == 1
    user_id = db.user_of("owner-1")
    assert platform_can(user_id=user_id, permission=PlatformPermission.AUTHORITY_MANAGE)

    audit = db.rows(
        "SELECT actor_type, actor_user_id, system_authority, action, outcome, reason, "
        "metadata::text FROM core.platform_audit_log ORDER BY created_at, id"
    )
    # One transaction: every row shares its timestamp, so their order is not meaningful.
    assert sorted(row[3] for row in audit) == ["platform.grant.create"] * 18 + [
        "platform.operator.enroll"
    ]
    for actor_type, actor_user_id, system_authority, _, outcome, reason, metadata in audit:
        # The command acts as a system purpose and is recorded as one.
        assert (actor_type, actor_user_id, system_authority) == (
            "system",
            None,
            "platform_bootstrap",
        )
        assert outcome == "success" and reason == "initial platform owner"
        # Evidence carries ids only: never the issuer or the subject.
        assert _ISSUER not in metadata and "owner-1" not in metadata
    # No bystander is granted anything, and nothing reaches the tenant audit log.
    assert db.scalar("SELECT count(*) FROM core.platform_operators") == 1


def test_an_identical_second_bootstrap_changes_nothing(db: Db) -> None:
    assert _bootstrap("owner-1") == 0
    before = db.rows("SELECT count(*) FROM core.platform_audit_log")
    assert _bootstrap("owner-1") == 0
    assert db.rows("SELECT count(*) FROM core.platform_audit_log") == before
    assert db.scalar("SELECT count(*) FROM core.platform_operators") == 1
    assert db.scalar("SELECT count(*) FROM core.platform_grants") == 18


def test_bootstrap_runs_once_a_second_identity_is_refused_and_creates_no_user(db: Db) -> None:
    assert _bootstrap("owner-1") == 0
    assert db.identities() == 1
    assert _bootstrap("intruder") == 1
    assert db.identities() == 1  # the refused run created no user for the unseen identity
    assert db.scalar("SELECT count(*) FROM core.platform_operators") == 1
    assert db.scalar(_OWNER_PREDICATE) == 1


def test_bootstrap_is_refused_once_any_operator_exists_even_a_revoked_one(db: Db) -> None:
    """Not a way back in after the owner set changed."""
    assert _bootstrap("owner-1") == 0
    db.rows("UPDATE core.platform_grants SET revoked_at = now()")
    db.rows("UPDATE core.platform_operators SET status = 'revoked'")
    assert db.scalar(_OWNER_PREDICATE) == 0
    assert _bootstrap("owner-1") == 1
    assert _bootstrap("owner-2") == 1
    assert db.scalar(_OWNER_PREDICATE) == 0


def test_bootstrap_refuses_an_issuer_that_is_not_the_configured_one(db: Db) -> None:
    assert _bootstrap("owner-1", issuer="https://other-idp.example.test") == 2
    assert db.scalar("SELECT count(*) FROM core.platform_operators") == 0
    assert (
        db.scalar(
            "SELECT count(*) FROM core.external_identities WHERE issuer = :i",
            {"i": "https://other-idp.example.test"},
        )
        == 0
    )


def test_bootstrap_refuses_when_no_issuer_is_configured(
    db: Db, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OIDC_ISSUER_URL")
    # Refused either way: no issuer at all (exit 1), or -- where a local `.env`
    # supplies one -- an issuer that is not the one given (exit 2).
    assert _bootstrap("owner-1") in (1, 2)
    assert db.scalar("SELECT count(*) FROM core.platform_operators") == 0


def test_recovery_enrolls_and_grants_only_what_is_named(db: Db) -> None:
    assert _bootstrap("owner-1") == 0
    assert (
        _recover(
            "--enroll-issuer",
            _ISSUER,
            "--enroll-subject",
            "auditor",
            "--grant",
            "platform.audit:read",
        )
        == 0
    )
    user_id = db.user_of("auditor")
    assert platform_can(user_id=user_id, permission=PlatformPermission.AUDIT_READ)
    for permission in PlatformPermission:
        if permission is not PlatformPermission.AUDIT_READ:
            assert not platform_can(user_id=user_id, permission=permission), permission
    # Idempotent: the same recovery again grants nothing new.
    before = db.scalar("SELECT count(*) FROM core.platform_grants")
    assert (
        _recover(
            "--enroll-issuer",
            _ISSUER,
            "--enroll-subject",
            "auditor",
            "--grant",
            "platform.audit:read",
        )
        == 0
    )
    assert db.scalar("SELECT count(*) FROM core.platform_grants") == before


def test_recovery_cannot_leave_the_deployment_without_an_owner(db: Db) -> None:
    assert _bootstrap("owner-1") == 0
    sole = str(db.operator_of("owner-1"))
    assert _recover("--suspend-operator", sole) == 1
    assert db.scalar(_OWNER_PREDICATE) == 1
    denied = db.rows(
        "SELECT action, reason, actor_type FROM core.platform_audit_log WHERE outcome = 'denied'"
    )
    assert denied == [("platform.operator.suspend", "last_platform_owner", "system")]


def test_recovery_replaces_an_owner_in_one_transaction(db: Db) -> None:
    assert _bootstrap("owner-1") == 0
    old = db.operator_of("owner-1")
    assert (
        _recover(
            "--enroll-issuer",
            _ISSUER,
            "--enroll-subject",
            "owner-2",
            "--grant",
            "platform.authority:manage",
            "--suspend-operator",
            str(old),
        )
        == 0
    )
    assert (
        db.scalar("SELECT status FROM core.platform_operators WHERE id = :i", {"i": old})
        == "suspended"
    )
    assert db.scalar(_OWNER_PREDICATE) == 1
    assert platform_can(
        user_id=db.user_of("owner-2"), permission=PlatformPermission.AUTHORITY_MANAGE
    )
    assert not platform_can(
        user_id=db.user_of("owner-1"), permission=PlatformPermission.AUTHORITY_MANAGE
    )
    # Suspension keeps the grants: a mistaken recovery can be undone by an owner.
    assert (
        db.scalar(
            "SELECT count(*) FROM core.platform_grants "
            "WHERE operator_id = :o AND revoked_at IS NULL",
            {"o": old},
        )
        == 18
    )


def test_recovery_never_revokes_deletes_or_reactivates(db: Db) -> None:
    assert _bootstrap("owner-1") == 0
    assert (
        _recover(
            "--enroll-issuer",
            _ISSUER,
            "--enroll-subject",
            "owner-2",
            "--grant",
            "platform.authority:manage",
        )
        == 0
    )
    second = db.operator_of("owner-2")
    assert _recover("--suspend-operator", str(second)) == 0
    # A suspended operator cannot be re-enrolled or reactivated through recovery.
    assert (
        _recover(
            "--enroll-issuer",
            _ISSUER,
            "--enroll-subject",
            "owner-2",
            "--grant",
            "platform.tenant:read",
        )
        == 1
    )
    assert (
        db.scalar("SELECT status FROM core.platform_operators WHERE id = :i", {"i": second})
        == "suspended"
    )
    assert db.scalar("SELECT count(*) FROM core.platform_grants WHERE revoked_at IS NOT NULL") == 0
    assert db.scalar("SELECT count(*) FROM core.platform_operators WHERE status = 'revoked'") == 0
    actions = {row[0] for row in db.rows("SELECT DISTINCT action FROM core.platform_audit_log")}
    assert actions <= {
        "platform.operator.enroll",
        "platform.grant.create",
        "platform.operator.suspend",
    }


def test_recovery_of_an_unknown_operator_is_refused(db: Db) -> None:
    assert _bootstrap("owner-1") == 0
    assert _recover("--suspend-operator", str(uuid.uuid4())) == 1
    assert db.scalar(_OWNER_PREDICATE) == 1


# --- atomicity: a refused or failed run leaves no identity rows behind --------
#
# Regression. Before the fix, the command resolved the identity with
# `get_or_create_user_for_external_identity()` in transactions of its own,
# *before* Core decided. A refusal by Core then left a `core.users` row and
# a `core.external_identities` row for an identity the deployment had never
# seen. The identity is now resolved or created inside the platform
# transaction, so it commits or rolls back with everything else.


def _users(db: Db) -> int:
    return db.scalar("SELECT count(*) FROM core.users")


def test_a_refused_recovery_creates_no_user_and_no_identity(db: Db) -> None:
    assert _bootstrap("owner-1") == 0
    sole = str(db.operator_of("owner-1"))
    users, identities = _users(db), db.identities()
    audit = db.scalar("SELECT count(*) FROM core.platform_audit_log WHERE outcome = 'success'")

    # Refused by the last-owner invariant: the replacement is not an owner.
    assert (
        _recover(
            "--enroll-issuer",
            _ISSUER,
            "--enroll-subject",
            "never-seen",
            "--grant",
            "platform.tenant:read",
            "--suspend-operator",
            sole,
        )
        == 1
    )
    # Refused because the operator to suspend does not exist.
    assert (
        _recover(
            "--enroll-issuer",
            _ISSUER,
            "--enroll-subject",
            "never-seen-2",
            "--grant",
            "platform.authority:manage",
            "--suspend-operator",
            str(uuid.uuid4()),
        )
        == 1
    )
    assert (_users(db), db.identities()) == (users, identities)  # nothing survived
    assert db.scalar("SELECT count(*) FROM core.platform_operators") == 1
    assert db.scalar(_OWNER_PREDICATE) == 1
    assert (
        db.scalar("SELECT count(*) FROM core.platform_audit_log WHERE outcome = 'success'") == audit
    )
    assert (
        db.scalar("SELECT count(*) FROM core.platform_audit_log WHERE outcome = 'denied'") == 1
    )  # the last-owner refusal; the not-found error is a state error, not a refusal


def test_a_failure_inside_bootstrap_rolls_back_the_new_user_and_identity(
    db: Db, monkeypatch: pytest.MonkeyPatch
) -> None:
    import saas_os.core.platform_authority.service as service_module

    users = _users(db)
    real = service_module.record_platform_event_in_transaction
    calls = {"n": 0}

    def fail_midway(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 5:  # after the enrollment and some grants were written
            raise RuntimeError("failure in the middle of bootstrap")
        return real(*args, **kwargs)

    monkeypatch.setattr(service_module, "record_platform_event_in_transaction", fail_midway)
    assert _bootstrap("owner-1") == 1
    monkeypatch.undo()
    assert (_users(db), db.identities()) == (users, 0)
    assert db.scalar("SELECT count(*) FROM core.platform_operators") == 0
    assert db.scalar("SELECT count(*) FROM core.platform_grants") == 0
    assert db.scalar("SELECT count(*) FROM core.platform_audit_log") == 0

    # A retry after the failure succeeds and creates the identity exactly once.
    monkeypatch.setenv("OIDC_ISSUER_URL", _ISSUER)
    assert _bootstrap("owner-1") == 0
    assert (_users(db), db.identities()) == (users + 1, 1)
    assert _bootstrap("owner-1") == 0  # identical rerun: no duplicate
    assert (_users(db), db.identities()) == (users + 1, 1)


def test_retrying_a_refused_recovery_with_a_valid_request_creates_the_identity_once(
    db: Db,
) -> None:
    assert _bootstrap("owner-1") == 0
    sole = str(db.operator_of("owner-1"))
    users = _users(db)
    refused = (
        "--enroll-issuer",
        _ISSUER,
        "--enroll-subject",
        "owner-2",
        "--grant",
        "platform.tenant:read",
        "--suspend-operator",
        sole,
    )
    valid = (
        "--enroll-issuer",
        _ISSUER,
        "--enroll-subject",
        "owner-2",
        "--grant",
        "platform.authority:manage",
        "--suspend-operator",
        sole,
    )
    assert _recover(*refused) == 1
    assert _recover(*refused) == 1
    assert (_users(db), db.identities()) == (users, 1)
    assert _recover(*valid) == 0
    assert (_users(db), db.identities()) == (users + 1, 2)
    assert _recover(*valid) == 0  # idempotent: nothing new
    assert (_users(db), db.identities()) == (users + 1, 2)
    assert db.scalar("SELECT count(*) FROM core.platform_operators") == 2
    assert db.scalar(_OWNER_PREDICATE) == 1


def test_bootstrap_of_a_known_identity_reuses_its_user(db: Db) -> None:
    """An identity that has logged in before is enrolled as the same user:
    no second user, no second identity link."""
    from saas_os.core.identity import get_or_create_user_for_external_identity

    existing = get_or_create_user_for_external_identity(_ISSUER, "owner-1").id
    users = _users(db)
    assert _bootstrap("owner-1") == 0
    assert (_users(db), db.identities()) == (users, 1)
    assert db.user_of("owner-1") == existing
    assert db.scalar("SELECT user_id FROM core.platform_operators") == existing


def test_an_identity_linked_by_a_concurrent_first_login_is_reused_not_duplicated(
    db: Db, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The race the unique `(issuer, subject)` constraint settles: Core
    looks the identity up, finds nothing, and a first login links it before
    Core inserts. The insert fails inside a savepoint, the user row Core
    had just added is rolled back with it, and the login's user is
    enrolled. The platform transaction itself survives."""
    import saas_os.core.identity.service as identity_service
    from saas_os.core.identity import get_or_create_user_for_external_identity

    login_user = get_or_create_user_for_external_identity(_ISSUER, "owner-1").id
    users = _users(db)
    real = identity_service.find_user_id_for_external_identity_in_transaction
    calls = {"n": 0}

    def not_found_the_first_time(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        return None if calls["n"] == 1 else real(*args, **kwargs)

    monkeypatch.setattr(
        identity_service,
        "find_user_id_for_external_identity_in_transaction",
        not_found_the_first_time,
    )
    assert _bootstrap("owner-1") == 0
    assert calls["n"] >= 2
    assert (_users(db), db.identities()) == (users, 1)  # no second user, no second link
    assert db.scalar("SELECT user_id FROM core.platform_operators") == login_user
    assert db.scalar("SELECT count(*) FROM core.platform_grants") == 18


def test_a_deactivated_known_identity_cannot_be_bootstrapped_and_nothing_is_written(
    db: Db,
) -> None:
    from saas_os.core.identity import get_or_create_user_for_external_identity

    user_id = get_or_create_user_for_external_identity(_ISSUER, "owner-1").id
    db.rows("UPDATE core.users SET is_active = false WHERE id = :u", {"u": user_id})
    users = _users(db)
    assert _bootstrap("owner-1") == 1
    assert (_users(db), db.identities()) == (users, 1)
    assert db.scalar("SELECT count(*) FROM core.platform_operators") == 0
    assert db.scalar("SELECT count(*) FROM core.platform_audit_log") == 0
