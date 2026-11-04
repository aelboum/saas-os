# Audit identity phase P1: SQL review of the retention proposal, section 8

**Status: review result, 2026-11-04. Reviewed on PostgreSQL 16.15 (`PostgreSQL 16.15 on x86_64-pc-linux-musl, compiled by gcc (Alpine 15.2.0) 15.2.0, 64-bit`, image `postgres:16-alpine`) against the schema of `main` at `3d1a33a` (migration head `f0cc2e656d79`, built with `python -m saas_os.infra.db.migration_cli upgrade`). 37 checks: 37 PASS, 0 FAIL. No blocking problem and nothing that needs an owner decision was found; four routine corrections to the proposal's text are listed in section 3 and are applied by the P1 migration.**

Scope: the platform-side pieces that P1 builds (proposal sections 4.3 and 4.4, platform variants; section 4.9 for the hold table) and the items of proposal section 8 that concern them (1 to 7, 9 to 13, 15 and, as a smoke test, 8 and 16), plus the owner decision of 2026-11-04 (option A1 of `AUDIT-P1-FOREIGN-KEY-OPTIONS.md`, in PR #211): the foreign key stays and the writers decide existence with `SELECT ... FOR KEY SHARE`. The tenant tables, the tenant expression index and the expiry command belong to P2 and P3 and were not reviewed, except where noted.

Method: the DDL of section 2 was run as the proposal gives it (the parts the proposal states only in prose or by name are marked `REVIEWER COMPLETION`) as the migrations role on a disposable database; then every claim was exercised with real connections: the runtime role `saas_os_app` for everything the application does, the migrations role `saas_os` where the claim concerns it. Every check in section 5 shows the SQL or procedure and what was observed. Nothing was inferred from documentation unless the check says so.

## 1. Result at a glance

| Item of proposal section 8 | Checks | Result |
|---|---|---|
| 1 Partial unique index as `ON CONFLICT` arbiter; primary-key collision; savepoint retry | A1 to A4 | PASS |
| 2 `NULLS NOT DISTINCT` with a partial index | N1, N2 | PASS |
| 3 UTC day | T1 | PASS |
| 4 Interval arithmetic and the worked values | I1 to I3 | PASS |
| 5 RLS (enable, force, exclusion policy, `ON CONFLICT` under RLS) | R1 to R3 | PASS |
| 6 Trigger semantics | TR1 to TR4 | PASS |
| 7 Lock levels | L1 | PASS (one operational note, section 4) |
| 8 Expression index on `json` (P3) | J1 | PASS (smoke test only) |
| 9 Advisory locks | AL1, C4 | PASS |
| 10 Text equality | TX1 | PASS |
| 11 `gen_random_uuid()` | G1 | PASS |
| 12 Bind parameters and casts | B1 | PASS |
| 13 Isolation check | IS1 | PASS |
| 15 Default privileges and grants | GR1, GR2, ER1 | PASS |
| 16 Plans of the expiry query (P2) | X1 | The query runs; plan review on realistic volumes **not performed** |
| 14 Downgrade | not a SQL claim | implemented and tested with the migration (see the PR) |
| A1: `FOR KEY SHARE` privilege of the runtime role (inferred in the options paper) | KS1, KS2 | **Verified** |
| A1: unknown-id path | U1, U2 | PASS |
| Concurrent get-or-create | C1 to C3 | PASS |

## 2. The DDL that was run

```sql
-- Proposal section 4.3 (platform tables), options paper 1.1 (link table),
-- section 4.9 (hold table, platform variant), section 4.3 grants and triggers.
-- Text the proposal does not give literally is marked "REVIEWER COMPLETION".
CREATE TABLE core.platform_audit_subject_links (
    subject_ref    uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id        uuid        NULL REFERENCES core.users (id),  -- NULL once unlinked
    subject_day    date        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    unlinked_at    timestamptz NULL,
    unlink_reason  text        NULL,
    CONSTRAINT pk_platform_audit_subject_links PRIMARY KEY (subject_ref),
    CONSTRAINT ck_platform_audit_subject_links_unlink_pairing CHECK (
        (user_id IS NULL) = (unlinked_at IS NOT NULL)
        AND (unlinked_at IS NULL) = (unlink_reason IS NULL)
    ),
    CONSTRAINT ck_platform_audit_subject_links_unlink_reason
        CHECK (unlink_reason IS NULL OR unlink_reason IN ('erasure', 'expiry'))
);
CREATE UNIQUE INDEX uq_platform_audit_subject_links_live
    ON core.platform_audit_subject_links (user_id, subject_day)
    WHERE user_id IS NOT NULL;
ALTER TABLE "core"."platform_audit_subject_links" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "core"."platform_audit_subject_links" FORCE ROW LEVEL SECURITY;
CREATE POLICY "platform_audit_subject_links_no_tenant_context" ON "core"."platform_audit_subject_links" USING (NULLIF(current_setting('app.tenant_id', true), '') IS NULL);

-- REVIEWER COMPLETION: proposal 4.3 gives "(user_id PRIMARY KEY, erased_at)" only.
CREATE TABLE core.platform_audit_subject_erasures (
    user_id    uuid        NOT NULL REFERENCES core.users (id),
    erased_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_platform_audit_subject_erasures PRIMARY KEY (user_id)
);
ALTER TABLE "core"."platform_audit_subject_erasures" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "core"."platform_audit_subject_erasures" FORCE ROW LEVEL SECURITY;
CREATE POLICY "platform_audit_subject_erasures_no_tenant_context" ON "core"."platform_audit_subject_erasures" USING (NULLIF(current_setting('app.tenant_id', true), '') IS NULL);

-- Proposal 4.9, tenant DDL minus tenant_id (platform variant).
CREATE TABLE core.platform_audit_identity_holds (
    id                             uuid         NOT NULL,
    reference                      varchar(100) NOT NULL,
    from_day                       date         NULL,
    to_day                         date         NULL,
    subject_ref                    uuid         NULL,
    placed_at                      timestamptz  NOT NULL DEFAULT now(),
    placed_by_platform_audit_id    uuid         NOT NULL,
    released_at                    timestamptz  NULL,
    released_by_platform_audit_id  uuid         NULL,
    CONSTRAINT pk_platform_audit_identity_holds PRIMARY KEY (id),
    CONSTRAINT ck_platform_audit_identity_holds_reference
        CHECK (reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$'),
    CONSTRAINT ck_platform_audit_identity_holds_days
        CHECK (from_day IS NULL OR to_day IS NULL OR from_day <= to_day),
    CONSTRAINT ck_platform_audit_identity_holds_release_pairing
        CHECK ((released_at IS NULL) = (released_by_platform_audit_id IS NULL)),
    CONSTRAINT ck_platform_audit_identity_holds_release_order
        CHECK (released_at IS NULL OR released_at >= placed_at)
);
CREATE UNIQUE INDEX uq_platform_audit_identity_holds_active
    ON core.platform_audit_identity_holds (reference, subject_ref)
    NULLS NOT DISTINCT WHERE released_at IS NULL;
ALTER TABLE "core"."platform_audit_identity_holds" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "core"."platform_audit_identity_holds" FORCE ROW LEVEL SECURITY;
CREATE POLICY "platform_audit_identity_holds_no_tenant_context" ON "core"."platform_audit_identity_holds" USING (NULLIF(current_setting('app.tenant_id', true), '') IS NULL);

-- REVIEWER COMPLETION: the one-way link trigger (proposal 4.3 states it in prose).
CREATE FUNCTION core.platform_audit_subject_links_one_way() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.user_id IS NOT NULL AND NEW.user_id IS NULL
     AND OLD.unlinked_at IS NULL AND NEW.unlinked_at IS NOT NULL
     AND NEW.subject_ref = OLD.subject_ref
     AND NEW.subject_day = OLD.subject_day
     AND NEW.created_at = OLD.created_at THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'a platform audit subject link only ever changes from live to unlinked'
    USING ERRCODE = 'check_violation';
END $$;
CREATE TRIGGER trg_platform_audit_subject_links_one_way
BEFORE UPDATE ON core.platform_audit_subject_links
FOR EACH ROW EXECUTE FUNCTION core.platform_audit_subject_links_one_way();

-- Hold release trigger: the PR #198 pattern (a9c3e5f7b1d4).
CREATE FUNCTION core.platform_audit_identity_holds_release_once() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.released_at IS NOT NULL THEN
    RAISE EXCEPTION 'a released audit identity hold is never changed'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_platform_audit_identity_holds_release_once
BEFORE UPDATE ON core.platform_audit_identity_holds
FOR EACH ROW EXECUTE FUNCTION core.platform_audit_identity_holds_release_once();

-- Grants, proposal 4.3 table. Default privileges of e99c76057719 give the app role arwd.
REVOKE UPDATE, DELETE ON core.platform_audit_subject_links FROM "saas_os_app";
GRANT UPDATE (user_id, unlinked_at, unlink_reason) ON core.platform_audit_subject_links TO "saas_os_app";
REVOKE UPDATE, DELETE ON core.platform_audit_subject_erasures FROM "saas_os_app";
REVOKE UPDATE, DELETE ON core.platform_audit_identity_holds FROM "saas_os_app";
GRANT UPDATE (released_at, released_by_platform_audit_id) ON core.platform_audit_identity_holds TO "saas_os_app";
```

## 3. Corrections and completions to the proposal text

None of these changes a decision.

1. **Name the foreign keys.** Left unnamed, PostgreSQL named the link-table key `platform_audit_subject_links_user_id_fkey` (U1). The repository names every constraint (`fk_<table>_<column>`); the migration uses `fk_platform_audit_subject_links_user_id` and `fk_platform_audit_subject_erasures_user_id`.
2. **The erasure marker table is given by name only** (`(user_id PRIMARY KEY, erased_at)`). The reviewed form is `user_id uuid NOT NULL REFERENCES core.users (id)` and `erased_at timestamptz NOT NULL DEFAULT now()`; the runtime role gets `SELECT` and `INSERT` only (GR2).
3. **The one-way link trigger is described in prose only.** The reviewed function (section 2) accepts exactly live -> unlinked with every other column unchanged and raises `check_violation` otherwise, for every role including the migrations role (TR1). The hold-release trigger is the pattern of `a9c3e5f7b1d4` (TR3).
4. **`NULLS NOT DISTINCT` and Alembic.** SQLAlchemy 2.1.2 emits the clause from `postgresql_nulls_not_distinct=True` (N2), but the package floor is `sqlalchemy>=2.0`, so the migration emits the index with `op.execute` and does not depend on the keyword.

Observations that are not defects and need no change now:

- `subject_day` is not constrained against `created_at` or the writing transaction: the database accepts any day. The day rule (proposal 4.2) is kept by the helper, as for every other value the runtime role writes. The expiry command's record bound (proposal 4.8, bound 2) exists for a reference used outside its day.
- The migrations role of the disposable database (`saas_os`, the container's `POSTGRES_USER`) is a superuser with `BYPASSRLS`, which no policy binds. `FORCE ROW LEVEL SECURITY` was therefore demonstrated with a scratch non-superuser owner (R3).

## 4. Operational notes

- **Lock on `core.users` while the migration runs (L1).** Creating the two tables that reference `core.users` takes `SHARE ROW EXCLUSIVE` on `core.users` until the migration transaction ends. Reads continue; writes to `core.users` (an `UPDATE`, a sign-up) wait. The tables are new and empty, so the transaction is short, but a long-running writer on `core.users` makes the migration wait and then queues other writers behind it. Deployment ordering: apply the migration before the new application version starts, as the existing procedure does, and prefer a quiet moment. `core.tenants` is not locked (the platform tables do not reference it).
- **`FOR KEY SHARE` (KS1, KS2).** The runtime role holds `SELECT`, `INSERT`, `UPDATE` and `DELETE` on `core.users`, so the lock is available. It does not block the non-key `UPDATE`s that application code issues on the user row, and it blocks a concurrent `DELETE` of that user until the audit transaction ends. A role with `SELECT` only cannot take it (`42501`), so a future narrowing of the runtime role's `UPDATE` on `core.users` would turn every platform user-target audit write into an error: the grant is a tested precondition (a test in the P1 slice pins it).

## 5. Every check

`SQL` is the exact statement, or the sequence of statements or connections where the claim needs more than one. The observed value is what the server returned or what the connections did.


### L1: PASS

Item 7. Lock modes held on existing tables while the migration transaction runs (item 7).

Observed: core.users: ['AccessShareLock', 'ShareRowExclusiveLock']; core.tenants: no lock (the platform tables have no FK to tenants); concurrent UPDATE on core.users during the DDL transaction (lock_timeout 700ms): ('55P03', 'canceling statement due to lock timeout'); concurrent SELECT: (None, 'no error')

SQL:

```sql
BEGIN; <ddl.sql>; SELECT c.relname, l.mode FROM pg_locks l JOIN pg_class c ON c.oid = l.relation WHERE l.pid = <backend>; -- second connection: UPDATE core.users ...; ROLLBACK
```

### D0: PASS

Item -. The proposal's platform DDL (links, erasures, holds, triggers, grants) applies without error on current main.

Observed: applied as role saas_os

SQL:

```sql
see the DDL block
```

### G1: PASS

Item 11. gen_random_uuid() is available without pgcrypto and returns random version-4 uuids (item 11; source of randomness).

Observed: extensions installed: ['plpgsql']; 200000 calls -> 200000 distinct, version nibble 4..4, variant nibble 8..b. That the source is a strong random generator comes from PostgreSQL's documentation and source (uuid.c uses pg_strong_random); SQL cannot prove it

SQL:

```sql
SELECT count(DISTINCT g) FROM (SELECT gen_random_uuid() g FROM generate_series(1,200000)) s
```

### A1: PASS

Item 1. The partial unique index is inferred as the ON CONFLICT arbiter; a second insert returns no row; the re-select returns the first reference (item 1).

Observed: first RETURNING d4bfc34d-fcf6-4159-a7b6-56bd6a5ea469, second RETURNING None, re-select d4bfc34d-fcf6-4159-a7b6-56bd6a5ea469

SQL:

```sql
INSERT INTO core.platform_audit_subject_links (user_id, subject_day) VALUES (%s, (now() AT TIME ZONE 'UTC')::date) ON CONFLICT (user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING RETURNING subject_ref; SELECT subject_ref FROM core.platform_audit_subject_links WHERE user_id = %s AND subject_day = (now() AT TIME ZONE 'UTC')::date AND user_id IS NOT NULL
```

### A2: PASS

Item 1. Without the WHERE predicate the arbiter cannot be inferred (42P10): the predicate is required.

Observed: SQLSTATE ('42P10', 'there is no unique or exclusion constraint matching the ON CONFLICT specification')

SQL:

```sql
INSERT ... ON CONFLICT (user_id, subject_day) DO NOTHING
```

### A3: PASS

Item 1. A primary-key collision on subject_ref is not absorbed by the arbiter: SQLSTATE 23505 on pk_platform_audit_subject_links.

Observed: ('23505', 'pk_platform_audit_subject_links')

SQL:

```sql
INSERT (subject_ref = an existing reference, user_id = another user) ... ON CONFLICT (user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING
```

### A4: PASS

Item 1. Savepoint retry through SQLAlchemy begin_nested(): two forced primary-key collisions roll back to the savepoint, the third attempt succeeds, and the outer transaction stays usable.

Observed: attempts=3, inserted=True, outer transaction usable=True

SQL:

```sql
with session.begin_nested(): INSERT ... ON CONFLICT ... DO NOTHING RETURNING subject_ref   -- catch IntegrityError 23505 on pk_platform_audit_subject_links; retry
```

### N1: PASS

Item 2. NULLS NOT DISTINCT with the partial WHERE released_at IS NULL: two active tenant-wide holds (subject_ref NULL) with one reference conflict; a different reference, a different subject_ref and a re-placement after release do not (item 2).

Observed: duplicate NULL/NULL 23505; other reference None; same reference with a subject None; same subject duplicate 23505; re-placement after release None

SQL:

```sql
CREATE UNIQUE INDEX uq_platform_audit_identity_holds_active ON core.platform_audit_identity_holds (reference, subject_ref) NULLS NOT DISTINCT WHERE released_at IS NULL
```

### N2: PASS

Item 2. SQLAlchemy emits NULLS NOT DISTINCT natively (postgresql_nulls_not_distinct), so alembic's op.create_index can emit it without raw SQL.

Observed: SQLAlchemy 2.1.2: CREATE UNIQUE INDEX uq_x ON core.t (a, b) NULLS NOT DISTINCT WHERE released_at IS NULL

SQL:

```sql
sa.Index(..., unique=True, postgresql_nulls_not_distinct=True, postgresql_where=...)
```

### T1: PASS

Item 3. (now() AT TIME ZONE 'UTC')::date and the three-argument date_trunc('day', now(), 'UTC') do not depend on the session TimeZone (item 3); the proposal uses the former.

Observed: per TimeZone (utc_date, date_trunc_utc, vector1, vector2, now()::date): UTC: ('2026-11-04', '2026-11-04', '2028-02-29', '2029-01-01', '2026-11-04'); Asia/Tokyo: ('2026-11-04', '2026-11-04', '2028-02-29', '2029-01-01', '2026-11-05'); America/Los_Angeles: ('2026-11-04', '2026-11-04', '2028-02-29', '2029-01-01', '2026-11-04'); Pacific/Kiritimati: ('2026-11-04', '2026-11-04', '2028-02-29', '2029-01-01', '2026-11-05'). now()::date takes 2 distinct value(s) here (it follows the zone and must not be used)

SQL:

```sql
SET TimeZone = ...; SELECT (now() AT TIME ZONE 'UTC')::date, (date_trunc('day', now(), 'UTC') AT TIME ZONE 'UTC')::date, now()::date
```

### I1: PASS

Item 4. timestamp + interval '2 years' on the UTC wall time reproduces all five worked values of the exact rule (including the 29 February clamp and 730/731-day cases) in three session time zones (item 4).

Observed: mismatches: none; results [('2028-02-29 12:00:00+00', '2030-02-28 12:00:00', '730 days'), ('2028-02-28 12:00:00+00', '2030-02-28 12:00:00', '731 days'), ('2027-03-01 00:00:00+00', '2029-03-01 00:00:00', '731 days'), ('2028-02-29 00:30:00+01', '2030-02-28 23:30:00', '731 days'), ('2028-12-31 23:59:59.999999+00', '2030-12-31 23:59:59.999999', '730 days')]

SQL:

```sql
SELECT ((:created_at::timestamptz) AT TIME ZONE 'UTC') + interval '2 years'
```

### I2: PASS

Item 4. The day bound ((subject_day + interval '2 years')::date + 2)::timestamp is never earlier than the latest record of that day expiring plus the one-day margin (section 4.8).

Observed: 2028-02-28: bound 2030-03-02 00:00:00 >= 2030-03-01 23:59:59.999999; 2028-02-29: bound 2030-03-02 00:00:00 >= 2030-03-01 23:59:59.999999; 2028-12-31: bound 2031-01-02 00:00:00 >= 2031-01-01 23:59:59.999999; 2027-03-01: bound 2029-03-03 00:00:00 >= 2029-03-02 23:59:59.999999

SQL:

```sql
SELECT ((d + interval '2 years')::date + 2)::timestamp, (d::timestamp + interval '23:59:59.999999') + interval '2 years' + interval '1 day'
```

### I3: PASS

Item 4. timestamptz + interval is session-zone dependent across a daylight-saving change (the reason section 4.8 computes on UTC timestamps).

Observed: Europe/Paris: 2028-03-25 12:00+00 + 1 day = 2028-03-26 13:00:00+02:00 versus UTC-wall arithmetic 2028-03-26 14:00:00+02:00

SQL:

```sql
SET TimeZone = 'Europe/Paris'; SELECT timestamptz + interval '1 day'
```

### R1: PASS

Item 5. Exclusion policy: link rows are visible only when app.tenant_id is unset or empty; in a tenant-bound transaction no rows are visible and INSERT ... ON CONFLICT DO NOTHING fails with 42501; after a tenant transaction the leftover empty setting does not break an untenanted query (item 5).

Observed: untenanted rows 1; tenant-bound rows 0; tenant-bound INSERT 42501; leftover setting after the transaction ''; rows afterwards 1

SQL:

```sql
SELECT set_config('app.tenant_id', :tenant, true); SELECT count(*) / INSERT ... ON CONFLICT DO NOTHING on core.platform_audit_subject_links
```

### R2: PASS

Item 5. ENABLE and FORCE ROW LEVEL SECURITY are set on all three platform tables; tenant-bound transactions see no rows in the erasure and hold tables.

Observed: [('platform_audit_identity_holds', True, True), ('platform_audit_subject_erasures', True, True), ('platform_audit_subject_links', True, True)]; tenant-bound counts {'platform_audit_subject_erasures': 0, 'platform_audit_identity_holds': 0}

SQL:

```sql
SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class ...
```

### R3: PASS

Item 5. FORCE ROW LEVEL SECURITY binds the table owner when the owner is neither superuser nor BYPASSRLS (item 5). The local migrations role saas_os is a superuser with BYPASSRLS, which no policy binds, so the check uses a scratch non-superuser owner.

Observed: the owner sees 1 row(s) in a tenant context without FORCE and 0 with FORCE

SQL:

```sql
SET ROLE p1x_owner; CREATE TABLE ...; CREATE POLICY ...; SELECT count(*) before and after ALTER TABLE ... FORCE ROW LEVEL SECURITY
```

### TR1: PASS

Item 6. One-way link trigger: the only accepted update is live -> unlinked (erasure); re-pointing, relinking, an update of an unlinked row and a bad reason are refused with 23514, for the migrations role as well (item 6).

Observed: re-point a live link 23514; swap the user 23514; unlink without a reason 23514 (pairing CHECK); bad reason 23514; valid unlink None; relink an unlinked row 23514; update an unlinked row 23514; the same relink as the migrations role 23514

SQL:

```sql
UPDATE core.platform_audit_subject_links SET user_id = NULL, unlinked_at = now(), unlink_reason = 'erasure' WHERE subject_ref = :r   -- accepted; every other UPDATE listed is refused
```

### TR2: PASS

Item 6. After an unlink the user's live slot for that day is free (the unlinked row is outside the partial unique index) and a new link gets a different reference.

Observed: new link created: True; different reference: True

SQL:

```sql
INSERT INTO core.platform_audit_subject_links (user_id, subject_day) VALUES (%s, (now() AT TIME ZONE 'UTC')::date) ON CONFLICT (user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING RETURNING subject_ref
```

### TR3: PASS

Item 6. Hold release is one-way: the first release is accepted, any later change is refused (23514) for the application role and the migrations role.

Observed: release None; second change 23514; migrations-role change 23514

SQL:

```sql
UPDATE core.platform_audit_identity_holds SET released_at = now(), released_by_platform_audit_id = :a WHERE id = :h
```

### TR4: PASS

Item 6. INSERT ... ON CONFLICT DO NOTHING (the only form used) does not fire the BEFORE UPDATE triggers.

Observed: the repeated insert of the same (user, day) returned no row and raised nothing (A1)

SQL:

```sql
INSERT INTO core.platform_audit_subject_links (user_id, subject_day) VALUES (%s, (now() AT TIME ZONE 'UTC')::date) ON CONFLICT (user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING RETURNING subject_ref
```

### GR1: PASS

Item 15. Runtime-role grants (item 15): SELECT and INSERT on all three tables; table-level UPDATE, DELETE and TRUNCATE on none; column-level UPDATE only on the three link columns and the two hold release columns.

Observed: table privileges: {"platform_audit_subject_links": {"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false, "TRUNCATE": false}, "platform_audit_subject_erasures": {"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false, "TRUNCATE": false}, "platform_audit_identity_holds": {"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false, "TRUNCATE": false}}; column UPDATE grants: [('platform_audit_identity_holds', 'released_at'), ('platform_audit_identity_holds', 'released_by_platform_audit_id'), ('platform_audit_subject_links', 'unlink_reason'), ('platform_audit_subject_links', 'unlinked_at'), ('platform_audit_subject_links', 'user_id')]

SQL:

```sql
SELECT has_table_privilege('saas_os_app', 'core.<t>', '<priv>'); SELECT table_name, column_name FROM information_schema.column_privileges WHERE grantee = 'saas_os_app' AND privilege_type = 'UPDATE'
```

### GR2: PASS

Item 15. As the runtime role: UPDATE of subject_ref, subject_day or created_at, DELETE and TRUNCATE on the link table, UPDATE and DELETE on the erasure table, DELETE and UPDATE of a non-release column on holds are all refused (42501); INSERT of an erasure marker works.

Observed: link UPDATE subject_day: 42501; link UPDATE created_at: 42501; link UPDATE subject_ref: 42501; link DELETE: 42501; link TRUNCATE: 42501; erasure INSERT: ok; erasure UPDATE: 42501; erasure DELETE: 42501; hold DELETE: 42501; hold UPDATE reference: 42501; hold UPDATE placed_by: 42501

SQL:

```sql
UPDATE / DELETE / TRUNCATE statements over a connection authenticated as saas_os_app
```

### ER1: PASS

Item -. Born-unlinked rows (erasure case 3c) insert under the runtime role, repeatedly (they are outside the live index); a user_id-NULL row without unlinked_at is refused by the pairing CHECK.

Observed: first None, second None, NULL without unlinked_at 23514

SQL:

```sql
INSERT INTO core.platform_audit_subject_links (user_id, subject_day, unlinked_at, unlink_reason) VALUES (NULL, ..., now(), 'erasure') RETURNING subject_ref
```

### KS1: PASS

Item A1. The runtime role can take SELECT ... FOR KEY SHARE on core.users (privilege VERIFIED, no longer inferred): it holds SELECT and UPDATE on core.users; a role with SELECT only cannot (42501).

Observed: as saas_os_app: existing user -> row, unknown id -> no row; SELECT/UPDATE/DELETE on core.users = (True, True, True); SELECT-only role -> 42501

SQL:

```sql
SELECT 1 FROM core.users WHERE id = :user_id FOR KEY SHARE
```

### KS2: PASS

Item A1. FOR KEY SHARE does not block a concurrent non-key UPDATE of the user row (activation changes) but does block a concurrent DELETE of that user until the audit transaction ends.

Observed: concurrent UPDATE core.users SET updated_at: proceeded; concurrent DELETE: 55P03 (canceling statement due to lock timeout)

SQL:

```sql
tx A: SELECT ... FOR KEY SHARE; tx B (lock_timeout 800ms): UPDATE core.users SET updated_at = now() WHERE id = :u / DELETE FROM core.users WHERE id = :u
```

### U1: PASS

Item A1. The FK stays: inserting a link for an unknown id raises 23503 and ABORTS the whole transaction (25P02 for the next statement), which is why the existence read must precede the insert.

Observed: insert for an unknown id: ('23503', 'platform_audit_subject_links_user_id_fkey'); next statement in the same transaction: 25P02

SQL:

```sql
INSERT INTO core.platform_audit_subject_links (user_id, subject_day) VALUES (:unknown, ...)
```

### U2: PASS

Item A1. Unknown-id path of A1: the existence read finds no row, no link row is created, and the platform audit row with target_type 'user' and target_id NULL is accepted by the table (no constraint pairs target_type with target_id); the runtime role can insert it.

Observed: existence none; audit insert ok; link rows before/after 5/5

SQL:

```sql
SELECT 1 FROM core.users WHERE id = :u FOR KEY SHARE;  INSERT INTO core.platform_audit_log (..., target_type, target_id, ...) VALUES (..., 'user', NULL, ...)
```

### B1: PASS

Item 12. SQLAlchemy text(): ':user_id::text' is mis-parsed; CAST(:user_id AS text) works (item 12).

Observed: ':user_id::text' -> ProgrammingError: syntax error at or near ":"; the CAST form executed

SQL:

```sql
text("... :user_id::text ...") versus text("... CAST(:user_id AS text) ...")
```

### AL1: PASS

Item 9. Advisory locks (item 9): shared locks coexist; an exclusive lock on the same key waits (55P03 under lock_timeout); the single-bigint key space does not collide with the two-int4 form the codebase uses (acquire_tenant_advisory_lock, c3f9e1a7b5d2).

Observed: exclusive against two shared holders: 55P03; two-int4 lock on the same 32+32 bits: granted (separate key space)

SQL:

```sql
SELECT pg_advisory_xact_lock_shared(hashtextextended(:key, 0)); SELECT pg_advisory_xact_lock(hashtextextended(:key, 0)); SELECT pg_advisory_xact_lock(int4, int4)
```

### IS1: PASS

Item 13. Isolation (item 13): transaction_isolation is 'read committed' by default and 'repeatable read' when requested; under REPEATABLE READ a marker committed after the snapshot is invisible, under READ COMMITTED it is visible, so the isolation check of section 4.4 is needed and is implementable.

Observed: default 'read committed'; requested 'repeatable read'; marker committed after the snapshot visible under REPEATABLE READ: False; under READ COMMITTED: True

SQL:

```sql
SELECT current_setting('transaction_isolation'); SELECT 1 FROM core.platform_audit_subject_erasures WHERE user_id = :u
```

### TX1: PASS

Item 10. uuid::text is the lowercase canonical hyphenated form, so target_id = subject_ref::text matches only str(uuid) (item 10); an upper-case target_id does not match.

Observed: canonical lowercase 8-4-4-4-12: True; equals its upper-case form: False

SQL:

```sql
SELECT subject_ref::text ~ '^[0-9a-f]{8}-...$' FROM core.platform_audit_subject_links
```

### X1: PASS

Item 16. The proposal's platform expiry query (section 4.8) parses and runs (FOR UPDATE OF l with two NOT EXISTS). Plan review on realistic volumes (item 16) is a P2 matter and was not performed.

Observed: executed

SQL:

```sql
SELECT l.subject_ref FROM core.platform_audit_subject_links l WHERE ((l.subject_day + interval '2 years')::date + 2)::timestamp <= (now() AT TIME ZONE 'UTC') AND NOT EXISTS (SELECT 1 FROM core.platform_audit_log a WHERE a.target_type = 'user_subject' AND a.target_id = l.subject_ref::text AND (a.created_at AT TIME ZONE 'UTC') + interval '2 years' + interval '1 day' > (now() AT TIME ZONE 'UTC')) AND NOT EXISTS (SELECT 1 FROM core.platform_audit_identity_holds h WHERE h.released_at IS NULL AND (h.subject_ref IS NULL OR h.subject_ref = l.subject_ref) AND (h.from_day IS NULL OR h.from_day <= l.subject_day) AND (h.to_day IS NULL OR h.to_day >= l.subject_day)) ORDER BY l.subject_ref FOR UPDATE OF l
```

### J1: PASS

Item 8. (P3, outside the P1 DDL; item 8) An expression index on json, (metadata -> 'initiated_by' ->> 'subject_ref'), builds and the planner uses it.

Observed: index build ok; plan: Index Scan using p1x_json_ix on p1x_json  (cost=0.31..8.33 rows=1 width=4)

SQL:

```sql
CREATE INDEX ... ON t (tenant_id, (metadata -> 'initiated_by' ->> 'subject_ref'))
```

### C1: PASS

Item -. Concurrent first get-or-create for one user and day (READ COMMITTED, two real connections): the second INSERT blocks on the first, returns no row after the first commits, the re-select returns the first's reference; one live row.

Observed: blocked sessions observed 1; B waited 1.01s; B's insert returned None; B's select equals A's reference: True

SQL:

```sql
A: INSERT INTO core.platform_audit_subject_links (user_id, subject_day) VALUES (%s, (now() AT TIME ZONE 'UTC')::date) ON CONFLICT (user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING RETURNING subject_ref (uncommitted) | B: same statement | A: COMMIT | B: SELECT subject_ref FROM core.platform_audit_subject_links WHERE user_id = %s AND subject_day = (now() AT TIME ZONE 'UTC')::date AND user_id IS NOT NULL
```

### C2: PASS

Item -. If the first transaction rolls back, the waiting second INSERT proceeds and creates the row (a rolled-back transaction leaves no link).

Observed: B inserted after A's rollback: True

SQL:

```sql
INSERT INTO core.platform_audit_subject_links (user_id, subject_day) VALUES (%s, (now() AT TIME ZONE 'UTC')::date) ON CONFLICT (user_id, subject_day) WHERE user_id IS NOT NULL DO NOTHING RETURNING subject_ref
```

### C3: PASS

Item -. Stress: 12 concurrent connections get-or-create the same 15 users: no error; every connection gets the same reference per user; exactly one live row per user.

Observed: errors 0; distinct references per user [1]; live rows per user [1]

SQL:

```sql
12 threads x (INSERT ... ON CONFLICT DO NOTHING RETURNING; else SELECT; COMMIT) over 15 users
```

### C4: PASS

Item -. Erasure against writer: a writer arriving while an erasure holds S(platform, user) exclusively waits, and after the erasure commits its next statement sees the marker (section 4.4 step 2).

Observed: writer blocked while the erasure was open: True; marker visible afterwards: True

SQL:

```sql
erasure: pg_advisory_xact_lock(...); INSERT marker; COMMIT | writer: pg_advisory_xact_lock_shared(...); SELECT 1 FROM core.platform_audit_subject_erasures WHERE user_id = :u
```

## 6. What this review did not do

- No plan review of the expiry query on realistic volumes (item 16); that is P2.
- The tenant link, erasure and hold tables and the `core.audit_log` expression index are P3 and were not built. J1 shows only that an expression index on a `json` column builds and is used.
- Timing differences of the A1 existence read (options paper, 1.3) were not measured.
- Random-number quality: G1 shows the version-4 shape and 200000 distinct values; that the source is a strong random generator is PostgreSQL's documented behaviour of `gen_random_uuid()` and cannot be shown from SQL.
- One disposable PostgreSQL 16.15 instance; other minor versions were not checked.
