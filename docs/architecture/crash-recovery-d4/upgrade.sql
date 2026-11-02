-- D4 REVIEW MATERIAL ONLY. NOT APPROVED. NOT IMPLEMENTED. DO NOT RUN.
-- Upgrade SQL of the proposed revisions A (0420025c3b4b) and B (f0cc2e656d79),
-- on the re-pointed chain (A's down_revision = a9c3e5f7b1d4, the head of #198).
-- Generated without a database by Alembic 1.20.0 offline mode:
--   alembic -c <scratch>/alembic.ini upgrade a9c3e5f7b1d4:f0cc2e656d79 --sql
-- against a scratch copy of the migrations directory outside the repository
-- (see README.md, "How the SQL files were produced"). Everything below the
-- line of dashes is the generated output, unchanged except CRLF -> LF and a
-- trailing secret-scanner pragma comment on each alembic_version UPDATE line.
-- The supported path is `saas-os-migrate upgrade` (online); if this offline
-- script were ever piped into psql, use -v ON_ERROR_STOP=1 (README, finding F4).
-- ---------------------------------------------------------------------------
BEGIN;

-- Running upgrade a9c3e5f7b1d4 -> 0420025c3b4b

SET LOCAL lock_timeout = '5s';

ALTER TABLE core.outbox_events ADD COLUMN external_started_at timestamptz NULL, ADD COLUMN external_started_claim uuid NULL, ADD CONSTRAINT ck_outbox_events_external_started_pair CHECK ((external_started_at IS NULL) = (external_started_claim IS NULL)) NOT VALID;

RESET lock_timeout;

UPDATE alembic_version_saas_os SET version_num='0420025c3b4b' WHERE alembic_version_saas_os.version_num = 'a9c3e5f7b1d4';  -- pragma: allowlist secret

-- Running upgrade 0420025c3b4b -> f0cc2e656d79

COMMIT;

SET lock_timeout = '5s';

ALTER TABLE core.outbox_events VALIDATE CONSTRAINT ck_outbox_events_external_started_pair;

RESET lock_timeout;

BEGIN;

UPDATE alembic_version_saas_os SET version_num='f0cc2e656d79' WHERE alembic_version_saas_os.version_num = '0420025c3b4b';  -- pragma: allowlist secret

COMMIT;

