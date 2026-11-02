-- D4 REVIEW MATERIAL ONLY. NOT APPROVED. NOT IMPLEMENTED. DO NOT RUN.
-- Downgrade SQL of the proposed revisions B (f0cc2e656d79) and A (0420025c3b4b),
-- on the re-pointed chain: the target is A's down_revision, a9c3e5f7b1d4,
-- never b3d5f7a9c2e4 (that would also roll back #192 and #198).
-- Generated without a database by Alembic 1.20.0 offline mode:
--   alembic -c <scratch>/alembic.ini downgrade f0cc2e656d79:a9c3e5f7b1d4 --sql
-- against a scratch copy of the migrations directory outside the repository
-- (see README.md, "How the SQL files were produced"). Everything below the
-- line of dashes is the generated output, unchanged except CRLF -> LF and a
-- trailing secret-scanner pragma comment on each alembic_version UPDATE line.
-- DATA LOSS: A's downgrade drops both columns; their values are lost.
-- ---------------------------------------------------------------------------
BEGIN;

-- Running downgrade f0cc2e656d79 -> 0420025c3b4b

UPDATE alembic_version_saas_os SET version_num='0420025c3b4b' WHERE alembic_version_saas_os.version_num = 'f0cc2e656d79';  -- pragma: allowlist secret

-- Running downgrade 0420025c3b4b -> a9c3e5f7b1d4

SET LOCAL lock_timeout = '5s';

ALTER TABLE core.outbox_events DROP CONSTRAINT ck_outbox_events_external_started_pair, DROP COLUMN external_started_claim, DROP COLUMN external_started_at;

RESET lock_timeout;

UPDATE alembic_version_saas_os SET version_num='a9c3e5f7b1d4' WHERE alembic_version_saas_os.version_num = '0420025c3b4b';  -- pragma: allowlist secret

COMMIT;

