-- Independent D4 reproduction (d4repro): populated data for items 3 to 7.
-- Run as the migrations role in the disposable container, at A's
-- down_revision, with: psql -v ON_ERROR_STOP=1 -v n=1000000 -f seed.sql
-- 50 tenants; n events (n = 1,000,000 in this reproduction):
--   90 % published, 4 % dead-lettered, 2 % pending due and unclaimed,
--   1 % pending claimed with a live lease (expires in one day),
--   1 % pending claimed with an expired lease, 2 % pending waiting for a retry.
-- Synthetic data only; no production data.
\set ON_ERROR_STOP 1
SELECT now() AS seed_started;
BEGIN;
INSERT INTO core.tenants (id, name, status)
SELECT ('00000000-0000-4000-8000-' || lpad(to_hex(g), 12, '0'))::uuid, 'd4r-seed ' || g, 'active'
FROM generate_series(1, 50) AS g;
INSERT INTO core.outbox_events (
    id, tenant_id, event_type, aggregate_type, aggregate_id, payload, correlation_id,
    status, attempts, next_attempt_at, last_error, published_at, claim_token,
    created_at, updated_at
)
SELECT
    gen_random_uuid(),
    ('00000000-0000-4000-8000-' || lpad(to_hex(1 + g % 50), 12, '0'))::uuid,
    'd4r.seed.' || (g % 7),
    'd4r-seed',
    'agg-' || g,
    json_build_object('n', g, 'note', repeat('x', 40)),
    'corr-' || g,
    CASE
        WHEN g <= :n * 90 / 100 THEN 'published'
        WHEN g <= :n * 94 / 100 THEN 'dead_lettered'
        ELSE 'pending'
    END,
    CASE
        WHEN g <= :n * 90 / 100 THEN 1
        WHEN g <= :n * 94 / 100 THEN 5
        WHEN g <= :n * 96 / 100 THEN 0
        WHEN g <= :n * 98 / 100 THEN 1
        ELSE 2
    END,
    CASE
        WHEN g <= :n * 94 / 100 THEN now() - interval '2 days'
        WHEN g <= :n * 96 / 100 THEN now() - interval '1 minute'
        WHEN g <= :n * 97 / 100 THEN now() + interval '1 day'
        WHEN g <= :n * 98 / 100 THEN now() - interval '10 minutes'
        ELSE now() + interval '1 hour'
    END,
    CASE
        WHEN g > :n * 90 / 100 AND g <= :n * 94 / 100 THEN 'd4r seed: attempts exhausted'
        WHEN g > :n * 98 / 100 THEN 'd4r seed: retry'
    END,
    CASE WHEN g <= :n * 90 / 100 THEN now() - interval '2 days' END,
    CASE WHEN g > :n * 96 / 100 AND g <= :n * 98 / 100 THEN gen_random_uuid() END,
    now() - interval '3 days',
    now() - interval '2 days'
FROM generate_series(1, :n) AS g;
COMMIT;
VACUUM (ANALYZE) core.outbox_events;
CHECKPOINT;
SELECT now() AS seed_finished,
       count(*) AS events,
       pg_size_pretty(pg_relation_size('core.outbox_events')) AS heap,
       pg_size_pretty(pg_total_relation_size('core.outbox_events')) AS total
FROM core.outbox_events;
SELECT status, claim_token IS NOT NULL AS claimed,
       CASE WHEN status = 'pending' THEN next_attempt_at <= now() END AS due,
       count(*)
FROM core.outbox_events GROUP BY 1, 2, 3 ORDER BY 1, 2, 3;
