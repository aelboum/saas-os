"""PRIV-03 Phase P10 (privacy re-audit RA-06): `infra.jobs` registers every
job with `keep_result=0` and builds every worker with `keep_result=0`, so
arq never writes an `arq:result:<job_id>` record (the pickled call --
payload included). Pinned here at the configuration level, the same way
`test_queue_retry.py` pins `max_tries`; the end-to-end absence of the key
is proven against a real Redis in `test_result_retention_integration.py`.
"""

from __future__ import annotations

from infra.jobs.config import JobsConfig
from infra.jobs.queue import build_worker, register_job

_CONFIG = JobsConfig(redis_url="redis://localhost:6379/0", max_tries=3)


async def _handler(payload: object) -> str:
    return "ok"


def test_register_job_disables_result_retention_on_the_function() -> None:
    registered = register_job(_handler, config=_CONFIG)
    assert registered.keep_result_s == 0
    assert registered.keep_result_forever is None  # never overrides the worker's False
    assert registered.max_tries == _CONFIG.max_tries  # unchanged retry policy


def test_build_worker_disables_result_retention_process_wide() -> None:
    worker = build_worker([register_job(_handler, config=_CONFIG)], config=_CONFIG)
    assert worker.keep_result_s == 0
    assert worker.keep_result_forever is False
