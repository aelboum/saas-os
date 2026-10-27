"""ADR-0059 (owner decision of 2026-10-27): the shipped resolver configuration
(`deploy/egress-dns/unbound.conf`) answers only the worker's DNS network,
validates DNSSEC, logs no query and filters no answer (the application must
see every address to refuse a mixed answer set)."""

from __future__ import annotations

from pathlib import Path

CONFIG = Path(__file__).resolve().parents[2] / "deploy" / "egress-dns" / "unbound.conf"
_SETTINGS = [
    line.strip()
    for line in CONFIG.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.strip().startswith("#")
]


def _values(name: str) -> list[str]:
    prefix = f"{name}:"
    return [line[len(prefix) :].strip() for line in _SETTINGS if line.startswith(prefix)]


def test_only_the_worker_dns_network_and_loopback_are_answered() -> None:
    assert _values("access-control") == [
        "0.0.0.0/0 refuse",
        "::/0 refuse",
        "127.0.0.0/8 allow",
        "172.31.53.0/28 allow",  # `worker-dns` in docker-compose.prod.yml
    ]


def test_dnssec_is_validated_and_failures_are_not_softened() -> None:
    assert _values("auto-trust-anchor-file") == ['"/etc/unbound/root.key"']
    assert _values("val-permissive-mode") == ["no"]
    assert _values("harden-dnssec-stripped") == ["yes"]
    assert _values("harden-algo-downgrade") == ["yes"]


def test_no_query_reply_or_failure_is_logged() -> None:
    assert _values("verbosity") == ["0"]
    for name in ("log-queries", "log-replies", "log-servfail", "log-local-actions", "use-syslog"):
        assert _values(name) == ["no"], name


def test_answers_are_not_filtered_so_the_application_sees_the_whole_set() -> None:
    for name in ("private-address", "private-domain", "do-not-query-address"):
        assert _values(name) == [], name


def test_the_only_local_answer_is_the_health_check() -> None:
    assert _values("local-zone") == ['"resolver.check." static']
    assert _values("local-data") == ['"health.resolver.check. A 127.0.0.1"']
    assert _values("control-enable") == ["no"]
