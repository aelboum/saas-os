"""R1 security hardening of webhook delivery and verification (ledger rows
F1, F2 and F4, `docs/architecture/UNIVERSAL_PLATFORM_ASSESSMENT.md`
section 6.2, 2026-11-01).

- F1: a delivery through the egress proxy trusts certifi only, never a
  store named by `SSL_CERT_FILE` or `SSL_CERT_DIR` (ADR-0035 amendment of
  2026-10-18). Before the fix, the proxied path built its TLS context with
  `httpx.create_ssl_context()` and its default `trust_env=True`.
- F2: `verify_webhook_signature()` refuses a non-ASCII or non-text signature
  with `WebhookSignatureInvalidError` instead of raising `TypeError` from
  `hmac.compare_digest`.
- F4: delivery refuses to run on an HTTP stack outside the tested range,
  through the same `require_supported_http_stack()` the strict egress client
  calls, before anything is resolved or sent.

No database or real network: a local TLS server and a local fake `CONNECT`
proxy (`tests/support/egress_support.py`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
import ssl
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

import certifi
import httpcore
import httpx
import pytest

from egress_support import (
    PUBLIC_V4,
    Certificates,
    FakeConnectProxy,
    LocalServer,
    client_context,
    issue_certificates,
    read_request,
    server_context,
)
from saas_os.core.webhooks import service as webhooks_service
from saas_os.core.webhooks.errors import WebhookDeliveryError, WebhookSignatureInvalidError
from saas_os.core.webhooks.service import compute_signed_envelope, verify_webhook_signature
from saas_os.infra.egress import Deadline, EgressConfigurationError
from saas_os.infra.egress import compat as egress_compat

HOSTNAME = "hooks.example.test"
SUBSCRIPTION = uuid.UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --- F1: proxied deliveries trust certifi only ---------------------------


def _tls_server(certs: Certificates, tmp_path: Path) -> LocalServer:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await read_request(holder[0], reader)
        writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
        await writer.drain()

    holder: list[LocalServer] = []
    server = LocalServer(handler, ssl_context=server_context(certs, tmp_path, []))
    holder.append(server)
    return server


async def _deliver_through(proxy: object) -> int:
    return await webhooks_service._post_to_validated_addresses(  # pyright: ignore[reportPrivateUsage]
        SUBSCRIPTION,
        f"https://{HOSTNAME}/hook?token=QUERY-TOKEN",
        [ipaddress.ip_address(PUBLIC_V4)],
        b"{}",
        {"X-Webhook-Signature": "sha256=fake"},
        Deadline.after(10),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("variable", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
async def test_a_proxied_delivery_ignores_a_trust_store_from_the_environment(
    variable: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The receiver's certificate is issued by a private CA that only the
    environment trusts. The delivery must refuse it: nothing reaches the
    receiver. Fails before the fix (the delivery returned 204)."""
    certs = issue_certificates(HOSTNAME)
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    ca_file = ca_dir / "private-ca.pem"
    ca_file.write_bytes(certs.ca_pem)
    if variable == "SSL_CERT_DIR":
        # OpenSSL looks a CA up by its subject hash in a directory; the
        # hashed name is what `c_rehash` would create.
        subject_hash = _subject_hash(certs.ca_pem, tmp_path)
        (ca_dir / f"{subject_hash}.0").write_bytes(certs.ca_pem)
        monkeypatch.setenv("SSL_CERT_DIR", str(ca_dir))
    else:
        monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))

    server = _tls_server(certs, tmp_path)
    async with server, FakeConnectProxy(relay_port=server.port) as fake:
        monkeypatch.setattr(webhooks_service, "get_egress_proxy", lambda: fake.proxy)
        with pytest.raises(WebhookDeliveryError) as excinfo:
            await _deliver_through(fake.proxy)

    assert server.heads == []
    assert "QUERY-TOKEN" not in str(excinfo.value) and HOSTNAME not in str(excinfo.value)


@pytest.mark.anyio
async def test_a_proxied_delivery_still_verifies_and_succeeds_with_a_trusted_receiver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive control: the same delivery succeeds when the delivery's own
    context trusts the receiver's CA (the test seam stands in for certifi)."""
    certs = issue_certificates(HOSTNAME)
    monkeypatch.setattr(
        webhooks_service, "_delivery_ssl_context", lambda: client_context(certs.ca_pem)
    )
    server = _tls_server(certs, tmp_path)
    async with server, FakeConnectProxy(relay_port=server.port) as fake:
        monkeypatch.setattr(webhooks_service, "get_egress_proxy", lambda: fake.proxy)
        status = await _deliver_through(fake.proxy)

    assert status == 204
    assert len(server.heads) == 1


def test_the_delivery_context_verifies_and_holds_exactly_certifis_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certs = issue_certificates(HOSTNAME)
    ca_file = tmp_path / "private-ca.pem"
    ca_file.write_bytes(certs.ca_pem)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))

    context = webhooks_service._delivery_ssl_context()  # pyright: ignore[reportPrivateUsage]

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    reference = ssl.create_default_context(cafile=certifi.where())
    assert context.cert_store_stats()["x509_ca"] == reference.cert_store_stats()["x509_ca"]


def _subject_hash(ca_pem: bytes, tmp_path: Path) -> str:
    """OpenSSL's subject-name hash of `ca_pem`, the file name `c_rehash`
    would give it in a CA directory. Computed by OpenSSL itself."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is needed to name a CA in an SSL_CERT_DIR")
    pem = tmp_path / "hash-input.pem"
    pem.write_bytes(ca_pem)
    result = subprocess.run(  # noqa: S603 -- fixed arguments, test-only
        [openssl, "x509", "-noout", "-subject_hash", "-in", str(pem)],
        capture_output=True,
        check=True,
        text=True,
    )
    return result.stdout.strip()


# --- F2: signature verification never raises TypeError ----------------------

_SECRET = "a-test-signing-secret"  # pragma: allowlist secret
_BODY = b'{"event_id":"abc","event_type":"test.event","data":{"x":1}}'
_NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
_TIMESTAMP = int(_NOW.timestamp())


def _valid_signature() -> str:
    return compute_signed_envelope(_SECRET, _BODY, _TIMESTAMP)


def test_a_valid_signature_still_verifies() -> None:
    verify_webhook_signature(_SECRET, _BODY, _TIMESTAMP, _valid_signature(), now=_NOW)


@pytest.mark.parametrize(
    "header",
    [
        "sha256=é" + "0" * 63,  # the reported case: non-ASCII
        _valid_signature()[:-1] + "é",  # valid prefix, one non-ASCII character
        "sha256=١" * 2,  # non-ASCII digits
        "\ud800",  # lone surrogate: not encodable at all
        "",  # empty
        "sha256=",  # prefix only
        _valid_signature()[:-1],  # one character short
        _valid_signature() + "0",  # one character long
        _valid_signature().upper(),  # case changed
        " " + _valid_signature(),  # surrounding whitespace
        "sha1=" + _valid_signature()[len("sha256=") :],  # other scheme
    ],
)
def test_a_malformed_or_non_ascii_signature_is_refused_cleanly(header: str) -> None:
    with pytest.raises(WebhookSignatureInvalidError) as excinfo:
        verify_webhook_signature(_SECRET, _BODY, _TIMESTAMP, header, now=_NOW)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


@pytest.mark.parametrize("header", [None, b"sha256=00", 12345])
def test_a_signature_that_is_not_text_is_refused_cleanly(header: object) -> None:
    with pytest.raises(WebhookSignatureInvalidError):
        verify_webhook_signature(_SECRET, _BODY, _TIMESTAMP, header, now=_NOW)  # type: ignore[arg-type]


def test_a_non_ascii_signature_is_never_accepted_for_a_tampered_body() -> None:
    """No accidental acceptance: the right signature for another body, with
    a non-ASCII byte appended, is still refused."""
    other = compute_signed_envelope(_SECRET, b"{}", _TIMESTAMP)
    with pytest.raises(WebhookSignatureInvalidError):
        verify_webhook_signature(_SECRET, _BODY, _TIMESTAMP, other + "é", now=_NOW)


# --- F4: one supported-stack check on both egress paths ---------------------


def test_delivery_uses_the_strict_clients_own_stack_check() -> None:
    """One function, not a copy: the check cannot drift between the paths."""
    assert webhooks_service.require_supported_http_stack is (
        egress_compat.require_supported_http_stack
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("module", "version", "reason"),
    [
        (httpx, "0.27.2", "unsupported_httpx_version"),
        (httpx, "0.29.0", "unsupported_httpx_version"),
        (httpcore, "1.0.8", "unsupported_httpcore_version"),
        (httpcore, "2.0.0", "unsupported_httpcore_version"),
    ],
)
async def test_an_unsupported_http_stack_refuses_delivery_before_resolution(
    module: object, version: str, reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved: list[str] = []
    monkeypatch.setattr(module, "__version__", version)
    monkeypatch.setattr(
        webhooks_service, "_validate_destination_addresses", lambda url: resolved.append(url)
    )

    with pytest.raises(EgressConfigurationError) as excinfo:
        await webhooks_service._send_signed(  # pyright: ignore[reportPrivateUsage]
            SUBSCRIPTION, "https://hooks.example.test/x?token=QUERY-TOKEN", "secret", b"{}"
        )

    assert excinfo.value.reason == reason
    assert "QUERY-TOKEN" not in str(excinfo.value)
    assert resolved == []


@pytest.mark.anyio
async def test_a_supported_http_stack_lets_delivery_proceed_to_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Stop(Exception):
        pass

    def stop(url: str) -> list[ipaddress.IPv4Address]:
        raise _Stop

    monkeypatch.setattr(webhooks_service, "_validate_destination_addresses", stop)
    with pytest.raises(_Stop):
        await webhooks_service._send_signed(  # pyright: ignore[reportPrivateUsage]
            SUBSCRIPTION, "https://hooks.example.test/x", "secret", b"{}"
        )


# --- F7: a legacy plaintext signing secret is visible, not silent ------------

_TENANT = uuid.UUID("00000000-0000-4000-8000-0000000000f7")
_LEGACY_SECRET = "legacy-plaintext-signing-value-0123456789"  # pragma: allowlist secret


def test_a_legacy_plaintext_secret_still_works_and_is_logged_without_its_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=webhooks_service.logger.name):
        secret = webhooks_service._decrypt_signing_secret(  # pyright: ignore[reportPrivateUsage]
            _TENANT, _LEGACY_SECRET, subscription_id=SUBSCRIPTION
        )

    assert secret == _LEGACY_SECRET  # backward compatible: nothing invalidated
    records = [
        r for r in caplog.records if r.getMessage() == "webhook_signing_secret_legacy_plaintext"
    ]
    assert len(records) == 1
    assert records[0].tenant_id == str(_TENANT)  # type: ignore[attr-defined]
    assert records[0].webhook_subscription_id == str(SUBSCRIPTION)  # type: ignore[attr-defined]
    for record in caplog.records:
        assert _LEGACY_SECRET not in record.getMessage()
        assert _LEGACY_SECRET not in repr(record.__dict__)


def test_an_encrypted_secret_is_decrypted_and_not_reported_as_legacy(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    decrypted: list[tuple[str, bytes]] = []

    class _FakeEncryptionService:
        def decrypt_str(self, value: str, *, associated_data: bytes) -> str:
            decrypted.append((value, associated_data))
            return "decrypted-value"

    monkeypatch.setattr(webhooks_service, "EncryptionService", _FakeEncryptionService)
    with caplog.at_level(logging.WARNING, logger=webhooks_service.logger.name):
        secret = webhooks_service._decrypt_signing_secret(  # pyright: ignore[reportPrivateUsage]
            _TENANT, "efv1:opaque-envelope", subscription_id=SUBSCRIPTION
        )

    assert secret == "decrypted-value"  # pragma: allowlist secret
    assert decrypted == [
        ("efv1:opaque-envelope", f"webhook_signing_secret:{_TENANT}".encode("ascii"))
    ]
    assert not any(
        r.getMessage() == "webhook_signing_secret_legacy_plaintext" for r in caplog.records
    )
