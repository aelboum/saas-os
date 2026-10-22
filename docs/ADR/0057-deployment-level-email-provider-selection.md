# ADR-0057: Deployment-level email provider selection

Status: Accepted (2026-10-22). The repository owner chose deployment-level provider selection (Option A) and approved four decisions on 2026-10-22: production worker egress stays a deployment responsibility (decision 1, option b); SMTP TLS is required in production by default, following ADR-0021 (decision 2); a fixed, built-in provider map (decision 3); and four SMTP hardening additions (decision 4). Implemented on branch `feat/email-provider-selection`; not merged.
Date: 2026-10-22
Supersedes / Superseded by: — (extends P1.12's `saas_os/core/email`; resolves finding F1 of `docs/architecture/PROVIDER-EXTENSIBILITY-REVIEW.md`)
Related: ADR-0007 (background jobs), ADR-0008 (billing provider pattern), ADR-0012 (secrets), ADR-0020 (logging redaction), ADR-0021 (transport encryption), ADR-0032/0033/0036 (outbox, dispatcher, consumer idempotency), ADR-0035 (webhook delivery off the event loop), ADR-0041 (optional dependencies).

## Context

- P1.12 shipped a transactional-email foundation in `saas_os/core/email`: the `EmailProvider` protocol, `SmtpEmailProvider` (stdlib `smtplib`, STARTTLS, bounded timeout, credentials through `SecretsProvider`), `FakeEmailProvider`, and `send_email(message, provider=None)`. The notification job's `"email"` channel (`saas_os/core/notifications`) sends through it, retried by the outbox dispatcher and dead-lettered by its existing policy.
- `send_email()`'s default was always SMTP, and the notification job never passed a provider, so platform notification mail could not use anything else (review finding F1, LOW). The sender address came from the SMTP configuration, so it required `SMTP_HOST` even for a provider that has no host.
- There was no development mail catcher in the Compose stack, and nothing stopped a development-style setting (plaintext SMTP) from being used in production.
- Other gaps found by the audit of 2026-10-22: only STARTTLS (no implicit TLS on port 465); every failure was retried until dead-lettered, including a 5xx refusal that a resend cannot fix; a connection lost after the message data was sent is ambiguous, and its retry sends a second copy with nothing to correlate the two; the blocking `smtplib` call ran on the worker's event loop.
- The reference production topology (`docker-compose.prod.yml`) puts the worker only on the `internal` network, which has no Internet route (`docs/DEPLOYMENT-ARCHITECTURE.md`). An external SMTP relay is not reachable from it as shipped.

## Options considered

1. **Deployment-level selection (chosen).** One provider per deployment, named by configuration, from a map SaaS-OS maintains. Mailpit for development; generic SMTP as the first production adapter.
2. **Thread a provider through the notification job** (F1's other option). Needs a product-supplied object at job time, i.e. a process-wide hook in a security-relevant place, which the provider review advised against.
3. **Per-tenant or database-managed provider configuration, or a dashboard.** Out of scope by owner decision: tenant-owned mail credentials, a new table and an administration surface, for no current need.

## Decision

### 1. Provider selection

- `EMAIL_PROVIDER` names the deployment's provider: `smtp` or `mailpit` (`saas_os/core/email/config.py::EMAIL_PROVIDER_NAMES`). Any other value is an `EmailConfigurationError` that lists the allowed names; it never falls back to another provider.
- **Unset keeps the pre-ADR-0057 behavior exactly**: SMTP when `SMTP_HOST` is set; otherwise email is not configured and fails at send time, never at startup.
- `saas_os/core/email/selection.py::get_email_provider()` constructs the provider from a fixed, read-only map (`MappingProxyType`). There is no plugin registry and no setter: a consuming product cannot replace the process-wide selection. `send_email(..., provider=...)` is unchanged; an explicit provider still wins and selection does not run.
- **Startup validation.** When `EMAIL_PROVIDER` is set, the worker calls `validate_email_configuration()` before touching the database: it constructs the provider (configuration, credentials, the production guards; no network call) and requires `EMAIL_DEFAULT_SENDER`. Any problem stops the worker with `worker_startup_failed` and the error's message (`EmailConfigurationError` never carries a secret). Unset, nothing is checked.

### 2. Sender

`EMAIL_DEFAULT_SENDER` is read on its own (`get_email_default_sender()`), not through the SMTP configuration. `EmailConfig.default_sender` remains for compatibility.

### 3. Mailpit, development only

- `MailpitEmailProvider` is a profile of the SMTP adapter: `MAILPIT_SMTP_HOST`/`MAILPIT_SMTP_PORT` (default `mailpit:1025`), plaintext, and **no credentials: `SMTP_USERNAME`/`SMTP_PASSWORD` are never read**. It never reads any `SMTP_*` setting, so production relay settings and the mail catcher cannot be swapped by a mistaken variable.
- Allowed only when `ENVIRONMENT` is exactly `development` or `test`. Production, an unset `ENVIRONMENT` and any other value are refused, **with no override**. The check runs both when the Mailpit configuration is resolved and when the provider is constructed.
- `docker-compose.yml` runs `axllent/mailpit:v1.31.3`. Its SMTP listener is reachable only inside the Compose network; its web UI, which shows every captured message, is published on `127.0.0.1:8025` only. Messages are held in memory, capped at 500. `docker-compose.prod.yml` has no Mailpit service; `tests/architecture/test_email_provider_topology.py` asserts all of this, and that no production-facing file selects it.

### 4. SMTP TLS

- `SMTP_TLS_MODE`: `starttls` (default), `implicit` (`smtplib.SMTP_SSL`, typically port 465) or `none`. `SMTP_USE_TLS=true/false` remains an alias for `starttls`/`none`; setting both with different meanings is an error.
- Both TLS modes use `ssl.create_default_context()`: certificate and hostname verification on. There is no setting that disables either. A server that does not offer STARTTLS fails the send; the adapter never continues in plaintext.
- **Production requires TLS by default** (ADR-0021's convention): with `ENVIRONMENT=production`, `SMTP_REQUIRE_TLS` defaults to true and `SMTP_TLS_MODE=none` is refused. `SMTP_REQUIRE_TLS=false` is the explicit operator override for a deliberately plaintext relay; `SMTP_REQUIRE_TLS=true` applies the requirement in any environment.

### 5. Delivery semantics

- **Retry ownership is unchanged.** The adapter raises once; the outbox dispatcher (and, for a directly queued job, `saas_os.infra.jobs`) retries and dead-letters.
- **Permanent failures.** `EmailProviderError` carries `permanent` and the numeric `reply_code` (never reply text). The SMTP adapter marks permanent only an SMTP 5xx refusing every recipient, the sender, or the message data. Everything else (4xx, authentication, connection, TLS, timeout, connection lost mid-conversation) stays transient. The notification job turns a permanent failure into `NotificationPermanentDispatchError`, a `PermanentEventError`, so the dispatcher dead-letters the event after one attempt instead of resending.
- **Message-ID.** Every message gets one: `EmailMessage.message_id` when the caller supplies it (validated as `<local@domain>`, no whitespace or control characters), otherwise `make_msgid()` on the sender's domain. The notification job derives it from the outbox event id, `<notification.{event_id}@{sender domain}>`, the same on every attempt, and the adapter returns it as `provider_message_id`.
- **At-least-once, never exactly-once.** The RE-5 completion fence still stops a resend once completion is recorded. If the worker dies after the relay accepted the message and before completion is recorded, or the connection drops after the data was sent, the retry sends again. The stable `Message-ID` lets receivers that deduplicate on it drop the copy; many do not. Delivery remains at-least-once.
- **Off the event loop.** The job handler runs the send with `asyncio.to_thread`, as ADR-0035 did for webhook DNS resolution. The ordering lifecycle check → send → record is unchanged (`tests/infra/jobs/test_typed_job_contexts_unit.py`).

### 6. Logging

`email_send_started`/`email_send_succeeded`/`email_send_failed` add `email_provider`, `duration_ms`, and on failure `permanent` and `smtp_reply_code`. Never the recipient, subject, body, credentials or server reply text (ADR-0020); tests check structured fields as well as messages.

### 7. Production egress (owner decision 1, option b)

The reference production topology is unchanged: the worker stays on the `internal` network without an Internet route. **As shipped, it cannot reach an external SMTP relay.** A deployment must provide the outbound connectivity its configured provider needs (for example its own network attachment, a relay reachable on the internal network, or an egress proxy). This is recorded as an open limitation (G9) in `docs/P-ROADMAP.md`; webhook delivery, which also runs in the worker, appears to be affected the same way and is tracked by a separate investigation. Webhook networking is not changed here.

### 8. Adding a provider

A new provider is a SaaS-OS change, not a plugin:

1. Implement `EmailProvider` in its own module under `saas_os/core/email`, raising `EmailProviderError` (with `permanent` where the provider says a resend cannot succeed) and never a raw SDK exception.
2. Put any vendor SDK behind an optional extra (ADR-0041); an HTTP adapter may use the existing `httpx` dependency and `saas_os.infra.egress`.
3. Read credentials only through `SecretsProvider`; add any production guard the provider needs.
4. Add its name to `EMAIL_PROVIDER_NAMES` and its factory to `selection._PROVIDER_FACTORIES` (an import-time check keeps the two equal).
5. Add configuration, failure-classification, redaction and selection tests like the SMTP adapter's; document its variables in `.env.example`.

## Compatibility

- A deployment that sets only `SMTP_*` and no `EMAIL_PROVIDER` selects SMTP as before; its notification mail is unchanged apart from the added `Message-ID` header and the dead-lettering of permanent refusals.
- **Breaking for one case:** a production deployment (`ENVIRONMENT=production`) with `SMTP_USE_TLS=false` now fails when email is used (at send time, or at worker start if `EMAIL_PROVIDER` is set) until it either enables TLS or sets `SMTP_REQUIRE_TLS=false`.
- Public API additions only: `EmailMessage.message_id`, `EmailProviderError.permanent`/`reason`/`reply_code`, `EmailConfig.tls_mode`/`require_tls`, `MailpitEmailProvider`, `MailpitConfig`, `get_email_provider()`, `validate_email_configuration()`, `get_email_default_sender()`, `get_email_provider_name()`, `NotificationPermanentDispatchError`. `EmailConfig.use_tls` keeps its meaning and is always a `bool` after construction. `SmtpEmailProvider(config=...)` gains a keyword-only `authenticate` argument whose default keeps the old behavior. No migration, no new dependency.

## What Would Be Difficult to Change Later

- The variable names `EMAIL_PROVIDER`, `SMTP_TLS_MODE`, `SMTP_REQUIRE_TLS`, `MAILPIT_SMTP_*` become part of every deployment's configuration.
- The `Message-ID` format for notifications: receivers that deduplicate rely on it being stable per event.
- Classifying a failure as permanent dead-letters mail without a retry; widening that classification later drops mail that a retry would have delivered.

## Validation

Unit: `tests/core/email/test_email_provider_selection_unit.py`, `test_smtp_provider_unit.py`, `test_email_service_unit.py`, `tests/core/notifications/test_email_channel_unit.py`, `tests/api/test_worker_unit.py`, `tests/infra/jobs/test_typed_job_contexts_unit.py`. Architecture: `tests/architecture/test_email_provider_topology.py`, `test_ci_hermeticity.py`. Integration (PostgreSQL, Redis): `tests/api/test_outbox_consumer_idempotency_integration.py` (stable `Message-ID` across an at-least-once resend; permanent refusal dead-lettered after one attempt; transient failure left pending), `tests/core/notifications/test_email_channel_integration.py`. Gate results and negative controls are in the implementation report.

## Residual limitations

- G9 (section 7): the reference production topology has no route to an external relay.
- A deployment that points `SMTP_HOST` at a Mailpit instance with TLS enabled and a valid certificate is not detected; the guards stop the documented paths (`EMAIL_PROVIDER=mailpit`, plaintext SMTP in production), not a deliberate misconfiguration.
- A partial recipient refusal (some recipients accepted) is reported as accepted; the notification channel sends to one recipient, so it does not arise there.
- Configuration errors at send time stay transient (an operator can fix them and the retry succeeds); with `EMAIL_PROVIDER` set they are caught at worker start instead.
