# Consumer guide — building a product on SaaS OS

How an independent product, in its own repository, integrates SaaS OS. The decisions behind this guide are ADR-0015 (distribution), ADR-0016 (migrations), ADR-0017 (application boundary) and ADR-0039 (scaffold). The worked example is `examples/consumer-scaffold/`.

Every Python sample below that is preceded by a `source:` marker is copied from the scaffold, and `tests/test_consumer_scaffold_unit.py` fails if it drifts from the file it names. The scaffold itself is exercised end to end by `tests/test_consumer_scaffold_integration.py`: installed wheel, real PostgreSQL, real Redis, run from outside this repository.

## 1. What you get and what you own

| SaaS OS provides (installed package) | Your product owns (your repository) |
|---|---|
| Tenancy, identity and sessions, RBAC, API keys, feature flags, webhooks, notifications, billing, usage, audit log | Every business table, route and job |
| The ingress chain: authentication → tenant resolution → rate limiting → authorization | The application entrypoint and its composition |
| The database chokepoint (`saas_os.infra.db`), tenant-scoped sessions, the RLS helper | Its own schema, migrations and grants |
| The job runner and the production worker entrypoint | Its own worker module and job handlers |
| Health routes and OIDC auth routes | Its own database, deployment, secrets and frontend |

SaaS OS never imports your product. The only dependency direction is `product → saas-os`.

Two limits to know before you start:

- **SaaS OS mounts almost no HTTP API by default.** `build_platform_app()` serves health and OIDC auth only. Membership, invitations, a member's own API keys, billing subscriptions and usage reports are available as **opt-in routers** you register yourself (section 9, ADR-0040). Accepting an invitation is a separate opt-in router, `invitation_acceptance_router` (ADR-0046). Receiving billing-provider events is an opt-in router too, `build_stripe_billing_events_router()` (ADR-0048). Tenant lifecycle, webhook subscriptions, feature-flag administration and usage ingestion have no platform route: your product writes those on top of the Core functions, or they stay operator commands.
- **There is no reusable frontend, by decision.** The frontend is product-owned, in any technology (ADR-0042).

## 2. The import root

The installed `saas-os` distribution owns exactly one top-level import name:

```
saas_os
```

Everything is imported from under it: `saas_os.api`, `saas_os.core`, `saas_os.infra`, `saas_os.contracts`, `saas_os.control_plane` (ADR-0038). **Do not name a top-level package or module of your project `saas_os`.**

Before ADR-0038 the distribution owned five generic names (`api`, `core`, `infra`, `contracts`, `control_plane`), and a project directory called `api/` silently shadowed the platform's. That hazard is gone: your project may have its own `api/` or `core/` package. Naming your package after your product (`my_product`) is still the simplest layout.

A commit from before ADR-0038 does not have the `saas_os` root. If your pin predates it, the imports in this guide do not exist at that commit.

## 3. Start from the scaffold

Copy `examples/consumer-scaffold/` into a new repository. From that moment every file is yours (ADR-0015 rule 10); SaaS OS does not track it.

1. Rename the `my_product` directory and every `my_product` reference to your product's name. The same string is the package name, the database schema, the permission prefix and the job-name prefix; keep them identical.
2. Rename the project in `pyproject.toml`.
3. Install: `pip install -e .` The scaffold depends on plain `saas-os`. Add an extra to the dependency only for an integration you use: `saas-os[stripe]` for the Stripe billing adapter, `saas-os[s3-backup]` for the S3-compatible backup destination, `saas-os[all]` for both (ADR-0041). Without the extra, the adapter raises an `ImportError` that names it; with `STRIPE_API_KEY` set and no `saas-os[stripe]`, the API and the worker refuse to start with that error.

The scaffold's layout:

```
my_product/
  app.py           application entrypoint        (uvicorn my_product.app:app)
  routes.py        HTTP routes
  permissions.py   the permissions the product declares
  models.py        tables
  items.py         data access, always tenant-scoped
  jobs.py          background job handlers
  worker.py        worker entrypoint             (python -m my_product.worker)
  purge.py         what happens to product data on tenant purge
  migrate.py       all migrations, in order      (python -m my_product.migrate)
  migrations/      the product's own Alembic history
```

### The dependency pin

Exactly one dependency on SaaS OS, pinned to an exact 40-character commit SHA — never a branch or a tag (ADR-0015 rule 8):

```toml
dependencies = [
    "saas-os @ git+https://github.com/aelboum/saas-os@<40-character commit SHA>",
]
```

**Releases.** A SaaS OS release is a version number in `pyproject.toml`, an annotated tag `v<version>` on a commit of `main`, and an entry in `CHANGELOG.md` that names the commit's full SHA (ADR-0015, "Release labels"). The tag is a name for people; the pin is still the commit SHA the tag points to. Before pinning a release, check that the tag still resolves to the SHA in `CHANGELOG.md` (`git ls-remote https://github.com/aelboum/saas-os refs/tags/v<version>^{}`); a tag that has moved is an incident, not a new release. The newest entry names its release pull request instead of a SHA until the next release records it (ADR-0015, "One pull request per release"); until then, check that the tag resolves to that pull request's merge commit. The example pins in this repository name the previous release. From v0.2.0, the Release workflow gives each tag a GitHub Release showing its changelog entry, full SHA and CI evidence (`docs/RELEASING.md`). v0.1.2 has a GitHub Release made by hand, with GitHub's generated notes; for it, `CHANGELOG.md` and the tag are the record. It is a page, not a package: you still install from the pinned SHA, and nothing is published to PyPI.

**The scaffold's pin.** It names `b03d87a`, `main` after pull request #101, released as v0.5.0 (`CHANGELOG.md`); before it, `a313c59`, `main` after pull request #93, released as v0.4.1, `77c9a22`, `main` after pull request #90, released as v0.4.0, `5905156`, `main` after pull request #86, released as v0.3.0, `8e053be`, `main` after pull request #79, released as v0.2.0, `b0809ee`, `main` after pull request #71, released as v0.1.2, `c7d8987`, `main` after pull request #65, released as v0.1.1, and `dab6357`, `main` after pull request #61, released as v0.1.0. Since `4197d2f`, the pin before those, it adds audit digests (ADR-0053), audit rows for the payment page, and governed AI inference (ADR-0054 to ADR-0056); section 14 lists what a product on `4197d2f` must do to move. `4197d2f` was `main` after pull request #43 and the first published commit with everything the rest of this guide relies on, including the payment page for a subscription (ADR-0052), Stripe subscriptions for a payer without a payment method (pending until paid) whose renewals are charged to the card that paid, billing-provider events (ADR-0048), multi-factor login for platform operators (ADR-0049), the `saas-os-operator` commands (ADR-0050), API-key request authentication on routes that opt in (ADR-0047) and the invitation acceptance router (ADR-0046): the `saas_os` import root (ADR-0038), the worker's `extra_functions` seam (ADR-0039), the optional extras (ADR-0041), and ADR-0045's platform authority -- the required `caller` on tenant lifecycle, purge and feature-flag functions, the opt-in platform-admin router, and the rule that only a user someone can log in as is enrolled as an operator. Do not pin anything older: code written against this guide does not run on it. CI proves the scaffold against a wheel built from the SaaS OS working tree (`tests/test_consumer_scaffold_integration.py`); a clean install of the pinned commit is a recorded manual proof.

Move the pin with `saas-os-update` (`docs/AUTO-UPDATE-CLI.md`). It classifies what changed between the two commits and applies only changes its policy marks safe; migrations, authorization, tenancy, billing and anything unknown require your review.

## 4. Configuration

Configuration is environment variables. Secrets and connection strings (`DATABASE_URL`, `MIGRATIONS_DATABASE_URL`, `REDIS_URL`, OIDC, Stripe, SMTP, `RESEND_API_KEY`) are resolved through SaaS OS's secrets provider: a `.env` file when `ENVIRONMENT=development`, the process environment otherwise. Non-secret tunables such as `APP_DB_USER` and `JOBS_MAX_TRIES` are read from the process environment directly, in every environment, so a value present only in `.env` is ignored for them. The minimum for the application and the worker:

| Variable | Used by | Notes |
|---|---|---|
| `ENVIRONMENT` | everything | `development`, `test` or `production`. Required; there is no default. |
| `DATABASE_URL` | application, worker, and the permission-registration step of `python -m my_product.migrate` | The **restricted application role**. |
| `MIGRATIONS_DATABASE_URL` | the two migration steps of `python -m my_product.migrate` | The **privileged migration role**. Never given to the application or the worker. |
| `APP_DB_USER` | migrations | Name of the application role, for grants. Default `saas_os_app`. |
| `PLATFORM_CONFIG_DB_USER` | migrations | Name of the platform-configuration role (section 5). Default `saas_os_platform_config`. |
| `PLATFORM_CONFIG_DATABASE_URL` | only `saas-os-operator ai-*` commands that change AI configuration | The **platform-configuration role**. Never given to the application or the worker: both refuse to start if they see it (ADR-0056). |
| `REDIS_URL` | application (rate limiting), worker (queue) | |
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID` | auth routes | Any OIDC issuer. See `docs/LOCAL-IDENTITY.md` for a local one. |
| `PUBLIC_APP_ORIGIN` | auth routes | The one browser-visible origin. See `docs/SINGLE-ORIGIN-RUNTIME.md`. |
| `WEBHOOK_ALLOWED_PORTS` | webhook subscription and delivery | Optional, for example `443`. Unset, any port on a public address is allowed. Set, a webhook URL must use a listed port (443 for `https` and 80 for `http` when it names none); existing subscriptions on other ports are dead-lettered at their next delivery. An empty or invalid value is a configuration error (ADR-0035, amendment of 2026-10-19). |
| `EMAIL_PROVIDER` | notification email, `send_email()` without `provider=`; worker startup | `smtp`, `mailpit` (ADR-0057) or `resend` (ADR-0058). Unset: SMTP when `SMTP_HOST` is set, as before. Set: the worker validates the email configuration at startup and refuses to start if it is invalid (no network call). `mailpit` is development-only: refused unless `ENVIRONMENT` is `development` or `test`, with no override. There is no way to register another provider from a product; a product that sends its own mail through another service passes `provider=` to `send_email()`. |
| `EMAIL_DEFAULT_SENDER` | notification email | The `From:` address, for every provider. Required when `EMAIL_PROVIDER` is set. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS_MODE`, `SMTP_REQUIRE_TLS` | the SMTP provider | Credentials `SMTP_USERNAME` and `SMTP_PASSWORD` come from the secrets provider, both or neither. `SMTP_TLS_MODE` is `starttls` (default), `implicit` (port 465) or `none`; `SMTP_USE_TLS=true/false` is still accepted for `starttls`/`none`. Certificates are always verified. In production `none` is refused unless `SMTP_REQUIRE_TLS=false`. The worker must be able to reach `SMTP_HOST`: the reference `docker-compose.prod.yml` gives it no Internet route, so your deployment provides that connectivity (ADR-0057, section 7). |
| `MAILPIT_SMTP_HOST`, `MAILPIT_SMTP_PORT` | the Mailpit provider (development) | Default `mailpit` and `1025`, the service in SaaS OS's `docker-compose.yml`. Mailpit reads no `SMTP_*` value and no credential. |
| `OUTBOX_RETRY_HINT_MAX_SECONDS` | the outbox dispatcher (worker) | Optional. The longest delay a consumer's `RetryAfterEventError` may ask for; a longer one is capped. Default `86400`; more than 0 and at most 31 days. |
| `OUTBOX_EXTERNAL_EFFECT_MARKERS` | the outbox dispatcher (worker) | Optional, `true` or `false` (also `1`/`0`); default `false`. Whether `TenantJobContext.external_effect()` commits a durable started marker before a consumer's external request, so that a crash after it is dead-lettered (`CrashAfterStart:`) instead of retried. Turn it on only after migrations `0420025c3b4b` and `f0cc2e656d79` and once no older dispatcher or worker can claim events; `docs/architecture/OUTBOX-STARTED-MARKER.md`. |
| `OUTBOX_LEASE_SECONDS` | the outbox dispatcher (worker) | Optional. How long a claim owns an event before another dispatcher may reclaim it. Default `900`; at least `360` (the outbox job's 300-second limit plus its time in the queue), or the worker refuses to start. |
| `API_KEY_MAX_PER_USER` | `create_api_key()` and the API-key create route | Optional. The most unrevoked user-owned API keys one user may hold, across every tenant. Default `50`; an integer from 1 to 100000, anything else is a configuration error and key creation fails. One more raises `ApiKeyLimitExceededError` (the route answers `409`). An expired key that was never revoked still counts; revoking it frees the slot. Rotation and service-account keys are not counted. Keys that exist above a newly lowered limit keep working. |
| `RESEND_API_KEY` | the Resend provider | Secret, from the secrets provider; read only when `EMAIL_PROVIDER=resend`. `EMAIL_TIMEOUT_SECONDS` bounds each request in total. See "Email through Resend" below. |

`.env.example` in the SaaS OS repository documents the deployment variables, including billing, email and backup. Its reference production topology splits them between `.env.app`, loaded into `backend` and `worker` only, and `.env`, which holds the identity provider's values and is loaded into no container (`.env.app.example`; ADR-0012 amendment of 2026-10-21). A few tunables are documented only where they are read (for example `OUTBOX_POLL_SECONDS`, `SECRETS_ENV_FILE`).

### Email through Resend

SaaS OS ships the Resend adapter; your product owns the Resend account, the API key, the sending domain and every message's content (ADR-0058).

1. In Resend, add your sending domain and publish the DNS records it shows (SPF and DKIM) until the domain is verified. Until then Resend refuses mail from it with `403`.
2. Create an API key with sending access and store it in your deployment's secret store as `RESEND_API_KEY`. Never put it in source control, a Compose file or an image.
3. Set `EMAIL_PROVIDER=resend` and `EMAIL_DEFAULT_SENDER` to an address on the verified domain, for example:

   ```
   EMAIL_PROVIDER=resend
   EMAIL_DEFAULT_SENDER=no-reply@mail.your-product.example
   EMAIL_TIMEOUT_SECONDS=10
   # RESEND_API_KEY comes from the secret store, never from this file
   ```

4. Start the worker. With `EMAIL_PROVIDER` set it checks the configuration first (no network call) and refuses to start without the key or the sender. Selecting Resend never falls back to SMTP.
5. Give the worker outbound HTTPS to `api.resend.com:443`: either through the egress proxy, by setting `EGRESS_PROXY_URL` on the worker (ADR-0059; the reference `docker-compose.prod.yml` does, and gives the worker no other Internet route), or directly. The adapter ignores `HTTP_PROXY`/`HTTPS_PROXY` and refuses a name that resolves to a private address.

What the results mean:

- A successful send means Resend accepted the request; the returned `provider_message_id` is Resend's email id. It does not mean the message reached an inbox. SaaS OS does not consume Resend's delivery webhooks.
- `400` and `422` are permanent: the notification event is dead-lettered after one attempt. So is `409 invalid_idempotent_request` (since 2026-11-01, reason `idempotency_payload_mismatch`): the key was already used with a different body. `401`, `403`, `409 concurrent_idempotent_requests`, `429` and failures before the request was sent (resolution, connection, TLS, proxy) are retried by the outbox's normal policy; a `429` waits at least as long as its `Retry-After` says (see below). A `5xx` is an unknown outcome since 2026-11-02 (next item): Resend may have processed a request it answered with an error.
- A send whose request may have reached Resend without a readable answer (a write or read timeout, the connection lost after the request was written, the deadline after the exchange started, an unreadable `2xx`, and since 2026-11-02 any `5xx`) has an **unknown outcome** (since 2026-11-01). It is never recorded as sent. It is retried, with the same `Idempotency-Key` and a byte-identical body, only while the retry is due within 23 hours of the event's creation, that is inside Resend's documented 24-hour idempotency period; after that it is dead-lettered with `last_error` starting `OutcomeUnknown:` for an operator to check Resend's dashboard and replay. From then on every later retry of that event, one deferred by a `429` included, must start within the same 23 hours, or it is dead-lettered instead of reaching Resend after the key has expired. A send without a key (a directly queued notification job with no outbox event) is dead-lettered at once: the job's own retry stops on an unknown outcome (since 2026-11-02; before, it could send up to twice more). A `429` keeps its hint because it reports a refused request; Resend does not document whether a refused request uses up its key, which matters only after an earlier attempt that may have been processed, and that attempt's 23-hour deadline already applies. The `email_send_failed` log line carries the HTTP status in `smtp_reply_code` and never Resend's message text. The `httpx` library also logs one `INFO` line per request (method, the URL with the resolved address, status), never headers or bodies.
- Each notification event sends the same `Idempotency-Key` on every attempt, so Resend does not send an identical retry again within 24 hours. Since 2026-11-01 the key is derived from the outbox event id alone (`EmailMessage.idempotency_key`, `notification.{event id}`), so it no longer changes when `EMAIL_DEFAULT_SENDER` moves to another domain; the `Message-ID` is still `<notification.{event id}@{sender domain}>`. The request body is serialised deterministically, so a retry with the same configuration is byte-identical. Delivery is still at-least-once:
  - a send replayed by an operator after 24 hours is a new request and can send a second copy;
  - a retry whose content changed under the same key (a new sender, in the same domain or another) is refused by Resend with `409 invalid_idempotent_request` and dead-lettered, never resent under another key. Change the sender only when no notification is pending, or replay the dead-lettered events after checking Resend.
- A `429` carries a retry hint to the outbox (since 2026-10-31): its `Retry-After` (seconds or an HTTP date), or, for `daily_quota_exceeded` and `monthly_quota_exceeded`, as long as `OUTBOX_RETRY_HINT_MAX_SECONDS` allows (default 86400, one day). The next attempt is never earlier than the normal backoff, and the attempt still counts, so a quota that stays exhausted for about nine days: ten attempts a day apart still dead-letters the notification. Raise the quota; what was dead-lettered meanwhile can be replayed by an operator.
- Not supported: attachments, CC/BCC, templates, scheduling, batch sending, tags and `EmailMessage.metadata`.

Development keeps `EMAIL_PROVIDER=mailpit` (`docker-compose.yml`); Resend sends real mail in every environment. SaaS OS's own tests never call Resend: they use a mock transport and a fake key.

### Email headers: unsubscribe and threading

`EmailMessage` has four optional, typed fields for `List-Unsubscribe`, `List-Unsubscribe-Post`, `In-Reply-To` and `References` (issue 224; ADR-0057 and ADR-0058 amendments of 2026-11-07). They work the same with SMTP, Mailpit and Resend. There is no way to set any other header, and `metadata` is still never sent.

```text
EmailMessage(
    sender=...,
    to=("person@example.com",),
    subject=...,
    text_body=...,
    message_id="<campaign-7.person-42@mail.your-product.example>",
    list_unsubscribe=("https://app.your-product.example/u/9f3c...",),  # no angle brackets
    list_unsubscribe_post=True,  # one-click
    in_reply_to=("<parent@mail.example>",),  # angle brackets included
    references=("<root@mail.example>", "<parent@mail.example>"),
)
```

| Field | Type | Rules (a failure raises `InvalidEmailHeaderError` before any provider call) |
| --- | --- | --- |
| `list_unsubscribe` | `tuple[str, ...]` | At most one `https://` URI and at most one plain `mailto:address` URI, in the order you give. You give the URI without `<` `>`; SaaS OS adds them. Printable ASCII, no space, none of `< > " \ ,` (percent-encode a comma); lower-case scheme; no userinfo; no query on `mailto:`; at most 2048 characters, and short enough for one header line of 998 characters. **The message must have exactly one recipient**: the URI identifies one person. |
| `list_unsubscribe_post` | `bool` | `True` emits `List-Unsubscribe-Post: List-Unsubscribe=One-Click`, the only value that can be sent. Refused unless `list_unsubscribe` has an `https` URI. |
| `in_reply_to`, `references` | `tuple[str, ...]` | Each item a strict `<id@host>` message id (ASCII, no comments), no duplicates, at most 20 per field. |

`InvalidEmailHeaderError` is a subclass of `InvalidEmailAddressError` (existing `except` clauses still catch it). Its message names the rule and never contains the value. Lists are refused where a tuple is required. CR, LF, NUL and every other control character are refused everywhere, in `send_email()` and again in both adapters, so a direct `provider.send()` call cannot inject a header either.

What to do and what this does not do:

- **The values must be a function of the logical message.** Derive the unsubscribe URI from the recipient and the campaign, never with a fresh random part per attempt. Resend sends the headers in the request body, which it compares under the `Idempotency-Key`: a retry with a different value is refused with `409` and dead-lettered (permanent). SMTP has no de-duplication; a retry can deliver twice, as before.
- **The URI is a capability.** It identifies the recipient and the list. Do not log it, put it in audit metadata or use the recipient's plain address in it. `repr(EmailMessage)` leaves these four fields out for that reason; do not log the message object's fields yourself.
- **SaaS OS checks syntax, not meaning.** It cannot know that a message id exists or belongs to the same conversation or tenant, or that your endpoint works. Your product serves the unsubscribe endpoint (it must accept the one-click `POST`, verify the opaque token, not redirect), keeps the suppression list and owns consent.
- **No compliance claim.** The headers are well formed. RFC 8058 also requires a DKIM signature that covers `List-Unsubscribe` and `List-Unsubscribe-Post`; the relay or Resend applies it after SaaS OS hands the message over, and SaaS OS cannot sign or check it. Whether your relay or Resend covers those headers, and how receivers (Gmail, Yahoo, others) treat the message, is not verified by SaaS OS: check a received message's raw headers in staging. Deliverability is not guaranteed.
- **On the wire.** SMTP writes the URI verbatim on the header line (the standard library would otherwise rewrite a URI of about 50 characters or more as an RFC 2047 encoded word) and folds only between URIs or ids. Resend receives them in its `headers` object beside `Message-ID`. Resend's own handling of these headers has not been verified.
- `metadata` and the `Message-ID` rules are unchanged.

### Reading from a provider with `StrictEgressClient.get`

`saas_os.infra.egress.StrictEgressClient` has two public methods that send a request: `post(url, *, headers, content, deadline)` and `get(url, *, headers, deadline)` (issue 205, first step). `get` sends a `GET` with no body and has exactly `post`'s policy: `https` only, the allowed ports, no user information, public addresses only with the connection pinned to the validated address, no redirect followed (any `3xx` is `EgressRedirectError`), a response with a `Content-Encoding` is refused, the response is capped, one total deadline, and errors that carry a reason, a phase and `request_may_have_been_sent` but never the URL. A caller-supplied `Host`, `Content-Length` or `Transfer-Encoding` header is refused. Through the egress proxy (ADR-0059) a `GET` is the same tunnel as a `POST`; the proxy never sees the method. There is no `delete`, no method that takes a verb, and no host allowlist: the client reaches any public HTTPS host on an allowed port, so an adapter holding a credential sends it only to a URL it builds from its own constant host.

What a caller must still do:

- **No automatic retry.** The client never repeats a request after it may have been sent. A `GET` has no effect at the provider, so the caller may repeat it after any failure; a `429` or other status is the caller's to classify.
- **The cap is per client.** `max_response_bytes` belongs to the `StrictEgressPolicy` the client was built with, and `get` has no per-call cap. The Resend provider's own client is capped at 64 KiB, sized for a send response, so a read adapter builds its own client with its own policy and its own limit. A response above the cap is `EgressResponseTooLargeError`, never truncated.
- **A response body is untrusted bytes.** The client parses nothing. An adapter decodes it (UTF-8, JSON), bounds its fields, rejects an unexpected shape with a fixed reason, and never logs or raises text from it. Content from a third party (for example an inbound e-mail) may carry HTML, links and script; rendering, sanitising and remote-content blocking are the product's.
- **Validate an identifier before it goes into a path.** The client checks the host, port and form of the URL, not its path. An identifier that an attacker can influence (a webhook field, a stored value) is matched against a strict, bounded pattern with no `/`, `?`, `#`, `%` or `.` before it is placed into a path. Never take a URL from a provider response and send your own credential to it.
- **Secrets go in headers.** Never in the query string.

Existing code needs no change: `post` is unchanged, and the AI adapters' `EgressClient` protocol still declares only `post`.

## 5. Database roles and grants

Two roles, with different jobs:

- The **migration role** owns the schema and runs DDL. It is used only by the migration step.
- The **application role** is what the running application and worker connect as. It must be `NOSUPERUSER NOBYPASSRLS`. SaaS OS checks this at startup, in the application and in the worker, and refuses to start under a role that can bypass Row-Level Security. There is no setting that disables the check.

Create the application role once per database, before the first migration:

```sql
CREATE ROLE saas_os_app LOGIN PASSWORD '...'
    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE my_database TO saas_os_app;
```

(`saas_os/infra/db/init/01-create-app-role.sh` in the SaaS OS repository does exactly this for a Compose-managed PostgreSQL.)

A third role, the **platform-configuration role** (ADR-0056), is the only one that may write the installation-wide AI configuration (`control_plane.ai_providers`, `ai_models`, `ai_aliases`, `ai_endpoint_trust`, `ai_destination_policy`, `ai_model_prices`). The application role can only read those tables, and the application and the worker refuse to start if it can write them. SaaS OS's migration creates the role `NOLOGIN` if it does not exist (the migration role then needs `CREATEROLE`; otherwise create it yourself first). To change AI configuration, give it a login and use its URL only for the command:

```sql
CREATE ROLE saas_os_platform_config NOLOGIN
    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;  -- if you create it yourself
ALTER ROLE saas_os_platform_config LOGIN PASSWORD '...';            -- to enable configuration changes
```

It must not be a member of the application role, nor the reverse; the migration refuses otherwise. Never put `PLATFORM_CONFIG_DATABASE_URL` or the role's password in the environment of the application or the worker. `docs/RUNBOOKS.md` ("AI configuration role") has the command form, rotation and revocation.

SaaS OS's own migrations grant the application role what it needs on SaaS OS's tables. **Your migrations must grant it what it needs on yours** — a table the application role has no grant on is unreadable, and the error appears only at runtime. Grant the four data privileges and nothing wider:

<!-- source: examples/consumer-scaffold/my_product/migrations/versions/0001_create_items_table.py -->
```python
    op.execute(f'GRANT USAGE ON SCHEMA {_SCHEMA} TO "{app_role}"')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {_SCHEMA}.items TO "{app_role}"')
```

Do not grant `ALL`, `TRUNCATE` or schema `CREATE` to the application role, and do not use `ALTER DEFAULT PRIVILEGES` to pre-grant future tables: a later table would become readable before anyone decided it should be, and before it has an RLS policy.

## 6. Migrations

Two independent Alembic histories share one database (ADR-0016):

| History | Version table | Applied by |
|---|---|---|
| SaaS OS's | `alembic_version_saas_os` | the installed package |
| Your product's | `alembic_version` | your own Alembic environment |

SaaS OS's history always runs first, because your tables reference `core.tenants`. Never point Alembic at a path inside `site-packages`; call the installed package. The scaffold does both, in order, in one step:

<!-- source: examples/consumer-scaffold/my_product/migrate.py -->
```python
def migrate() -> None:
    run_core_migrations()
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    command.upgrade(config, "head")
    register_permissions()
```

Run `python -m my_product.migrate` as a deployment step before the application and the worker start. It is safe to run again.

One database belongs to one product. Two products cannot share a database: both use the default `alembic_version` table.

## 7. Tenant-owned tables and RLS

Every table that holds tenant data follows one pattern:

1. it lives in the product's own schema, never in `core`;
2. it has a non-null `tenant_id` foreign key to `core.tenants.id`, indexed;
3. it has forced Row-Level Security, created with SaaS OS's own helper.

<!-- source: examples/consumer-scaffold/my_product/migrations/versions/0001_create_items_table.py -->
```python
    for statement in tenant_rls_statements("items", schema=_SCHEMA):
        op.execute(statement)
```

`tenant_rls_statements` emits the same policy SaaS OS's own tenant tables use. Do not hand-write a policy.

Models are declared on SaaS OS's shared base, with column types imported from `saas_os.infra.db`:

<!-- source: examples/consumer-scaffold/my_product/models.py -->
```python
class Item(Base):
    __tablename__ = "items"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.tenants.id"), nullable=False)
```

All data access goes through `saas_os.infra.db.tenant_session_scope(tenant_id)`, which binds the session to one tenant for RLS:

<!-- source: examples/consumer-scaffold/my_product/items.py -->
```python
def get_item(tenant_id: uuid.UUID, item_id: uuid.UUID) -> Item | None:
    """The tenant's item, or `None`. An item of another tenant and an item
    that does not exist are indistinguishable to the caller, by design."""
    with tenant_session_scope(tenant_id) as session:
        item = session.execute(
            select(Item).where(Item.id == item_id, Item.tenant_id == tenant_id)
        ).scalar_one_or_none()
```

Rules:

- **Product code outside `migrations/` does not import `sqlalchemy` or `psycopg`.** Everything needed is re-exported by `saas_os.infra.db`. This keeps every query on the path RLS is enforced on.
- **The `tenant_id` passed to `tenant_session_scope` must be verified** — taken from the request context, the job context or Core's purge call, never from a URL, a body or free-form job data.
- **Never build SQL text or an operator from data.** Row-level security is keyed on the session setting `app.tenant_id`, which any SQL your process runs can change, so it protects against a missing predicate, not against SQL text chosen at run time. Do not pass anything but a literal operator to `.op()` or `.bool_op()` (`@@`, `->>`, `||`; never one containing `--`, `/*` or `*/`), and do not use `Session.connection().exec_driver_sql()`, `literal_column()`, `column(..., is_literal=True)`, `text()`, `TextClause()` or `DDL()` in product code, under any import alias, nor pass `execute()` a string you formatted, directly or through a variable. An index predicate (`Index(..., postgresql_where=...)`) is SQL too: build it from column expressions, never from text built from input. `tests/architecture/test_raw_sql_guardrails.py` checks SaaS OS and its examples for these patterns (not `postgresql_where`, `getattr`, `custom_op` or `quoted_name(..., quote=False)`; its docstring lists what it misses). To check your repository, copy it and adapt its scanned roots, raw-SQL zones, migration path and coverage test to your layout; unadapted, it checks nothing of yours. It is a guardrail, not a complete security boundary: it reads source patterns with a deliberately simple, local data flow, and code running in your process can always reach the database another way.
- **Keep the explicit tenant predicate.** RLS is the guarantee; the predicate is defence in depth. The integration test proves the guarantee by running a query with no predicate and still seeing one tenant's rows.

## 8. Permissions

A permission is a `(resource, action)` pair in a catalog shared with Core. Prefix the resource with your product's name.

<!-- source: examples/consumer-scaffold/my_product/permissions.py -->
```python
ITEMS_RESOURCE = "my_product.items"
READ = "read"

PERMISSIONS: tuple[tuple[str, str], ...] = ((ITEMS_RESOURCE, READ),)


def register_permissions() -> None:
    for resource, action in PERMISSIONS:
        register_permission(resource, action)
```

Registration is idempotent, needs the database, and therefore runs in the migration step, not at import time. Registering grants nothing. A tenant's role receives a permission through `saas_os.core.rbac.grant_permission(...)`, a member receives the role, and `saas_os.core.rbac.can(...)` decides. Missing information is always a denial.

**New permissions for existing tenants (ADR 0060).** When a release adds a permission, tenants provisioned earlier do not have it, and nobody inside them can grant it (anti-amplification: a user grants only what they hold). Do not use `SystemCaller(SystemAuthority.PROVISIONING)` on existing tenants for this. Declare a permission grant migration instead: a module-level tuple `PERMISSION_GRANT_MIGRATIONS` of `saas_os.core.permission_grants.PermissionGrantMigration` entries, which each release appends to and never edits. One entry: `PermissionGrantMigration(id="2026-11-reports", namespace="my_product", role_name="admin", permissions=(("my_product.reports", "read"), ("my_product.reports", "export")), reason="Reports module, release 4.2")`. The `id` is stable, unique in the namespace and never reused; `role_name` is a role your provisioning creates.

After your migrations have run and registered the permissions, a platform operator holding `platform.permission_grant:apply` runs `saas-os-operator apply-permission-grants --module my_product.grants ...` (`docs/RUNBOOKS.md`, "Operator commands"), first without `--apply`. Per tenant, each migration is applied once and recorded in `core.permission_grant_applications`: a role that already holds a permission is left alone, a tenant without the role is recorded as `role_missing` (no role is created), and a permission a tenant administrator later revokes is never put back by a later run. A migration may only add registered permissions that do not change authority (`saas_os.core.rbac.is_authority_changing`): roles, grants, memberships, delegations, deny grants, service accounts, API keys, invitations, support access, webhooks, billing mutations and tenant suspension stay with the tenant's administrators. A suspended tenant receives the grant; its members can use it once it is reactivated. Editing a migration that was applied anywhere is refused: add a new one. The record of what was applied is kept when a tenant is purged (security history: ids, a digest, an outcome and counts; no names), by default for two years after the purge and longer under a legal hold that an independently authorised platform operator places (`docs/RUNBOOKS.md`); expired rows can be removed only by a manual, audited platform procedure, never by your product or a purge, and that procedure needs an authenticated approval by two independently enrolled people and is still disabled (enabling it is a separate owner decision), so rows are kept. Keep personal data and secrets out of migration ids and the namespace.

**Refusals.** When a Core operation that takes an explicit `caller` (`saas_os.core.authority`) finds that the caller lacks the authority it requires, it usually raises `saas_os.core.rbac.AuthorityNotAuthorizedError`, before any write. Some operations raise an operation-specific refusal instead (`RoleAssignmentNotAuthorizedError`, `DelegationNotAuthorizedError` and the others in `saas_os.core.rbac.__all__`), and platform operations raise `saas_os.core.platform_authority.PlatformNotAuthorizedError` (ADR-0045). Import `AuthorityNotAuthorizedError` from `saas_os.core.rbac`, not from `saas_os.core.rbac.errors`. Its stable contract is the class, its `PermissionError` base, its constructor `(operation, tenant_id)`, and its `operation` and `tenant_id` attributes: the operation the caller attempted and the tenant it named. The message text is not part of the contract. It never says why the caller was refused. A missing capability, a failed anti-amplification check, an inactive user, a disabled service account and an unaccepted `SystemCaller` purpose all raise the same exception, with no subclass or attribute that tells them apart (ADR-0031). Treat it as a plain refusal, and do not show your users a reason you cannot know.

## 9. Routes

Build the application on `build_platform_app` and mount your routers on top:

<!-- source: examples/consumer-scaffold/my_product/app.py -->
```python
def create_app() -> FastAPI:
    app = build_platform_app(title="My Product", version="0.1.0")
    app.include_router(items_router)
    register_purge_participants()
    return app
```

Do not import `saas_os.api.main:app` as your application (ADR-0017).

**Every route must declare exactly one route policy.** The application checks this at startup against the fully assembled app and refuses to start if a route has none. For tenant data the policy is `require_permission`:

<!-- source: examples/consumer-scaffold/my_product/routes.py -->
```python
router = APIRouter(prefix="/v1/tenants/{tenant_id}/items", tags=["items"])

_read_item = require_permission(ITEMS_RESOURCE, READ)


@router.get("/{item_id}")
def read_item(
    item_id: uuid.UUID,
    context: RequestContext = Depends(_read_item),  # noqa: B008 -- FastAPI's own dependency idiom
) -> dict[str, object]:
    item = get_item(context.tenant_id, item_id)
```

What that one dependency does, in order: authenticates the session (bearer header or cookie); resolves the tenant in the path and checks that it exists, admits principals and that the caller is a member — any failure is the same 404; applies per-tenant rate limiting; evaluates the permission, auditing a denial.

Rules:

- **Read the tenant from `context.tenant_id`**, never from the path parameter. The path value is only an input to the chain.
- **A row of another tenant and a missing row return the same 404.**
- Use `/v1/...` paths (ADR-0006).
- Authentication at the HTTP layer is session-based, and a route you choose can also accept an API key (ADR-0047): declare it with `require_permission(resource, action, api_key=True)` and the route answers a request carrying `X-API-Key: sok_...` as the key's owner -- the user who created it, or a service account (`context.principal`; build Core callers with `saas_os.api.v1.request_caller(context)`, which gives a `UserCaller` or a `ServiceAccountCaller`). A key reaches only its own tenant, never with a session credential in the same request, and is rate-limited per key as well as per tenant. A permission that changes authority (memberships, roles, invitations, API keys, service accounts, the billing mutations, tenant self-suspension: `saas_os.core.rbac.is_authority_changing`) cannot accept a key. Keys issued over HTTP expire within 365 days (`expires_in_days`). None of SaaS OS's own routers accepts a key. On a route you open to keys, `context.actor_id` may be a service account's id: never use it as a user id there (no `UserCaller(context.actor_id)`, no foreign key to `core.users`); check `context.principal`.
- Other available dependencies: `require_entitlement_and_quota` (billing entitlement plus usage quota) and `get_idempotency_key`, both in `saas_os.api.dependencies`.
- A route that changes security-relevant state must leave audit evidence in the same transaction (`saas_os.core.audit_log`).

### Opt-in platform routers

SaaS OS ships routers for capabilities that are the same in every product. None is mounted for you; each exists in your application only if you register it:

```
from saas_os.api.v1 import (
    api_keys_router, build_billing_router, invitation_acceptance_router, invitations_router,
    members_router, usage_router,
)

app.include_router(members_router)          # /v1/tenants/{tenant_id}/members
app.include_router(invitations_router)      # /v1/tenants/{tenant_id}/invitations
app.include_router(invitation_acceptance_router)  # .../invitations/accept (ADR-0046)
app.include_router(api_keys_router)         # /v1/tenants/{tenant_id}/api-keys
app.include_router(build_billing_router(provider=my_billing_provider))   # .../billing
app.include_router(usage_router)            # /v1/tenants/{tenant_id}/usage
```

- **Permissions.** Every route requires one permission (`saas_os/api/v1/permissions.py`). Call `saas_os.api.v1.register_capability_permissions()` in your migration step, next to your own, then grant the pairs to your tenants' roles. Three exist only for HTTP: `membership:read`, `invitation:read`, and `api_key:self_manage`, which a member needs to manage their own keys.
- **Billing provider.** `build_billing_router()` with no argument uses the Stripe adapter and needs `saas-os[stripe]`; pass your own `BillingProvider` otherwise. Subscribing requires an `Idempotency-Key` header and authority at the payer as well as at the service tenant. For a payer without a payment method the Stripe adapter creates the subscription `incomplete`, with an open first invoice, so it is `pending` and grants nothing until the payer pays. `POST /v1/tenants/{tenant_id}/billing/subscriptions/{subscription_id}/payment-page` returns `{"url": ...}`, Stripe's hosted page for the open invoice (ADR-0052): send the payer there. It needs `billing.subscription:read` at the service tenant and `billing.account:charge` at the payer, answers `409` when nothing is due, and also pays a failed renewal (`past_due`). The card that pays becomes the subscription's own, so the renewals are charged to it. The page has no return link: show your own page and poll the subscription or the entitlements. From Python, `saas_os.core.billing.get_payment_page(caller, service_tenant_id=..., subscription_id=...)`. A custom `BillingProvider` offers the page only if it also implements `PaymentPageProvider`. With the events router below mounted, the payment activates the subscription within seconds; without it, call `saas_os.core.billing.reconcile_subscription_status(caller, service_tenant_id=..., subscription_id=...)` with a caller allowed `billing.subscription:read` and SaaS OS's own subscription id. A first invoice left unpaid expires at Stripe (`incomplete_expired`, after about a day); the subscription becomes `canceled` when that event is delivered or on the next reconciliation. Until then the `pending` subscription counts as live: the payer cannot start a second one at the same merchant. This applies to subscriptions created through `create_subscription` (and the billing router); the legacy `saas_os.core.billing.service.subscribe()` does not use it, refuses at Stripe for a customer without a payment method, and its rows are ignored by billing events.
- **Shown once.** The invitation token and the API key are in the create (and rotate) response only. Deliver the invitation token to the invitee yourself.
- **A per-user key limit.** Creating an API key answers `409` once the member holds `API_KEY_MAX_PER_USER` unrevoked keys (default 50, across every tenant; section 4).
- **A tenant keeps its last administrator** (ADR-0043). An administrator is an active member who can assign roles (`membership_role:create`) and does not owe that to a delegation with an expiry. Core refuses — and the members route answers `409` — any change that would leave a tenant that has an administrator without one. That covers membership suspension and revocation, role removal, permission revocation, deny grants and delegation revocation, whether made in the tenant or in a parent tenant whose SUBTREE grants reach it, and also `saas_os.core.tenancy.move_tenant` and suspending or closing a parent tenant. Catch `saas_os.core.identity.LastTenantAdministratorError` wherever your code calls these; its `tenant_id` names the tenant that would be emptied, which may be a child of the one you were changing. The remedy is to give that tenant an administrator of its own first. Give the permission to more than one person per tenant.
- **Cookie-authenticated mutations must be same-origin** (ADR-0044). A `POST`, `PUT`, `PATCH` or `DELETE` that authenticates with the session cookie must carry an `Origin` header equal to `PUBLIC_APP_ORIGIN`; a browser does this by itself. Anything else gets `403`, including a sibling subdomain. Requests with `Authorization: Bearer` are not checked. This applies to your own routes too, because it lives in the authentication dependency, and to `POST /auth/logout`.
- **Accepting an invitation** (ADR-0046) is its own router, because the person accepting is not yet a member: `app.include_router(invitation_acceptance_router)` serves `POST /v1/tenants/{tenant_id}/invitations/accept` with `{"token": "..."}`. It needs a signed-in user and no permission. It accepts only when the session carries an email your identity provider verified at login and that email is the invited one; every refusal is the same `404`. Your invitation link therefore carries the tenant id and the token, and leads through login first. Your identity provider must put `email` and `email_verified` in the ID token for the `email` scope (the bundled ZITADEL is configured to by `saas-os-local-identity`); otherwise nobody can accept over HTTP. A session issued before you upgraded carries no email: the person logs in again.
- **Billing-provider events (ADR-0048).** `app.include_router(build_stripe_billing_events_router())` serves `POST /v1/billing/providers/stripe/events`. Register that URL as a webhook endpoint in the Stripe account of the platform tenant's merchant and set its signing secret as `STRIPE_WEBHOOK_SECRET`; the router refuses to build without it, and needs the `saas-os[stripe]` extra. Every event is verified, recorded once in `core.billing_provider_events`, and used only as a signal: the subscription it names is reconciled from Stripe's current state, so a paid checkout activates its subscription and a cancellation or failed payment is reflected. Events about other objects, or about another account, are recorded as ignored; an event about a subscription SaaS OS does not know yet is answered with a retry for an hour, then ignored. Install `deploy/saas-os-billing-event-retention.timer` to prune the ledger after 90 days.
- **Not provided.** Webhook subscriptions and usage ingestion. (A route of your own can accept an API key: see section 1.) Tenant creation and lifecycle and feature flags are platform operations: see "Platform administration" below.

### Platform administration (opt-in)

Some work is not any tenant's: listing every tenant, suspending one, deactivating a user, reading who administers the installation. SaaS OS calls the people who do it **platform operators** (ADR-0045). An operator is an ordinary user of your deployment whom this deployment enrolled, holding only the platform permissions it was granted. Platform authority is a separate system from tenant RBAC: a platform permission cannot be attached to a tenant role, delegated, or satisfied by support access, and `saas_os.core.rbac.can()` never reads it.

**Do not model platform staff as administrators of one root tenant.** Putting every customer under a single root tenant and giving your staff a `SUBTREE` role there does grant them authority over every customer, and that is the problem: it is tenant authority, so it reaches customer data, it can be delegated, it is recorded in each customer's own audit trail as if a member of that customer had acted, and nothing distinguishes your staff from a customer's administrator. Use platform operators for platform work, and the tenant-approved support-access request for looking at a customer's data.

**The first owner** is enrolled once per deployment by a command, never over HTTP (`docs/RUNBOOKS.md`, "Platform operators"):

```
python -m saas_os.api.platform_bootstrap bootstrap \
    --owner-issuer https://<your-identity-provider> \
    --owner-subject <the owner's OIDC subject> \
    --reason "initial platform owner"
```

**The HTTP surface needs two opt-ins.** You mount the router in code, and the deployment sets `PLATFORM_ADMIN_HTTP_ENABLED=true`. With the router mounted and the setting absent the application refuses to start; the setting alone exposes nothing.

```
from saas_os.api.platform_admin import build_platform_admin_router

app = build_platform_app(title="My Product", version="1.0.0")
app.include_router(build_platform_admin_router())     # /v1/platform/...
```

What you get under `/v1/platform`, one platform permission per route:

| Routes | Permission |
|---|---|
| `GET /tenants`, `GET /tenants/{tenant_id}` | `platform.tenant:read` |
| `POST /tenants`, `POST /tenants/{tenant_id}/activate` | `platform.tenant:create` |
| `POST /tenants/{tenant_id}/suspend`, `.../reactivate` | `platform.tenant:suspend`, `platform.tenant:reactivate` |
| `GET /users/{user_id}`, `POST /users/resolve` | `platform.user:read` |
| `POST /users/{user_id}/deactivate`, `.../reactivate` | `platform.user:deactivate`, `platform.user:reactivate` |
| `POST /users/{user_id}/sessions/revoke`, `.../api-keys/revoke` | `platform.session:revoke`, `platform.api_key:revoke` |
| `GET /feature-flags`, `GET /tenants/{tenant_id}/feature-flags` | `platform.feature_flag:read` |
| `POST /feature-flags`; `PUT` and `DELETE /tenants/{tenant_id}/feature-flags/{key}` | `platform.feature_flag:define`; `platform.feature_flag:override` |
| `GET /billing/overview` | `platform.billing:read` |
| `GET /audit` | `platform.audit:read` |
| `GET /operators`, `GET /grants` | `platform.operator:read` |
| `POST /operators`, `POST /operators/{operator_id}/suspend`, `.../reactivate`, `.../revoke`, `.../grants`, `.../grants/revoke` | `platform.authority:manage`, with a session at most 15 minutes old (the default and the maximum) |

- **There is no route for moving or deleting a tenant, purging, erasing an identity, the owner bootstrap or recovery.** Those stay operator-run calls and commands.
- **Who sees what.** No credential is `401`. An authenticated caller who is not an active operator gets the `404` an unknown path returns, on every one of these routes. An operator without the route's permission gets `403`. Core authorizes the same caller again inside its own transaction; the route decides nothing.
- **Oversight is data-minimized.** The reads return fixed projections (for a tenant: id, name, status, parent and timestamps; for billing: subscription status, plan key, payer and timestamp). No route returns a customer's business data. An operator who needs to see it files a support-access request, which the tenant approves.
- **A tenant cannot opt out of oversight**, and a suspended or deleted tenant is still listed. Say so to your customers: you owe them the same statement SaaS OS makes to you.
- **Every call Core authorizes is recorded** in `core.platform_audit_log`, which no tenant can read: a read leaves an attempt row and a completion row, a change leaves a row in the same transaction, and a refusal for want of authority or by an invariant leaves a `denied` row (best effort). A change to a tenant also leaves a row in that tenant's own audit trail, so its administrators see that the platform acted on them; a read does not. Not recorded: a caller who is not an operator, and a request rejected as invalid (`400`, `422`) or as not fitting the resource's state (`404`, `409` with a state reason). **A row about a user stores a reference, not the user id** (audit identity phase P1, owner decisions of 2026-11-02 to 2026-11-04): `GET /audit` returns `target_type` `user_subject` with a random `target_id` that is the same for one user on one UTC day and different on another, for every platform operation that targets a user (operators included) and for the user lookup's attempt and completion rows; a request about an id that names no user is recorded with `target_type` `user` and no `target_id`. The `user_id` key of operator events (enrol, suspend, reactivate, revoke, grant, revoke grant) is now `user_subject_ref`. **The permission grant approver register's rows follow the same rule** (since v0.9.0, the register events under `platform.permission_grant_ledger.*` that target `permission_grant_ledger_approver_register` carry `user_subject_ref` in the metadata instead of `subject_user_id`; their `target_type` and `target_id` are the register entry, as before; a report that reads `metadata->>'subject_user_id'` finds only the old rows). A reference can be resolved to a user only through the link table (`docs/RUNBOOKS.md`, "Audit digests", section 5); no route does it yet. Rows written before the change keep their raw ids, so a lookup by raw user id (`target_id`, or the `user_id` key of an operator event) finds the old rows and no new ones: query new rows by the reference, and resolve it through the link table. **A `core.users` row that a platform audit link or erasure marker references can no longer be deleted**: the foreign keys are `NO ACTION` (migration `e2b7c4d9a1f6`). Core never deletes a user (it erases through `erase_user_identity`, which unlinks the references and records a marker); a product or a test that deletes `core.users` rows directly must first clear `core.platform_audit_subject_links` and `core.platform_audit_subject_erasures` with the migration role, and the migration's downgrade refuses while any of the three new tables holds a row (`docs/RUNBOOKS.md`). A refusal row written while the reference mechanism itself failed has no target either and carries the fixed metadata `{"subject_unavailable": true}`, which tells it apart from the row of an id that named nobody. `IdentityErasureResult` has two new counts, `platform_references_unlinked` and `platform_references_kept_under_hold` (default 0).
- **Settings.** `PLATFORM_ADMIN_HTTP_ENABLED` (`true` or `false`); `PLATFORM_AUTHORITY_SESSION_MAX_AGE_SECONDS` (60 to 900, default 900); `PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS` (100 to 60000, default 5000); `PLATFORM_MUTATION_STATEMENT_TIMEOUT_MS` (100 to 60000, default 5000: a platform change, or the self-service suspension route, that a lock holds longer is answered `503` with `Retry-After`); `PLATFORM_DEACTIVATION_MAX_TENANTS` (default 10000). An invalid value stops startup.

**Building your own operator dashboard.** SaaS OS ships no operator interface; the router is the contract a product builds one on.

- Serve it from the same origin as your application and let the browser send the operator's own session. A cookie-authenticated change must be same-origin (ADR-0044). Do not put a shared service credential behind the dashboard: every platform audit row should name the person who acted, and an API key cannot hold platform authority at all.
- There is no "my permissions" route. An operator who holds `platform.operator:read` can read `GET /v1/platform/grants?operator_id=...` (ignore rows that have a `revoked_at`; every such call is itself audited). For everyone else, attempt the action and treat `403` as the answer: the interface hides, Core refuses.
- Lists are pages. Pass `cursor` from `next_cursor`; a `limit` above the maximum is a `400`, never a shortened page.
- A route that changes platform authority answers `401` with the header `X-Error-Code: session_not_fresh` when the session is older than the limit. Send the operator through a new login and repeat the request.
- A `409` carries a fixed reason (`last_platform_owner`, `self_target`, `invalid_tenant_transition`, ...); a `503` with `Retry-After` means the request was not carried out and can be repeated: the database did not finish in time or resolved a conflict by aborting it, a user's memberships kept changing during a deactivation, or the rate-limit backend was unavailable.
- Restricting `/v1/platform` by network at your edge is a good additional layer. It is not the control.

**Tenant self-service suspension** is a separate opt-in, a tenant route, not a platform one:

```
from saas_os.api.v1 import register_tenant_suspension_permission, tenant_suspension_router

app.include_router(tenant_suspension_router)          # POST /v1/tenants/{tenant_id}/suspend
```

Call `register_tenant_suspension_permission()` in your migration step and grant `tenant:suspend` to the roles that may use it; no role has it by default. The caller must hold it through a role of their own membership in exactly that tenant, give a reason, and repeat the tenant id in the body. **Nobody inside a suspended tenant can reactivate it**: that takes an operator with `platform.tenant:reactivate`. Say so in your interface before the member confirms.

## 10. Background jobs

Register a tenant job with `register_tenant_job`. The handler receives a validated tenant context:

<!-- source: examples/consumer-scaffold/my_product/jobs.py -->
```python
async def my_product_mark_item_processed(
    context: TenantJobContext, payload: TenantJobPayload
) -> None:
    # The tenant comes from the validated context. `payload.data` is
    # product data only and is never used to choose a tenant.
    item_id = uuid.UUID(str(payload.data["item_id"]))
    mark_item_processed(context.tenant_id, item_id)


MARK_ITEM_PROCESSED = my_product_mark_item_processed.__name__

JOB_FUNCTIONS = [register_tenant_job(my_product_mark_item_processed)]
```

Run your jobs on SaaS OS's production worker, with yours added:

<!-- source: examples/consumer-scaffold/my_product/worker.py -->
```python
def run(argv: list[str] | None = None) -> int:
    # Imported here: registering a job resolves REDIS_URL. A failure (for
    # example REDIS_URL unset) is logged like SaaS OS's own startup failures,
    # by error type only, never as a traceback, and exits 1.
    try:
        from my_product.jobs import JOB_FUNCTIONS
    except Exception as exc:  # noqa: BLE001 -- every startup failure must exit non-zero
        configure_logging()
        logger.error("worker_startup_failed", extra={"error_type": type(exc).__name__})
        return 1

    return main(argv, extra_functions=JOB_FUNCTIONS)
```

`python -m my_product.worker` replaces `python -m saas_os.api.worker`; do not run both. It keeps every platform job (webhook delivery, usage ingestion, notifications, session cleanup, the outbox dispatcher), the fail-closed database-role guard and the `--check` health probe.

Rules:

- **Delivery is at-least-once.** A handler must be idempotent.
- **Prefix job names with your product's name.** The worker refuses to start if one of your jobs shares a name with a platform job or with another of your jobs, or was not built by `register_tenant_job` / `register_system_job` (or `system_cron` for a schedule).
- **Never choose the tenant from `payload.data`.** A payload whose `tenant_id` is not a valid UUID is dead-lettered before the handler runs.
- Failures are retried with exponential backoff (`JOBS_MAX_TRIES`, default 3) and then dead-lettered. Except (since 2026-11-02): an error that is a `saas_os.core.outbox.AmbiguousOutcomeError` (its request may have been sent) is dead-lettered at once, not retried, unless it declares `at_least_once=True`; an idempotency window is not honoured in a directly queued job, because nothing records when its first attempt ran. Since 2026-11-13 the same holds for an `AmbiguousOutcomeError` inside an exception group (any one of its errors, nested groups included), and for `saas_os.core.email.EmailOutcomeUnknownError` that escapes your job from `send_email()`, with or without its `retry_within` (it is now also a `NonRetriableJobError`; `except EmailProviderError` still catches it). A `saas_os.core.outbox.PermanentEventError` (or an exception group whose every error is one) is dead-lettered at once as well, since a retry meets the same refusal; before 2026-11-13 it used up `JOBS_MAX_TRIES`. Both are logged as `job_not_retried`.
- A handler gets 300 seconds (`saas_os.infra.jobs.queue.HANDLER_TIMEOUT_SECONDS`, the limit arq already imposed). One that runs longer is cancelled, logged as `job_timed_out` and dead-lettered at once, not retried in the same run: work it started in a thread (`asyncio.to_thread`) is not stopped by the cancellation and could otherwise run twice. Before 2026-11-01 such a job was dropped by arq with no dead-letter entry. Keep long work in smaller jobs.
- An outbox event whose consumer runs longer than `OUTBOX_CONSUMER_TIMEOUT_SECONDS` (270, inside the job's 300) is dead-lettered at once with `last_error` starting `ConsumerTimedOut:`, because its external effect (an e-mail, a webhook) may already have happened. It is never claimed again automatically, not even when its lease expires; an operator checks the destination and replays it with `saas-os-operator replay-outbox-events` (`platform.outbox:replay`, audited). A replay can repeat the effect: a Resend send replayed within 24 hours reuses its `Idempotency-Key`, a webhook carries the same `event_id`, an SMTP message the same `Message-ID`. A worker that crashes mid-send is a different case and still runs the event again when the lease expires (at-least-once, ADR-0033). The deadline decides, not the exception's type: a consumer that catches the cancellation and raises another error after the deadline has timed out all the same (since 2026-11-02). If the worker cannot record a failed attempt (the database is briefly unavailable), it tries the write twice more within a few seconds and then logs `outbox_event_outcome_unrecorded` and stops; it no longer lets the job retry, which ran the consumer again at once with the same claim. The event then runs again only when its lease expires, as after a crash: check the destination when you see that log line.
- **An outbox consumer reports an unknown outcome with `AmbiguousOutcomeError`** (`saas_os.core.outbox`, since 2026-11-01): raise it when your request may already have reached the destination and you have no answer (a timeout after writing, a connection lost before the response). Only the code that saw the phase can tell. The event is never published for it. By default it is dead-lettered at once with `last_error` `OutcomeUnknown: <reason> (<phase>); ...`, for an operator to check the destination and replay it. Declare a retry only when it is safe: `retry_within=timedelta(...)` when the destination de-duplicates the same idempotency key with an identical payload for that long (the event is retried while the retry is due before its `created_at` plus that window, a lower bound of the first send, and dead-lettered after it, even if the retry was already scheduled), or `at_least_once=True` when the receiver de-duplicates on a stable id (retried within the normal attempt budget). `reason` and `phase` are stored, so give categories only, never a URL, a recipient, a secret or payload content.
- **A bare timeout is an unknown outcome (owner decision D of 2026-11-01; compatibility change).** A `TimeoutError` that escapes your outbox consumer unclassified -- including `asyncio.TimeoutError`, `socket.timeout`, `concurrent.futures.TimeoutError`, any subclass of them, an `httpx` timeout (`httpx.TimeoutException` and its subclasses), or an exception group holding one -- is treated as `AmbiguousOutcomeError` with no retry policy: the event is dead-lettered at once with `last_error` `OutcomeUnknown: <type> (unclassified); not retried automatically. ...`, never claimed again, and runs again only through the audited replay. **Before this change it was retried with backoff; a consumer that let a timeout escape will now see its event dead-lettered instead.** Only the exception's type name is stored. The dispatcher's own deadline (`ConsumerTimedOut:`) is unchanged. The rule looks at the type of the exception that escapes, not at its message or its cause: the timeouts of your own database and queue clients are not `TimeoutError` (SQLAlchemy's pool `TimeoutError`, psycopg's `ConnectionTimeout` and `QueryCanceled` from `statement_timeout`, Redis's `TimeoutError` all derive from their library's own error class), so they keep the ordinary retry. Who is affected: the dispatcher runs the consumers that `saas_os.api.outbox_dispatcher.outbox_event_handlers()` returns, which are SaaS OS's own, and SaaS OS has no public API to add a product's consumer to it. A product is affected only if it runs its own consumer through the dispatcher anyway (for example by replacing that function); SaaS OS's own consumers are covered in the bullet after next.
- **Say "not sent" explicitly with `ConfirmedNotSentError`** (`saas_os.core.outbox`, additive) when you have evidence that your request was not sent: the connection was refused, the host did not resolve, a connect or pool timeout, a deadline that expired before the request started, or no request was made. Raise it, or make your own error class inherit from it as well as from `TimeoutError` or your client's error; the event then keeps the ordinary retry (backoff, attempt counted, dead-lettered when the attempts run out), even if the error is also a `TimeoutError`. Catch a timeout where you can tell its phase and raise `AmbiguousOutcomeError` (possibly sent) or `ConfirmedNotSentError` (not sent); never mark a timeout after writing as not sent. A class cannot be both (`TypeError`). `PermanentEventError` and `RetryAfterEventError` keep their meaning, also when combined with it. A timeout that you catch and re-raise as your own, non-timeout error is your classification and keeps the ordinary retry. **Inside `context.external_effect()` with markers on** (`OUTBOX_EXTERNAL_EFFECT_MARKERS`), the retry is credited only if the `ConfirmedNotSentError` (or an exception group whose every leaf is one) is the very exception that left the `with` block: raise it from inside the block, or let it propagate out of it unchanged. An error raised after the block, a fresh one raised after you caught the block's failure, or a different error wrapped around it is not credited and the attempt is dead-lettered `OutcomeUnknown:`; so is an exception group that also holds anything else. An `AmbiguousOutcomeError(at_least_once=True)` that you raise inside the block is retried within the attempt budget; `retry_within`, no policy and every other failure after a marker stay dead-lettered (`docs/architecture/OUTBOX-RETRY-AFTER-MARKER-DESIGN.md`).
- **Email: tell an unknown outcome from a transient failure (`EmailOutcomeUnknownError`, `EmailNotSentError`; both public in `saas_os.core.email`).** `send_email()` raises `EmailOutcomeUnknownError` when the transport failed after the message may already have been handed over (SMTP: after the server invited the data; Resend: the response never arrived or could not be read), and `EmailNotSentError` when it failed before anything could have been sent. Both subclass `EmailProviderError`. `EmailOutcomeUnknownError` carries `phase` (where the transport was, such as `data`, `read` or `response`) and `retry_within`: a `timedelta` only when a repeated request is provably de-duplicated by the provider for that long (Resend, same `Idempotency-Key` and identical body), otherwise `None`, which means a retry may deliver the message twice, so do not retry automatically and mark the message for an operator. `EmailNotSentError` is safe to retry. Catch the two before `EmailProviderError`; neither carries an address, a URL or a provider body.
- Any other exception your consumer raises keeps the ordinary retry, as before: a database error (a serialization failure, a deadlock, a lost connection), a `ConnectionError`, a `RuntimeError`, or a timeout you re-raised as your own non-timeout error. Owner decision of 2026-11-02: unclassified exceptions are **not** all treated as unknown outcomes; only the bare timeouts above are. If such an exception can follow a request that may have reached the destination, raise `AmbiguousOutcomeError` yourself, since the dispatcher will retry it.
- What SaaS OS's own consumers do with an unknown outcome: SMTP (the relay invited the message data and no final reply came) dead-letters it; Resend retries it within 23 hours with the same key (see section 4); webhooks retry it at least once more on the same `event_id` (see "Webhook receivers" below). SaaS OS's own consumers state "not sent" explicitly where their transport knows it (a refused or timed-out connection, an unresolvable host, the egress proxy down, the deadline before any address was tried, an SMTP failure before the relay invited the data, a Resend request never sent, a missing e-mail configuration), so those keep retrying; none lets a bare timeout escape. Stripe billing, AI inference and every other consumer are unchanged: no automatic retry of an ambiguous outcome is enabled for them, and none assumes idempotency it does not have.
- The queue is as durable as your Redis. Configure Redis persistence in production.
- A scheduled job is a system job (`register_system_job`) wrapped with `saas_os.infra.jobs.queue.system_cron` and passed as `extra_cron_jobs`.

### Attributing actions no member performs (system actor)

A job, a schedule, a webhook or provider-event processor, inbound mail handling, a public link (an unsubscribe link), a maintenance command or a billing step acts with no member behind it. Record such an action in the affected tenant's audit trail with `record_system_action_in_transaction` (`saas_os.core.audit_log`), in the transaction of the change it describes, so the change and its evidence commit or roll back together (ADR 0061, option B, step 1).

**Three roles, recorded apart** (owner decision C, 2026-11-01). A system row names each of them under its own metadata key, and none of them stands in for another:

| Role | What it is | Type (`saas_os.core.authority`) | Metadata key and shape |
|---|---|---|---|
| Executing actor | The job or component that runs the action, for example the outbox run job or your worker job. | `SystemActor(kind, name)` | `system_actor`: `{"kind", "name"}` |
| Initiating actor | Who or what originally requested it: a user, a service account, or a system actor such as a schedule, an inbound provider event or a public link. | `Initiator` | `initiated_by`: `{"type": "service_account", "service_account_id"}` or `{"type": "system", "kind", "name"}` with optional `record_type` and `record_id`; or the string `"unavailable"`. A user initiator (`{"type": "user", "user_id"}`) is refused in a new audit row (owner decision D2, below) |
| Correlation | Ids that tie the chain together: the arq job id, the outbox event id, the request id. | `SystemCorrelation` | `correlation`: `{"arq_job_id", "outbox_event_id", "request_id"}`, only the parts present; `{}` when none |

An arq job id identifies an execution and correlates it. It is never the initiator.

**When the initiator is unavailable,** the row says so: `initiated_by` is exactly the string `"unavailable"` (`INITIATOR_UNAVAILABLE`). That is what you get when you pass `initiated_by=None`, in a job enqueued directly, for an outbox event whose producer recorded no initiator (every event appended before this change), and for a stored initiator that no longer parses (logged as `outbox_event_initiator_unreadable`). SaaS OS never fills the gap with the executing job.

**A user initiator is not recorded in a new tenant audit row** (owner decision D2, 2026-11-02). The tenant audit writers `record_system_action_in_transaction` and `record_in_transaction` accept only a service-account or system `Initiator` (or `None`), and refuse an `Initiator` of type user (`Initiator.user(...)`, `Initiator.from_caller(UserCaller(...))`, or `Initiator.from_job_initiator(...)` of a user) with `InvalidActorError`, before the insert; if you let it propagate, the change the row describes rolls back with it. The error names no id. The same holds for metadata, in tenant and platform audit rows alike: `record()`, `record_in_transaction()`, `record_system_action_in_transaction()` and every platform writer (`record_platform_event_in_transaction`, `record_oversight_attempt`, `record_platform_refusal`, `recording_platform_refusal`, the `request_metadata` of `run_oversight_read` and `run_tenant_oversight_read`, and the `PlatformChange.metadata` of `run_platform_change`) refuse an `initiated_by` key, in any case, with any padding, separator or Unicode compatibility form (`initiatedBy`, `Initiated-By`, `initiated/by`, a no-break space, a zero-width character, fullwidth letters) and at any depth (inside dicts, lists and tuples), unless it holds `None`, exactly `"unavailable"` or the exact recorded shape of a service-account or system initiator (`Initiator.as_metadata()`): `InvalidActorError`, before the insert. A user initiator is never turned into `None` for you; the write fails. `record_platform_refusal` (and `recording_platform_refusal`) must not lose the evidence of a refusal, so there the refused metadata is replaced by the fixed marker `{"metadata_refused": "d2"}` and the `denied` row is written with it (log line `platform_refusal_metadata_refused`). A top-level `initiated_by` key in tenant metadata stays a reserved key (`ReservedMetadataKeyError`, below). A new audit row therefore never stores a raw user id under `initiated_by`.

**What an audit row stores is rebuilt, never your objects** (owner, final closure of 2026-11-03). Every tenant and platform audit writer stores a plain-JSON copy of your metadata (only dicts, lists, strings, numbers, booleans and null; a tuple becomes a list), and in that copy the value under every key spelling `initiated_by`, `correlation` or `system_actor` (compared on letters and digits only, after NFKC normalisation and case folding, at any depth; in tenant metadata the top-level keys stay reserved) is rebuilt through the constructor of `Initiator` (service-account or system only), `SystemCorrelation` or `SystemActor` and must equal its recorded shape. Null stays null and `initiated_by` may be exactly `"unavailable"`. Anything else -- a `correlation` with another field (`user_id`), an id naming a user, a non-canonical `outbox_event_id`, a `system_actor` with an extra field, a typed object -- is refused with `InvalidActorError` before the insert (the platform refusal writer records its marker instead). Metadata that is not JSON (NaN or Infinity, nesting deeper than the interpreter's recursion limit, an arbitrary object) is refused with `MetadataNotJSONSerializableError`; the platform refusal writer then still writes the `denied` row, with `{"metadata_refused": "invalid"}`. The typed `correlation=` argument is rebuilt from its fields the same way, and the actor columns and the `system_authority` purpose from the caller's fields. Metadata made of plain JSON values, with attribution values in their recorded shapes, is stored unchanged, to the same bytes. For an action a user requested, pass `initiated_by=None`: the row records `"unavailable"`. This holds until a reference mechanism for user initiators ships (proposal: `docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md`). Service-account and system initiators are unaffected. The gate is about `initiated_by` only: a `UserCaller`'s own id is still written to `actor_user_id`, which the database requires for a user row. The outbox is unchanged: `append_event` still stores a user initiator with the event, the dispatcher still hands it to your consumer as `context.initiated_by`, and user erasure still rewrites it.

- **In a job,** the worker fills the context: `context.system_actor` is the executing job (`worker_job`, or `scheduled_job` for a `system_cron` run, and the registered job name), `context.job_id` is the arq job id, and in an outbox consumer `context.event_id` is the event id and `context.initiated_by` is what the producer recorded. Convert them with `SystemActor.from_job_actor(context.system_actor)`, `Initiator.from_job_initiator(context.initiated_by)` and `SystemCorrelation.from_job_context(context)`, and pass the three as `actor=`, `initiated_by=` and `correlation=`, except that when the converted initiator's `type` is `InitiatorType.USER` you pass `initiated_by=None` (owner decision D2). A consumer that passes a user initiator on gets `InvalidActorError` on every attempt: the event is retried and, after its last attempt, dead-lettered, with no audit row written. A job or request id that is not a valid correlation value (over 100 characters, outside `[A-Za-z0-9_.:-]`, or shaped like an API key or JWT, or naming a principal as below) is left out of `correlation`; the row's own `correlation_id` column is unchanged. **A correlation id never names a principal** (owner decision D2, final closure of 2026-11-03): `SystemCorrelation` refuses an `arq_job_id` or `request_id` whose first word names a user or other principal (`user:42`, `user_<uuid>`, `member-7`, `service_account:...`; the record-id rule of a system initiator) with `InvalidSystemActorError`. arq's own job ids (32 hex digits, `cron:<name>:<ms>`), generated request ids (UUIDs), outbox event ids and other opaque ids are unaffected.
- **Migrating a consumer to this rule.** What to pass: `initiated_by=None` when `Initiator.from_job_initiator(context.initiated_by)` is of type `InitiatorType.USER` (the row records `"unavailable"`), the converted initiator otherwise; never copy a user initiator into metadata under `initiated_by` instead, which is refused the same way. The consequence of not doing so: the consumer fails on every attempt, so its outbox event is retried and then dead-lettered, and no audit row is written. How to detect it: `core.outbox_events` rows with `status = 'dead_lettered'` and `last_error` starting with `InvalidActorError:` (or `ReservedMetadataKeyError:` for a top-level key), and the worker log line `outbox_event_failed` with `error_type` `InvalidActorError`. After fixing the consumer, replay those events with `saas-os-operator replay-outbox-events` (`platform.outbox:replay`). A key with another name is not covered (it is your metadata); keep user ids out of it. The audit of every SaaS OS callsite and of the consumers checked: `docs/architecture/AUDIT-D2-CALLSITE-AUDIT.md`.
- **When you append an outbox event,** pass who requested the change: `append_event(..., initiated_by=Initiator.from_caller(caller))` for the caller your mutation authorized. `from_caller` turns a `UserCaller` into a user initiator, a `ServiceAccountCaller` into a service-account initiator, a `SystemCaller` with an actor into a system initiator, and a `SystemCaller` without one into `None` (unavailable), because a purpose names an authority, not an initiator. The initiator is stored with the event, in the existing `payload` column under the reserved top-level key `saas_os.initiated_by` (no schema change). The dispatcher splits it off again: your consumer's `payload.data` is exactly the payload you appended, and the initiator arrives as `context.initiated_by`. A payload that already carries that key is refused (`InvalidOutboxEventError`).
- **Outside a job,** build the values yourself, for example `SystemActor(SystemActorKind.PUBLIC_LINK, "my_product.unsubscribe")` as the executor and `Initiator.system(actor, record_type="unsubscribe_link", record_id=link_id)` as the initiator.
- **Then, in the change's own `tenant_session_scope(tenant_id)` session,** call `record_system_action_in_transaction(session, tenant_id=tenant_id, actor=actor, initiated_by=initiator, correlation=correlation, action="my_product.trials.expired", resource_type="my_product.trial", metadata={"count": expired})`. Like `record_in_transaction`, it flushes and never commits, and it fails closed before the insert.
- **With a `SystemCaller`,** `record_in_transaction(..., caller=SystemCaller(purpose, actor=actor), initiated_by=..., correlation=...)` records the same three keys beside `system_authority`, and refuses a user initiator the same way. A `SystemCaller` with no actor, initiator or correlation is recorded exactly as before. A `UserCaller` or `ServiceAccountCaller` is its own initiator, so passing `initiated_by` or `correlation` with one is refused (`InvalidActorError`).

Rules:

- **Attribution, never authority.** None of the three is a caller: `require_caller()` and every Core operation refuse a `SystemActor`, and `record_system_action_in_transaction` authorizes nothing. An action that needs Core authority keeps its `SystemCaller` purpose and attaches the actor for attribution only, `SystemCaller(SystemAuthority.PROVISIONING, actor=actor)`; the actor changes nothing about what that caller may do, and neither does an initiator. Never pick a purpose just to get an audit row.
- **Core owns the kinds.** `SystemActorKind` is a closed list: `worker_job`, `scheduled_job`, `webhook_processor`, `provider_event_processor`, `inbound_processor`, `public_link`, `maintenance`, `billing_process`. `InitiatorType` is closed too: `user`, `service_account`, `system`. You choose only `name` (`[a-z0-9_.:-]{1,100}`; prefix it with your product's name).
- **A record reference names a record, never a credential.** A system initiator's `record_type` and `record_id` (a provider event, a link record) are optional and go together. A type naming a token or secret, or an id shaped like an API key or a JWT, is refused at construction. **A system initiator must not encode a user** (owner decision D2): a `record_type` that names a principal (any word starting with `user`, or `member`, `membership`, `principal`, `operator`, `person`, `people`, `identity`, `subject`, `owner`, `actor`, a bare `account` or `service_account`, as words split at `_ . : -`) or embeds a UUID (also split by `- _ . :`), a string `record_id` whose first word names a principal (`user:42`), and a `SystemActor` name that embeds a UUID are refused at construction (`InvalidSystemActorError`), so they can reach neither an audit row nor the outbox. A user who requested an action is a user initiator, recorded as `None` under D2; never disguise one as a system record. `billing_account` and `merchant_account` name records and are accepted. **This word rule is a guard against mistakes, not a security boundary.** It catches the honest slip (`record_type="user"`, `user:42`, a UUID pasted into a component name), not deliberate obfuscation, which it does not detect: an abbreviation or other word (`usr`, `uid`, `acct_holder`, `customer`), an id in another encoding (base64, decimal, a hash of the id), an id that is not in the first word of a `record_id` (`evt_<user uuid>`, `link:<user uuid>`), or a bare user UUID as the `record_id` of a non-principal `record_type` (indistinguishable from any record's UUID). Keeping user ids out of system initiators remains the caller's obligation under D2. The writers rebuild every `SystemActor` and `Initiator` from its fields before recording it, so an object assembled around its validation cannot store anything a valid one could not; deliberately forging objects in your own process is outside the threat model (such code could write rows directly).
- **The tenant comes from verified context** (the job context, the event's own tenant, the caller's tenant), never from the actor or the initiator, which carry none. The session must be that tenant's `tenant_session_scope`; a row for any other tenant fails at the database.
- **`system_actor`, `initiated_by` and `correlation` are reserved metadata keys.** `record()`, `record_in_transaction()` and `record_system_action_in_transaction()` refuse them in the metadata you pass (`ReservedMetadataKeyError`, before any write, in any case, with any padding, separator or Unicode compatibility form); they are written only from validated values. Nested deeper, they are rebuilt or refused (above). They count toward the 8 KiB metadata limit.
- **Erasing a user also deletes the invitations addressed to them** (privacy gap OP-6, closed 2026-11-04). `erase_user_identity(..., invited_emails=())` deletes, in each tenant it is given, every `core.invitations` row, in any state, that the user accepted or that is addressed to one of their addresses: the ones you declare in `invited_emails`, the verified e-mail of their sessions, and the address of an invitation they accepted in that tenant. A pending invitation is deleted with its token, so its link stops working. Invitations the person issued or revoked for someone else stay, with `inviter_user_id` and `revoked_by_user_id`. Core stores no e-mail on the user: if your product keeps the address a person was invited at, pass it. The session e-mail is a weak source (logout clears it, retention deletes old sessions). Matching is exact on the trimmed, case-folded address: no NFC, no plus-address handling (`person+tag@x` is not matched by `person@x`), and case folding can equate distinct non-ASCII addresses, which is why only addresses you declare are matched. The count (never an address) is in an `identity.erasure_invitations_erased` audit row.
- **Erasing a user erases them as an initiator** (owner decision of 2026-11-02). `erase_user_identity` replaces, in each tenant it is given, every stored initiator that names that user (`{"type": "user", "user_id": ...}`) with `"unavailable"`, in pending (claimed or not), dead-lettered and published events alike, in the transaction that locks the user's membership and under that tenant's row security. This is part of erasure only: it is not a public outbox function, and products cannot import it. Nothing else about the event changes: your payload (every key, in its original order), the event id (your idempotency key), status, attempts, claim and schedule stay as they were, and service-account, system and other users' initiators are untouched. A retry or replay after the erasure gives your consumer `context.initiated_by = None`, so its row records `"unavailable"`. An attempt that read the event before the erasure committed keeps the user id for that attempt: your consumer may see it once, in memory. Under owner decision D2 an audit row it commits cannot record it (a user initiator is refused; record it as `None`). SaaS OS never rewrites a committed audit row; how long completed audit rows keep a user id is the retention policy in the next item.
- **Retention of user ids in completed audit rows: approved policy, mechanism not implemented** (owner policy of 2026-11-02). A completed audit row that identifies a user as its initiator (`initiated_by` with a `user_id`, which can only be a row written before the D2 gate above, and other user ids in audit metadata) is kept with that identifier for two years from the row's creation by default. A legal hold suspends that expiry. After expiry, a controlled privacy process removes or anonymises the direct user identification where that is legally permissible, keeping the non-identifying history (what happened, when, in which tenant) where possible. Audit rows are never changed silently and never deleted without control. **None of this runs yet**: SaaS OS today keeps every audit row and every user id in it indefinitely, has no legal-hold function, and offers no expiry job. How it could be built without breaking the audit digests is a proposal awaiting approval: `docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md`. Until then, do not build your own deletion or rewriting of audit rows (the application role cannot, and a change made with the migrations role is reported by the digest verifier as tampering); keep user ids out of audit metadata you write unless you need them.
- **Actorless system rows: a warning now, a refusal later.** A successful `system` row written through `record()` with neither a `system_authority` purpose nor a `system_actor` is still written, but emits a `DeprecationWarning` and an `audit_system_row_unattributed` log line naming the calling module. Nothing is refused yet; a later release, approved separately, will refuse such rows. Keep `record()` for denials, and move successful system actions to `record_system_action_in_transaction`.

### Webhook receivers: de-duplicate on `event_id` (mandatory)

Webhook delivery is **at-least-once**. A receiver that may act twice on the same event **must** de-duplicate on the body's `event_id`: it is the same on every attempt of one event to one subscription (and on an operator's replay), while the signature's timestamp is fresh on each attempt. SaaS OS retries a delivery whose outcome it cannot know (since 2026-11-01): a write or read timeout, the connection closed after it was opened, a protocol error, or the delivery deadline expiring while an address was being tried. The receiver may have processed such a request already, so without de-duplication it acts twice. A receiver built on SaaS OS gets this from `verify_and_record_webhook_delivery()`, which refuses an `event_id` it has recorded (`WebhookReplayDetectedError`; ADR-0035). A connection that was refused, or a deadline that expired before any address was tried, sent nothing and is retried like any transient failure. An ambiguous delivery is never recorded as delivered; once the outbox's attempts run out it is dead-lettered with `last_error` starting `OutcomeUnknown:`. Status codes keep their meaning: `400`, `410`, `413`, `422` and redirects are permanent; every other status is retried.

### Diagnostics in worker and API processes

A failed webhook delivery's traceback keeps, in its frame locals, the decrypted signing secret, the full destination URL (with any token in its path or query), the signature header and the event body, for as long as the error and its traceback exist. SaaS OS never records frame locals (ledger row 899), and arq stores no job results. Its own log lines name error types only. The dead-letter list and the outbox's `last_error` hold the failing error's type and message. When a job is dead-lettered, arq also logs the formatted traceback: the type and message of every chained exception and the source line of each frame, without locals. That says nothing about what your product adds to the same process.

- Treat secrets, URL tokens, request headers and request bodies as sensitive in every diagnostic sink.
- Keep secrets out of your jobs' exception messages, and out of literals in their source. A message, a message of an exception it was raised from, or a source line shown in the traceback reaches the worker log when the job is dead-lettered.
- In an error tracker, APM agent or debugger integration that runs in the worker or the API process, turn off the capture of local variables unless you have shown that its configuration is safe. For example: `include_local_variables=False` in the Sentry Python SDK, `show_locals=False` for structlog's `ExceptionDictTransformer` and for rich tracebacks, and no log handler that formats with `traceback.TracebackException(..., capture_locals=True)`. Scrubbing by variable name is not enough: the URL, the headers and the body are in locals named `url`, `headers` and `body`.
- Check it before production and after any change to a diagnostic integration. In a non-production deployment, create a subscription whose URL has a unique fake token in its query and points to an endpoint you control that answers `500`. Let one delivery fail, then search every sink the integration feeds (tracker events, the log store, APM traces) for the token and for the subscription's signing secret, which `subscribe()` returned once. Keep the search as deployment evidence; a match is a failed check.

## 11. Tenant purge

When a tenant is purged, Core deletes Core's data and calls every registered participant for product data. **A product that registers no participant leaves its rows behind a purged tenant.**

<!-- source: examples/consumer-scaffold/my_product/purge.py -->
```python
class ItemPurgeParticipant:
    @property
    def name(self) -> str:
        return "my_product.items"

    def purge_tenant_data(self, tenant_id: uuid.UUID) -> None:
        with tenant_session_scope(tenant_id) as session:
```

Register it through the public API, from one function of your own that every purging process calls:

<!-- source: examples/consumer-scaffold/my_product/purge.py -->
```python
# One instance per process: registering the same object again is a no-op.
ITEM_PURGE_PARTICIPANT = ItemPurgeParticipant()


def register_purge_participants() -> None:
```

**The public API.** Import everything from `saas_os.core.tenancy`; nothing else is supported for registration, and a product's own code never touches a registry object (the one exception is test isolation, under *Testing your participant* below):

| Name | What it is |
|---|---|
| `TenantPurgeParticipant` | the protocol: a `name` property and `purge_tenant_data(tenant_id)` |
| `register_purge_participant(participant)` | registers in this process; returns `participant` |
| `registered_purge_participant_names()` | the names registered in this process, in registration order |
| `DuplicateTenantPurgeParticipantError` | a *different* object was registered under a name already taken |
| `InvalidTenantPurgeParticipantError` | not a participant, or a name outside the grammar below |

Both errors are `ValueError`s, and nothing is registered when either is raised.

**Names.** 1 to 100 characters: lowercase ASCII letters, digits, `.`, `_` and `-`, starting with a letter or digit. Prefix it with your product's name (`my_product.items`). The name is read once, at registration, and is the value the audit records.

**Registering twice.** The same object again is a no-op, so a `create_app()` that runs twice in one process (tests do this) is safe. Keep one instance per participant, as above: a *new* instance under the same name raises `DuplicateTenantPurgeParticipantError`.

**Order.** Participants run in registration order, after Core's own data is purged, one at a time. There are no declared dependencies between participants: if one needs to run before another, register it first. A participant that fails stops the participants after it in that attempt.

**Processes.** The registry is per process, and registering in one process registers nothing anywhere else:

| Process | Runs `purge_tenant()`? | Register? |
|---|---|---|
| API (`uvicorn my_product.app:app`) | no: purge is never an HTTP route | optional; the scaffold does it in `create_app()` |
| Worker (`python -m my_product.worker`) | no: no platform job purges a tenant | not needed |
| `saas-os-operator purge-tenant` | yes | always, through `--setup my_product.purge:register_purge_participants` |
| A Python call of your own to `purge_tenant()` | yes | call `register_purge_participants()` first in that process |

The supported ways to run a purge today are these two: the operator command and a direct `purge_tenant()` call. There is no HTTP route and no worker job that purges a tenant; that is the current contract, and a later one would need its own decision record.

The operator command refuses to run without `--setup` (or an explicit `--no-product-participants` when there is no product data), and refuses a `--setup` that registered nothing, before it touches the tenant. Core itself cannot know which participants a product has: a direct call to `purge_tenant()` in a process that registered nothing purges Core's data, reaches `PURGED` and leaves product rows behind. `TenantPurgeResult.participant_names` and `tenant.purge_completed`'s `participants_run` record what ran. A purge run with `--no-product-participants` also records `product_participants_skipped: true` in `tenant.purge_completed` (a direct call can declare the same with `purge_tenant(..., product_participants_skipped=True)`). Other purges do not carry the key. The key records the declaration only: its absence does not prove that every participant your product needs was registered. Participants already registered in the process still run, so `participants_run` can be above 0.

**Completeness is the product's job.** A non-empty registry proves only that at least one participant is registered, not that every one your product needs is; neither the operator command nor `purge_tenant()` can tell. Keep the guarantee where the list is known, in your product:

- register every participant from one function (`register_purge_participants()` above), and use that function for `--setup` and before any direct call;
- test that, after calling it, `registered_purge_participant_names()` equals the exact tuple your product expects (the scaffold's end-to-end test asserts `("my_product.items",)`), so a participant left out of that function fails your tests (keeping the expected tuple in step with your tenant-owned tables is a review item: no test can find a table nobody listed);
- if your own code calls `purge_tenant()` directly, make the same comparison before the call and refuse on a mismatch.

There is no automatic discovery of participants from installed packages, entry points or imports; a possible later enhancement, not implemented.

**The contract:**

- **Idempotent.** It runs again on every retry, including after it already succeeded. Deleting rows that are already gone must be a silent no-op.
- **Fails by raising.** Core then leaves the tenant in `PURGING`, never `PURGED`, records one `tenant.purge_failed` with only the failure class `participant_error`, the step `participant:<name>` and the exception's type (never its message), and re-raises. The operator command exits 1.
- **Success** is returning normally, including when there was nothing to purge. A purge is complete only when Core's data, every registered participant and the job dead-letter cleanup have all succeeded in the same attempt; only then is the tenant `PURGED` and one `tenant.purge_completed` (with `participants_run`) recorded.
- **Retry.** Run the same purge again. It resumes from `PURGING`, records a new `tenant.purge_started` (`resumed: true`) and runs every participant again. Once `PURGED`, a further call returns `already_purged=True` and runs nothing.
- **Tenant scope.** It receives only the tenant being purged, while that tenant is locked in `PURGING`. Use `tenant_session_scope(tenant_id)` with that id, as above; never a raw or unscoped query.
- **Running a purge.** It is an operator-run call with no route: `purge_tenant(tenant_id, caller=SystemCaller(SystemAuthority.TENANT_PURGE), actor_user_id=<the person running it>)`, on a tenant an operator already marked deleted. The packaged command does the same: `saas-os-operator purge-tenant --tenant <id> --actor <user id> --setup my_product.purge:register_purge_participants --confirm <id>` (ADR-0050). `--setup my_product.app:create_app` also works, at the cost of building the application. No other caller is accepted, including a platform operator; each transition is recorded in the platform audit, and `actor_user_id` names who ran it.
- Deleting is a choice. Anonymizing or retaining is valid if it is your documented policy.

**Testing your participant.** Construct an isolated `TenantPurgeParticipantRegistry` (`saas_os.core.tenancy.purge_participants`), register your participant in it, and pass it as `purge_tenant(..., registry=...)`; that override exists for tests and nothing else. Against a real database, prove that it deletes the purged tenant's rows and no other tenant's, that a second purge after success is a no-op, and that a participant that raises leaves the tenant `PURGING`. The scaffold's end-to-end test does this through the operator command (`tests/test_consumer_scaffold_integration.py`).

Products pinned to v0.4.1 or earlier register through `saas_os.core.tenancy.purge_participants.default_registry().register(...)`, which still works; there, registering the same object twice raises.

## 12. First tenant

Creating the first tenant and its first administrator is an operator command of the installed package, not an HTTP route:

```
python -m saas_os.api.tenant_bootstrap --help
```

See `docs/RUNBOOKS.md`, "First-tenant bootstrap".

## 12a. Governed AI inference

**Platform hold (Gap 20b; released in v0.11.0, see `CHANGELOG.md`).** A platform operator can hold one tenant's AI. A held tenant's `run_inference` raises `InferencePolicyDeniedError` with `reason == "tenant_ai_held"` before any provider call, even when the tenant's policy is enabled; an attempt already under way completes, and no retry or fallback starts after the hold commits. A product should treat it like any other policy denial (do not retry; show the tenant that AI is suspended) and must not try to clear it: the tenant's own policy cannot, and only a platform operator can (`saas-os-operator ai-hold-lift`). There is no public API to hold or lift: it is operator tooling (`ai-hold-set`, `ai-hold-lift`, `ai-hold-show`), which needs `platform.ai_tenant_hold:manage`, never granted to an existing operator automatically. Contract: `docs/architecture/AI-INFERENCE-CONTRACTS.md` section 8.1. Upgrade steps: section 14, "From v0.10.0 to v0.11.0".

Products call models only through `saas_os.inference` (ADR-0054, ADR-0055;
both Accepted on 2026-10-18 with explicit scope: the supported, non-streaming
interface; provisional defaults; open questions and deferred capabilities
listed in ADR-0054 section 12c. `saas-os-update` classifies any change to it
as a public-API change for review). Never import `saas_os.control_plane.inference`: import-linter
refuses it in `products/`, and calling a provider adapter directly would skip
every safeguard. Non-streaming only; `stream_inference` refuses every request.

The tested example is `examples/reference-consumer/reference_consumer/inference.py`
(end-to-end test: `tests/test_reference_consumer_inference_integration.py`): register
each `UseCase` once at start-up (registration declares a ceiling and authorizes
nothing), then `await run_inference(caller, tenant_id=..., request=InferenceRequest(...))`
with a `UserCaller` or the tenant's `ServiceAccountCaller`, an alias the operator
configured, and a classification on every content part.

What must be true for a call to be sent, and who makes it true:

| Requirement | Who |
|---|---|
| The provider's secret listed in `AI_PROVIDER_CREDENTIALS` (comma-separated secret names provisioned for AI provider use) and injected like any other secret. A name not listed is refused, even if it resolves | Deployment (whoever controls the environment) |
| A provider, model, alias, and installation destination policy for the classification (`saas-os-operator ai-*`, run with `PLATFORM_CONFIG_DATABASE_URL`, section 5); after a change of credential name or endpoint origin, `ai-provider-confirm-binding` | Platform operator |
| The tenant's AI policy enabled; the use case granted for the classification; the model granted as a destination; optional preferences (residency, retention, training use) | Tenant, with `ai.policy:manage` |
| The caller holds `ai.inference:run` in the tenant (support access never does) | Tenant RBAC |
| The plan grants the boolean entitlement `ai.inference`; optionally a monthly `ai.tokens` limit (soft) | Billing plan |
| Every content part carries its classification (`none`, `tenant_data`, `sensitive`) | Product |

Every refusal is a typed `InferenceError` with a category and no content.
Each attempt is recorded before anything is sent; the output comes back only
after the attempt is settled. Refusals for authority, policy and entitlement
add a `denied` row (`ai.inference.run`, reason code only) to the tenant's
audit log; the row is written after the refusal and best effort, so a failed
write never lets a request through, and is logged as
`ai_inference_denial_unrecorded`. Quota and capacity refusals add no audit row.
For `sensitive` parts the use case's ceiling, the tenant's grants and an
installation destination policy for (provider, `sensitive`) must all allow it. Usage and a cost estimate are on
`result.usage` (`provenance` says whether the provider reported it). Register
the tenant permissions up front with `register_ai_permissions()` if roles must
be granted them before first use.

### Deployment settings

All are optional, non-secret environment variables of the processes that call
`run_inference`. Each is read when a request uses it, not at startup. An empty
value means the default. The defaults are provisional (ADR-0054 Q3, R3
revised), not validated production values: SaaS OS's own tests use fake
providers and prove the mechanism, not the values. Validate your settings
against your providers and workloads before enabling real-provider traffic.

| Variable | Default | Accepted values | Effect |
|---|---|---|---|
| `AI_EGRESS_CONNECT_TIMEOUT_SECONDS` | `5` | a finite number of seconds, `0 < s <= 3600` | Bound on opening each connection to the provider (`saas_os/control_plane/inference/egress_config.py`) |
| `AI_EGRESS_READ_TIMEOUT_SECONDS` | `30` | same | Bound on each read from the provider |
| `AI_EGRESS_TOTAL_DEADLINE_SECONDS` | `120` | same | Deadline for the whole request: every attempt, retry and fallback share it. A request's own `deadline_seconds` can only shorten it. The concurrency lease lives for this deadline plus 30 seconds |
| `AI_EGRESS_MAX_RESPONSE_BYTES` | `8388608` (8 MiB) | a whole number of bytes, `0 < n <= 268435456` (256 MiB) | Largest provider response read; a larger one is refused |
| `AI_INFERENCE_TENANT_CONCURRENCY` | `4` | an integer, `1` to `100000` | Requests in flight per tenant, across all instances (Redis lease) (`saas_os/control_plane/inference/admission.py`). Over the limit: `InferenceCapacityExhaustedError` |
| `AI_INFERENCE_GLOBAL_CONCURRENCY` | `64` | an integer, `1` to `100000` | Requests in flight for the whole installation, across all instances |
| `AI_INFERENCE_TOKEN_QUOTA_REQUIRED` | unset (off) | `1`, `true`, `yes` or `on` (any case, surrounding spaces ignored) turns it on; empty, `0`, `false`, `no` or `off` leaves it off; any other value is invalid | Whether a tenant must have a valid `ai.tokens` limit (`saas_os/control_plane/inference/accounting.py`). See below |
| `AI_PRICE_MAX_AGE_SECONDS` | `86400` (24 hours) | an integer, `1` to `86400`; empty means the default | How long a model price counts as current after an operator last confirmed it (`saas_os/control_plane/inference/accounting.py`). It can shorten the 24 hours, never lengthen them. Until Gap 21b no request reads it; with Gap 21b (released in v0.11.0) a budgeted request reads it. See "Model prices" below |
| `AI_INFERENCE_BUDGET_REQUIRED` | unset (off) | as `AI_INFERENCE_TOKEN_QUOTA_REQUIRED`; any other value is invalid (`invalid_ai_inference_budget_required`) | Gap 21b (released in v0.11.0). Whether a tenant must have a monthly AI budget (`saas_os/control_plane/inference/budget.py`). The owner's rule: on in production whenever AI is enabled. See "Monthly AI budget" below |

An invalid value is refused for every request that reads it; nothing is sent and the defaults are not used in its place. The four `AI_EGRESS_*` settings are parsed together at the start of `run_inference`, before authorization: an invalid one fails the request with `InferenceInternalError` (reason `invalid_<variable name in lower case>`). An invalid concurrency limit fails at admission, also with `InferenceInternalError`, and so does an invalid `AI_INFERENCE_TOKEN_QUOTA_REQUIRED` (reason `invalid_ai_inference_token_quota_required`). Until 2026-10-18 an unrecognised value of that setting, a typo such as `ture` included, silently left the requirement off; it now refuses, so a typo can no longer turn the requirement off.

**The token quota is soft.** `ai.tokens`, a plan entitlement, is a monthly (UTC calendar month) limit on input plus output tokens. A request is refused (`InferenceQuotaExceededError`) when the tenant's recorded usage this month, plus an estimate of the request's input and its full `max_output_tokens`, would exceed the limit. Recorded usage is the token counts of this month's settled attempts, provider-reported or estimated. Usage that is unknown, or of attempts still in flight, is not counted, and concurrent requests are checked against the same recorded usage, so together they can overshoot the limit. It is not a hard token cap; a hard cap needs a reservation design (ADR-0054 Q8).

`AI_INFERENCE_TOKEN_QUOTA_REQUIRED` decides what a missing limit means:

- **Off (default):** a tenant whose plan has no `ai.tokens` has no token limit.
- **On:** such a tenant is refused (`quota_not_configured`), so no tenant runs unlimited by omission.
- **Either way:** a present `ai.tokens` that is not a non-negative integer (a string, a float, a negative number, a boolean) refuses the request (`quota_invalid`), and is logged as `ai_token_quota_invalid` with the value's type only. Until 2026-10-31 such a value meant no limit while the setting was off; it now refuses, so a typo in a plan never grants unlimited AI spend. If the entitlements or the usage cannot be read, the request is refused (`quota_unavailable`).

Set it in any deployment where unlimited AI spend for a tenant would be a mistake.

**Model prices: units and age (Gap 21a; released in v0.11.0).** A price in `control_plane.ai_model_prices` gives a rate per million input, output and (optionally) cached-input and cache-write tokens, an optional amount per provider request, and optional rates for other billable units. `estimated_cost` on an attempt is computed from the price in effect when the attempt settles. It is an estimate of platform spend, never an amount a provider invoices, and it is NULL (cost unknown, never zero) when the model has no price, when the token counts are unknown, or when the attempt used a unit the price has no rate for, for example cache-write tokens under a price without a cache-write rate.

A price also records when a platform operator last confirmed it against the provider's own price (`reviewed_at`). `price_status` in `saas_os/control_plane/inference/accounting.py` classifies a price as `fresh`, `stale` (confirmed longer ago than `AI_PRICE_MAX_AGE_SECONDS`, 24 hours at most), `unverifiable` (never confirmed, or confirmed at a time still in the future) or `missing`. **No request is refused on that status yet**: the refusal belongs to the spend limit of a later release, where a spend-controlled request without a fresh price is refused. Two things to know now:

- Every price created before migration `a4c8e1f3b7d5` has no confirmation time and is `unverifiable` until an operator confirms it (`confirm_model_price`; `docs/RUNBOOKS.md`, "AI model prices").
- An invalid `AI_PRICE_MAX_AGE_SECONDS` (not a whole number, `0`, or more than `86400`) makes `price_max_age` and `price_status` raise `InferenceInternalError` (reason `invalid_ai_price_max_age_seconds`). It is never read as "no limit".

**Monthly AI budget (Gap 21b; released in v0.11.0).** A tenant can have a monthly budget of **estimated platform spend**, in one currency and per UTC calendar month: its billing plan's budget (set by a platform operator per plan), replaced by a platform operator's override while one is active, and never above the tenant's own cap. A tenant user holding `ai.budget:manage` can lower the budget with a cap and can never raise it; reading it needs `ai.usage:read` and is audited. The budget limits the platform's own estimate (tokens times the operator's listed rates); it is not what a provider invoices, and the two can differ. It is checked after the token quota, which stays soft and unchanged; a request must pass both.

What your product sees:

- **Refusals** are `InferenceQuotaExceededError` with `reason` `monthly_budget_exhausted` (this attempt's worst case does not fit what remains this month), `budget_pricing_unavailable` (the model's price is missing, in another currency, or not confirmed in the last 24 hours), `budget_currency_conflict` (the budget's parts are in two currencies), `budget_unavailable` (the budget data could not be read) or `budget_not_configured` (`AI_INFERENCE_BUDGET_REQUIRED` is on and the tenant has no budget). Nothing is sent and no attempt is recorded. A retry or fallback candidate is checked again with its own model's price.
- **The worst case** of an attempt counts one token per input byte and all of `max_output_tokens`. Set `max_output_tokens` as tightly as your use case allows: a large value reserves more of the budget while the call runs.
- **Unknown outcomes stay charged.** When a provider call may have been accepted but its result is unknown (a timeout after sending, an interrupted call, a process that died), the attempt's worst case stays counted against the month until a platform operator releases it after checking the provider's records.
- **Warnings (Gap 21c; released in v0.11.0).** A plan budget (operator) or the tenant (with its cap, `warn_thresholds=[50, 80, 100]`) can set warning thresholds, whole percentages of the limit. The first time in a UTC month the tenant's reserved, retained and settled estimate reaches a threshold, SaaS OS sends a webhook event `ai.budget.threshold_crossed` to each of the tenant's webhook subscriptions, with `threshold_percent`, `period_start`, `currency` and `basis` and **no amount**, and writes an audit row. It is sent once per threshold per month, at admission (it counts the request's worst case, so it can come before the spend) or at a settlement that cost more than reserved. Every webhook subscription receives it, because subscriptions have no event filter: make your webhook receiver ignore event types it does not handle. Turning the warning into an email or an inbox item is your product's job. `read_tenant_budget` reports `state` `warning` and `threshold_reached`. SaaS OS sets no thresholds by default.
- **No budget, no change.** A tenant without a plan budget, override or cap is admitted exactly as before, unless `AI_INFERENCE_BUDGET_REQUIRED` is on. Every model a budgeted tenant uses needs a price confirmed within the last 24 hours (`docs/RUNBOOKS.md`, "AI model prices"), or its requests are refused.
- **No HTTP route for budget management, and nothing in `saas_os.inference`.** The functions are in `saas_os.control_plane.inference.budget_admin` (`docs/architecture/AI-INFERENCE-CONTRACTS.md` section 7.4).

**AI usage reporting (Gaps 22a and 22b; released in v0.11.0).** A tenant administrator holding `ai.usage:read` (SaaS OS grants it to no role; bind it to your owner and admin roles) can read the tenant's own AI usage and limits. Python: `saas_os.control_plane.inference.tenant_usage.read_tenant_ai_usage` (attempts, at most 93 days), `read_tenant_ai_monthly_usage` (whole UTC months from the monthly rollup, at most 24; finished attempts only, still counted after their attempt rows are gone) and `read_tenant_ai_limits` (the soft token quota and the monthly budget). HTTP, opt-in:

    from saas_os.api.v1.ai_usage import router as ai_usage_router
    app.include_router(ai_usage_router)

adds `GET /v1/tenants/{tenant_id}/ai/usage?since=&until=&group_by=`, `GET /v1/tenants/{tenant_id}/ai/usage/monthly?since=&until=&group_by=` (released in v0.13.0; owner decision of 2026-11-13: the monthly rollup, whole UTC months, default `group_by=month`) and `GET /v1/tenants/{tenant_id}/ai/limits`. Users only (no API key, no service account, no support access). Every read writes an `ai.usage.read` audit row. Cost is **estimated platform spend** per currency as decimal strings, never an invoice; never sum across currencies. Responses carry no prompt, completion, credential or request id. `docs/architecture/AI-INFERENCE-CONTRACTS.md` sections 7.1, 7.6 and 7.7.

**AI attempt retention (released in v0.13.0; owner decision of 2026-11-13).** Off by default. Attempt rows otherwise grow without bound; to delete old ones, opt in twice. Register the job in your worker and enqueue it on a schedule (daily is enough):

    from saas_os.api.worker import main
    from saas_os.inference.retention import AI_ATTEMPT_RETENTION_JOB_FUNCTIONS

    sys.exit(main(extra_functions=[*my_jobs, *AI_ATTEMPT_RETENTION_JOB_FUNCTIONS]))

    # from a host timer:
    python -m saas_os.inference.retention

and set `AI_ATTEMPT_RETENTION_ENABLED=true` on the worker. `AI_ATTEMPT_RETENTION_DAYS` (default 100, at least 93, so the 93-day usage read stays complete) sets the age. Each run deletes, tenant by tenant, finished attempts that finished before the cutoff and have no budget reservation (a reservation is a financial record and keeps its attempt); a `started` attempt is never deleted. The monthly rollup keeps their totals, so `read_tenant_ai_monthly_usage` and `/ai/usage/monthly` still report them. Each batch writes one `ai.attempts.purged` row into the tenant's audit trail (count, cutoff, period; no attempt id). Importing `saas_os.inference.retention` reads `REDIS_URL`. Whether 100 days fits your legal obligations is your decision; SaaS OS makes no compliance claim. Once anything has been deleted, downgrading below migration `c7d2a9f4e1b6` is refused (`docs/RUNBOOKS.md`, "AI usage reporting").

**AI usage rollup expiry (released in v0.13.0; owner decisions of 2026-11-13; migration `e8a3c6f1d9b4`).** The same job, with its own switch: set `AI_USAGE_ROLLUP_RETENTION_ENABLED=true` to delete monthly rollup rows older than `AI_USAGE_ROLLUP_RETENTION_MONTHS` (default 24, at least 24) whole months before the current UTC month. The two switches are independent; a malformed value in either fails the run before anything is deleted. Each batch writes one `ai.usage_monthly.expired` row into the tenant's audit trail (count, cutoff, period). After expiry, `read_tenant_ai_monthly_usage` and `/ai/usage/monthly` return nothing, or less, for the removed months, with no marker; a window ending at the current month is never affected. The database itself refuses your application role any delete of the current month or the 24 before it. Expired rows cannot be restored; export them first if you need them. Whether 24 months fits your obligations is your decision.

## 13. Checklist for every new table, route and job

- [ ] Table in the product schema, `tenant_id` foreign key, index, `tenant_rls_statements`, explicit grant to the application role.
- [ ] A test that reads the table as one tenant with no tenant predicate and sees only that tenant's rows.
- [ ] Route declares a policy; handler reads `context.tenant_id`; foreign and missing rows both return 404.
- [ ] Tests for: no credential (401), member without the permission (403), another tenant in the path (404).
- [ ] Job registered through `saas_os.infra.jobs`, product-prefixed name, idempotent handler, tenant taken from the context.
- [ ] New tenant-owned data is covered by the purge participant.
- [ ] No top-level package named `saas_os`; every platform import starts with `saas_os.`.

## 14. Upgrading SaaS OS

Read the release's entry in `CHANGELOG.md`, run `saas-os-update check` (`docs/AUTO-UPDATE-CLI.md`), and do the steps below for every release between your pin and the target, in order. Run SaaS OS's migrations before starting the new application and worker.

### From `4197d2f` to v0.1.0 (`dab6357`)

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (migration, authorization, security-control and provider-boundary paths among the changes). No public function your code calls changed its signature; the scaffold's code runs unchanged. What changes for a deployment:

1. **Six additive migrations**, all in SaaS OS's own history: `d3e9a1c47b20` (`core.audit_digests`), `a7f3c91e2d48`, `e4b8c2d6f1a3`, `b8e2d4f6a1c3`, `c5d7e9f1a2b4` (the AI tables in `control_plane`) and `f6a2c8e4b1d9` (the platform-configuration role and its grants). No table, column or row is removed or rewritten. The new head is `f6a2c8e4b1d9`.
2. **The platform-configuration role** (section 5, ADR-0056). `f6a2c8e4b1d9` creates `saas_os_platform_config` (or `PLATFORM_CONFIG_DB_USER`) `NOLOGIN` if it does not exist, which needs `CREATEROLE` on the migration role; without it, create the role yourself first. The migration refuses an existing role that is a superuser, `BYPASSRLS`, `CREATEROLE`, the application role, or a member of it or the reverse. The application and the worker refuse to start if `PLATFORM_CONFIG_DATABASE_URL` or the role's credential is in their environment.
3. **Audit digests** (ADR-0053, `docs/RUNBOOKS.md` "Audit digests"). The production worker runs a new system job every minute that writes one `audit_digest` line per settled window of `core.audit_log` and `core.platform_audit_log` to its log. Defaults: `AUDIT_DIGEST_WINDOW_SECONDS=3600`, `AUDIT_DIGEST_SETTLE_SECONDS=900`, `AUDIT_DIGEST_MAX_WINDOWS_PER_RUN=24`. Before production, ship the worker's log to an append-only store that the database administrators cannot change, alert when the lines stop, and run `python -m saas_os.ops.audit_digest verify` once. Without the external store the digests prove nothing.
4. **New audit actions for the payment page** (ADR-0052): `billing.payment_page_issued`, `billing.payment_page_issued_for_account` and `billing.payment_page_refused`. Update any audit export, report or alert that lists billing actions.
5. **Governed AI inference** (section 12a) is new and opt-in: nothing runs until a product calls `saas_os.inference`, an operator configures a provider, and a plan grants `ai.inference`. A product that uses it qualifies its deployment with `docs/AI-PROVIDER-QUALIFICATION.md` section 3 first.
6. **Rolling back** to `4197d2f` after these migrations: do not run that pin's `saas-os-migrate upgrade`; its history does not contain `f6a2c8e4b1d9` and it exits 1 (`Can't locate revision`) without changing anything. The added tables stay; downgrading the database is a separate decision.

### From v0.1.0 to v0.1.1

No migration (the head stays `f6a2c8e4b1d9`), no changed public signature, no new setting or deployment step. What changes for a product that uses governed AI inference:

1. **Exhausted provider accounts.** An OpenAI-compatible 429 whose `error.code` is `insufficient_quota` is recorded as `provider_quota_exhausted`, not `rate_limited`. It is not retried on the same destination and may fall back; with no destination left, the caller gets `InferenceProviderUnavailableError("provider_quota_exhausted")` instead of `InferenceRateLimitedError`. Update any alert, report or handler that counts `rate_limited` attempts or catches the rate-limit error to detect an account without credit.
2. **Trust entries are re-checked before every attempt.** Revoking a trust entry (`saas-os-operator ai-trust-revoke`) now also stops the retries of requests already running; they end with `destination_changed`.
3. **Rolling back** to v0.1.0 needs nothing beyond moving the pin back: both have the same migration head.

### From v0.1.1 to v0.1.2

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4: architecture, security-control and unknown paths among the changes, all in the webhook delivery code of pull request #70). There is no migration (the head stays `f6a2c8e4b1d9`) and no changed public signature. What changes for a product that uses webhooks:

1. **One 10-second deadline per delivery attempt**, instead of 10 seconds per phase. A receiver that took more than 10 seconds in total, while every phase stayed under 10 seconds, used to succeed; it now fails with `deadline_expired` and is retried by the outbox.
2. **A second address is tried** when connecting to the first fails before anything was sent. A receiver behind several addresses is reached when one of them is down.
3. **`WEBHOOK_ALLOWED_PORTS` is new and optional** (section 4). Leave it unset to keep accepting any port. If you set it, existing subscriptions on other ports are dead-lettered at their next delivery, so list their ports first. An empty or invalid value stops subscription and delivery with `WebhookConfigurationError`.
4. **Rolling back** to v0.1.1 needs nothing beyond moving the pin back: both have the same migration head.

### From v0.1.2 to v0.2.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4: architecture, dependency-toolchain, provider-boundary and unknown paths among the changes; checked against `main` at `43f788f`, the commit before the release pull request). The Compose files, the Caddy configuration, the identity bootstrap and the frontend lock file changed (pull requests #76 and #78), and the release tooling was added (#72). There is no migration (the head stays `f6a2c8e4b1d9`) and no changed public signature. What changes for a deployment that runs SaaS OS's identity topology:

1. **Set `ZITADEL_SESSION_COOKIE_SECRET` before deploying.** `docker-compose.prod.yml` refuses to start without it. Use a random value of at least 32 characters (`openssl rand -base64 32`), keep it in the same secret store as the ZITADEL master key, and give every `zitadel-login` replica the same value. To rotate, list the new value first and the old one after it, comma-separated, then drop the old one once its sessions have expired (`docs/RUNBOOKS.md`, "Self-hosted identity operations", section 11).
2. **Upgrade ZITADEL from v4.19.0 to v4.19.5** in this order: set the secret, take a backup of ZITADEL's database (section 5 of the same runbook), deploy `zitadel`, wait for `/debug/ready`, then deploy `zitadel-login`. Both images move together. Login V2 users sign in again once, because sessions in the old unsigned cookie are refused.
3. **The identity bootstrap reads complete listings.** If `saas-os-local-identity` stops with `IncompleteListingError`, the instance answered a list call with fewer rows than it reported; nothing is created from a partial list. Rerun it once the instance is healthy.
4. **Frontend development dependency only**: vite 8.3.4. Nothing changes in the production frontend image.
5. **Rolling back** to v0.1.2: move the pin back and redeploy `zitadel-login` first, then `zitadel`, from the v0.1.2 Compose file. Restore the backup from step 2 if ZITADEL's own setup steps have already run on v4.19.5 (`docs/DEPLOYMENT-ARCHITECTURE.md` section 6). The secret can stay set; v4.19.0 ignores it.

### From v0.2.0 to v0.3.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4: architecture, dependency-toolchain and unknown paths among the changes; checked against `main` at `8d9ab5d`, the commit before the release pull request). The production Compose file, the `deploy/` units, the certifi floor, the CI and Release workflows and the production check scripts changed (pull requests #81 to #85). There is no migration (the head stays `f6a2c8e4b1d9`) and no changed public signature. What changes:

1. **Your dependency resolver must accept `certifi>=2026.10.19`.** If your product pins or locks certifi below that, raise it.
2. **For a deployment that runs `docker-compose.prod.yml`: create `.env.app` before deploying.** Compose refuses every command on the file without it. Copy `.env.app.example` to `.env.app` next to the Compose file, give it mode `0600`, and move into it every application setting from `.env` (`DATABASE_URL`, `MIGRATIONS_DATABASE_URL`, `REDIS_URL`, `OIDC_*`, Stripe, SMTP, `PLATFORM_TENANT_ID`, `BACKUP_*`). Never copy a `ZITADEL_*` value, `PUBLIC_DOMAIN`, `IDENTITY_PUBLIC_DOMAIN` or `IDENTITY_PROFILE` into it; those stay in `.env`, which now only fills in Compose's `${...}` values.
3. **Reinstall the `deploy/*.service` units** (they now name `.env.app`; the ZITADEL backup unit names both files) and run `systemctl daemon-reload`.
4. **Recreate the services**: `docker compose -f docker-compose.prod.yml up -d --force-recreate backend worker frontend proxy`. `proxy` now waits until `zitadel-login` is healthy.
5. **Check** that `docker compose -f docker-compose.prod.yml exec backend env | cut -d= -f1 | grep '^ZITADEL_'` prints nothing, and the same for `worker`. The full procedure is `docs/RUNBOOKS.md`, "Production configuration files".
6. **Rolling back** to v0.2.0: v0.2.0's Compose file and units read the application settings from `.env` again. If you removed them from `.env` in step 2, put them back first. Then move the pin back, reinstall v0.2.0's `deploy/*.service` units, run `systemctl daemon-reload`, and recreate the four services from the v0.2.0 Compose file. Both releases have the same migration head.

### From v0.3.0 to v0.4.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4: architecture, dependency-toolchain, public-API and unknown paths among the changes; checked against `main` at `a00aed8`, the commit before the release pull request). The email package, the notification email channel, the worker's startup check, the development Compose file and the environment templates changed (pull request #89, ADR-0057). There is no migration (the head stays `f6a2c8e4b1d9`) and no changed public signature: the public changes are additions (`EMAIL_PROVIDER` selection, `MailpitEmailProvider`, `EmailMessage.message_id`, `NotificationPermanentDispatchError` and the new settings). What changes:

1. **Nothing to do if you keep SMTP with TLS.** With `EMAIL_PROVIDER` unset, SMTP is selected exactly as before, and an unset `SMTP_TLS_MODE` still means STARTTLS.
2. **Production with plaintext SMTP must change before upgrading.** If `ENVIRONMENT=production` and you set `SMTP_USE_TLS=false` (or `SMTP_TLS_MODE=none`), email now fails: at send time, and at worker start when `EMAIL_PROVIDER` is set. Either enable TLS, `SMTP_TLS_MODE=starttls` or `implicit` (for a relay that expects TLS from the first byte, usually port 465), or, only for a relay you deliberately reach without TLS, set `SMTP_REQUIRE_TLS=false`. That override permits plaintext; it does not and cannot turn off certificate verification when TLS is used.
3. **Optional: check the configuration at worker start.** Set `EMAIL_PROVIDER=smtp` and `EMAIL_DEFAULT_SENDER` in production; the worker then refuses to start with a missing sender, an invalid setting or half-configured credentials. Never set `EMAIL_PROVIDER=mailpit` there: it is refused outside `development` and `test`.
4. **Outbound connectivity is the deployment's.** In the reference `docker-compose.prod.yml` the worker is on the `internal` network only and cannot reach an external relay (G9, open). A product that sends email must give the worker that route itself (`docs/DEPLOYMENT-ARCHITECTURE.md`).
5. **Development.** `EMAIL_PROVIDER=mailpit` sends to the `mailpit` service of `docker-compose.yml`; captured mail is at `http://127.0.0.1:8025`.
6. **Behavior you may notice.** Every message carries a `Message-ID`; for a notification it is derived from the outbox event id and is the same on every attempt of that event. A permanent SMTP refusal (5xx for the sender, the data, or every recipient) dead-letters the notification event after one attempt instead of retrying. Delivery is still at-least-once: a worker that dies after sending and before recording completion sends again, with the same `Message-ID`.
7. **Rolling back** to v0.3.0: move the pin back; both releases have the same migration head. v0.3.0 ignores `EMAIL_PROVIDER`, `SMTP_TLS_MODE` and `SMTP_REQUIRE_TLS` and knows only STARTTLS or plaintext (`SMTP_USE_TLS`), so a relay you moved to `SMTP_TLS_MODE=implicit` needs its STARTTLS port again before you roll back.

### From v0.4.0 to v0.4.1

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4: dependency-toolchain and unknown paths among the changes; checked against `main` at `7f52be1`, the commit before the release pull request). The paths needing review are `frontend/package.json` and `frontend/package-lock.json` (pull request #92) and `scripts/release.py` (pull request #91). There is no migration (the head stays `f6a2c8e4b1d9`), no changed public signature and no new setting. What changes:

1. **If you build or deploy the SaaS OS frontend, rebuild it from this release.** It now locks `next` 15.5.28, which fixes GHSA-2464-fhr4-w9xw (critical: remote code execution in Image Optimization when SVG files are used) and GHSA-p3m5-59mp-jv5r (high: denial of service with Server Actions). A frontend built from v0.4.0 or earlier still contains 15.5.27. If your product has its own frontend on Next.js 15, move it to 15.5.28 or later independently; SaaS OS's lockfile does not reach it.
2. **Nothing else to do.** The Python package, its dependencies, the Compose files and the settings are unchanged; `scripts/release.py` is SaaS OS's own release tooling.
3. **Rolling back** to v0.4.0: move the pin back. Both releases have the same migration head; a frontend rebuilt from v0.4.0 has the vulnerable Next.js again.

### From v0.4.1 to v0.5.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4: architecture, authorization, dependency-toolchain, tenant-RLS and unknown paths among the changes; checked against `main` at `f5c5880`, the commit before the release pull request). The paths needing review are `saas_os/core/tenancy/__init__.py`, `saas_os/core/tenancy/purge_participants.py` and `saas_os/core/tenancy/service.py` (tenant-RLS, pull requests #94 and #99), `saas_os/core/rbac/__init__.py` (authorization, #98), `saas_os/ops/operator_cli.py` (unknown, #94 and #99), ADR-0050 (architecture, #99) and `scripts/security-exceptions.json` (dependency toolchain, #100: the withdrawn `braces` advisory's exception removed; it is SaaS OS's own `npm audit` gate and does not affect a product). There is no migration (the head stays `f6a2c8e4b1d9`), no new setting and no new deployment step. What changes:

1. **Register purge participants through the public API.** Import `register_purge_participant`, `registered_purge_participant_names` and `TenantPurgeParticipant` from `saas_os.core.tenancy` (section 11). `saas_os.core.tenancy.purge_participants.default_registry().register(...)` still works, but it is not the supported path.
2. **Check your participant names.** Registration now refuses a name outside `[a-z0-9][a-z0-9._-]{0,99}`, or an object without a callable `purge_tenant_data`, with `InvalidTenantPurgeParticipantError` (a `ValueError`). A name such as `MyProduct.Widgets` worked on v0.4.1 and is refused now: rename it, lowercase. The name appears in `tenant.purge_failed` as `participant:<name>`, so old and new failure records use different names. Registering the same object twice is no longer an error.
3. **Use `--setup` with your registration function.** `saas-os-operator purge-tenant --setup my_product.purge:register_purge_participants` now works without building the application. Add a test that `registered_purge_participant_names()` equals the exact tuple you expect (section 11).
4. **Audit readers.** `tenant.purge_completed` may carry `product_participants_skipped: true` (a purge run with `--no-product-participants`); a reader that accepts only a fixed set of keys must allow it. A participant that raises one of Core's exception types is now recorded as `participant_error`.
5. **Optional.** `AuthorityNotAuthorizedError` can be imported from `saas_os.core.rbac`; the class is unchanged.
6. **Rolling back** to v0.4.1: move the pin back. Both releases have the same migration head. Code that imports the new names from `saas_os.core.tenancy` or `saas_os.core.rbac` does not import on v0.4.1, and v0.4.1 does not accept `product_participants_skipped`.

### From v0.5.0 to v0.6.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4; checked against `main` at `5267f14`, the commit before the release pull request, from a copy of the scaffold pinned at v0.5.0: 210 commits; architecture 19, authorization 16, autonomous orchestration 7, billing 2, dependency toolchain 22, documentation 14, internal 11, migration 1, provider boundary 4, public API 10, security control 13, tenant RLS 2, tests 85, unknown 12). Every one of those paths is listed with its pull request in `CHANGELOG.md`, v0.6.0. What a product must do:

1. **Migrate.** Run `saas-os-migrate upgrade head` with the migration role before starting the new code. The head moves from `f6a2c8e4b1d9` to `b3d5f7a9c2e4`, which widens `ck_platform_grants_permission` to twenty-four permissions; it adds no column and rewrites no row.
2. **Grant `platform.outbox:replay` to an existing owner,** if you want operators to replay dead-lettered outbox events: `python -m saas_os.api.platform_bootstrap recover ... --grant platform.outbox:replay` (`docs/RUNBOOKS.md`, "Platform operators"). A new installation's first owner holds it already.
3. **If you deploy the reference stack:** set `ZITADEL_MASTERKEY_FILE` and move the key into that file without a trailing newline (`docs/RUNBOOKS.md`, "Self-hosted identity operations", section 5a); add the `egress-proxy` and `dns-resolver` services and give the worker `EGRESS_PROXY_URL` (ADR-0059); make the SMTP relay reachable on `internal` if you send SMTP.
4. **Stripe:** with `STRIPE_API_KEY` set, install `saas-os[stripe]`; the API and the worker refuse to start without it.
5. **Check the new refusals your code may now meet:** `ApiKeyLimitExceededError` (`409` on the route) above `API_KEY_MAX_PER_USER` (default 50) unrevoked keys per user; `InferenceQuotaExceededError` with `quota_invalid` for a malformed `ai.tokens` entitlement; `TenantParentRuleError` with `parent_suspended` for a move under a suspended parent; a validation error for control characters in stored strings; `InvalidWebhookUrlError` for `http://` destinations when `WEBHOOK_ALLOW_HTTP=false`.
6. **Optional:** raise `RetryAfterEventError` from an outbox consumer when its destination asks to be retried later (bounded by `OUTBOX_RETRY_HINT_MAX_SECONDS`); page `list_tenant_members`, `list_invitations_for_tenant` and `list_api_keys` with `limit` and `offset`; declare `outbox`, `email` or `egress` in a Product Contract.
7. **Check the tag's signature** before pinning: `git tag -v v0.6.0`, and that it resolves to the release commit.
8. **Rolling back** to v0.5.0: move the pin back; the old code runs on the new schema, since the migration only widens a check. To downgrade the schema too, revoke every `platform.outbox:replay` grant first; the downgrade refuses while one exists.

### From v0.6.0 to v0.7.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4; checked against `main` at `96d355d`, the last commit before the release pull request, from a copy of the scaffold pinned at v0.6.0: 213 commits, 231 changed files; architecture 45, authorization 21, billing 1, dependency toolchain 6, documentation 10, internal 22, migration 7, provider boundary 1, public API 6, security control 13, tenant RLS 4, tests 91, unknown 4). Every one of those paths is listed with its pull request in `CHANGELOG.md`, v0.7.0. What a product must do:

1. **Migrate.** Run `saas-os-migrate upgrade head` with the migration role before starting the new code. The head moves from `b3d5f7a9c2e4` to `f0cc2e656d79` through seven revisions. `c5e8a1d3f7b2`, `d7e2a9c4f1b6` and `a9c3e5f7b1d4` widen `ck_platform_grants_permission` to 25, 26 and 28 permissions (a brief `ACCESS EXCLUSIVE` lock on `core.platform_grants` each). `e8f3b1d5a2c7` creates `core.permission_grant_applications`, `a9c3e5f7b1d4` also creates `core.permission_grant_ledger_holds`, and `c3f9e1a7b5d2` creates the approver register and the deletion request, approval and execution authorisation tables. `0420025c3b4b` adds two nullable columns and a `NOT VALID` pair check to `core.outbox_events` under `lock_timeout` 5 s, and `f0cc2e656d79` validates the check. If the lock times out, the whole run rolls back: run it again. If the validation (`f0cc2e656d79`) fails, the database stays at `0420025c3b4b` and the next `upgrade` runs only that revision. No row is rewritten and no column is dropped. Do not apply `f0cc2e656d79` as offline SQL. Run it from the `saas-os-migrate` of the new pin.
2. **Grant the new permissions to an existing owner,** only for the operations you want to run: `platform.webhook_secret:reencrypt`, `platform.permission_grant:apply` and `platform.security_retention:report`, with `python -m saas_os.api.platform_bootstrap recover ... --grant <permission>` (`docs/RUNBOOKS.md`, "Platform operators"). A new installation's first owner holds those three. Nobody holds `platform.security_retention_hold:manage` at bootstrap, on purpose; grant it only by the break-glass route of `docs/RUNBOOKS.md`, "Granting legal-hold management".
3. **`http://` webhook destinations.** Find them before upgrading (the `webhook_http_destination_deprecated` log line of v0.6.0, or the query in `docs/architecture/WEBHOOK-HTTP-DESTINATIONS-ASSESSMENT.md`, section 2) and move them to `https://`, or set `WEBHOOK_ALLOW_HTTP=true` deliberately. With the setting unset or `false`, `subscribe()` raises `InvalidWebhookUrlError` for `http://`, and each delivery to an existing `http://` subscription is dead-lettered at once (`WebhookDestinationRejectedError`, nothing sent). The setting never widens the network: the reference topology's egress proxy allows port 443 only.
4. **`OUTBOX_LEASE_SECONDS` must be 360 or more** (note 7). The default, 900, needs no change.
5. **Audit initiators.** A user initiator is refused in a new audit row (`InvalidActorError`): where your consumer records an audit row for an event a user initiated, pass `initiated_by=None` (stored as `"unavailable"`). Search your outbox consumers and jobs for `record_in_transaction(`, `record_system_action_in_transaction(` and the platform audit writers. The consumer that does not fails on every attempt and its event is dead-lettered after its attempts (`last_error` starts with `InvalidActorError:`; the worker logs `outbox_event_failed`); replay it after the fix. Section 10, "Attributing actions no member performs (system actor)", has the rule, the migration steps and the detection query; `docs/architecture/AUDIT-D2-CALLSITE-AUDIT.md` has the audit of SaaS OS's own call sites.
6. **Webhook receivers** must de-duplicate on `event_id` (section 10; note 5).
7. **Your outbox consumers** that can let a timeout escape are dead-lettered, not retried (note 6).
8. **Public API.** Compare `tests/architecture/public_api_snapshot.txt` with v0.6.0's (`git diff v0.6.0 -- tests/architecture/public_api_snapshot.txt`). Nothing was removed; ten entries changed. Construct `SystemCaller`, `EmailMessage`, `EventExecution`, `OutboxDispatchConfig`, `SystemJobContext` and `TenantJobContext` by keyword: each gained optional fields (`actor`, `idempotency_key`, `initiated_by`, `external_effect_markers`, `system_actor`, `job_id`, and on `TenantJobContext` also `start_external_effect`); a positional call that passed only the old fields still works. `audit_log.record_in_transaction()` takes `initiated_by` and `correlation`, `outbox.append_event()` takes `initiated_by`, and `record_platform_event_in_transaction()` takes `entry_id`, all optional keywords. `saas_os.core.permission_grants` is new.
9. **Leave `OUTBOX_EXTERNAL_EFFECT_MARKERS` unset (off), and do not call `TenantJobContext.external_effect()` yet.** With the markers on, a lost attempt that was marked is dead-lettered (`CrashAfterStart:`), and the retry branches that would let an approved consumer retry it are not built (pull request #214 was open when v0.7.0 was prepared; it is merged and in v0.8.0, see "From v0.7.0 to v0.8.0" below). Turn markers on only after both outbox migrations, once no older dispatcher or worker can claim events (`docs/architecture/OUTBOX-STARTED-MARKER.md`).
10. **Optional operations.** `saas-os-operator reencrypt-webhook-secrets` encrypts legacy plaintext webhook signing secrets, one tenant per run, counting only without `--apply` (`docs/RUNBOOKS.md`). `apply-permission-grants` applies a product's declared permission grant migrations to existing tenants (ADR 0060; `docs/RUNBOOKS.md`). `permission-grant-ledger-retention` and `hold-permission-grant-ledger` report retention eligibility and place legal holds; no command releases a hold. Ledger deletion is disabled: there is no switch for it. `saas-os-operator erase-user --invited-email` and `erase_user_identity(..., invited_emails=...)` also delete the invitations addressed to the person.
11. **Check the tag's signature** before pinning: `git tag -v v0.7.0`, and that it resolves to the release commit.
12. **Rolling back** to v0.6.0: move the pin back, and set `WEBHOOK_ALLOW_HTTP=true` first if you need `http://` destinations again (then replay the deliveries dead-lettered in between by event id). The migrations only add; v0.6.0's code on the new schema was not run for this release. Do not run v0.6.0's `saas-os-migrate upgrade` against a database at the new head: its history does not contain the new revisions and it exits 1 (`Can't locate revision`) without changing anything. A schema downgrade refuses while a ledger, hold, register or approval row exists, or a platform grant names one of the new permissions, and loses the outbox marker values; it is a separate decision.

#### The changes in detail (notes 1 to 10)

1. **Webhook trust through the egress proxy (finding F1).** With `EGRESS_PROXY_URL` set, webhook deliveries verify receivers' certificates against certifi only, as the direct path already did (ADR-0035 amendment of 2026-10-18). `SSL_CERT_FILE` and `SSL_CERT_DIR` on the worker no longer change that trust. **A receiver whose certificate is trusted only through those variables (a private CA) now fails TLS and its deliveries are retried, then dead-lettered.** Give such a receiver a publicly trusted certificate.
2. **One mailbox per address field (finding F3).** `validate_email_address()` and `send_email()` refuse an address containing `,` `;` `:` `<` `>` `"` `(` `)` or `\`, and an ASCII address that is not exactly one RFC 5322 `addr-spec` (for example `a..b@x.com`, `.a@x.com`, `"q"@x.com`, `a(c)@x.com`, `Name <a@x.com>`). These raise `InvalidEmailAddressError` before any provider call. Non-ASCII local parts stay accepted, and so do IPv4 domain literals (`user@[192.0.2.1]`). IPv6 domain literals are refused (`user@[IPv6:::1]` contains `:`), and so is a domain with a trailing dot (`a@b.c.`). (Corrected 2026-11-02: this item first said that domain literals in general stay accepted.) The SMTP provider now names the envelope recipients explicitly. Check stored addresses before upgrading.
3. **Job and outbox timeouts (finding F5).** A job handler that runs past 300 seconds is dead-lettered instead of being dropped by arq; an outbox consumer that runs past 270 seconds dead-letters its event (`ConsumerTimedOut:`) and is never run again automatically; replay it after checking the destination (section 10).
4. **Legacy webhook secrets (finding F7).** A subscription whose signing secret predates encryption logs `webhook_signing_secret_legacy_plaintext` (tenant and subscription ids, never the secret) on each delivery. It keeps working.
5. **Unknown outcomes (finding F5, owner decision of 2026-11-01).** `AmbiguousOutcomeError` is new in `saas_os.core.outbox` and `EmailMessage` has a new optional field, `idempotency_key` (both additive). SMTP: a connection lost or timed out after the relay invited the message data, before its final reply, is dead-lettered (`OutcomeUnknown:`) instead of retried; a failure after the final `250` no longer fails the send. Resend: an ambiguous send is retried with the same key only within 23 hours of the event's creation, then dead-lettered; `409 invalid_idempotent_request` is now permanent; the notification key no longer depends on the sender's domain (a send in flight across the upgrade gets a new key once). Webhooks: write and read timeouts, protocol errors and a deadline after sending are still retried, as at-least-once deliveries on the same `event_id` (`WebhookAmbiguousDeliveryError`, a `WebhookDeliveryError`); receivers **must** de-duplicate on it (section 10). Watch for `outbox_event_outcome_unknown` and `outbox_event_retry_window_closed` in the worker's logs and replay after checking the destination.
6. **A bare timeout from your outbox consumer is dead-lettered, not retried (owner decision D of 2026-11-01; behaviour change for product consumers).** A `TimeoutError` (including `asyncio.TimeoutError`, `socket.timeout`, subclasses) or an `httpx` timeout that escapes an outbox consumer unclassified now dead-letters its event at once with `last_error` `OutcomeUnknown: <type> (unclassified); ...` (log line `outbox_event_outcome_unknown`, `outcome_phase` `unclassified`); before, it was retried with backoff. Before upgrading, find every outbox consumer that can let a timeout escape. Where you know nothing was sent (a refused connection, a connect timeout), raise `saas_os.core.outbox.ConfirmedNotSentError` (new, additive) or mix it into your error class to keep the retry; where the request may have been sent, raise `AmbiguousOutcomeError` with the retry policy the destination supports. Events dead-lettered this way are replayed with `saas-os-operator replay-outbox-events` after checking the destination. Other exceptions, including database and Redis errors whose names mention a timeout, are retried as before (owner decision of 2026-11-02; section 10). SaaS OS has no public API that adds a product's consumer to the outbox dispatcher, so this reaches a product only if it runs its own consumer through the dispatcher anyway; SaaS OS's own consumers already classify their timeouts (note 5). Rolling back restores the retry; rows already dead-lettered stay dead-lettered until replayed.
7. **`OUTBOX_LEASE_SECONDS` must be at least 360 (review of 2026-11-02; compatibility change).** The worker now refuses to start with a shorter lease (`OutboxConfigurationError`). The outbox job may take up to 300 seconds (the consumer's 270-second deadline plus recording its outcome), and a lease shorter than that plus time in the queue let another dispatcher reclaim and run an event again while its first consumer was still sending. The default, 900, is unchanged; raise a smaller value before upgrading.
8. **Outbox job robustness (review of 2026-11-02).** A consumer that turns the dispatcher's cancellation into another error is recorded as `ConsumerTimedOut:` (dead-lettered) instead of being retried. A failed attempt that cannot be recorded is no longer retried by the job, which ran the consumer again at once with the same claim; it logs `outbox_event_outcome_unrecorded` and the event runs again only after its lease expires (section 10).
9. **A notification whose recipient address is invalid is dead-lettered at once (review of 2026-11-02).** The address is part of the event, so no retry can make it valid: such an event is now permanent (`NotificationPermanentDispatchError`) instead of being retried until its attempts run out. This mainly concerns addresses stored before the stricter check of note 2. An invalid `EMAIL_DEFAULT_SENDER` is configuration and keeps the retry: fix it and the pending events go out.
10. **Unknown outcomes outside the outbox, Resend `5xx`, a failed record after a send (review of 2026-11-02).** A directly queued job that raises `AmbiguousOutcomeError` (an SMTP connection lost after the data, an unkeyed Resend send) is dead-lettered at once instead of being retried up to `JOBS_MAX_TRIES` times (unless it declares `at_least_once`). A Resend `5xx` is now an unknown outcome: retried only with the same idempotency key and an identical payload, and only within 23 hours of the event's creation (inside Resend's documented 24-hour idempotency period), and that deadline then bounds every later retry of the event, a `429`'s day-long hint included; unkeyed, it is dead-lettered. A notification e-mail that was sent but whose notification row could not be recorded is dead-lettered (`OutcomeUnknown: record_after_send_... (record)`) instead of being retried, which sent it again. The idempotent-retry deadline in `last_error` is now read only in the exact form SaaS OS writes; any other text containing its marker is stored neutralised, and a malformed deadline counts as already passed (the retry is dead-lettered for an operator).

### From v0.7.0 to v0.8.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4; checked on 2026-11-05 against `main` at `93a0f66`, the last commit before the release pull request, from a copy of the scaffold pinned at v0.7.0 `ee2a64c`: 29 commits, 56 changed paths; architecture 6, authorization 7, dependency toolchain 2, documentation 4, internal 2, migration 1, public API 2, security control 1, tenant RLS 3, tests 27, unknown 1). Every one of those paths is listed with its pull request in `CHANGELOG.md`, v0.8.0. What a product must do:

1. **Migrate.** Run `saas-os-migrate upgrade head` with the migration role before starting the new code. The head moves from `f0cc2e656d79` to `e2b7c4d9a1f6` through one revision. It creates three new, empty tables: `core.platform_audit_subject_links`, `core.platform_audit_subject_erasures` and `core.platform_audit_identity_holds`. The first two reference `core.users`, so creating them takes a `SHARE ROW EXCLUSIVE` lock on `core.users` until the migration transaction ends: writes to `core.users` wait for the few milliseconds it lasts, reads do not. The migration sets `lock_timeout` to 5 seconds, so a long-running writer on `core.users` makes it fail instead of queueing every other writer behind it. **If it times out, nothing was changed: run it again at a quieter moment** (the failure rolls the whole revision back; the database stays at `f0cc2e656d79`). No existing row is read, rewritten or removed, and no column is dropped. Run it from the `saas-os-migrate` of the new pin.
2. **Downgrade guard.** The revision's downgrade refuses (`refusing to drop it`, nothing changed) while any of the three new tables holds a row. On an installation that has recorded any platform action against a user it therefore always refuses, because dropping the link table would make every reference already written to the audit log unresolvable. To move the schema back anyway, the owner must approve it in writing, empty the three tables with the migration role, record the case, and then downgrade (`docs/RUNBOOKS.md`, section 5 of the audit digests chapter). The audit rows keep their references, and older code writes raw ids again. Moving the pin back without a schema downgrade is the usual way back (step 10).
3. **What a platform audit row about a user now stores (a change for everything that reads `core.platform_audit_log` or `GET /v1/platform/audit`).**
   - `target_type` is `user_subject` and `target_id` is a random reference (one per user and UTC day, never derived from the user id) for every platform operation that targets a user, operators included: the user operations, the refusal rows of operator enrolment, the attempt and completion rows of a user lookup, and the refused erasure of an enrolled operator.
   - The metadata key `user_id` of the operator events (enrol, suspend, reactivate, revoke, grant, revoke grant) is now `user_subject_ref`. **A report, dashboard or alert that reads `metadata->>'user_id'` of those events, or filters on a user's raw id as `target_id`, finds the old rows and none of the new ones.** Rows written before the upgrade keep their raw ids and are not rewritten; read both shapes during the transition. To find a user's new rows, resolve through the link table with the migration role (`core.platform_audit_subject_links` maps a reference to a user); no route resolves a reference yet.
   - A request about an id that names no user is recorded with `target_type` `user` and no `target_id` (NULL). A refusal row written while the reference mechanism itself failed also has no target and carries the metadata `{"subject_unavailable": true}`.
   - The platform audit writers (`record_platform_event_in_transaction()`, `record_platform_refusal()`, `recording_platform_refusal()`, `record_oversight_attempt()`, `run_oversight_read()`) refuse a `user` target that carries an id (`InvalidPlatformRequestError`); a user target is passed as the new optional keyword `target_user_id`. Code that calls them with `target_type="user"` and a `target_id` must change.
   - Tenant audit rows, `actor_user_id`, `filters.actor_user_id` of an audit read and the other raw ids are unchanged. In v0.8.0 the permission grant register still wrote `subject_user_id` into the metadata of its platform audit rows; v0.9.0 replaces it with `user_subject_ref` (section 14, "From v0.8.0 to v0.9.0").
4. **A user row that an audit link or erasure marker references cannot be deleted.** The foreign keys from the link and marker tables to `core.users` are `NO ACTION`, so removing such a `core.users` row fails with a foreign-key violation. Core never deletes a user: `erase_user_identity()` (and `saas-os-operator erase-user`) unlinks the user's live references, records an erasure marker, honours legal holds and then erases the identity; `IdentityErasureResult` has two new counts, `platform_references_unlinked` and `platform_references_kept_under_hold` (default 0). A product or a test that removes `core.users` rows directly must first clear that user's rows in `core.platform_audit_subject_links` and `core.platform_audit_subject_erasures` with the migration role, or use the erasure path. Search your code, fixtures and clean-up scripts for direct deletes of `core.users` rows and ORM deletes of `User`. The reference consumer's scenario test needed exactly this change.
5. **After a restore.** A restore to a point before an erasure brings the user's live links back and lacks the marker: run `erase-user` for that user again before serving traffic (`docs/RUNBOOKS.md`, same section).
6. **Outbox retry after a started marker (#214; relevant only if you turn `OUTBOX_EXTERNAL_EFFECT_MARKERS` on or write a consumer that calls `TenantJobContext.external_effect()`).** No migration, and nothing changes while markers are off (the default). With markers on, an attempt that wrote its started marker is now retried, within the attempt budget, with the attempt counted and the marker cleared, in exactly two cases: the consumer raised a `ConfirmedNotSentError` (or an exception group whose every leaf is one) that is the very exception that left the `external_effect()` block, or it raised an `AmbiguousOutcomeError(at_least_once=True)` from the block. Before this release both were dead-lettered `OutcomeUnknown:`. Every other failure after a marker stays dead-lettered: `retry_within` (so Resend), no policy, a bare timeout, the consumer deadline, `RetryAfterEventError` alone, a received `4xx` or `5xx`, a `ConfirmedNotSentError` raised after the block or wrapped around another error, an exception group that also holds anything else, and a crash (`CrashAfterStart:`). The check verifies the form of the statement, not the fact: a consumer that raises `ConfirmedNotSentError` after it has sent causes a duplicate, bounded by the attempt budget (`docs/architecture/OUTBOX-RETRY-AFTER-MARKER-DESIGN.md`, section 15). No SaaS OS consumer calls `external_effect()` yet; leave the setting off unless you have read `docs/architecture/OUTBOX-STARTED-MARKER.md`. SaaS OS's own `at_least_once` declarations are pinned by `tests/architecture/test_at_least_once_declarations.py`; a product that declares it in its own error classes is governed by its own review.
7. **Public API.** Compare `tests/architecture/public_api_snapshot.txt` with v0.7.0's (`git diff v0.7.0 -- tests/architecture/public_api_snapshot.txt`). Nothing was removed; the changes are additive optional parameters and fields: `target_user_id` on the five platform audit writers above, a `target_user_id` field on `OversightOutcome`, an `on_external_effect_failure` field on `TenantJobContext` (construct both by keyword), and three helpers in `saas_os.infra.db` (`current_transaction_isolation()`, `insert_ignoring_conflict_returning()`, `utc_transaction_date()`).
8. **Images.** The base image digests moved (`python:3.13-slim` and `node:22-slim`; #218), and the temporary `apt` upgrade step that v0.7.0 carried (#217, for CVE-2026-109518) is gone because the new digests already contain the fixed `apt`. If you build from this repository's Dockerfiles, rebuild; if you build your own image, update its base as `docs/SECURITY.md`, "Base image digests", describes.
9. **Check the tag's signature** before pinning: `git tag -v v0.8.0`, and that it resolves to the release commit. Pin the commit SHA, never the tag.
10. **Rolling back** to v0.7.0: move the pin back. The migration only adds tables, and v0.7.0's code does not read them, so it should run on the new schema (not run for this release); it writes raw ids again, and rows written meanwhile keep their references. **v0.7.0's erasure does not know the new tables**: it neither unlinks a user's references nor records a marker, so a person erased while you run v0.7.0 on the new schema keeps live references; run `erase-user` again for them after you return to v0.8.0 (step 5). Do not run v0.7.0's `saas-os-migrate upgrade` against a database at the new head: its history does not contain the new revision and it exits 1 (`Can't locate revision`) without changing anything. A schema downgrade is a separate decision (step 2).

### From v0.8.0 to v0.9.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4; checked on 2026-11-06 against `main` at `bb9e233`, the last commit before the release pull request, from a copy of the scaffold pinned at v0.8.0 `140d9dd`: 9 commits, 21 changed paths; architecture 10, documentation 4, internal 1, public API 1, tests 5). The architecture paths are ADR and design status lines; the one internal path is `saas_os/core/permission_grants/register.py` and the public API path is `saas_os/core/email/__init__.py`. Every path is listed with its pull request in `CHANGELOG.md`, v0.9.0. What a product must do:

1. **No migration.** The head stays `e2b7c4d9a1f6`; `saas-os-migrate upgrade head` has nothing to apply. There is no new setting and no new deployment step beyond step 2.
2. **Platform audit rows of the permission grant approver register store a reference, not the user id (a change for everything that reads `core.platform_audit_log` or `GET /v1/platform/audit` for those rows).** Every register write (representative proposal, confirmation, approver enrolment and renewal, revocations) and the replay row of an identical retry now carry the metadata key `user_subject_ref`, the random per-user, per-UTC-day platform reference of the approver or representative the entry is about (the key and mechanism of the operator events in v0.8.0), and no longer carry `subject_user_id`. The row's `target_type` and `target_id` are unchanged: they name the register entry.
   - **A report, dashboard or alert that reads `metadata->>'subject_user_id'` of the `platform.permission_grant_ledger.*` register rows finds the old rows and none of the new ones.** Read both shapes during the transition: `metadata->>'user_subject_ref'` for the new rows and `metadata->>'subject_user_id'` for the old ones. Rows written before the upgrade keep `subject_user_id` and are not rewritten.
   - **To read the reference:** it is a random UUID, never derived from the user id. Resolve it through `core.platform_audit_subject_links` with the migration role (the table maps a reference to a user; no route resolves a reference yet; `docs/RUNBOOKS.md`, "Audit digests", section 5). When the person's identity is erased, the link is removed (unless a legal hold keeps it) and the reference no longer resolves, which is the point of the change.
   - If the reference cannot be obtained, the register write fails and rolls back together with its audit row (same-transaction audit, ADR 0031); nothing is written without it.
   - The register table itself still holds `subject_user_id` (it is the eligibility record, retained for security). Tenant audit rows are unchanged, including `operator_user_id` in the tenant audit metadata of the registered-permission upgrade, which waits for the tenant reference mechanism (audit identity phase P3).
3. **Email: two exported error classes.** `EmailOutcomeUnknownError` and `EmailNotSentError` can now be imported from `saas_os.core.email` (`from saas_os.core.email import EmailOutcomeUnknownError, EmailNotSentError`). They already existed and were raised by the SMTP and Resend providers since v0.7.0; nothing about when they are raised changed. If you handled `EmailProviderError` only, or imported them from `saas_os.core.email.errors` (not public), switch to the public names and catch them **before** `EmailProviderError`: `EmailOutcomeUnknownError` has `phase` and `retry_within` (a `timedelta` only when the provider provably de-duplicates a repeated request for that long, otherwise `None`, which means do not retry automatically, because a retry may deliver the message twice), and `EmailNotSentError` is safe to retry. See section 10 (the email bullet).
4. **Public API.** Compare `tests/architecture/public_api_snapshot.txt` with v0.8.0's (`git diff v0.8.0 -- tests/architecture/public_api_snapshot.txt`): exactly two added lines, the two classes above. Nothing was removed or changed.
5. **Check the tag's signature** before pinning: `git tag -v v0.9.0`, and that it resolves to the release commit. Pin the commit SHA, never the tag.
6. **Rolling back** to v0.8.0: move the pin back. There is no schema change to undo. v0.8.0 writes `subject_user_id` into the register's audit rows again; rows written meanwhile keep their references.

### From v0.9.0 to v0.10.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4; checked on 2026-11-07 against `main` at `20db944`, the last commit before the release pull request, from a copy of the scaffold pinned at v0.9.0 `fb08e47`: 17 commits, 28 changed paths; architecture 6, dependency toolchain 4, documentation 2, internal 6, public API 1, security control 1, tests 8). The one public API path is `saas_os/core/email/__init__.py`; the security control path is `saas_os/infra/egress/client.py`; the six internal paths are the email package (`errors.py`, `headers.py` (new), `provider.py`, `resend_provider.py`, `service.py`, `smtp_provider.py`); the dependency toolchain paths are `.secrets.baseline` and three files of the Docker egress gate under `scripts/egress_e2e/`. Every pull request is listed in `CHANGELOG.md`, v0.10.0. What a product must do:

1. **No migration.** The head stays `e2b7c4d9a1f6`; `saas-os-migrate upgrade head` has nothing to apply. There is no new setting and no deployment step. If you change nothing in your code, nothing about your sends or your egress calls changes.
2. **`StrictEgressClient.get` (issue 205, first step; optional).** `StrictEgressClient` gains `get(url, *, headers, deadline)`, a `GET` with no body that has exactly `post`'s policy (one private request method serves both). `post` and every other egress name are unchanged. The AI adapters' `EgressClient` protocol still declares only `post`: an adapter that needs `get` takes a `StrictEgressClient` (or its own protocol), not that protocol. The cap on a response stays per client, and there is no `delete`, no host allowlist and no per-call cap. Read "Reading from a provider with `StrictEgressClient.get`" in section 4 before you build a reader; in particular, validate any identifier before it goes into a path and send a credential only to a URL you built from your own constant host. Nothing here is a Resend read adapter or a sending-domain interface; those are not built (issues 205 `delete` and 225 are open).
3. **Email headers (issue 224; optional).** `EmailMessage` gains four defaulted, `repr=False` fields, declared after the existing ones, so existing construction is unchanged: `list_unsubscribe`, `list_unsubscribe_post`, `in_reply_to` and `references`. `InvalidEmailHeaderError` is exported from `saas_os.core.email`. What to know before you use them (the full table is in section 4, "Email headers: unsubscribe and threading"):
   - **Types and form.** Each of `list_unsubscribe`, `in_reply_to` and `references` is a `tuple[str, ...]` (a list is refused). `list_unsubscribe` takes URIs without angle brackets (SaaS OS adds them); `in_reply_to` and `references` take ids with angle brackets, `<id@host>`.
   - **`list_unsubscribe` rules.** At most one `https` and one plain `mailto:` URI; the message must have exactly one recipient; at most 2048 characters per URI, and short enough for one header line of 998 characters; no `< > " \ ,` or space, lower-case scheme, no userinfo.
   - **`list_unsubscribe_post=True`** sends `List-Unsubscribe=One-Click` (the only value) and is refused unless `list_unsubscribe` has an `https` URI.
   - **Validation errors.** A bad value raises `InvalidEmailHeaderError` from `send_email()` before any provider call, with a message that names the rule and never the value. It subclasses `InvalidEmailAddressError`, so an existing `except InvalidEmailAddressError` also catches it: if that clause treats the error as a bad recipient address, tell the two apart. The adapters refuse CR, LF and NUL in these values when called directly.
   - **Idempotency.** Derive the values from the logical message (recipient and campaign), never a fresh random part per attempt: Resend compares the request body under the `Idempotency-Key`, and a retry with a different value is refused with `409` and dead-lettered.
   - **The URI is a capability.** Do not log it or put it in audit metadata; `repr(EmailMessage)` leaves the four fields out for that reason.
4. **SMTP: the encoded-word fix (visible only when you use the new fields).** The SMTP provider (and Mailpit) writes the four headers verbatim through a private header policy. Before this change, the standard library would have rewritten a long `List-Unsubscribe` URI (about 50 characters or more) as an RFC 2047 encoded word, which a receiver cannot follow. A message that sets none of the four fields is written exactly as before. Check one received message's raw headers in staging, and note that the Resend request body gains a `headers` entry only for a message that uses the fields.
5. **What SaaS OS does not guarantee.** The headers are well formed; that is all. No RFC 8058 compliance is claimed: RFC 8058 also needs a DKIM signature covering `List-Unsubscribe` and `List-Unsubscribe-Post`, which the relay or Resend applies after SaaS OS hands the message over and SaaS OS cannot sign or check. Whether your relay or Resend covers those headers, how receivers treat the message, and deliverability are not verified. SaaS OS cannot know that a message id exists or that your unsubscribe endpoint works; the endpoint, the suppression list and consent are the product's.
6. **Public API.** Compare `tests/architecture/public_api_snapshot.txt` with v0.9.0's (`git diff v0.9.0 -- tests/architecture/public_api_snapshot.txt`): three lines change, all additive (the `EmailMessage` field list gains four names, `InvalidEmailHeaderError` is new, `StrictEgressClient` gains `get`). Nothing was removed.
7. **Check the tag's signature** before pinning: `git tag -v v0.10.0`, and that it resolves to the release commit. Pin the commit SHA, never the tag.
8. **Rolling back** to v0.9.0: move the pin back. There is no schema change to undo. A product that already sends the new `EmailMessage` fields or calls `get` must stop first: under v0.9.0 the fields do not exist (a keyword argument raises `TypeError`) and `StrictEgressClient` has no `get` (`AttributeError`). Messages already sent keep their headers; v0.9.0's SMTP provider would never have produced them.

### From v0.10.0 to v0.11.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4; checked on 2026-11-12 against `main` at `ee6ce77`, the last commit before the release pull request, from a copy of the scaffold pinned at v0.10.0 `0f9bf4d`: 41 commits, 93 changed paths: tests 40, provider boundary 15, architecture 10, migration 6, authorization 5, documentation 5, dependency toolchain 3, tenant RLS 3, billing 2, public API 2, unknown 2). Review is required: there are migrations, new permissions and a change to the authorization and tenancy registries.

1. **Six migrations; run them at low traffic.** The head moves from `e2b7c4d9a1f6` to `c7d2a9f4e1b6` through `c8e5a2f7d1b3`, `b3d6f8a1c5e7`, `d2f7a9c4e6b8`, `a4c8e1f3b7d5`, `f1b9d3e7a5c2` and `c7d2a9f4e1b6`. The last one fills the monthly AI usage rollup from the finished attempts while holding `control_plane.ai_inference_attempts` in `SHARE ROW EXCLUSIVE` mode: AI requests that start or finish during it wait; reads do not (`docs/RUNBOOKS.md`, "AI usage reporting"). On 2026-11-12, as a migrations role that is neither superuser nor `BYPASSRLS`, v0.10.0 to head took under 2 seconds with 4,500 attempts.
2. **Nothing changes until you configure it.** With no budget, no hold and the two new settings unset, AI requests behave as under v0.10.0; the only new effect is that a finished attempt is also counted in `control_plane.ai_usage_monthly`.
3. **New settings (optional).** `AI_PRICE_MAX_AGE_SECONDS` (default `86400`): how long a confirmed price counts as fresh. `AI_INFERENCE_BUDGET_REQUIRED` (default `false`): when `true`, a tenant whose plan has no budget and that has no override or cap is refused (`budget_not_configured`). Turn it on, as the owner's rule asks for production, only after every AI-enabled plan has a budget (`docs/RUNBOOKS.md`).
4. **New permissions, granted to no role by SaaS OS.** Tenant: `ai.usage:read` (`read_tenant_ai_usage`, `read_tenant_ai_monthly_usage`, `read_tenant_ai_limits` and the HTTP router) and `ai.budget:manage` (the tenant's own cap). Platform: `platform.ai_tenant_hold:manage` and `platform.ai_budget:manage`. Bind the tenant permissions to your owner and admin roles (section 8, `apply-permission-grants` for existing tenants) and grant the platform ones to operators.
5. **The AI HTTP router is opt-in.** `from saas_os.api.v1.ai_usage import router as ai_usage_router` and `app.include_router(ai_usage_router)` add `GET /v1/tenants/{tenant_id}/ai/usage` and `/ai/limits` (users only, `ai.usage:read`). `build_platform_app()` does not mount them. See "AI usage reporting" in section 12a.
6. **Public API.** Compare `tests/architecture/public_api_snapshot.txt` with v0.10.0's (`git diff v0.10.0 -- tests/architecture/public_api_snapshot.txt`): two lines are added (`saas_os.core.billing.entitlement_plan_ids`, `saas_os.core.platform_authority.run_tenant_platform_change`), nothing changes or goes. The AI functions are documented in `docs/architecture/AI-INFERENCE-CONTRACTS.md`.
7. **Check the tag's signature** before pinning: `git tag -v v0.11.0`, and that it resolves to the release commit. Pin the commit SHA, never the tag.
8. **Rolling back** to v0.10.0: downgrade SaaS OS's migrations to `e2b7c4d9a1f6` first, then move the pin back. The downgrade of `f1b9d3e7a5c2` refuses while any budget row or a grant of `platform.ai_budget:manage` exists, and the downgrade of `c8e5a2f7d1b3` refuses while any hold or a grant of `platform.ai_tenant_hold:manage` exists: export and remove them deliberately first. The rollup is dropped and rebuilt from the attempts on a later upgrade.

### From v0.11.0 to v0.12.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4; checked on 2026-11-13 against `main` at `67e2ab4`, the last commit before the release pull request, from a copy of the scaffold pinned at v0.11.0 `2158a81`: 12 commits, 24 changed paths: architecture 6, tests 6, documentation 5, internal 3, dependency toolchain 2, security control 1, unknown 1). Review is required for the job retry change below; there is no migration (the head stays `c7d2a9f4e1b6`), no new setting and no new permission.

1. **Directly queued jobs retry less (#260).** This affects only jobs your product queues itself with `register_tenant_job` / `register_system_job`. Outbox consumers are unchanged. A job is now dead-lettered on its first attempt, logged as `job_not_retried`, instead of being retried up to `JOBS_MAX_TRIES`, when it raises:
   - `saas_os.core.outbox.PermanentEventError`, or one of its subclasses (the notification, webhook and usage permanent errors);
   - `saas_os.core.email.EmailOutcomeUnknownError` from `send_email()`, with or without `retry_within`;
   - an exception group holding an `AmbiguousOutcomeError` (or any `NonRetriableJobError` that is not `job_retry_safe`), or one whose every error is permanent.

   If a job of yours relied on those retries, catch the error in the job and decide there. For an e-mail whose outcome is unknown, check with the provider before sending again.
2. **Public API.** Compare `tests/architecture/public_api_snapshot.txt` with v0.11.0's (`git diff v0.11.0 -- tests/architecture/public_api_snapshot.txt`): two lines change, nothing is added or removed. `EmailOutcomeUnknownError` gains the base class `NonRetriableJobError` and `PermanentEventError` gains `PermanentJobError` (`saas_os.infra.jobs.errors`). Constructors and attributes are unchanged; `except EmailProviderError` and `except PermanentEventError` catch the same errors as before.
3. **Check the tag's signature** before pinning: `git tag -v v0.12.0`, and that it resolves to the release commit. Pin the commit SHA, never the tag.
4. **Rolling back** to v0.11.0: move the pin back. There is no migration to undo.

### From v0.12.0 to v0.13.0

`saas-os-update check` reports `REVIEW_REQUIRED` for this move (exit 20, policy version 4; checked on 2026-11-14 against `main` at `2d53257`, the last commit before the release pull request, from a copy of the scaffold pinned at v0.12.0 `c17c7b4`: 8 commits, 23 changed paths: tests 8, documentation 4, provider boundary 4, architecture 3, migration 2, public API 2). Review is required for the migration and the new opt-in AI retention below; there is no new permission.

1. **Migrate first.** Run SaaS OS's migrations to `e8a3c6f1d9b4` before starting the new code. It grants your application role DELETE on `control_plane.ai_usage_monthly` behind a trigger that refuses the current UTC month and the 24 before it; no row changes.
2. **Nothing else changes until you opt in.** The new monthly usage route is served only if you register `saas_os.api.v1.ai_usage.router` (`GET /v1/tenants/{tenant_id}/ai/usage/monthly`). The AI retention job deletes nothing unless you add `AI_ATTEMPT_RETENTION_JOB_FUNCTIONS` (`saas_os.inference.retention`) to your worker, enqueue it, and set `AI_ATTEMPT_RETENTION_ENABLED=true` (attempts) or `AI_USAGE_ROLLUP_RETENTION_ENABLED=true` (monthly rollup). Section 12a's "AI attempt retention" and "AI usage rollup expiry" paragraphs describe the settings, limits and audit rows. Decide the periods against your own obligations, and export data you need before enabling: nothing deleted can be restored.
3. **Public API.** `tests/architecture/public_api_snapshot.txt` is unchanged from v0.12.0. The new entry points are the module `saas_os.inference.retention`, the route and the four settings `AI_ATTEMPT_RETENTION_ENABLED`, `AI_ATTEMPT_RETENTION_DAYS`, `AI_USAGE_ROLLUP_RETENTION_ENABLED` and `AI_USAGE_ROLLUP_RETENTION_MONTHS`.
4. **Check the tag's signature** before pinning: `git tag -v v0.13.0`, and that it resolves to the release commit. Pin the commit SHA, never the tag.
5. **Rolling back** to v0.12.0: stop enqueuing the retention job, downgrade SaaS OS's migrations to `c7d2a9f4e1b6` first (this revokes the DELETE grant and drops the trigger), then move the pin back. Rows the job deleted stay deleted. Going further, below `c7d2a9f4e1b6`, is refused once any attempt has been deleted (`docs/RUNBOOKS.md`, "AI usage reporting").

## 15. Product deployment checklist

SaaS OS is a library; each product qualifies its own deployment (ADR-0015). Before production, with evidence kept by the product:

- [ ] **Databases and Redis.** `docs/RUNBOOKS.md` "Production external PostgreSQL and Redis", section 8: TLS (`sslmode=verify-full`, `rediss://`), the three database roles of section 5, SaaS OS's and your migrations at head, `/readyz` 200.
- [ ] **Redis `noeviction`.** Keep the default policy (`docs/RUNBOOKS.md`, Redis configuration): an eviction policy can drop queued jobs.
- [ ] **Identity.** ZITADEL bootstrapped and its OIDC configuration verified (`docs/RUNBOOKS.md` "Self-hosted identity operations", sections 1 and 8); the bootstrap token handled as section 10 says.
- [ ] **Operator second factor.** Each platform operator enrolled with TOTP or a user-verified passkey, the organization's login policy set to `forceMfa`, and one login checked to record `multi_factor = true` (`docs/RUNBOOKS.md` "Platform operators", section 1). If every operator is refused, the ID tokens carry no `amr`.
- [ ] **Backups.** Encrypted, off-host backups of the database and of ZITADEL's database, and one restore drill into an isolated target (`docs/BACKUP-RESTORE.md`; ADR-0023 phase 4). After any restore, follow `docs/RUNBOOKS.md` "Audit digests", section 3.
- [ ] **Audit digests.** The worker's log shipped to an append-only store whose administrators hold no tier-0 database credential, an alert on missing `audit_digest` lines, and one successful `python -m saas_os.ops.audit_digest verify` (`docs/RUNBOOKS.md` "Audit digests").
- [ ] **Billing.** If you use Stripe: the webhook endpoint registered and its signing secret injected as a secret (section 9, billing-provider events).
- [ ] **Diagnostics.** No error tracker, APM agent or debugger integration in the worker or API process captures local variables, checked with a failing test delivery as section 10 ("Diagnostics in worker and API processes") says.
- [ ] **AI inference.** If you use it: D1 to D14 of `docs/AI-PROVIDER-QUALIFICATION.md` section 3 in your non-production deployment.
