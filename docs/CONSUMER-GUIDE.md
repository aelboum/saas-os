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
3. Install: `pip install -e .` The scaffold depends on plain `saas-os`. Add an extra to the dependency only for an integration you use: `saas-os[stripe]` for the Stripe billing adapter, `saas-os[s3-backup]` for the S3-compatible backup destination, `saas-os[all]` for both (ADR-0041). Without the extra, the adapter raises an `ImportError` that names it.

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

**Releases.** A SaaS OS release is a version number in `pyproject.toml`, an annotated tag `v<version>` on a commit of `main`, and an entry in `CHANGELOG.md` that names the commit's full SHA (ADR-0015, "Release labels"). The tag is a name for people; the pin is still the commit SHA the tag points to. Before pinning a release, check that the tag still resolves to the SHA in `CHANGELOG.md` (`git ls-remote https://github.com/aelboum/saas-os refs/tags/v<version>^{}`); a tag that has moved is an incident, not a new release.

**The scaffold's pin.** It names `c7d8987`, `main` after pull request #65, released as v0.1.1 (`CHANGELOG.md`); before it, `dab6357`, `main` after pull request #61, released as v0.1.0. Since `4197d2f`, the pin before those, it adds audit digests (ADR-0053), audit rows for the payment page, and governed AI inference (ADR-0054 to ADR-0056); section 14 lists what a product on `4197d2f` must do to move. `4197d2f` was `main` after pull request #43 and the first published commit with everything the rest of this guide relies on, including the payment page for a subscription (ADR-0052), Stripe subscriptions for a payer without a payment method (pending until paid) whose renewals are charged to the card that paid, billing-provider events (ADR-0048), multi-factor login for platform operators (ADR-0049), the `saas-os-operator` commands (ADR-0050), API-key request authentication on routes that opt in (ADR-0047) and the invitation acceptance router (ADR-0046): the `saas_os` import root (ADR-0038), the worker's `extra_functions` seam (ADR-0039), the optional extras (ADR-0041), and ADR-0045's platform authority -- the required `caller` on tenant lifecycle, purge and feature-flag functions, the opt-in platform-admin router, and the rule that only a user someone can log in as is enrolled as an operator. Do not pin anything older: code written against this guide does not run on it. CI proves the scaffold against a wheel built from the SaaS OS working tree (`tests/test_consumer_scaffold_integration.py`); a clean install of the pinned commit is a recorded manual proof.

Move the pin with `saas-os-update` (`docs/AUTO-UPDATE-CLI.md`). It classifies what changed between the two commits and applies only changes its policy marks safe; migrations, authorization, tenancy, billing and anything unknown require your review.

## 4. Configuration

Configuration is environment variables. Secrets and connection strings (`DATABASE_URL`, `MIGRATIONS_DATABASE_URL`, `REDIS_URL`, OIDC, Stripe, SMTP) are resolved through SaaS OS's secrets provider: a `.env` file when `ENVIRONMENT=development`, the process environment otherwise. Non-secret tunables such as `APP_DB_USER` and `JOBS_MAX_TRIES` are read from the process environment directly, in every environment, so a value present only in `.env` is ignored for them. The minimum for the application and the worker:

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

`.env.example` in the SaaS OS repository documents the deployment variables, including billing, email and backup. A few tunables are documented only where they are read (for example `OUTBOX_POLL_SECONDS`, `SECRETS_ENV_FILE`).

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

## 9. Routes

Build the application on `build_platform_app` and mount your routers on top:

<!-- source: examples/consumer-scaffold/my_product/app.py -->
```python
def create_app() -> FastAPI:
    app = build_platform_app(title="My Product", version="0.1.0")
    app.include_router(items_router)
    register_purge_participant()
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
- **Every call Core authorizes is recorded** in `core.platform_audit_log`, which no tenant can read: a read leaves an attempt row and a completion row, a change leaves a row in the same transaction, and a refusal for want of authority or by an invariant leaves a `denied` row (best effort). A change to a tenant also leaves a row in that tenant's own audit trail, so its administrators see that the platform acted on them; a read does not. Not recorded: a caller who is not an operator, and a request rejected as invalid (`400`, `422`) or as not fitting the resource's state (`404`, `409` with a state reason).
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
    # Imported here: registering a job resolves REDIS_URL.
    from my_product.jobs import JOB_FUNCTIONS

    return main(argv, extra_functions=JOB_FUNCTIONS)
```

`python -m my_product.worker` replaces `python -m saas_os.api.worker`; do not run both. It keeps every platform job (webhook delivery, usage ingestion, notifications, session cleanup, the outbox dispatcher), the fail-closed database-role guard and the `--check` health probe.

Rules:

- **Delivery is at-least-once.** A handler must be idempotent.
- **Prefix job names with your product's name.** The worker refuses to start if one of your jobs shares a name with a platform job or with another of your jobs, or was not built by `register_tenant_job` / `register_system_job` (or `system_cron` for a schedule).
- **Never choose the tenant from `payload.data`.** A payload whose `tenant_id` is not a valid UUID is dead-lettered before the handler runs.
- Failures are retried with exponential backoff (`JOBS_MAX_TRIES`, default 3) and then dead-lettered.
- The queue is as durable as your Redis. Configure Redis persistence in production.
- A scheduled job is a system job (`register_system_job`) wrapped with `saas_os.infra.jobs.queue.system_cron` and passed as `extra_cron_jobs`.

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

The contract:

- **Idempotent.** It runs again on every retry, including after it already succeeded.
- **Fails by raising.** Core then leaves the tenant in `PURGING` and records only the participant's name and the exception type.
- Register it in every process that can run `purge_tenant()`. The scaffold registers it in `create_app()`.
- **Running a purge.** It is an operator-run call with no route: `purge_tenant(tenant_id, caller=SystemCaller(SystemAuthority.TENANT_PURGE), actor_user_id=<the person running it>)`, on a tenant an operator already marked deleted. The packaged command does the same: `saas-os-operator purge-tenant --tenant <id> --actor <user id> --setup my_product.app:create_app --confirm <id>`, where `--setup` registers your participants first (ADR-0050). No other caller is accepted, including a platform operator; each transition is recorded in the platform audit, and `actor_user_id` names who ran it.
- Deleting is a choice. Anonymizing or retaining is valid if it is your documented policy.

## 12. First tenant

Creating the first tenant and its first administrator is an operator command of the installed package, not an HTTP route:

```
python -m saas_os.api.tenant_bootstrap --help
```

See `docs/RUNBOOKS.md`, "First-tenant bootstrap".

## 12a. Governed AI inference

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

An invalid value is refused for every request that reads it; nothing is sent and the defaults are not used in its place. The four `AI_EGRESS_*` settings are parsed together at the start of `run_inference`, before authorization: an invalid one fails the request with `InferenceInternalError` (reason `invalid_<variable name in lower case>`). An invalid concurrency limit fails at admission, also with `InferenceInternalError`, and so does an invalid `AI_INFERENCE_TOKEN_QUOTA_REQUIRED` (reason `invalid_ai_inference_token_quota_required`). Until 2026-10-18 an unrecognised value of that setting, a typo such as `ture` included, silently left the requirement off; it now refuses, so a typo can no longer turn the requirement off.

**The token quota is soft.** `ai.tokens`, a plan entitlement, is a monthly (UTC calendar month) limit on input plus output tokens. A request is refused (`InferenceQuotaExceededError`) when the tenant's recorded usage this month, plus an estimate of the request's input and its full `max_output_tokens`, would exceed the limit. Recorded usage is the token counts of this month's settled attempts, provider-reported or estimated. Usage that is unknown, or of attempts still in flight, is not counted, and concurrent requests are checked against the same recorded usage, so together they can overshoot the limit. It is not a hard token cap; a hard cap needs a reservation design (ADR-0054 Q8).

`AI_INFERENCE_TOKEN_QUOTA_REQUIRED` decides what a missing or malformed limit means:

- **Off (default):** a tenant whose plan has no `ai.tokens`, or a value that is not a non-negative integer (a string, a float, a negative number, a boolean), has no token limit. A malformed value is logged as `ai_token_quota_invalid`, with the value's type only.
- **On:** such a tenant is refused (`quota_not_configured`), so no tenant runs unlimited by omission or by a typo.
- **Either way:** if the entitlements or the usage cannot be read, the request is refused (`quota_unavailable`).

Set it in any deployment where unlimited AI spend for a tenant would be a mistake.

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

## 15. Product deployment checklist

SaaS OS is a library; each product qualifies its own deployment (ADR-0015). Before production, with evidence kept by the product:

- [ ] **Databases and Redis.** `docs/RUNBOOKS.md` "Production external PostgreSQL and Redis", section 8: TLS (`sslmode=verify-full`, `rediss://`), the three database roles of section 5, SaaS OS's and your migrations at head, `/readyz` 200.
- [ ] **Redis `noeviction`.** Keep the default policy (`docs/RUNBOOKS.md`, Redis configuration): an eviction policy can drop queued jobs.
- [ ] **Identity.** ZITADEL bootstrapped and its OIDC configuration verified (`docs/RUNBOOKS.md` "Self-hosted identity operations", sections 1 and 8); the bootstrap token handled as section 10 says.
- [ ] **Operator second factor.** Each platform operator enrolled with TOTP or a user-verified passkey, the organization's login policy set to `forceMfa`, and one login checked to record `multi_factor = true` (`docs/RUNBOOKS.md` "Platform operators", section 1). If every operator is refused, the ID tokens carry no `amr`.
- [ ] **Backups.** Encrypted, off-host backups of the database and of ZITADEL's database, and one restore drill into an isolated target (`docs/BACKUP-RESTORE.md`; ADR-0023 phase 4). After any restore, follow `docs/RUNBOOKS.md` "Audit digests", section 3.
- [ ] **Audit digests.** The worker's log shipped to an append-only store whose administrators hold no tier-0 database credential, an alert on missing `audit_digest` lines, and one successful `python -m saas_os.ops.audit_digest verify` (`docs/RUNBOOKS.md` "Audit digests").
- [ ] **Billing.** If you use Stripe: the webhook endpoint registered and its signing secret injected as a secret (section 9, billing-provider events).
- [ ] **AI inference.** If you use it: D1 to D14 of `docs/AI-PROVIDER-QUALIFICATION.md` section 3 in your non-production deployment.
