# AI inference — threat model and safe egress

Status: written as Proposed (2026-10-16), Phase AI-A; companion of ADR-0054 and ADR-0055, Accepted 2026-10-18 (section 6 records the mitigations as implemented); reconciled three times with owner decisions on 2026-10-16. Companion to [ADR-0054](../ADR/0054-governed-ai-inference-subsystem.md) and [ADR-0055](../ADR/0055-ai-data-governance-and-destination-authorization.md). When written (2026-10-16) no control described here existed in code; section 6 records the mitigation status since the implementation was merged (pull request #53, 2026-10-17). Labels follow ADR-0054 section 12: "approved owner decision", "approved in principle" and "established requirement" are owner positions of 2026-10-16, and none means implemented; "candidate value" is not policy; everything else is proposed. Webhook behaviour is not changed by anything here. Statements marked **verified** were read at `7ab9422`.

## 1. Scope and assets

In scope: the inference subsystem (proposed on 2026-10-16, implemented since 2026-10-17: internal implementation `saas_os.control_plane.inference`; public interface `saas_os.inference`, ADR-0054 Q11, settled in section 3a), its configuration, its outbound HTTP path (`saas_os.infra.egress`), and the existing webhook egress code it would share.

| Asset | Why it matters |
|---|---|
| Tenant content sent in requests | Leaving the installation is irreversible (ADR-0013) |
| Provider credentials | Spend, provider-side data access, reputational harm |
| Internal network reachable from the worker and backend | SSRF to databases, Redis, ZITADEL, metadata services |
| Usage ledger and quota state | Billing and fairness between tenants |
| Configuration (providers, aliases, trust entries, policy) | Changing it changes where data goes |
| Audit evidence | Required by ADR-0013 invariant 7, ADR-0031, ADR-0045 |

## 2. Actors and trust

| Actor | Trust |
|---|---|
| Tenant user / service account calling a product feature | Authenticated, authorized per tenant; untrusted content |
| Product code in the same process | Trusted (ADR-0045 section 1); can mislabel within its own declared ceilings (ADR-0055 section 4) |
| Platform operator | Holds explicit platform grants; must not reach tenant data |
| Provider / gateway / custom endpoint | Untrusted: responses, headers, redirects, timing, usage numbers |
| DNS | Untrusted between validation and connection |
| Tier-0 (host, database owner, ZITADEL `IAM_OWNER`) | Outside the boundary (ADR-0045 constraint 7) |

## 3. Threats and controls

Each row: threat → proposed control → phase. "Verified gap" marks something true of today's code.

### 3.1 Bypass of governance

| Threat | Control | Phase |
|---|---|---|
| A product or SaaS OS module calls a provider directly | Import contracts (ADR-0054 section 3): the AI SDK list is forbidden for `saas_os.control_plane` outside the adapters, for `saas_os.inference` and for `products`; `inference.adapters` is importable only by the internal package. Verified gap: today only Core, Infra and `data_authorization` are covered. Consumers outside this repository are bound by documentation | AI-B |
| A product imports the internal implementation and skips the public interface | Products use only a supported public interface (approved owner decision). A direct-import contract on `products` and an architecture test over `examples/` would forbid `saas_os.control_plane.inference`. The interface itself is undecided (Q11) | AI-D, after Q11 |
| A public interface becomes a way around the package boundary | Existing boundaries are not weakened (approved owner decision): F2, a facade that lets `saas_os.api` reach Control Plane behaviour indirectly, is not approved. Import rules are not changed to make a design pass (ADR-0054 section 3) | Q11 |
| A product obtains a credential or raw client | No API returns a client or credential; adapters are not exported | AI-B/D |
| Caller passes another tenant's id | Authorization of the typed caller at that tenant (`can()` / `authorize_caller`); `ServiceAccountCaller` is tenant-bound; `SystemCaller` refused | AI-D |

### 3.2 DNS resolution and rebinding

- Verified (webhooks): every A/AAAA answer is checked; one non-public answer rejects the destination; the connection is made to the validated IP, so httpcore never resolves again (`saas_os/core/webhooks/service.py:264-316, 319-368`).
- Verified gaps: `socket.getaddrinfo` is blocking inside `async def` (stalls the worker loop); the chosen address is the lexicographically first, with no fallback to other validated addresses.
- Proposed: resolve with the event loop's resolver (`loop.getaddrinfo`) under the request deadline; validate all answers; try validated addresses in resolver order (Happy-Eyeballs style, bounded); re-resolve and re-validate on every new connection, never cache validation past the connection.

### 3.3 Address classification

- Verified predicate (`service.py:210-234`): refuses anything not `is_global`, plus private, loopback, link-local (including `169.254.169.254`), unspecified, reserved, multicast, IPv6 site-local, and checks IPv4 embedded in IPv4-mapped, NAT64 `64:ff9b::/96` and 6to4 `2002::/16`. CGNAT `100.64.0.0/10` is refused through `is_global`.
- Verified discrepancy: ADR-0035 says NAT64 is "refused outright on the Python in use"; on the installed Python 3.13.14, `ipaddress.ip_address("64:ff9b::808:808").is_global` is `True`. NAT64 is handled by the embedded-IPv4 check, which is safe, but the ADR sentence is wrong (deferred ledger).
- Proposed for shared egress: the same predicate, plus an explicit deny list that no trust entry can override: `169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254/128`, `100.100.100.200/32`, and loopback in production.

### 3.4 TLS and SNI with IP pinning

- Verified: the pinned connection passes `sni_hostname` and an explicit `Host`, so certificate verification uses the original name (`service.py:853-858`). This relies on httpcore internals (`sni_hostname` extension) read against httpcore 1.0.9 while `pyproject.toml` pins only `httpx>=0.27`.
- Verified gap: through an HTTPS proxy, httpcore uses the pinned IP as the TLS name, so verification fails (fails closed but broken).
- Verified gap: no test performs a real TLS handshake against the pinned path.
- Proposed: a real-TLS test with a local certificate; a tested upper bound or exact pin for `httpx`/`httpcore` (dependency change, owner-visible in AI-B); certificate verification never disabled; no per-endpoint CA override in the first release (a private CA for a trusted private endpoint is a later, separately reviewed option).

### 3.5 Redirects

- Verified: webhooks set `follow_redirects=False` and dead-letter any 3xx.
- Proposed: same for AI calls; a 3xx is a normalized `endpoint_security` error, never followed, never retried, never a fallback trigger. A credential can therefore never be sent to a redirect target.

### 3.6 Proxies

- Verified gap: webhook delivery does not set `trust_env`, so `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `SSL_CERT_FILE` and `SSL_CERT_DIR` silently change the egress path and trust store. The same is true for `GitHubPullRequestProvider`, the OIDC token exchange and the ZITADEL bootstrap client; OIDC discovery and JWKS use `urllib`, which follows redirects and honours proxy variables. (Webhook delivery: `trust_env=False` since 2026-10-18. Identity clients: explicit `OIDC_CA_BUNDLE`/`OIDC_PROXY_URL` only and no redirects since 2026-10-28, ADR-0023 amendment; ledger row 965.)
- **Established requirement (AI endpoints only, owner 2026-10-16):** the AI endpoint egress policy sets `trust_env=False`, unless a separately reviewed, explicit requirement justifies otherwise. Implicit, environment-derived proxy configuration is disabled for AI calls.
- If a proxy is ever needed for AI calls, it is explicit configuration, documented and security-reviewed. It must not bypass destination validation or IP pinning: the destination is validated and pinned exactly as without a proxy, and a CONNECT tunnel carries the original hostname as the TLS name. Today's verified behaviour, where the pinned IP becomes the TLS name through a proxy, must not be carried over. No proxy support is assumed to exist.
- Note: `SSL_CERT_FILE` is used deliberately by ADR-0027/0028 for Redis and the identity CA. `trust_env=False` stops httpx reading it, so the AI egress client must name its trust store explicitly (the default system/certifi store). AI-B tests which trust store it uses.
- **Webhooks (updated 2026-10-18).** Until 2026-10-18 webhook delivery kept httpx's `trust_env` default; the owner then decided `trust_env=False` for it (ADR-0054 Q2; ADR-0035 amendment), so the gap above is closed for webhook delivery. The other clients listed above (GitHub, OIDC, ZITADEL bootstrap, `urllib` discovery and JWKS) are out of scope and remain a deferred ledger finding.

### 3.7 Schemes and ports

- Verified: webhooks allow `http` and `https` with no port restriction on a globally routable address (any port, for example 25 or 6379). ADR-0035 accepts this and lists HTTPS-only as deferred. **That contract is unchanged.**
- **Established requirement (AI endpoints only, owner 2026-10-16):**
  - HTTPS on port 443 by default;
  - other ports only through explicit, validated configuration: the provider row's `base_url` port, validated and platform-audited (ADR-0054 section 5);
  - plain HTTP denied for external destinations by default;
  - private or internal endpoints only through explicit, narrowly scoped trust entries (3.10); plain `http` is possible only to such a destination (a local vLLM/Ollama);
  - no global switch that permits arbitrary private destinations.
- TLS hostname verification is preserved on every AI path, including pinned connections and any approved proxy. Credentials are bound to an approved origin (3.11) and are never forwarded to another host: no redirects, no origin change without rebinding.
- Proposed: URL userinfo, fragments and non-ASCII hosts not in IDNA form are rejected at configuration time.
- **Webhooks:** see 4.4 for the compatibility and security implications of ever applying such a policy to webhook subscriber URLs. Any change is a separate explicit architectural decision (ADR-0054 Q2) and an ADR-0035 amendment.

### 3.8 Deadlines

- Verified: webhooks use one 10-second value (`_DELIVERY_TIMEOUT_SECONDS`, `saas_os/core/webhooks/service.py:91`) applied separately to connect, read, write and pool, with no total deadline. A slow server can hold a worker. **Unchanged** unless the owner decides otherwise (Q2).
- **Established requirement (AI endpoints):** the five-timeout model of ADR-0054 section 8a: connection establishment, read inactivity, total non-streaming operation, streaming idle, and maximum streaming lifetime. Retries and fallback share the original deadline.
- **Candidate values only** (ADR-0054 section 8a): 5 s, 30 s, 120 s, 60 s and 10 min. They are for evidence-based evaluation and are not policy. Latency-sensitive use cases such as voice may need tighter, per-use-case limits.
- Semantics AI-B must define and test:
  - the total deadline covers DNS resolution, connection attempts across validated addresses, TLS, request write, provider processing and response read;
  - streaming adds idle and maximum-lifetime limits;
  - expiry cancels the exchange and closes the connection and response;
  - cancellation by the caller has the same cleanup;
  - slow connections, stalled headers, stalled bodies, cancellation and cleanup each have a test.
- **Transport limitations** (ADR-0054 section 8a): an in-flight `getaddrinfo` thread cannot be interrupted, so the deadline bounds the caller's wait, not the resolver; httpx has no total deadline of its own, so the total deadline relies on task cancellation in async code; a slow-but-steady server is bounded only by the total or lifetime limit.

### 3.9 Body limits

- Verified: webhooks bound the response by never reading it; there is no request body cap.
- Proposed:
  - a request body limit, both per use case and absolute;
  - the non-streaming response is read through a streamed, byte-capped reader;
  - for streaming, per-event and total byte caps and a maximum event count;
  - decompression is bounded (no unbounded gzip expansion);
  - header size is bounded by h11.
- Limit values are implementation decisions for AI-B, selected from tested requirements. None is fixed here.

### 3.10 Private endpoints

**Approved owner decision R1 (2026-10-16), implemented in AI-B:** the AI egress client rejects every non-public destination, literal or resolved, with no trust mechanism at all. The trust-entry design below is deferred to AI-C.

- Verified: webhook egress refuses every non-public address; there is no allowlist and no override flag.
- Proposed: `ai_endpoint_trust` entries, each naming one exact host, one port, the CIDRs its addresses must fall in, a reason, an expiry, and who created it (`platform.ai_endpoint_trust:manage`, platform-audited). A resolved address must be inside the entry's CIDRs; an address outside them is refused even if public. The always-deny list of 3.3 cannot be trusted. No global "allow private" switch exists. Loopback is trustable only when `ENVIRONMENT` is not `production`. Trust entries expire; renewal is a new audited operation.

### 3.11 Credential protection

| Threat | Control |
|---|---|
| Credential reaches a different host after a configuration change | Origin binding (ADR-0054 section 6): connect only if the target origin equals the bound origin |
| Credential in logs, exceptions, audit | Credentials never in `extra=`, never in exception messages; adapter exceptions carry status, category and provider request id only. ADR-0020 redaction applies to `extra=` keys only — message interpolation and tracebacks are not redacted (verified ADR-0020 limitation), so adapter code must never format a header or request into a message; enforced by a test that injects a canary credential and scans logs, audit rows and exceptions |
| Credential returned to products | No API returns configuration values; `platform.ai_config:read` returns the reference name only |
| Rotation/revocation | Platform: environment change + restart, provider row disable is immediate. Tenant-owned (AI-E): row state, immediate |
| Provider error echoes the key | Provider error bodies are not logged by default; a bounded, redacted excerpt only behind an operator diagnostic flag |

### 3.12 Authorization and tenancy

- Typed caller authorized in the transaction that records the attempt; RLS on all tenant-owned AI tables (`tenant_rls_statements`); global configuration tables use the tenant-context exclusion policy. That policy is proposed and **not implemented**: the global tables have no RLS, because inference reads them inside a tenant transaction. Their writes are database-enforced instead (ADR-0056, Accepted; migration `f6a2c8e4b1d9`): the application role can only read them, whatever `app.tenant_id` holds, and only a separate platform-configuration role, whose credential the API and the worker refuse to hold, can insert or update them, inside `run_platform_change` with platform authorization and same-transaction platform audit. Remaining trust: the operator-command process, and the application role's own write access to `core.platform_operators` and `core.platform_grants` (ADR-0045 section 9a, unchanged).
- Platform operators: configuration and data-minimized usage totals only; never content, never tenant policy writes (ADR-0045 constraint 4).
- Stale authorization: authorization is evaluated per request, inside the attempt transaction; a long stream is not re-authorized mid-stream (accepted: bounded by the stream's total deadline).
- Cross-tenant leakage through shared state: circuit-breaker and health state is per (provider, model), never contains content; rate-limit and concurrency keys are per tenant; no response caching in SaaS OS.
- Entitlement and concurrency (approved owner decision Q12; required in AI-D):
  - the entitlement gate is server-side, sourced from Core's entitlements (`has_entitlement`), and denies on missing or ambiguous data;
  - concurrency is bounded per tenant and installation-wide, across instances (a verified gap today: `infra.ratelimit` counts requests per window, not requests in flight);
  - tenant identity comes from the trusted authorization context;
  - a rejected request sends no provider content;
  - exhaustion is a defined, observable result;
  - one tenant cannot hold shared capacity without bounds.

### 3.13 Provider failure, retry and fallback

See ADR-0054 section 8 and the contracts document section 4. Threats specifically controlled:

- Duplicate billing by retrying an accepted request → no retry after possible acceptance.
- Fallback bypassing a restriction → every fallback re-runs eligibility and data authorization; policy, auth, endpoint-security, invalid-request and quota failures never fall back.
- Fallback loops → each candidate at most once; candidate list fixed at resolution time.
- Partial output followed by a different model's output → no fallback once any output reached the caller.

### 3.14 Observability and leakage

- Logs: request id, attempt id, tenant id, use case, provider key, model id, outcome, error category, durations, token counts. Never prompts, completions, tool arguments, credentials or provider error bodies by default.
- Metrics: counters and histograms labelled by provider, model, outcome, error category; **tenant id never a metric label** (cardinality and cross-tenant exposure in shared monitoring).
- Traces (OpenTelemetry, ADR-0009): spans for resolution, authorization, attempt, egress; attributes as for logs; no content attributes.
- Diagnostics: an operator-enabled, time-limited diagnostic mode may capture *sizes*, part counts, finish reasons and redacted provider error excerpts; never content. Capturing content for debugging is Learning Authorization (ADR-0014) territory and out of scope.

### 3.15 Usage integrity

| Threat | Control |
|---|---|
| Duplicate usage events | Attempt row is the unit; mirror to `core.usage_events` through the outbox with consumption idempotency (ADR-0036) |
| No evidence of an attempt that sent content | Pre-send attempt evidence in AI-D (approved owner decision Q10): nothing is sent until the required decision and attempt records are written; a failed write sends nothing |
| Process dies mid-call | `started` attempt remains; AI-D's reconciliation job marks it `abandoned`, usage `unknown`; operators see unknown usage rather than none. Full reconciliation with provider outcomes is AI-F |
| Provider omits or misreports usage | Provenance column: `provider_reported`, `estimated` (local count), `unknown`; quotas use the best available; never silently zero |
| Interrupted stream | Usage from the last usage event if the provider sent one, else estimated from bytes/tokens delivered, marked `estimated` |
| Concurrent overspend | The bounded per-tenant concurrency of AI-D limits in-flight work. Token quotas (AI-F) are soft and stated as soft; a hard cap needs a separate reservation design (Q8) |
| Provider-reported cost differs from estimate | Estimates carry pricing version; reconciliation with provider invoices is AI-F |

### 3.16 Prompt injection

Inference returns model output to the product; it executes nothing. Tool use (function calling) returns tool-call requests to the product as data. SaaS OS never executes a tool call from a model response in this subsystem. A product that executes them owns that risk; the AI Control Plane's own agents remain governed by ADR-0004 tools.

## 4. Reusing webhook egress

### 4.1 What is reusable (verified)

The address predicate and embedded-IPv4 extraction; resolve-all-then-reject; IP pinning with `sni_hostname` and explicit `Host`; `follow_redirects=False`; the test corpus of non-public addresses (`tests/core/webhooks/test_webhook_ssrf_policy_unit.py`).

### 4.2 Why it cannot be used as is (verified)

1. It lives in `saas_os.core.webhooks.service` as private functions, coupled to webhook and outbox error types (`WebhookDestinationRejectedError` derives from `core.outbox.PermanentEventError`).
2. `trust_env` defaults to `True`; no port policy; no total deadline; blocking DNS in async code; no bounded response reader (it never reads the body); no trust mechanism for private endpoints; single-address choice with no fallback; proxy path breaks TLS.

### 4.3 Smallest safe extraction (Phase AI-B; implemented 2026-10-16, on branch `feat/ai-inference`; merged by pull request #53)

Status: step 2's move was done as module-level aliases in `saas_os.core.webhooks.service`, so every name the webhook tests import or patch is still the one the delivery path looks up at call time. This is pinned by `tests/core/webhooks/test_webhook_shared_egress_unit.py`, including seam non-vacuity checks. Step 3 was done as a separate strict client for AI calls; webhook delivery code is otherwise untouched.


1. **Step 1 — regression baseline.** Before any change, add regression tests that pin today's webhook behaviour where the existing suite does not (4.5).
2. **Step 2 — move, do not change.** Create `saas_os.infra.egress` with the address predicate, embedded-IPv4 extraction, validation and pinning, with its own error types and no Core import. `core.webhooks` calls it and maps its errors to the existing webhook errors. Webhook behaviour is identical: the existing webhook tests and the regression tests pass unchanged.
3. **Step 3 — explicit per-caller policies.** Add an `EgressPolicy` (schemes, ports, timeouts, body limits, trust entries, proxy, `trust_env`) passed per call.
   - The **AI endpoint policy** implements ADR-0054 section 8b.
   - The **webhook policy** reproduces today's behaviour exactly: `http`/`https`, any port on a globally routable address, environment `trust_env` default, 10 s per phase, response not read.
   - No AI restriction reaches webhooks through a shared default.
4. **Not in AI-B:** any change to webhook scheme, port, proxy or deadline behaviour. That is a separate architectural decision (ADR-0054 Q2) with its own ADR-0035 amendment.

### 4.4 Compatibility and security implications of a future webhook change (for decision Q2; nothing proposed for AI-B)

| Behaviour today (verified; allowed by ADR-0035) | Possible change | Security benefit | Who could be affected |
|---|---|---|---|
| `trust_env` defaults to `True` | `False` | No silent proxy or trust-store change from the environment; pinned path cannot be redirected through an unvalidated proxy | Deployments that send plain-`http` webhooks through an environment proxy (`https` through a proxy already fails, verified) |
| `http` and `https` allowed | HTTPS only | Payloads and signatures not readable in transit | Subscribers with `http` URLs |
| Any port on a public address | Port policy | No use of webhooks to probe or hit non-web services (for example SMTP 25) on public hosts | Subscribers on non-standard ports |
| 10 s per phase, no total deadline | Bounded total deadline | A slow subscriber cannot hold a worker indefinitely | Very slow subscribers |
| Blocking `socket.getaddrinfo` in async code | Non-blocking resolution | Worker event loop not stalled | None functionally (4.6) |
| First validated address only | Bounded attempts over validated addresses | Delivery on IPv4-only egress hosts | None adversely |

The last two rows are internal behaviour, not a contract change. Whether AI-B may include them for webhooks, as behaviour-preserving improvements, is also part of Q2.

### 4.5 AI-B compatibility and regression obligations (established requirements)

AI-B must:

1. establish regression tests for existing webhook behaviour before changing shared code (status classification, retry versus dead-letter, signing headers, pinning, SNI and `Host`, redirect refusal, the non-public corpus, accepted schemes and ports);
2. identify and document every compatibility-sensitive behaviour (4.4);
3. test proxy behaviour explicitly: environment proxy variables are ignored by the AI policy, and the webhook policy keeps its current behaviour;
4. test allowed and denied schemes and ports under the AI policy, and the unchanged acceptance under the webhook policy;
5. test AI deadline enforcement and resource cleanup: slow connect, stalled headers, stalled body, cancellation, and closed connections afterwards;
6. preserve existing webhook behaviour;
7. document any intentional breaking behaviour. None is planned for webhooks; any would come only from a Q2 decision.

### 4.6 Asynchronous DNS

- Verified concern: `_default_resolve_hostname` calls `socket.getaddrinfo` inside the async delivery path (`saas_os/core/webhooks/service.py:264`, reached from `:818`). This blocks the worker's event loop for the duration of resolution.
- Requirement for the future solution: resolve without blocking the event loop (for example the loop's own `getaddrinfo` or a thread offload), under the total deadline.
- It must preserve, unchanged:
  - validation of **every** returned address before connecting;
  - connecting only to an address that was validated in the same resolution, so there is no second resolution and no rebinding window;
  - the original hostname as TLS server name and `Host`;
  - the existing resolver-injection seam used by tests.
- The choice of mechanism is AI-B's; it is tested with the rebinding tests that exist today (`tests/core/webhooks/test_webhooks_delivery_integration.py`).

## 5. Residual risks (accepted or open)

| Risk | Status |
|---|---|
| Product mislabels content within the scope it is authorized to submit | Accepted by the owner with the classification trust model (2026-10-16). The platform enforces boundaries, it does not verify labels, and it never claims to |
| Webhook gaps (`trust_env` default, any port, `http`, no total deadline) | `trust_env` closed 2026-10-18 (ADR-0035 amendment); any port, `http` and no total deadline open (ADR-0054 Q2) |
| `getaddrinfo` cannot be interrupted | Accepted limitation (AI-B): the total deadline bounds the caller's wait, not the resolver thread |
| Internal adapters on `main` before governed inference (R2) | Accepted by the owner for AI-B; recorded in the ledger |
| Provider retains or trains on data contrary to its declared handling | Outside SaaS OS's control; data-handling attributes are operator declarations |
| Platform credentials are process-wide; host compromise exposes them | Accepted (ADR-0012 residual risk) |
| Soft token cap overshoot | Accepted until AI-F reservation decision |
| `httpcore` internal API for SNI pinning | Open until AI-B pins and tests it |
| Consumer code can still call providers directly | Documentation and review only; SaaS OS cannot constrain a consumer's own imports |
| Audit volume of one row per attempt | Open; owner decision if it becomes a problem |

## 6. Mitigation status (2026-10-17; implemented on branch `feat/ai-inference`; merged by pull request #53)

- **SSRF and egress (3.3, 3.10).** Strict egress client: public HTTPS
  destinations, every resolved address validated and the connection pinned,
  no redirects, no environment proxies; private destinations only through an
  exact host-and-port trust entry; loopback, link-local, metadata, multicast,
  unspecified and reserved ranges never trustable, also through embedded IPv4.
- **Credential misuse.** Secret names only; values never stored, returned,
  logged or audited (tests assert the canary is absent); origin binding
  cleared on an endpoint change; a missing credential is never hidden by a
  fallback. Implemented 2026-10-17 on `feat/ai-inference`:
  - Only names the deployment lists in `AI_PROVIDER_CREDENTIALS` are eligible. Other installation secrets that resolve, such as `DATABASE_URL`, are refused and never looked up.
  - The list is checked at configuration, at binding confirmation, and at every call.
  - A change of credential name clears the binding until it is reconfirmed (ADR-0054 section 6, implementation status).
  - A direct write to the provider row (`base_url`, `credential_ref`, `credential_origin`) needs the platform-configuration database role (ADR-0056); the application role is refused by PostgreSQL. Remaining risk: code inside the operator-command process that holds that credential.
- **Cross-tenant exposure.** Tenant RLS on every tenant table; authorization
  in the tenant's own transaction; a service account of another tenant
  refused; support access excluded from sending and from changing policy.
- **Policy bypass.** The facade is thin by test and the only product entry;
  SaaS OS itself cannot import it; products cannot import the internals; the
  adapters are unreachable from the operator commands.
- **Evidence gaps.** Pre-send attempt row in a committed transaction; output
  returned only after settlement commits; abandoned attempts become
  `abandoned` with usage unknown. Refusals write `denied` tenant audit rows,
  including entitlement refusals since 2026-10-18; those rows are best effort
  (`ai_inference_denial_unrecorded` when the write fails; the refusal stands),
  and quota and capacity refusals write none (ADR-0055 section 6).
- **Resource exhaustion.** Entitlement gate, per-tenant and installation-wide
  concurrency across instances, total deadline shared by retries and
  fallback, response size limit, shared circuit breaker, soft token quota.
  The timeout, response-size and concurrency values are provisional
  defaults, not validated against real providers; each deployment validates
  its own (ADR-0054 section 8a, R3 revised 2026-10-18). Observability is
  structured log events; no metrics exist.
- **Residual risks.** The soft quota can be overshot under concurrency; a
  product's declared classification is trusted within its ceilings and grants
  (ADR-0055 section 4); streaming is disabled; tenant-owned credentials and
  provider-report reconciliation do not exist.
