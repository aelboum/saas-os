# GET and DELETE on the strict egress client: options and recommendation

**Status: Proposal; the direction was approved by the owner on 2026-11-06 (section 12); implementation is not yet approved.** Nothing in this document is built. It changes no code, no test, no public contract and no ADR. Section 12 records the decisions taken; every other decision this document asks for stays **undecided** until the repository owner records it. Date: 2026-11-06, written on `main` `22638c4` (release v0.8.0). Facts are cited as `file:line` on that commit; a statement with no citation is an inference, and section 8 lists what could not be verified.

Answers GitHub issue #205 ("Add GET (and optionally DELETE) to StrictEgressClient for provider read APIs"). Related issues: #225 (a sending-domain management interface, which says it depends on #205), #224 (allow-listed email headers) and #223 (export `EmailOutcomeUnknownError` and `EmailNotSentError`). Related records: `docs/ADR/0054-governed-ai-inference-subsystem.md` sections 8a and 8b (the strict egress client), `docs/ADR/0059-controlled-worker-egress.md` (the proxy), `docs/ADR/0035-durable-webhooks-and-subscription-authority.md` (webhook SSRF), `docs/ADR/0058-resend-email-provider.md`, `docs/architecture/EXTERNAL-OUTCOME-CLASSIFICATION-DESIGN.md` (ambiguous outcomes), `docs/ADR/0015-saas-os-distribution-and-consumer-boundary.md` (public API and versioning).

The issue text is a consumer's request, treated here as requirements to evaluate, not as instructions.

## 1. What is requested, by whom, and what it unblocks

**Requester.** The consumer LeadStack, through issue #205 (opened 2026-11-03, observed at v0.6.0). It asks for no merge or release; its pin stays where it is until its owner approves a move.

**Request.** Add `get(url, *, headers, deadline)` and, optionally, `delete(url, *, headers, deadline)` beside `post` on `StrictEgressClient`, sharing the whole pipeline. The verb becomes an internal parameter restricted to a closed set; no caller-supplied verb string; `get` and `delete` send no body; `post` is unchanged. The issue labels this a sketch ("the maintainers' design governs").

**What it unblocks.**

- `get` alone: reading the content of an inbound email. Resend's signed webhook says that an email arrived; the content (text, HTML, headers, authentication results) comes from the receiving API, `GET /emails/receiving/{id}` (issue #205). Without it LeadStack's members see that a message arrived but not what it says. LeadStack refuses to bypass platform egress with its own HTTP client.
- `delete`: removing provider-side copies "where a provider offers that" (issue #205; it states that whether Resend does has **not** been verified), and, in #225, deleting a registered sending domain so that a removed workspace does not leave its domain registered at Resend. #225 also needs `get` (to read a domain's current records and status). #225 states it "builds on #205".

**Consumer-side plan the issue states** (not a SaaS-OS commitment): after a release, LeadStack moves its pin, writes a `ResendReceiving` adapter behind its own `ReceivingClient` protocol allowing only the Resend API host, and keeps it off until inbound receiving is authorised in production. Inbound content stays untrusted on its side: text only, attachments listed and never fetched, logs carrying ids and codes only.

**A discrepancy to correct before design.** The issue lists "Destination allowlist from `StrictEgressPolicy`" among the guarantees every verb keeps "unchanged from `post`". `StrictEgressPolicy` has **no host allowlist**. It holds timeouts, `max_response_bytes`, `allowed_ports` (default 443), `max_addresses_tried` and `trusted_endpoints` (a private-address exception for an exact host and port) (`saas_os/infra/egress/policy.py:65-70`). Any public HTTPS host on an allowed port is reachable. Restricting a credential to one host is today the adapter's job: Resend's URL is a module constant, "no setting can point the API key at another host" (`saas_os/core/email/resend_provider.py:135`, docstring lines 10-12). That matters for `get` and `delete` (section 4.4).

## 2. Current client behaviour (facts)

### 2.1 Surface and callers

- Public methods: `policy` (property) and `post(url, *, headers, content, deadline)` only (`saas_os/infra/egress/client.py:180-211`; `tests/architecture/public_api_snapshot.txt:1118`). `EgressResponse` has `status_code`, `headers` (lower-cased keys) and `body`, with `headers` and `body` excluded from `repr` (`client.py:90-94`, `client.py:353-357`).
- The verb is the literal `"POST"` in the one place the request is built (`client.py:325-331`); `content=content` is always passed.
- Callers today, by search of `saas_os/`: the AI provider adapters, through an `EgressClient` protocol that declares only `post` (`saas_os/control_plane/inference/adapters/base.py:106-116`, call at `saas_os/control_plane/inference/adapters/_common.py:67`), and the Resend adapter (`saas_os/core/email/resend_provider.py:374`). Webhook delivery shares the address helpers, the HTTP-stack check and the proxy transport, but does not use `StrictEgressClient` (`saas_os/core/webhooks/service.py:90-100`).
- Public export: `StrictEgressClient`, `StrictEgressPolicy`, `EgressResponse` and the `Egress*` errors in `saas_os/infra/egress/__init__.py:245-281`. A new public method changes the snapshot test, which says an added entry must be reviewed and the file rewritten; a changed or removed signature is a `0.Y.0` change (`tests/architecture/test_public_api_snapshot.py:42-52`, ADR-0015).
- The whole `saas_os/infra/egress/` tree is classified a security control that requires review in the updater policy (`saas_os/infra/update/policy.py:32-36`, `saas_os/infra/update/policy.py:118`).

### 2.2 What every `post` call does

| Step | Behaviour | Evidence |
| --- | --- | --- |
| URL validation | Non-empty, at most 2048 characters, ASCII, `https` only, no user information, a hostname of at most 253 characters, port in `allowed_ports`, a literal IP must be public. The fragment is dropped | `client.py:85-86`, `client.py:215-242` |
| Caller headers | `host`, `content-length` and `transfer-encoding` are refused (`forbidden_header`). The client sets `Host` and `Accept-Encoding: identity` itself | `client.py:87`, `client.py:193-195`, `client.py:309-311` |
| Deadline | An expired deadline sends nothing; one total `asyncio.timeout` covers resolution and exchange; connect and read timeouts are capped by the time left | `client.py:196-211`, `client.py:305-308` |
| Resolution | The resolver runs once. If **any** answer is non-public and not covered by a `TrustedEndpoint` for that exact host and port, the destination is refused | `client.py:244-272` |
| Pinning | The connection goes to the validated literal address, with the hostname as TLS server name and `Host`; at most `max_addresses_tried` (default 2) are tried, and a next address is tried only when `request_may_have_been_sent` is false | `client.py:276-294`, `client.py:304`, `client.py:313-314`, `saas_os/infra/egress/policy.py:69` |
| TLS | Certificate and hostname verification are required; the trust store is certifi's; a context that disables them is refused at construction | `client.py:123-127`, `client.py:175-178` |
| Proxy | With an `EgressProxy`, every connection is an HTTP `CONNECT` to the validated IP literal and port; the proxy sees only that, never a URL path, query, method or header. A proxy refusal is `EgressProxyRefusedError` (permanent); an unreachable proxy is `EgressProxyUnavailableError` (transient); there is no direct fallback | `client.py:164-173`, `saas_os/infra/egress/proxy.py:1-24`, `saas_os/infra/egress/errors.py:122-137`, `docs/ADR/0059-controlled-worker-egress.md` decision 2 |
| Redirects | `follow_redirects=False`; any 3xx raises `EgressRedirectError` | `client.py:322`, `client.py:334-335`, `errors.py:167-173` |
| Response encoding | A `Content-Encoding` other than identity is refused, so the bytes read are the bytes on the wire (no decompression bomb) | `client.py:336-342`, `client.py:347-348` |
| Response size | A declared `Content-Length` above `max_response_bytes` is refused; the body is streamed into memory and refused as soon as it exceeds the limit | `client.py:343-352` |
| Environment | `trust_env=False`; no proxy or CA setting is read from the environment | `client.py:114`, `client.py:321` |
| Errors | `EgressError` carries `reason`, `phase` and `request_may_have_been_sent` (false only when nothing could have reached the destination); messages hold reason and phase only; errors are raised after the `httpx` handler so no `__cause__` or `__context__` carries the request | `saas_os/infra/egress/errors.py:1-103`, `client.py:358-384` |
| Logging | The client never logs. `httpx` logs each request at `INFO`; `install_sensitive_log_filters()` is called at import and reduces every URL argument to scheme, host and port, whatever level is set | `client.py:26-31`, `client.py:78-80`, `saas_os/infra/observability/log_filters.py:1-60` |

### 2.3 What already holds for any verb, and what does not

- Two of the issue's requirements already hold for every verb because they are checked **before** the exchange: the forbidden `content-length` and `transfer-encoding` headers (`client.py:193-195`) and the whole validation pipeline. Adding verbs reuses them if the new methods go through the same entry sequence.
- **Policy fields are per client, not per call.** `max_response_bytes`, the timeouts and `allowed_ports` live in a frozen `StrictEgressPolicy` fixed at construction (`policy.py:48-80`). The Resend adapter builds its client with `max_response_bytes = 64 KiB`, sized for "a success body is `{"id": "<uuid>"}`; an error body is a few hundred bytes" (`resend_provider.py:144-146`, `resend_provider.py:342-346`). An inbound email will not fit that limit (section 5.2). The AI path uses a separate provisional 8 MiB limit (`docs/ADR/0054-governed-ai-inference-subsystem.md` line 528, `saas_os/control_plane/inference/egress_config.py:83-86`).
- The body is held in memory up to the limit (`client.py:346-352`). The worker's default concurrency is ten jobs (`saas_os/core/email/resend_provider.py:188-190`), so the worst case is that many times the limit.
- `post` is `async`; the Resend adapter wraps it with `asyncio.run()` or a helper thread because `EmailProvider.send()` is synchronous (`resend_provider.py:372-388`). A read or delete adapter would need the same wrapper.

### 2.4 Tests that pin this behaviour

`tests/infra/egress/test_strict_egress_unit.py` (URL, port, address, pinning, header, redirect, size, encoding, deadline, TLS, cancellation and error-hygiene tests, for example `test_redirects_are_never_followed` at line 274, `test_errors_do_not_carry_urls_or_headers` at line 508), `tests/infra/egress/test_strict_egress_socket_unit.py`, `tests/infra/egress/test_strict_egress_trust_unit.py`, `tests/infra/egress/test_egress_proxy_unit.py` (proxy refusal, unreachable proxy, redirect through the proxy, environment proxy ignored), `tests/infra/observability/test_log_filters_unit.py`, and `scripts/check-egress-e2e.sh` (real resolver and proxy on isolated Docker networks, driver in `scripts/egress_e2e/driver.py`, which calls `client.post`). All exercise `post`; none names another verb.

## 3. Facts about the related issues

- **#225** wants `create`, `get`, `verify` and `delete` for sending domains "beside the email provider, Resend first", with a `SendingDomain` result and fixed reason codes. It needs `get` and `delete` on the egress client; it says it would replace LeadStack's own `post`-based calls. It is a new Core interface, not an egress change.
- **#224** is `EmailMessage.headers`, an allow-listed header set (List-Unsubscribe, List-Unsubscribe-Post, In-Reply-To, References). It touches `request_body` (`resend_provider.py:235-253`, currently `headers` carries only `Message-ID`) and the SMTP provider. It does not touch the egress client and does not depend on #205.
- **#223** asks to export `EmailOutcomeUnknownError` and `EmailNotSentError` from `saas_os.core.email`. Both exist in `saas_os/core/email/errors.py:67-104` and are raised by the Resend adapter (`resend_provider.py:405-418`, `resend_provider.py:425`, `resend_provider.py:447`), and neither is in `saas_os/core/email/__init__.py` or in `tests/architecture/public_api_snapshot.txt` (searched: no match). #224 and #223 concern the send path; #205 and #225 concern new provider operations.

## 4. Options

All options keep these invariants unless stated: SaaS-OS Core stays provider-neutral where the `EmailProvider` abstraction already is; Resend request and response shapes stay in the Resend adapter (the boundary `saas_os/core/email/resend_provider.py` draws around itself, docstring lines 1-5); `StrictEgressClient` stays infrastructure that "knows nothing about tenants, providers or AI" (`client.py:26-28`).

### Option A: add `get` and `delete` to `StrictEgressClient`, same policy as `post`

`post`, `get` and `delete` become thin public methods over one private request method whose verb is a closed internal `Literal`. `get` and `delete` take `url`, `headers`, `deadline` and send no body. Everything in section 2.2 applies to each verb. `post` keeps its exact signature and behaviour.

- **Security impact.**
  - SSRF: unchanged. Validation, resolution, pinning and the proxy tunnel are verb-independent, and the proxy never sees the method (`proxy.py:1-24`), so the Squid policy (`CONNECT` only, IP literals, port 443; ADR-0059 decision 3) needs no change.
  - Redirects: a redirect on `GET` is not followed, same as `POST` (`client.py:334-335`). The cost is that a provider endpoint that legitimately redirects (for example a signed download URL) cannot be read through this client. That is a feature here.
  - Response size and memory: the existing cap applies, but it is per client (section 2.3). A read needs a client built with a larger cap; see the open question in section 9 on a per-call cap.
  - Secrets: the credential travels in a header; the log filter reduces URLs to the origin; errors carry no URL (`client.py:33-37`). A `GET` URL may carry an identifier in the path or query, which is covered by the same filter; the new tests must prove it for `GET` (section 7).
  - Confused-deputy risk: with a generic verb, a caller can send a credential-bearing `GET` or `DELETE` to any public host on port 443. The client cannot prevent it today (section 1). Mitigation is the adapter-constant host, an id pattern, and optionally a host allowlist (section 4.4).
  - DELETE retry: the client never retries after the request may have been sent (`client.py:290-292`), so it adds no duplicate-delete risk itself. Retry is a caller decision (section 6.2).
  - Untrusted content: the client returns bytes and headers; it parses nothing. Content-type, charset and parsing are the adapter's job (section 6.1).
- **Public API impact.** Additive: two new methods on an exported class. The snapshot test fails until the entries are reviewed and the snapshot rewritten (`test_public_api_snapshot.py:42-52`). A `0.Y.0` release by the project's rule for public API changes (ADR-0015); the owner decides the version.
- **Protocol impact.** The AI adapters' `EgressClient` protocol declares only `post` (`base.py:106-116`) and is unaffected; a structural fake that satisfies it stays valid.
- **Provider boundary.** Clean. Infra gains two verbs; Resend specifics (paths, JSON shape, error names) live in adapters.
- **Test plan.** A shared verb matrix over the existing guarantees (section 7).
- **Effort.** Small to medium: about a dozen lines of production change in `client.py` (a verb parameter, `content` optional) plus the test matrix, the snapshot rewrite, an e2e driver case, and documentation. Most of the work is the tests.

### Option B: a narrower read-only method (`GET` only, with a response cap)

Add only `get` (not `delete`), optionally named for reads, with a **required per-call response limit** at or below the policy limit, and optionally a refusal of any response whose `Content-Type` is not the expected one. The issue suggests `get_json` as an example name.

- **Security impact.** Smaller than A: no state-changing verb is added, so the irreversible-delete concern (section 6.2) does not arise in infra. A per-call cap lets a read use a lower limit than the client's. A JSON-specific method would put parsing, charset handling and duplicate-key or depth limits into infrastructure, which this module deliberately does not do (callers pass headers and bytes, `client.py:26-28`). The cap alone gives most of the protection, so a `get_json` that parses adds risk and little else; a `get` that returns bytes does not.
- **Public API impact.** Additive, same snapshot work; one method, plus a keyword that `post` does not have (an asymmetry).
- **Provider boundary.** Clean.
- **Limits.** #225's `delete` is not served; a second proposal would follow. A required per-call cap raises the cap above the client's policy only if the semantics allow it (section 9, question 3); lower-only does not help a read that needs more than the client's 64 KiB.
- **Test plan.** As A for `get`, plus the per-call cap.
- **Effort.** Small, then small again when `delete` is wanted.

### Option C: no generic verbs; the Resend adapter does its own read and delete calls using the existing client

As worded in the task, this means calling the existing client from the adapter. **It is not feasible without changing the client.** `StrictEgressClient` can only send `POST` (`client.py:325-326`); there is no hook to choose the verb, and nothing in Resend's documented behaviour (not verified here) is known to accept a method override on `POST`. The remaining variants each move the problem:

- C1: the adapter builds its own `httpx` request path. It would then re-implement or bypass validation, pinning, proxy tunnelling and limits, which is what LeadStack declined and what ADR-0059 requirement R1 and R9 forbid in spirit. **Rejected as unsafe.**
- C2: subclass `StrictEgressClient` in the adapter and override the private `_exchange`. It depends on a private method, duplicates its body (including the `httpx` error classification) and would break silently on any refactor. **Rejected as fragile.**
- C3: do not provide read or delete in SaaS-OS at all; the consumer lives without them (keep today's behaviour). This is "do nothing" and leaves LeadStack and #225 blocked.

So Option C reduces to Option A or to doing nothing. It is listed to record why the adapter-only route does not exist, not as a viable design.

### Option D: other shapes

- **D1: one public `request(method, url, ...)` taking a verb from a closed enum.** One entry point, fewer methods. Cost: a verb becomes a caller-visible value, which the issue explicitly wants to avoid ("no caller-supplied verb string"), and `post`-style signatures diverge. Not recommended.
- **D2: A, staged.** Ship `get` first (unblocks inbound content), `delete` when #225 is approved. Same final surface as A; the risk of the irreversible verb is paid only when its first real caller exists, and each step can be judged on its own test evidence. The cost is two releases and two snapshot rewrites.
- **D3: A plus a host allowlist in `StrictEgressPolicy`** (a frozen set of exact hostnames, empty meaning today's behaviour). It would make "only api.resend.com" a policy fact, enforced in the client for every verb and checked before DNS. This is a new security control the issue assumes already exists. It is a separate decision (section 9, question 4) and could be added to A or D2 without changing their method surface.

### Summary table

| | A: `get` + `delete` | B: read-only `get` | C: adapter only | D2: staged A | D3: A + host allowlist |
| --- | --- | --- | --- | --- | --- |
| Unblocks inbound content | yes | yes | no (infeasible) | yes, first release | yes |
| Unblocks domain delete (#225) | yes | no | no | yes, second release | yes |
| New irreversible-verb path in infra | yes | no | n/a | later | yes |
| Policy changes | none | none | n/a | none | adds `allowed_hosts` |
| Public API | +2 methods | +1 method | none | +1 then +1 | +2 methods, +1 policy field |
| Proxy / Squid change | none | none | n/a | none | none |
| ADR vehicle | amend 0054 sec. 8b | amend 0054 sec. 8b | n/a | amend 0054 sec. 8b | amend 0054 sec. 8b, note in 0059 |
| Effort | small to medium | small | n/a | small + small | medium |

## 5. Threat analysis specific to the new verbs

### 5.1 SSRF and routing

Unchanged by the verb: same validation, the all-answers-must-be-public rule, pinning, the tunnel, no redirects. The e2e proof in ADR-0059 ("Refused by the application", "Refused by the proxy on its own", "No direct connection", the negative control) is written for `post`; it is evidence for the shared pipeline only if the new methods really share it. The tests must prove that by running the same matrix per verb, so that a future change which gives `get` its own path is caught (section 7).

### 5.2 Inbound email is attacker-controlled data

`GET /emails/receiving/{id}` (issue #205) returns content authored by an arbitrary third party. Consequences that exist regardless of which option is chosen:

- **Size.** The 64 KiB Resend client limit (`resend_provider.py:146`) is far below a realistic message; a read client needs its own policy with a larger cap. The limit Resend itself imposes on inbound messages was **not verified**. The cap must be a deliberate constant, chosen with the worker's concurrency in mind (section 2.3), and a message above it must fail as `EgressResponseTooLargeError`, not be truncated (the client already refuses rather than truncates, `client.py:352`).
- **Streaming and memory.** The client holds the body in memory up to the cap; it does not stream to disk. That is acceptable only with a modest cap.
- **Compression.** Refused at the transport (`client.py:336-342`), so a compressed response cannot expand beyond the cap. A MIME or archive bomb **inside** an attachment is a content concern: attachments are listed, not fetched (the consumer's stated plan), and nothing in this proposal fetches them.
- **Encoding.** The JSON envelope is UTF-8 (assumption: Resend's API returns JSON, which the issue implies but does not show). Decoding, rejecting invalid UTF-8, bounding string lengths and depth, and refusing duplicate or unexpected keys is the adapter's job, as `_json_object` and `_provider_id` already do for the send response (`resend_provider.py:260-272`, `resend_provider.py:299-310`). The inner message may use any MIME charset; that is the product's concern.
- **HTML, script and tracking pixels.** The library should return HTML as an inert string and never render, fetch or follow anything in it. Sanitisation, remote-content blocking, link rewriting and any rendering are the **product's** responsibility; SaaS-OS cannot know the display context. Whether SaaS-OS should provide a helper is an open question (section 9, question 6); this proposal recommends it not do so in this change.
- **Logging.** Message content must never reach logs or exception text. `EgressResponse.body` is already excluded from `repr` (`client.py:93`), and Resend errors copy only fixed reason words (`resend_provider.py:160-185`, `resend_provider.py:433-455`). The read adapter must follow the same rule, and `tests/core/email/test_resend_provider_unit.py` shows the pattern (a canary text and a canary key checked against logs and exceptions).
- **Prompt injection into the AI path.** If a product passes inbound text to the governed AI inference path, that is a product decision outside this change; it is mentioned because the content is untrusted in that setting too.

### 5.3 Path and identifier injection

A caller-built URL such as `https://api.resend.com/emails/receiving/{id}` or `https://api.resend.com/domains/{id}` puts an identifier into a path. `StrictEgressClient` validates the URL's host, port and form, not its path (`client.py:215-242`). If an attacker influences the identifier (a webhook field, a stored value), an id such as `../domains/other` could redirect a credential-bearing `GET` or, worse, a `DELETE` to a different endpoint of the same provider. `httpx` normalises dot segments (assumption from its URL handling, not tested here). Mitigation belongs to the adapter: a strict identifier pattern with a bounded length and no `/`, `?`, `#`, `%` or `.` (the Resend adapter already bounds and checks a provider id as printable ASCII, `resend_provider.py:299-310`, which is not strict enough for a path segment), and #225's own requirement 3 ("provider id against a bounded pattern"). Tests must cover it (section 7).

### 5.4 Credential reach

With a generic verb, any adapter holding a credential can send it to whatever URL it builds. The risk is concrete for read APIs, which return URLs (attachment download links, pagination links). An adapter must never take a URL from a provider response and send its own credential to it, and must never follow a `Link`-style next URL without checking that its host and path prefix are the adapter's own. A host allowlist in the policy (Option D3) would make the first rule enforceable in the client rather than by convention. Today's R9 ("Resend's credential cannot be sent to an unintended destination", ADR-0059) is satisfied by the constant URL; it does not generalise automatically to a client that serves several URLs.

### 5.5 Query strings

A `GET` makes it natural to put parameters in the query. The log filter and error hygiene keep URLs out of logs and errors (`saas_os/infra/observability/log_filters.py:1-60`, `client.py:33-37`), and the proxy never sees them. The remaining rule is for adapters: no secret in a query string, ever (credentials go in `Authorization`), because intermediaries other than SaaS-OS's logs (the provider's, a CDN's) may record URLs.

## 6. Retry, outcome and idempotency

### 6.1 GET

A `GET` has no side effect at the provider. The client performs no retry of a request that may have been sent (`client.py:290-292`); the caller may retry a `GET` after any failure. Provider rate limits still apply: a `429` is the adapter's to classify, as for sending (`resend_provider.py:274-296`, `resend_provider.py:455`).

### 6.2 DELETE

- **Irreversible.** A deleted domain or email copy cannot be restored by SaaS-OS. The client must not hide that: it should be a plain method with no retry and no convenience that suggests safety.
- **Idempotent in HTTP terms, not in outcome.** A repeat `DELETE` of a resource that is already gone usually answers `404` (assumption about Resend, not verified). The issue states "`DELETE` is idempotent at the provider"; the caller therefore cannot tell from the retry's `404` whether its first attempt deleted the resource or someone else did. For the domain case the desired end state is "absent", so `404` after an ambiguous first attempt can be read as success; for any case where the caller must know it was the one that deleted, it cannot.
- **Ambiguous first attempt.** `EgressError.request_may_have_been_sent` already says when a retry might repeat work (`errors.py:1-9`). For `DELETE` the same classification applies as for sending in `docs/architecture/EXTERNAL-OUTCOME-CLASSIFICATION-DESIGN.md` section 1: not sent (retry), succeeded, failed-safe, ambiguous. Recommended for the adapter: on an ambiguous outcome do **not** blind-retry; reconcile by a `GET` of the resource (absent means done) or surface an unknown outcome to the caller.
- **Tie to #223.** `EmailOutcomeUnknownError` (`phase`, `retry_within`) and `EmailNotSentError` (`saas_os/core/email/errors.py:67-104`) were designed for sending, with `retry_within` meaning "a repeated request is provably de-duplicated by the provider for that long". A domain operation has no `Idempotency-Key`, so `retry_within` would always be `None` for `create`, and for `delete` the honest rule is "reconcile, do not retry". #225 must decide whether domain operations raise the same two classes (with `operation="delete_domain"`) or new ones; that is #225's design, but it needs #223's export first so that a consumer can distinguish the cases through the public surface (section 10). Whether `retry_within` is meaningful for a domain `create` is undecided.
- **Authorisation of the caller.** The client has no notion of who may delete. Authorisation of "this tenant may delete this domain" belongs to the Core interface #225 proposes, not to egress.

### 6.3 Redirect and error mapping for the new verbs

No new error classes are needed: the existing `EgressRedirectError`, `EgressResponseTooLargeError`, `EgressTimeoutError` (with `phase` and `request_may_have_been_sent`), `EgressProtocolError` and the destination errors cover both verbs. Whether to add a `reason` or error for "unexpected content type" is a question for the adapter, not the client (section 9, question 5).

## 7. Test plan and negative controls (for whichever option is approved)

Unit tests, in `tests/infra/egress/`, parametrised over the verbs so the same assertion runs for `post`, `get` and `delete` where it applies:

1. **Verb and body.** The request line carries the right method; `get` and `delete` send no body, no `Content-Length` and no `Transfer-Encoding` (socket-level, using the pattern of `tests/infra/egress/test_strict_egress_socket_unit.py`), through the default transport and through the proxied transport.
2. **Shared guarantees, once per verb:** disallowed scheme, port and URL forms; a non-public literal; a non-public resolved answer; a mixed answer; resolution once per call (rebinding); pinning with the original TLS name and `Host`; forbidden caller headers (`host`, `content-length`, `transfer-encoding`); redirects not followed for every 3xx; a declared and a streamed oversized response; refused content encoding; expired deadline sends nothing; total deadline; each timeout phase and its `request_may_have_been_sent`; failure after send is not retried on another address; TLS failure not retried; cancellation closes the response; proxy refusal permanent, unreachable proxy transient, no direct fallback; environment proxy ignored.
3. **Hygiene.** Errors and `repr` carry no URL, query, header or body for each verb; an `httpx` record at `DEBUG` for a `GET` with a path and query carries only the origin (extends `tests/infra/observability/test_log_filters_unit.py`).
4. **Compatibility.** The existing `post` tests pass unchanged; the public API snapshot lists exactly the new methods; the AI adapters' `EgressClient` protocol still accepts a client; `scripts/check-egress-e2e.sh` gains a `GET` and a `DELETE` through the real proxy and resolver, including a raw-`CONNECT` refusal case unchanged.
5. **Adapter tests (when a read or delete adapter is built, not part of the egress change):** identifier patterns refuse traversal and encoded forms; a response with a wrong content type, invalid UTF-8 or an unexpected shape is a fixed-reason error; message text appears in no log or exception (canary); `DELETE` is not retried blindly after an ambiguous outcome.

**Negative controls** (done by temporary mutation, then restored; never left in the tree): remove the address validation from the `get` path and confirm the non-public tests fail for the intended reason; remove the redirect check; remove the size check; let a `Content-Length` header through; remove the forbidden-header loop for `delete`; send the body on `get`. Each must make exactly the corresponding test fail. If the implementation uses one shared private method, a mutation there must fail the tests of all three verbs; if only one verb's tests fail, the verbs do not share the path and the matrix is incomplete.

## 8. What could not be verified

- Resend's API itself: that `GET /emails/receiving/{id}` exists and what it returns, any limit on inbound message size, whether it ever redirects, how it answers a repeated `DELETE`, whether `DELETE /domains/{id}` exists, its rate limits for these endpoints, and whether attachment download links point to other hosts. Everything above that depends on these is marked as an assumption. The issue states the `GET` endpoint but not the rest.
- That `httpx` normalises `..` path segments (relevant to section 5.3); not tested here.
- Whether a `GET` through the CONNECT tunnel behaves exactly as `POST` (it should, because the tunnel is below HTTP, `proxy.py:1-24`); not run here. The Docker end-to-end gate would show it.
- The memory behaviour under the worker's real concurrency with a larger cap; no measurement was made.
- No code or tests were run for this document beyond the repository's documentation-reference test.

## 9. Open questions that only the owner can answer

1. **Scope of the first step.** `get` only (unblocks inbound content), or `get` and `delete` together (unblocks #225 too)? Undecided.
2. **Version.** Is an additive public method a `0.Y.0` change for this project (ADR-0015 says a changed or removed signature is)? Undecided.
3. **Response cap.** Keep the cap per client (a read adapter builds its own client with its own cap, no API change), or add a per-call lower-only cap, or a per-call cap that may exceed the policy? The recommendation below is the first, but the owner owns the memory-risk trade-off, and the actual cap value for inbound mail is undecided and depends on what Resend can return.
4. **Host allowlist.** Add `allowed_hosts` to `StrictEgressPolicy` now (Option D3), later, or never (convention only)? It changes a security control and is not required for A.
5. **Content type.** Should the client or the adapter enforce `Content-Type: application/json` on read responses? Recommendation: the adapter.
6. **Sanitisation helper.** Should SaaS-OS offer any inbound-content helper (HTML stripping, link neutralising), or leave all of it to the product? Recommendation: leave it to the product, and document the boundary in `docs/CONSUMER-GUIDE.md` when the adapter exists.
7. **Domain operation outcome classes (for #225).** Reuse `EmailOutcomeUnknownError` and `EmailNotSentError` for domain operations, or new classes; and whether `delete` reconciles by `GET`.
8. **Where Resend read and domain code lives.** In `saas_os/core/email/` next to `resend_provider.py`, or a separate module, and whether it is a new public interface (it would be, in #225). A new public Core interface needs the owner's approval of its contract.
9. **Attachments.** Confirm that fetching attachments is out of scope for any SaaS-OS read adapter (the consumer says it never fetches them).

## 10. Recommendation (separate from the facts above)

**Recommended: Option A, delivered as D2 (staged), without a per-call cap and without a host allowlist in this change.**

1. First change: add `get` to `StrictEgressClient`, implemented as a thin public method over a private request method with a closed internal verb type, sharing the whole pipeline with `post`. `post` unchanged. Use a dedicated client with its own policy (and cap) for the inbound read adapter. Test per verb with a matrix; extend the e2e driver.
2. Second change, only when #225 is approved: add `delete` the same way, with the same matrix, and document in the module docstring and consumer guide that the client never retries, that `DELETE` outcome after an ambiguous failure must be reconciled, and that a redirect or a non-2xx is the caller's to classify.
3. Do not add `get_json` or any parsing to infrastructure (Option B's JSON variant), and do not pursue Option C.
4. Treat the host allowlist (Option D3) as a **separate** proposal; do not block the verbs on it. Meanwhile require, in the adapter tests and the review checklist, a constant provider host and a strict identifier pattern.

Reasons, in order of weight: it is the only route that keeps the guarantees in one audited place (the whole point of ADR-0054 8b and ADR-0059); the proxy and Squid policy need no change; it is additive; staging avoids shipping an irreversible verb before it has a caller; and `get` alone fully unblocks the stated business need.

**Smallest decision the owner must make:** approve (or refuse) adding `get` to `StrictEgressClient` with the same policy as `post` (question 1 and 2 of section 9 follow). Everything else in this document can be decided later.

**ADR vehicle.** No new ADR number for the verbs alone: the client's contract is defined by `docs/ADR/0054-governed-ai-inference-subsystem.md` section 8b, and the change keeps its policy and adds no behaviour that the ADR forbids. Recommended: a short dated amendment to ADR-0054 section 8b (new public methods, the per-verb test matrix, the caller-side rules for `DELETE`), plus a one-line note in ADR-0059 that the proxy is verb-independent. If the owner chooses Option D3 (host allowlist), that is a security-control change and deserves an amendment (or a new ADR in Proposed status) of its own. #225 introduces a new Core interface and a new provider operation set and should have its own new ADR (status Proposed) before implementation, in the way ADR-0057 and ADR-0058 were added; this proposal does not allocate a number.

**Order and dependencies.**

1. #223 (export the two email error classes): independent of #205, additive, small. Land it before or with #225, because #225's consumers need the classes on the public surface to tell an unknown outcome from a transient failure.
2. #205, first step (`get`): independent of #223, #224 and #225. Unblocks inbound content immediately.
3. #224 (allow-listed headers): independent of everything here; touches the send path and the SMTP provider only.
4. #225 (domain interface): after #205's `delete` step and #223, with its own ADR.
5. #205, second step (`delete`): together with, or just before, #225's implementation.

## 11. Acceptance criteria (for the first step, if approved)

1. `StrictEgressClient.get(url, *, headers, deadline)` exists; it sends `GET` with no body; `post` is byte-for-byte unchanged in behaviour and signature.
2. `get` runs the same validation, resolution, pinning, TLS, proxy, redirect, encoding, size, deadline and error paths as `post`, shown by a verb-parametrised test matrix, not by code inspection.
3. A `Content-Length`, `Transfer-Encoding` or `Host` header from the caller is refused for `get`.
4. No URL, query, header or body appears in an error, a `repr` or a log record produced by a `get` call.
5. The public API snapshot contains exactly the new entry; the updater policy review and the architecture tests pass; import boundaries unchanged.
6. The Docker egress end-to-end gate includes a `GET` through the real proxy and resolver, and its negative control still fails when the application's address check is disabled.
7. Negative controls (section 7) were run, each failed for the intended reason, and the tree was restored.
8. Documentation updated: the module docstring of `saas_os/infra/egress/client.py`, ADR-0054 section 8b amendment, `docs/CONSUMER-GUIDE.md` (methods, no automatic retry, caller-side rules), the changelog marking the change additive.
9. No change to `StrictEgressPolicy`, `EgressResponse` or the error classes.

## 12. Owner decisions (recorded 2026-11-06)

The owner approved the recommendations of section 10 in the form below, after reading the summary of this document. This section records what was decided; the earlier sections are unchanged and keep the facts and the reasoning. Implementation is a separate approval.

| # | Question (section 9) | Decision |
|---|---|---|
| 1 | Scope of the first step | `get` first, with exactly `post`'s policy. `delete` is added together with #225, which is its only consumer, and reconciles with a `GET` instead of a blind retry. |
| 2 | Version | An additive public method is not a `0.Y.0` change on its own (ADR-0015 names a removed or changed public signature). The label of a release that carries it is decided at that release, as for v0.9.0. |
| 3 | Response cap | Per client, set by the adapter that needs it (no change to `StrictEgressPolicy` or `EgressResponse`). The first value for the inbound-mail read adapter is **1 MiB, configurable**; this value is a starting point chosen without a measurement and is to be settled by the inbound-mail requirement. |
| 4 | Host allowlist | Later, as its own proposal. Nothing is added to `StrictEgressPolicy` now. |

**Not decided here** (questions 5 to 9 of section 9, and the ADR vehicle of section 10): where `Content-Type` is enforced, whether SaaS-OS offers any sanitising helper, the outcome classes and the home of the code for #225, attachments, and whether the vehicle is an amendment of ADR-0054 section 8b plus a note in ADR-0059. Each stays **undecided**; the recommendations of section 10 stand as recommendations.

**What this authorises.** Recording the direction only. Building `get` needs its own approval after the acceptance criteria of section 11 are read; `delete` waits for the #225 proposal.
