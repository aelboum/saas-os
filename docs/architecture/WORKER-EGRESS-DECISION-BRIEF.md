# Worker egress: decision brief (ledger rows 891 and 892)

**Status: decided 2026-10-27; see [ADR-0059](../ADR/0059-controlled-worker-egress.md).** The owner chose option C. The text below is the brief as presented. Prepared 2026-10-27 against `main` `502e51a`. It records what the reference production topology does today, what outbound traffic has to work, and the options, with a recommendation. Every option that changes the topology, the egress clients or a dependency needs the owner's approval (section 7).

## 1. Current restriction (verified)

- `docker-compose.prod.yml`: `worker` is a member of `internal` only; `internal` is `internal: true`. `backend` is on `edge`, `internal` and `identity-edge`; `edge` is the only network with a gateway.
- Docker on this machine, a network created with `--internal` like `internal` (2026-10-27): DNS for a public name answers `SERVFAIL`; the only route is the network's own subnet; a TCP connection to a public IP literal (`1.1.1.1:443`) fails. The same probes succeed on the default bridge. Row 892 had this as "inferred, not tested"; it is now observed.
- Consequence in the reference topology:
  - **Webhooks:** `_default_resolve_hostname()` cannot resolve the destination, raises `WebhookDestinationUnresolvedError` (transient), and the delivery is retried until the job's attempts run out, then dead-lettered. Nothing is sent and nothing is recorded as delivered.
  - **Email:** `smtplib` cannot reach the relay, and Resend's strict egress client cannot resolve `api.resend.com`. Notifications are retried and dead-lettered, never recorded as sent (row 891).
- ADR-0057 section 7 (owner decision 1, option b) chose this for email: the topology is unchanged and a deployment provides the connectivity its provider needs. Webhooks were left to this investigation.

## 2. Traffic that must work

| Flow | Process | Destination | Protocol and port | Client and controls today |
|---|---|---|---|---|
| Customer webhooks | worker | any public host a tenant subscribed | HTTPS 443, optionally HTTP 80 or other ports (`WEBHOOK_ALLOWED_PORTS`, unset by default) | `httpx`, `trust_env=False`, `follow_redirects=False`, one resolution per attempt, every address judged by `is_non_public_address()`, the connection pinned to the validated address with SNI on the original name, a 10 s overall deadline, response body never read |
| Resend | worker | `api.resend.com` | HTTPS 443 | `StrictEgressClient`: no proxy, refuses a private resolution, pinned connection (ADR-0058; row 894) |
| SMTP relay | worker | the operator's relay (`SMTP_HOST`) | 587 STARTTLS or 465 implicit TLS | `smtplib`, operator-configured host; no SSRF policy, because the host is not tenant input |

Not in scope: AI providers and GitHub (called from the API process, on `edge`), ZITADEL (`identity-edge`), backups (host timers).

## 3. Trust boundaries

- **Tenant-controlled:** the webhook URL. It is the SSRF surface: a tenant administrator chooses where the worker connects. All current controls are in the application.
- **Operator-controlled:** the SMTP relay and the Resend endpoint. Their configuration comes from `.env.app` or the secrets provider, not from tenants.
- **The worker holds** the database and Redis credentials for every tenant and the webhook signing secrets. Whatever the worker can reach, a defect in its outbound code can reach with those credentials in memory.
- **Today the network is the second layer:** with no route out, an application-level SSRF defect cannot reach anything outside `internal`. Any option that gives the worker a route removes that layer unless it puts another in its place.

## 4. Threats any option must still answer

- **SSRF to internal and metadata addresses** (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`, RFC 1918, CGNAT, loopback, link-local, the Docker host's bridge gateway): refused today by `is_non_public_address()`, including IPv4 embedded in IPv6 (mapped, NAT64, 6to4).
- **DNS rebinding:** defeated today by resolving once, judging every address, and connecting to the judged IP. A proxy that re-resolves the name would reopen the window; the application must hand it the IP literal.
- **Redirects:** never followed (`follow_redirects=False`); a 3xx is a response.
- **Proxies from the environment:** ignored (`trust_env=False`; ADR-0035 amendment of 2026-10-18).
- **DNS itself:** the resolver the worker uses decides what names map to. A split-horizon resolver that returns private addresses is refused by the policy, but a resolver controlled by an attacker can still steer deliveries among public addresses.
- **Ports:** any port is allowed unless `WEBHOOK_ALLOWED_PORTS` is set.
- **Exfiltration and abuse:** a tenant can make the worker send requests to arbitrary public hosts at the worker's rate. That is the feature; it should be bounded and observable.

## 5. Options

**A. Attach the worker to an egress network.** Add a non-internal network with a gateway to `worker` only.
- For: no code change; webhooks, Resend and SMTP all work; small Compose diff.
- Against: the network layer stops limiting anything. The application policy becomes the only control, and the worker can reach whatever the host can route, including the bridge gateway and, on a cloud host, the metadata service, unless the host firewall blocks them. Network-level limits then live outside this repository (for example `DOCKER-USER` iptables rules), so they are deployment-specific and untested here.

**B. A separate egress worker.** Run webhook and email jobs on their own queue, in a second worker on `internal` and an egress network; every other job stays on the internal-only worker.
- For: narrows which code has a route out.
- Against: code and configuration change (queue routing, a second service). The egress worker still holds the database credentials, so the blast radius of an SSRF defect is barely smaller. Same network-layer gap as A.

**C. A controlling egress proxy (recommended for the reference topology).** Keep `worker` internal-only. Add an egress proxy dual-homed on `internal` and an egress network, for example Smokescreen (Stripe's SSRF-focused CONNECT proxy). Webhook deliveries and Resend go through it with HTTP `CONNECT` to the already-validated IP literal and port.
- For: the network keeps a second layer. The proxy refuses private, link-local, metadata and CGNAT ranges and non-allowed ports on its own, so an application defect is still contained. It is the single point that can rate-limit and log outbound connections, by host and port only; HTTPS paths stay encrypted, consistent with pull request #122. The worker still has no route.
- Against:
  - The webhook client and `StrictEgressClient` must support an explicit proxy that receives the pinned IP literal, not the name, without reading the environment. That changes ADR-0035's amendment and ADR-0054 Q2 (no proxy) and row 894.
  - It adds a container image and its maintenance (a new dependency).
  - `smtplib` cannot use an HTTP `CONNECT` proxy, so SMTP needs either a relay reachable on `internal` (which ADR-0057 section 7 already allows) or a proxy-capable SMTP client.

**D. Status quo, documented.** The deployment provides connectivity (ADR-0057 section 7, extended to webhooks).
- For: no change.
- Against: webhooks do not work in the reference topology, and every deployment designs its own egress controls without a tested pattern.

## 6. Recommendation

1. **Target: option C.** The worker stays internal-only. Webhooks and Resend go through a CONNECT proxy that receives the validated IP literal and enforces the same deny ranges and a port allowlist (443 by default) independently of the application. Mail goes to an operator relay reachable on `internal`, or to Resend through the proxy. Outbound connections are logged by host and port only.
2. **Defaults to adopt with it:** `WEBHOOK_ALLOWED_PORTS=443` in the reference topology (refusing `http://` there), and a per-tenant or global delivery rate limit if abuse is seen.
3. **Until C exists:** a deployment that needs webhooks may use option A only with host firewall rules that deny RFC 1918, CGNAT, link-local and metadata destinations and allow only the needed ports. Document that as a deployment responsibility; it should not be presented as tested by this repository.
4. **Not recommended:** B, which adds complexity without materially reducing the blast radius, and D for webhooks, which leaves the feature unusable in the reference topology.

## 7. Decisions that require owner approval

1. Change the reference production topology (any of A, B or C), revisiting ADR-0057 section 7 (owner decision 1, option b).
2. Allow an explicit proxy in the webhook client and `StrictEgressClient` (amending ADR-0035's 2026-10-18 amendment, ADR-0054 Q2 and ADR-0058's no-proxy rule), and the rule that the proxy is given the pinned IP literal.
3. Add the proxy as a new dependency (choice of image, version and digest pinning, update process).
4. Set `WEBHOOK_ALLOWED_PORTS=443` as the reference default and whether `http://` destinations stay allowed (ADR-0035 accepts them today).
5. If option B is preferred: a queue split for outbound jobs.

## 8. Observability and regression testing for the chosen option

- **Observability:**
  - per-destination-class counters for refused, failed and delivered deliveries (the job already records reason codes such as `ConnectError` or `deadline_expired`);
  - proxy logs and denial counts by host and port;
  - an alert on dead-lettered webhook and notification jobs;
  - no URL path or query in any log (`tests/infra/observability/test_logging.py`).
- **Static tests:** extend the existing topology tests (`tests/architecture/test_production_identity_topology.py`, `test_email_provider_topology.py`) to pin which services join which networks and that `worker` has no gateway (for C).
- **Client tests:** the webhook client and `StrictEgressClient` send `CONNECT` with the IP literal, never the name; refuse to use a proxy from the environment; and keep pinning and SNI.
- **Integration:** a disposable stack in which a delivery to a public test endpoint succeeds through the proxy, and deliveries to the metadata address, a private address, the bridge gateway, a non-allowed port, a redirect and a rebinding name are refused at both layers (application refusal, and proxy refusal with the application check disabled as a negative control).
- **CI:** decide whether the production-topology check (`check-docker-prod.sh`) becomes a required check; today it is manual.
