# ADR-0059: Controlled worker egress through a policy-enforcing proxy

Status: Accepted (direction, 2026-10-27). The repository owner approved the direction on 2026-10-27 (decisions 1 to 5 below). Implementation follows in separate pull requests, and this record is amended with each one's evidence.
Date: 2026-10-27
Supersedes / Superseded by: amends ADR-0057 section 7 (owner decision 1, option b), the ADR-0035 amendment of 2026-10-18 (no proxy), ADR-0054 Q2 (no proxy from the environment) and ADR-0058's no-proxy rule.
Related: `docs/architecture/WORKER-EGRESS-DECISION-BRIEF.md` (the brief this decides), ADR-0035 (webhooks), ADR-0054 sections 8a and 8b (strict egress), ADR-0057 (email providers), ADR-0058 (Resend), deferred-issue ledger rows "G9: the reference production topology cannot reach an external SMTP relay", "Worker egress investigation", and "The Resend adapter cannot use an environment HTTP(S) proxy".

## Context

- In `docker-compose.prod.yml` the worker joins only `internal` (`internal: true`). It was observed on 2026-10-27 to have no DNS for public names, no default route and no TCP connectivity, so webhook delivery and external email cannot work in the reference topology (the brief, section 1).
- That isolation is the second layer behind the application's SSRF policy. Giving the worker a route directly would remove it.
- Owner decisions of 2026-10-27:
  1. The worker stays isolated, with no direct outbound route, and uses a controlled egress proxy.
  2. The webhook client and the Resend client (`StrictEgressClient`) gain explicit proxy support.
  3. A maintained proxy is evaluated and chosen, with its licensing, maintenance, configuration, threat model and rationale documented before the dependency is introduced (this record).
  4. HTTPS on port 443 is the proposed production default. An HTTP webhook destination needs an explicit opt-in, with the compatibility and migration consequences documented before any default changes.
  5. Defence in depth for `httpx` request-line logging and for the OIDC callback's access-log line (pull request #126).

## Requirements (from the owner's decision)

- R1 The worker has no direct egress, and nothing falls back silently to a direct connection.
- R2 The application passes the validated destination IP to the proxy.
- R3 The proxy independently enforces address-range and port restrictions and connects only to the destination it was given.
- R4 TLS is verified on the hostname, and `Host` and SNI are correct when the connection is made to an IP.
- R5 IPv4 and IPv6 reserved, private, loopback, link-local and metadata destinations are refused.
- R6 Redirects stay disabled; any future redirect support revalidates every destination.
- R7 A proxy failure fails closed.
- R8 No URL path, query, credential or sensitive header reaches the proxy's, `httpx`'s, arq's or the application's logs.
- R9 Resend's credential cannot be sent to an unintended destination.

## Proxy evaluation

Facts as of 2026-10-27, from each project's repository and the probe below.

| | Squid | Smokescreen | Envoy | tinyproxy |
|---|---|---|---|---|
| Licence | GPL-2.0 (separate process; SaaS OS links nothing) | MIT | Apache-2.0 | GPL-2.0 |
| Maintenance | Active; release 7.7 on 2026-08-24; Canonical maintains `ubuntu/squid` long-term images (6.6 on 24.04 LTS) | Active (Stripe); first tagged release v0.1.0 on 2026-09-21 | Very active; v1.40.2 on 2026-10-27 | Active; 1.11.3 on 2026-03-07 |
| Image | `ubuntu/squid` (Canonical) | `ghcr.io/stripe/smokescreen` | `envoyproxy/envoy` | community images |
| Destination ranges | `dst` ACLs, IPv4 and IPv6 | built-in private-range refusal, `--deny-range` and `--allow-range` | RBAC and cluster configuration, complex for a forward proxy | coarse |
| Port allowlist | `port` ACL | **no global allowlist**: ports only on single `ip:port` rules (`pkg/smokescreen/config.go`) | possible | `ConnectPort` |
| Refuse hostname targets (no proxy DNS) | `dstdom_regex` | resolves names itself | configurable | no |
| Log format without URL | `logformat` | not documented | configurable | limited |

**Choice: Squid**, as `ubuntu/squid` pinned by digest, with a minimal configuration that SaaS OS ships. It is the only candidate that meets R3 (ranges and a port allowlist) and R2 (IP-literal targets only) by configuration alone, and it has a long-term maintained image. Smokescreen is purpose-built for SSRF and runs Stripe's webhooks, but it cannot restrict ports for every destination, and it resolves hostnames itself. Envoy could meet the requirements, but its forward-proxy configuration is large for one policy. tinyproxy cannot refuse hostname targets. GPL-2.0 applies to the Squid program, which runs unmodified in its own container; no SaaS OS code is linked with it.

## Probe (2026-10-27, `ubuntu/squid:6.6-24.04_edge`, `sha256:8a3baed477e2c282ab8aa5edad442f69873246964f225c5c2ae8364b6610963c`)

The policy: `CONNECT` only; IPv4 or IPv6 literal targets only; port 443; a deny list of never-public ranges; no cache; a log format of time, client, method, destination `ip:port`, status and result. It was run in a disposable container, and raw `CONNECT` requests produced these answers:

- **200**:
  - `1.1.1.1:443`;
  - `[::ffff:1.1.1.1]:443`;
  - `[2606:4700:4700::1111]:443`, which the policy allowed and the connection then failed with 503, because the probe host has no IPv6 route.
- **403**, every prohibited case:
  - IPv4: `169.254.169.254`, `10.0.0.1`, `127.0.0.1`, `100.100.100.200`;
  - IPv6: `[::1]`, `[fd00:ec2::254]`, `[fe80::1]`;
  - embedded loopback: `[::ffff:127.0.0.1]`, `[64:ff9b::7f00:1]`;
  - ports `80` and `8443` on a public address;
  - a hostname target (`one.one.one.one:443`);
  - plain HTTP forwarding (`GET http://1.1.1.1/`).
- **TLS through a tunnel to an IP literal**, verified with `certifi`:
  - `server_hostname="one.one.one.one"` verified (TLS 1.3, HTTP 200);
  - `github.com` was refused (`Hostname mismatch`).

  A CDN address can legitimately serve certificates for many names: `api.resend.com` also verified against `1.1.1.1`. So TLS proves the hostname, not the address. The destination is bound by the application connecting only to an address it resolved for that hostname, together with TLS verification of the hostname.
- **Access log:**
  - allowed lines read `CONNECT 1.1.1.1:443 200 TCP_TUNNEL`;
  - denied lines read `CONNECT -:- 403 TCP_DENIED`;
  - there is no URL path, query or header in any line.
- **Two configuration pitfalls found:**
  - Squid stores IPv4 addresses as IPv4-mapped IPv6, so listing `::ffff:0:0/96` in a `dst` ACL means `0.0.0.0/0`. That entry broke the deny list ("is a subnetwork of 0.0.0.0/0 … ignored"). The mapped prefix must not be listed; mapped addresses are judged by their IPv4 form, as the `[::ffff:127.0.0.1]` result shows.
  - Squid runs as the `proxy` user and cannot open `/dev/stdout`, so the shipped configuration must log to a path the user can write, or through a log daemon.

## Decision

1. **Topology (amends ADR-0057 section 7).**
   - `worker` stays on `internal` only.
   - A new `egress-proxy` service (Squid) joins `internal` and a new network, `egress`, which is not `internal`. It publishes no host port.
   - No other service joins `egress`.
2. **Clients (amends the ADR-0035 amendment of 2026-10-18, ADR-0054 Q2 and ADR-0058).**
   - The webhook client and `StrictEgressClient` take an explicit proxy from configuration, never from the environment (`trust_env=False` stays).
   - When a proxy is configured, every connection is an HTTP `CONNECT` to the validated IP literal and port, with TLS and SNI on the original hostname and `Host` set to it.
   - A proxy refusal or failure ends the attempt. There is no direct retry.
   - With no proxy configured, behaviour is as today, which suits development and products that provide their own egress. In the reference production topology, the worker has no route to fall back to anyway.
3. **Proxy policy.** It lives in a shipped configuration file under `deploy/`:
   - `CONNECT` only, to IPv4 or IPv6 literals only;
   - the port allowlist is `443`;
   - the deny list covers the ranges `is_non_public_address()` refuses (RFC 1918, CGNAT, loopback, link-local and metadata, documentation, benchmarking, multicast, reserved; IPv6 ULA, link-local, site-local, NAT64, 6to4, Teredo);
   - no cache;
   - a log format without URL, header or body.
4. **Failure classes.**
   - A `403` from the proxy, meaning its policy refused a destination the application accepted, is a permanent rejection, because a retry cannot change it.
   - A proxy that cannot be reached, a `5xx`, or a tunnel that fails to establish is transient, retried within the existing policy, and never sent directly.
5. **HTTP destinations.** HTTPS on port 443 is the reference default. An `http://` webhook destination needs an explicit opt-in. Its compatibility and migration consequences are recorded before any default changes. With the proxy, plain HTTP also goes through `CONNECT`; `httpx` would otherwise forward it with the full URL visible to the proxy. A product that opts in widens the proxy's port allowlist itself.
6. **Redirects** stay disabled (`follow_redirects=False`). Any future support must validate and pin every hop again.
7. **Email.**
   - Resend goes through the proxy with the same rule. Its fixed endpoint, `api.resend.com`, is resolved and validated by the application, and TLS is verified on that name.
   - `smtplib` cannot use `CONNECT`. SMTP needs a relay reachable on `internal`, as ADR-0057 section 7 already allows, and this record does not change SMTP.

## Consequences

- One container image is added to the reference topology. It is pinned by digest and updated deliberately, like the ZITADEL images.
- The proxy is the single place where outbound connections are visible, by destination IP and port only.
- Webhooks and Resend work in the reference topology once implemented; SMTP still needs a reachable relay.
- Products that run their own worker choose whether to configure the proxy.

## Validation plan

Each implementation pull request adds its tests to this section.

**Pull request #128, client proxy support (2026-10-27).** `EGRESS_PROXY_URL` (`http://<host>:<port>` only) enables it for webhook delivery and the Resend provider. `saas_os/infra/egress/proxy.py` tunnels each connection through a network backend, because httpx's own proxy verifies TLS against the `CONNECT` host (the IP). Evidence, on real sockets with a fake `CONNECT` proxy and a local TLS server (`tests/infra/egress/test_egress_proxy_unit.py`, `tests/core/webhooks/test_webhook_egress_proxy_unit.py`, `tests/core/email/test_resend_provider_unit.py`, `tests/api/test_worker_unit.py`):
- the proxy receives only `CONNECT <ip>:<port>` (IPv6 bracketed), also for plain HTTP;
- the destination sees SNI and `Host` on the hostname, and a certificate for another name fails;
- the proxy's `403` makes a webhook permanently rejected; every other failure is transient;
- no direct connection is made in any failure (every TCP connect is recorded);
- redirects are not followed, and environment proxies are ignored;
- Resend's `Authorization` header reaches only the TLS session verified on `api.resend.com`, never the proxy;
- an invalid `EGRESS_PROXY_URL` stops the worker and the Resend provider.

Negative controls (the client ignoring the proxy; a `403` treated as unavailable; a direct fallback) each fail the tests meant to catch them.

Still to validate: the topology and the Squid configuration in a disposable stack (next pull request), including the policy with the application's own check bypassed, a rebinding name, and the worker failing to connect directly.

Planned checks:

- **Client tests:** `CONNECT` carries the IP literal; there is no use of an environment proxy; TLS is verified on the hostname with correct SNI and `Host`; a proxy `403` is permanent and a proxy failure is transient, with no direct fallback; redirects are not followed; and no URL path, query or header reaches any log.
- **Topology tests:** `worker` is on `internal` only; `egress-proxy` is the only member of `egress`; the configuration's deny list matches `is_non_public_address()` for a table of addresses.
- **A disposable stack:**
  - Proxy policy: prohibited destinations are refused by the proxy with the application's own check bypassed, as a negative control.
  - DNS rebinding: a name that resolves differently for the second lookup is delivered only to the address the application validated.
  - Direct egress: the worker fails to connect directly.
