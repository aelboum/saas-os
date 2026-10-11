# ADR-0042: Reusable frontend strategy

Status: Accepted (2026-10-11)
Date: 2026-10-11
Supersedes / Superseded by: —

## Context

ADR-0011 chose TypeScript and Next.js for "any UI the platform itself ships" and as the expected default for product frontends. `docs/SINGLE-ORIGIN-RUNTIME.md` already assigns ownership: the product provides "its frontend", "its authenticated entry route", "its dashboard" and "its navigation and tenant UX"; SaaS OS provides identity, the origin contract and the edge routing.

What `frontend/` contains today (about 1,160 lines including tests and configuration):

| Part | Content | Reusable by a product? |
|---|---|---|
| `frontend/i18n/` | locale list and resolution (cookie, `Accept-Language`), dictionary loading, interpolation and plural rules, date/number formatting, text direction (LTR/RTL), a React context, a lint-style test that forbids hard-coded UI strings | Yes, as a pattern. Generic, with English, French and Arabic dictionaries for the one placeholder page. |
| `frontend/components/LanguageSwitcher.tsx` | one component | Yes, trivially. |
| `frontend/app/` | a layout and one placeholder page that demonstrates the i18n functions | No. |
| Build and test configuration | Next.js, ESLint, Vitest, Dockerfile | As a starting point only. |

What it does not contain: any call to `/auth/*` or `/v1/*`, any session handling, any tenant switcher, any API client, any design system, any authenticated page. It is not published as a package (`"private": true`), and the Python distribution does not ship it.

So the question is not "should the existing frontend be packaged" — there is almost nothing to package — but "should SaaS OS grow a reusable frontend layer".

There is no product, so there is no evidence about which UI a product would actually share with another.

## Options Considered

### Option A — Frontend stays product-owned; `frontend/` remains this repository's own development fixture
- Advantages: matches `docs/SINGLE-ORIGIN-RUNTIME.md` as written; no second distribution channel, versioning scheme or release process; no design decisions imposed on products that will each have their own brand and UX.
- Disadvantages: each product writes its own login redirect handling, `/auth/me` call and tenant context. Those are small, but they are security-adjacent and easy to get subtly wrong (open redirect after login, treating a cached `me` as authoritative).

### Option B — A small, headless client package (`@saas-os/client`)
Typed functions and React hooks only: current user, login/logout redirects, a tenant-scoped `fetch` wrapper with consistent error shapes, the i18n utilities. No visual components.
- Advantages: the security-adjacent glue is written once; no styling is imposed.
- Disadvantages: needs an npm distribution channel (a registry or Git dependency), a versioning policy coupled to the backend's route contract, and CI for a second ecosystem. Its API depends directly on ADR-0040: until the platform's HTTP routes are decided, a client has only four auth routes to wrap.

### Option C — A component library or admin console (members, invitations, API keys, billing)
- Advantages: a product gets working administration screens.
- Disadvantages: depends on ADR-0040's routes existing; imposes a design system; by far the largest surface to maintain; nothing indicates products would accept its look and structure.

### Option D — A frontend scaffold, copied once, parallel to `examples/consumer-scaffold/`
A minimal Next.js application with the login round trip, a `me` fetch and the i18n module, owned by the product after copying.
- Advantages: the same model ADR-0015 rules 9–10 and ADR-0039 use for the backend; no package, no registry, no versioning; testable in this repository's CI.
- Disadvantages: copied code does not receive fixes.

## Recommendation

**Option A now. Option D is the next step when the first product starts, and Option B only if two products end up copying the same glue.** Option C is not recommended.

Reasons:

1. A reusable frontend layer is a wrapper around HTTP routes, and the routes are undecided (ADR-0040). Building the wrapper first would fix a client API around four auth routes and then change it.
2. Nothing in the current `frontend/` is worth a distribution channel. The i18n module is about 400 lines a product can copy.
3. The ownership line already written in `docs/SINGLE-ORIGIN-RUNTIME.md` is coherent and no evidence contradicts it.

What Option A means concretely:

- `frontend/` is documented as this repository's own fixture for the single-origin runtime and the i18n foundation — not a product, and not a deliverable to consumers.
- `docs/CONSUMER-GUIDE.md` states that there is no reusable frontend.
- The login round trip a product frontend must implement stays documented in `docs/SINGLE-ORIGIN-RUNTIME.md`.

## Decision

**Accepted by the repository owner on 2026-10-11: Option A — the frontend remains product-owned.**

1. SaaS OS defines reusable backend capabilities and stable API contracts. It does not define a product frontend.
2. SaaS OS does not impose a universal product frontend or a mandatory frontend framework. ADR-0011's TypeScript + Next.js choice applies to any UI this repository itself ships and is a default a product may adopt, not a requirement on products; a product may use any frontend technology that can call the HTTP API and follow the single-origin contract.
3. Any future shared UI library must be optional and independently versioned, distributed separately from the `saas-os` Python package, and decided by its own ADR.
4. No shared frontend package is created.
5. `frontend/` in this repository is its own fixture for the single-origin runtime and the i18n foundation. It is not a deliverable to consumers.

## Security note for any later option

Any shared frontend code that reads `/auth/me`, handles the post-login redirect or attaches credentials is security surface: it must not accept a redirect target from a query parameter, must treat the server's answer as authoritative on every navigation that matters, and must never store the session secret where script can read it (the backend sets an HTTP-only cookie). That code would need the same review as `api/auth`.

## What Would Be Difficult to Change Later

Option A is the cheapest to leave: adding a scaffold or a package later breaks nothing. Options B and C are the opposite — a published client or component API is contract in every product's frontend, in a second ecosystem with its own release cadence.

## Related

ADR-0011 (frontend stack); ADR-0024 and `docs/SINGLE-ORIGIN-RUNTIME.md` (origin contract and the ownership table); ADR-0025, ADR-0026 (login topology; embedded login is a draft); ADR-0039 (backend scaffold, the model Option D copies); ADR-0040 (HTTP routes any client would wrap); `docs/P-ROADMAP.md` P6.
