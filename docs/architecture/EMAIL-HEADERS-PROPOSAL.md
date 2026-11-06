# Allow-listed email headers (List-Unsubscribe, In-Reply-To, References): options and recommendation

**Status: Proposal; Option A was approved by the owner on 2026-11-06 (section 14); implementation is not yet approved.** Nothing in this document is built. It changes no code, no test, no public contract and no ADR. Section 14 records the decisions taken; every other decision this document asks for stays **undecided** until the repository owner records it. Date: 2026-11-06, written on `main` `fb08e47` (release v0.9.0). Facts are cited as `file:line` on that commit. A statement with no citation is an inference. Section 9 lists what could not be verified, and section 4 marks which RFC statements were read in the RFC text and which were not.

Answers GitHub issue #224 ("Allow-listed email headers: List-Unsubscribe (RFC 8058), In-Reply-To, References"). Related records: `docs/ADR/0057-deployment-level-email-provider-selection.md` (SMTP, Mailpit, the `Message-ID` rule), `docs/ADR/0058-resend-email-provider.md` (Resend), `docs/ADR/0015-saas-os-distribution-and-consumer-boundary.md` (public API and release labels), `docs/ADR/0020-logging-audit-redaction-boundary.md` (logging), `docs/CONSUMER-GUIDE.md` (finding F3, one mailbox per address field). Pull request #226 (a proposal for `GET` and `DELETE` on the egress client, issues #205 and #225) is an open proposal in the same style; this issue does not depend on it, and it does not depend on this one (section 8).

The issue text is a consumer's request, treated here as requirements to evaluate, not as instructions.

## 1. What is requested, by whom, and what it unblocks

**Requester.** The consumer LeadStack, through issue #224 (opened 2026-11-06, observed at v0.8.0). It asks for no merge or release; its pin stays where it is until its owner approves a move. The issue labels its code a sketch ("the maintainers' design governs").

**Request.** An allow-listed set of headers on `EmailMessage`, validated by SaaS-OS, "at least":

- `List-Unsubscribe`: one or more `<https://...>` or `<mailto:...>` URIs;
- `List-Unsubscribe-Post`: exactly `List-Unsubscribe=One-Click`;
- `In-Reply-To` and `References`: one or more `<msg-id>` values.

Sketch: `EmailMessage(..., headers: Mapping[str, str] = {})` with names from a closed allow-list. Stated security requirements: a closed, case-insensitive allow-list; refusal of CR, LF and other control characters and of over-long values; per-header validation; no override of headers SaaS-OS sets itself (`From`, `To`, `Subject`, `Message-ID`, `Date`, MIME headers); header values not logged. Stated compatibility: additive, defaulting to empty; SMTP sets the headers on the MIME message, Resend sends them in its `headers` field. Stated tests: refusal of an unknown name, of CR or LF, of a malformed URI or msg-id and of an override; SMTP and Resend each carrying the allowed headers.

**What it unblocks.**

- Campaign sending. LeadStack has built audiences, approval, per-recipient unsubscribe links and suppression, but keeps sending off (`crm_app.campaigns.SENDING_AVAILABLE` is false, per the issue) until one-click unsubscribe headers exist. The issue's business reason is the Gmail and Yahoo bulk-sender rules in force since 2024; this document does not verify those rules (section 9). RFC 8058 itself is read in section 4.
- Reply threading. LeadStack threads replies today by a per-conversation routing address; `In-Reply-To` and `References` would let mail clients thread them too. This is an improvement, not a blocker.

**Two corrections to the issue's premises.**

- It says `metadata` is not forwarded by either provider. That is correct: the Resend adapter documents it (`saas_os/core/email/resend_provider.py:97-98`, `docs/ADR/0058-resend-email-provider.md` line 35), and the SMTP adapter builds its message from named fields only (`saas_os/core/email/smtp_provider.py:225-234`). `metadata` is documented as correlation data a provider "may" forward (`saas_os/core/email/provider.py:31-35`), so changing it to carry headers would turn an unvalidated free-form dict into a header channel. This document does not propose that.
- It lists "mailto" as an allowed unsubscribe URI. RFC 8058 requires an https URI for one-click and allows others in addition (section 4); a `mailto`-only `List-Unsubscribe` is valid RFC 2369 but is not one-click. The field design must let the caller express both.

## 2. Current behaviour (facts)

### 2.1 `EmailMessage` and its validation

- `EmailMessage` is a frozen dataclass with `sender`, `to` (a tuple), `subject`, `text_body`, `html_body`, `reply_to`, `metadata` (a mutable `dict`), `message_id` and `idempotency_key` (`saas_os/core/email/provider.py:30-59`). It is public: `tests/architecture/public_api_snapshot.txt:444` lists exactly those nine fields. There is no header field other than `message_id`.
- `message_id` is "an optional RFC 5322 `Message-ID`, angle brackets included"; `idempotency_key` "never becomes a header" (`provider.py:37-49`).
- Validation is `send_email()` calling `_validate_message()` before any provider call (`saas_os/core/email/service.py:100-116`, `service.py:127-150`):
  - every address (sender, each recipient, reply-to): non-empty, no `\r`, `\n` or NUL, the shape pattern, none of the RFC 5322 separators (`, ; : < > " ( ) \`), and for ASCII addresses exactly one `addr-spec` as the standard-library parser reads it (`service.py:46-54`, `service.py:63-80`, finding F3 of 2026-11-01; `docs/CONSUMER-GUIDE.md` line 807);
  - `subject`: no CR, LF or NUL (`service.py:109-110`). Nothing else is checked: a non-ASCII subject is allowed and is encoded by the provider;
  - `message_id`: `fullmatch` of `<[^\s<>@]+@[^\s<>@]+>` (`service.py:58`, `service.py:111-112`);
  - `idempotency_key`: printable ASCII, 1 to 200 characters (`service.py:60`, `service.py:113-116`).
- All of these raise `InvalidEmailAddressError`, including the `Message-ID` and idempotency-key refusals. The error never echoes the value (`saas_os/core/email/errors.py:12-20`).
- Validation lives in `send_email()`, not in the providers. `SmtpEmailProvider.send()` and `ResendEmailProvider.send()` are public (`public_api_snapshot.txt:455-456`) and validate nothing about the message except Resend's recipient count (`resend_provider.py:402-403`). A caller that calls `provider.send()` directly bypasses every check above. Today that is also true of `Message-ID`.
- Adjacent finding, verified on this commit (not part of this proposal, section 10 question 9): the `Message-ID` pattern excludes only whitespace, `<`, `>` and `@`, so it accepts a NUL byte, other control characters below 0x20 that are not whitespace, non-ASCII characters and `"` (`'<a\x00b@c.d>'`, `'<a\x01@c.d>'`, `'<é@c.d>'`, `'<a"b@c.d>'` all match). CR and LF are impossible (they are whitespace), so this is not a header-injection path, but a value that is not a valid RFC 5322 `msg-id` can reach the wire. A new msg-id check for `In-Reply-To` and `References` should not copy this pattern.

### 2.2 How each provider turns a message into a wire request

**SMTP** (`saas_os/core/email/smtp_provider.py:222-279`). A stdlib `email.message.EmailMessage` with the default policy is built (`smtp_provider.py:44`, `:225`): `From`, `To` (the recipients joined with `, `), `Subject`, `Message-ID` (the caller's, else `make_msgid` on the sender's domain), optional `Reply-To`, then `set_content` and an HTML alternative (`:226-234`). `send_message` is called with an explicit envelope, never derived from headers (`:254-256`). Header encoding, folding and the final CRLF line endings are done by the standard library, not by SaaS-OS code. Observed on this machine, Python 3.13.14, default policy, stdlib `EmailMessage`:

- A header value with CR or LF is refused by the library (`ValueError: Header values may not contain linefeed or carriage return characters`). The library is a second defence behind `service.py`, not the first.
- A NUL byte is **not** refused: `m["In-Reply-To"] = "a\x00b"` serialises to `In-Reply-To: a\x00b`. The explicit NUL check in `service.py` is therefore the only barrier, as it is for the subject today.
- A non-ASCII character in a header the library parses as a message-id raises `UnicodeEncodeError` at serialisation, after validation; for an unstructured header it is encoded as an RFC 2047 encoded word.
- **Headers the library does not know are "unstructured" and are folded at 78 characters. A value with no space that does not fit on one line is turned into an RFC 2047 encoded word.** `List-Unsubscribe: <https://e.example/` followed by 40 characters and `>` was written verbatim; with 60 characters it was written as `=?utf-8?q?=3Chttps=3A//e=2Eexample/...?=`. Real unsubscribe URLs carry an opaque token and are routinely longer than that. A receiver that does not decode the encoded word (RFC 2369 and RFC 8058 describe plain angle-bracketed URIs; the encoded-word behaviour is not in either RFC, and what each receiver does with it is not verified) sees no URI, so the message would look compliant in the caller's tests and have no working one-click unsubscribe. Cloning the message policy with `max_line_length=998` wrote the same 120-character URI unencoded. The fix is small, but it is exactly the kind of detail that makes "SMTP sets the headers on the MIME message" less trivial than the issue suggests, and it needs a wire-bytes test (section 7).
- Duplicates: the library refuses a second `In-Reply-To`, `References`, `Message-ID`, `Date`, `Reply-To`, `Bcc` and `Content-Type` (`ValueError: There may be at most 1 ...`), but silently accepts a second `List-Unsubscribe`, `List-Unsubscribe-Post`, `Return-Path` and `Received`. RFC 2369 says there must be no more than one of each list field (section 4), so uniqueness of `List-Unsubscribe` has to be enforced by SaaS-OS, not left to the library.
- `Content-Type`, `Content-Transfer-Encoding` and `MIME-Version` are added by `set_content`; setting `Content-Type` first would make `set_content` conflict. This is why a caller-supplied MIME header can never be allowed.

**Resend** (`saas_os/core/email/resend_provider.py:235-253`, `:360-388`). `request_body()` builds a JSON object with `from`, `to`, `subject`, `text`, optional `html` and `reply_to`, and, only when `message_id` is set, `headers = {"Message-ID": ...}`. It is serialised with sorted keys and fixed separators so that every attempt of one message sends identical bytes (`:251-253`). There is no other header path: `Authorization`, `Content-Type`, `Accept`, `User-Agent` and `Idempotency-Key` are the HTTP request headers of the call to Resend, built separately (`:360-370`) and unrelated to message headers. The `Idempotency-Key` is derived from `idempotency_key` or `message_id` (`:367-369`, `:229-232`). Response size is bounded at 64 KiB (`:146`), which does not matter here.

**Fake provider.** `FakeEmailProvider` records the message object (`provider.py:88-108`), so a new field is visible to consumer tests with no change to it.

### 2.3 Existing tests the change would touch

- `tests/core/email/test_email_service_unit.py:56` (header-injection parametrisation of addresses), `:159` (subject), `:198` onward (`Message-ID`).
- `tests/core/email/test_smtp_provider_unit.py:465-512` (the `Message-ID` on a real local SMTP responder, including the raw bytes at `:512`).
- `tests/core/email/test_resend_provider_unit.py:268-296` (`metadata` never forwarded; no `headers` key without a message id; `headers == {"Message-ID": ...}` with one) and `tests/core/email/test_resend_ambiguous_outcome_unit.py:238` (the same `headers` object in a retry).
- `tests/architecture/public_api_snapshot.txt:444`, the reviewed public surface of `EmailMessage`, which fails when a field is added (`tests/architecture/test_public_api_snapshot.py:42-52`).

### 2.4 Logging and error discipline that already holds

- The Resend adapter and the egress client write no log line; `httpx` logs the method, the pinned address and the status, never headers or bodies (`docs/ADR/0058-resend-email-provider.md` line 67). The raised `EmailProviderError` is not chained to the `httpx` exception, because `httpx` attaches the request (headers and body) to it (`resend_provider.py:24-27`, `:390-399`).
- `EmailProviderError` and the outcome classes carry categories only: operation, a fixed reason, a numeric reply code (`saas_os/core/email/errors.py:30-85`). `InvalidEmailAddressError` never echoes the value.
- Tests search for canary values in exceptions and in captured logs at every level (`tests/core/email/test_resend_provider_unit.py:58-59`, `:143-149`).
- **The dataclass `repr` of `EmailMessage` includes every field** (the dataclass default; `provider.py:29-30` sets no `repr=False`), so `repr(message)` already prints the bodies. Nothing in `saas_os/core/email` or `saas_os/core/notifications` logs a message object (the notification path logs the channel, provider name, failure type name, permanence and reply code only, `saas_os/core/notifications/service.py:336-350`), but a consumer that did would print the new fields. That matters because an RFC 8058 unsubscribe URI should contain an opaque, hard-to-forge component identifying the recipient and list (section 4): the value is a capability, not just a URL.

## 3. Where a header could be injected or conflict

| Vector | Today | Under any option |
| --- | --- | --- |
| CR or LF in a value (header injection) | Subject and addresses refused in `service.py`; the stdlib also refuses CR and LF | Must be refused in `service.py` and, because `provider.send()` is public, ideally re-checked in each adapter. Resend has no stdlib backstop: a CR in a JSON string value would be passed to Resend, which then decides what to do (not verified) |
| NUL and other control characters | NUL refused in subject and addresses; **not** refused by the stdlib; not refused in the `Message-ID` pattern | Refuse every character outside printable ASCII in these headers; no fold or encode is wanted |
| Non-ASCII | Allowed in the subject (encoded by the provider) | Not needed by any of the four headers (URIs and msg-ids are ASCII; RFC 2369 restricts URL content to URL-safe characters, section 4). Refuse |
| Folding | Library-controlled on SMTP, none visible on Resend | A caller-supplied fold or whitespace inside a value must be refused; the SMTP adapter must make long unbreakable URIs come out unencoded (2.2) |
| Duplicate or conflicting headers | Library refuses some, accepts others (2.2) | Exactly one occurrence of each allowed name; case-insensitive duplicates (`list-unsubscribe` and `List-Unsubscribe`) refused if a mapping is used |
| `From`, `To`, `Subject`, `Date`, `Message-ID`, `Reply-To`, `Bcc`, `Return-Path`, `Received`, `Content-Type`, `Content-Transfer-Encoding`, `MIME-Version` | Set by the adapter or by the stdlib; no caller path | Must stay without a caller path. A closed allow-list achieves that by construction; `Bcc`, `Return-Path` and `Received` are the dangerous ones (hidden recipients, envelope and trace forgery) |
| Value that is syntactically a header but semantically wrong (an https URI pointing elsewhere, a msg-id naming another tenant's message) | Not applicable | Syntax can be validated; meaning cannot. Section 6 |

## 4. RFC facts needed for correctness

The three RFC texts were fetched from `https://www.rfc-editor.org/rfc/` on 2026-11-06 and the passages below were read. Quoted section numbers are those of the fetched text. Anything not found there is marked "not verified".

**RFC 8058 (one-click), read in full text.**

- Section 3.1: a sender "places one List-Unsubscribe header field and one List-Unsubscribe-Post header field in the message". The `List-Unsubscribe` field "MUST contain one HTTPS URI" and "MAY contain other non-HTTP/S URIs such as MAILTO:". The `List-Unsubscribe-Post` field "MUST contain the single key/value pair `List-Unsubscribe=One-Click`". Section 5 gives the ABNF: `list-unsubscribe-post = "List-Unsubscribe-Post:" 0*1WSP postarg CRLF` and `postarg = "List-Unsubscribe=One-Click"`.
- Section 3.1 also says the URI "MUST contain enough information to identify the mail recipient and the list", that it "SHOULD include an opaque identifier or another hard-to-forge component", that the server handling it "SHOULD verify" that component, that the POST carries no cookies or authorisation, and that the sender "MUST NOT return an HTTPS redirect". These are obligations of the product that serves the endpoint, not of an email-sending library.
- Section 4: "senders MUST apply at least one valid DKIM signature to the message", and "The List-Unsubscribe and List-Unsubscribe-Post headers MUST be covered by the signature and included in the 'h=' tag of a valid DKIM-Signature header field." Without it "the mail receiver SHOULD NOT offer a one-click unsubscribe for that message."
- Section 3.2: a receiver sends the POST body `List-Unsubscribe=One-Click` (as `multipart/form-data`, "SHOULD", or `application/x-www-form-urlencoded`, "MAY") and "MUST NOT perform a POST ... without user consent".
- **Who signs.** In every deployment SaaS-OS supports, the DKIM signature is applied by the relay or provider after SaaS-OS hands the message over: the SMTP relay for `SmtpEmailProvider`, Resend for `ResendEmailProvider`. SaaS-OS cannot sign (it has no key and the `EmailProvider` interface sends a message, it does not receive the signed form) and cannot verify the `h=` tag afterwards. So no SaaS-OS check can establish RFC 8058 compliance; it can only produce correctly formed headers. Whether Resend's signature covers these two headers: **not verified** (their documentation, read for this document, says nothing about it; section 9). Whether a given SMTP relay does: depends on the relay and is unknowable here.
- RFC 8058 "does not update RFC 2369", so `List-Unsubscribe` URIs "other than for one-click remain unchanged".

**RFC 2369 (list header fields), read in full text.**

- The contents "mostly consist of angle-bracket enclosed URLs"; MTAs "MUST NOT insert whitespace within the brackets". Several URLs "MAY be specified by a comma-separated list of angle-bracket enclosed URLs", in order of preference, so an unencoded comma inside a URL would be misread as a separator; a validator should require commas inside a URL to be percent-encoded.
- "the URL content is further restricted to the set of URL safe characters [RFC1738]" and the fields are subject to the mail header character restrictions (ASCII).
- "There MUST be no more than one of each field present in any given message", so one `List-Unsubscribe` field, whose value may list several URIs.
- "These fields MUST only be generated by mailing lists, not end users." This is a statement about the generator of the field, not about what an application may do; whether transactional or campaign mail from a product counts is not decided by the RFC text I read. Not a SaaS-OS check.
- Example forms include a comment before the URL (`List-Unsubscribe: (comment) <mailto:...>`). RFC 8058 and the issue use the plain form. A validator that accepts only `<uri>[, <uri>]*` is stricter than RFC 2369 and is the safe choice.

**RFC 5322 (In-Reply-To, References), read in full text.**

- Section 3.6.4: `in-reply-to = "In-Reply-To:" 1*msg-id CRLF`, `references = "References:" 1*msg-id CRLF`, `msg-id = [CFWS] "<" id-left "@" id-right ">" [CFWS]`, `id-left = dot-atom-text / obs-id-left`, `id-right = dot-atom-text / no-fold-literal / obs-id-right`, `no-fold-literal = "[" *dtext "]"`. The table in section 3.6 lists `in-reply-to` (and `references`) with a minimum of 0 and a maximum of 1 per message ("SHOULD occur in some replies"). A msg-id "has no internal CFWS".
- Construction: `In-Reply-To` holds the parent's `Message-ID`; `References` holds the parent's `References` followed by the parent's `Message-ID` (or, failing a `References`, the parent's single-id `In-Reply-To`). The text notes that building `References` for a reply with several parents "is discouraged".
- Line length: lines MUST be at most 998 characters and SHOULD be at most 78 (section 2.1.1). I found **no limit in RFC 5322 on the number of identifiers in `References`**, only the line limits, which folding at whitespace between ids satisfies. A bound on count or total length is therefore an implementation choice, not an RFC rule. Mail clients and providers may truncate or reject long chains; not verified. The standard-library folding of eight 38-character ids was observed to break only at the spaces between ids (2.2).
- The existing `Message-ID` pattern is looser than `msg-id` (2.1). A strict check (dot-atom-text left side, domain or `[literal]` right side, ASCII, no controls) is possible with a regular expression and would be the base for `In-Reply-To` and `References`.

**Not verified against RFC text:** the Gmail and Yahoo bulk-sender requirements the issue cites (they are provider policy, not RFCs); RFC 6376 (DKIM) itself, which RFC 8058 cites for the `h=` tag; RFC 3986 and RFC 1738 URI syntax, from which a URI validator would be built (what is quoted above is only RFC 2369's reference to RFC 1738).

## 5. Options

Notation: **public API** is the effect on `tests/architecture/public_api_snapshot.txt` and on ADR-0015 release labels; **provider boundary** is the invariant that provider-specific behaviour stays in the adapter files (`smtp_provider.py`, `resend_provider.py`); **parity** is SMTP against Resend. All three options keep `metadata` as it is.

### Option A: typed, closed fields on `EmailMessage`

Add defaulted fields at the end of the dataclass (so positional construction of the existing nine fields keeps working), for example:

- `list_unsubscribe: tuple[str, ...] = ()`: URIs without angle brackets (SaaS-OS adds `<` `>` and `, `), each `https:` or `mailto:`;
- `list_unsubscribe_one_click: bool = False`: when true, the adapter emits the fixed `List-Unsubscribe-Post: List-Unsubscribe=One-Click`; refused unless at least one `https:` URI is present (RFC 8058 section 3.1);
- `in_reply_to: tuple[str, ...] = ()` and `references: tuple[str, ...] = ()`: msg-ids with angle brackets, each matching a strict `msg-id` pattern.

Names and shapes here are illustrative; they are open (section 10).

- **Injection risk.** Lowest. No caller-chosen header name exists, so `Bcc`, `Return-Path`, `Received`, MIME headers and `Date` cannot be reached. A boolean replaces the `List-Unsubscribe-Post` string, so its value is not caller data at all. The remaining surface is the values: URIs and msg-ids, both validated against a narrow ASCII grammar. A new header means a code change and a review of this table.
- **Public API.** Additive: four new defaulted fields. The snapshot line for `EmailMessage` changes (`test_the_public_api_matches_the_reviewed_snapshot` reports a "changed" entry), so the snapshot is rewritten in the same pull request after review. No existing signature changes. Release label: section 11, "Version label".
- **Parity.** SMTP: set the headers on the MIME message in the adapter, with the unfolded-URI handling of 2.2. Resend: add them to the `headers` object beside `Message-ID`; sorted-key serialisation already makes the body deterministic (`resend_provider.py:251-253`). Resend's documentation (read 2026-11-06) shows exactly this use, a `headers` object with `'List-Unsubscribe': '<https://example.com/unsubscribe>'` and a `List-Unsubscribe-Post` entry, and describes the field as "Custom headers to add to the email"; it does not say which names are refused or reserved, or whether it adds its own `List-Unsubscribe` (section 9).
- **Provider boundary.** Kept. The validated fields are provider-neutral vocabulary like `reply_to`; the adapters decide how to emit them. Nothing from Resend or the standard library leaks into `provider.py` or `service.py`.
- **Effort.** Smallest of the three that is safe: roughly one validation function and four adapter lines, plus tests. Each future header (for example `List-Id`, `Precedence`, `X-...`) is another field and another snapshot change.

### Option B: a generic `headers: Mapping[str, str]` with a name allow-list

The issue's own sketch.

- **Injection risk.** Higher, for structural reasons rather than because it is unsafe if done right. Names must be compared case-insensitively and normalised, duplicates differing only in case refused, and the allow-list kept in step in three places (service validation, SMTP, Resend). Every value needs a per-name validator anyway, so the allow-list removes none of the per-header work. A mapping inside a frozen dataclass is mutable (as `metadata` already is, `provider.py:57`): a caller can mutate it after validation and before the provider reads it, a time-of-check to time-of-use gap that tuple and bool fields do not have, unless the field is copied into an immutable mapping at construction (a `__post_init__` the dataclass does not have today). It also collides with `message_id`: a `Message-ID` key would have to be refused by name.
- **Public API.** Additive: one new defaulted field. The mapping accepts any key at the type level, so the allow-list is a runtime contract the type does not express. Adding a header later is an allow-list edit with no snapshot change: cheaper to extend, but also easier to widen without a public-API review, which the closed-fields option forces. Release label: section 11, "Version label".
- **Parity.** Same as A: SMTP iterates the validated mapping onto the MIME message; Resend merges it into `headers`.
- **Provider boundary.** Kept, with the allow-list and validators living in `service.py` (provider-neutral), as in A.
- **Effort.** Similar to A in validation, plus the normalisation and the mutation hazard.

### Option C: leave it to the product

Not available as the issue frames it. A product cannot add a header to a message sent through `send_email()`: there is no field, `metadata` is not forwarded, and the providers build the request internally (2.2). The remaining ways to get the headers on the wire are:

- implement its own `EmailProvider` (the protocol and the `provider=` parameter of `send_email()` are public, `public_api_snapshot.txt:447`, `:461`), which means re-implementing transport, secrets, the egress rules, TLS, the outcome classification (`EmailOutcomeUnknownError`, `EmailNotSentError`), Resend's idempotency retention logic and the injection defences, and taking itself out of `get_email_provider()` selection and the notification job, which uses the configured provider; or
- subclass a SaaS-OS provider and override `send()`, which has the same cost and relies on non-public internals (`request_body()` is module-level, not exported; the SMTP message is built inside `send()`).

Both are possible and both defeat the purpose of a shared email foundation, with a larger injection surface in consumer code. C costs SaaS-OS nothing and leaves LeadStack with campaign sending off. It is a valid outcome if the owner decides that campaign mail is not a SaaS-OS concern, because the module docstring says "No campaign, audience-list, open/click-tracking, unsubscribe-management, or bulk-delivery concept exists here, deliberately" (`saas_os/core/email/provider.py:14-20`). Options A and B change that sentence; see section 6.

### Comparison

| | A: typed fields | B: allow-listed mapping | C: product-owned |
| --- | --- | --- | --- |
| Header names reachable by a caller | Exactly four, by construction | Allow-list, enforced at runtime | Anything, in consumer code |
| Mutation after validation | None (tuples, bool) | Possible unless copied at construction | Not applicable |
| Public API change | 4 fields; snapshot reviewed | 1 field; snapshot reviewed once | None |
| Adding the next header | Field plus review | Allow-list edit | Not applicable |
| One-click value cannot be wrong | Yes (boolean) | Only if validated | No |
| SaaS-OS tests | Provider-neutral validation plus per-adapter wire tests | Same | None |
| Consumer outcome | Campaign sending can be enabled | Same | Stays off or bypasses SaaS-OS |

## 6. What the change does to the stated scope of the email module

`provider.py:14-20` says the vocabulary is "deliberately minimal": no campaign, unsubscribe-management or bulk-delivery concept. Options A and B do **not** add campaign or unsubscribe management: SaaS-OS would only carry four validated headers; recipient lists, suppression, the unsubscribe endpoint and the signed token remain the product's (LeadStack's own, per the issue). The sentence should be amended to say so, and the documentation should state plainly that the fields make correctly formed headers possible and do not make a message compliant (section 4: the DKIM requirement is the relay's, and the endpoint obligations are the product's).

Two design questions follow from RFC 8058's "identify the mail recipient":

- A one-click URI identifies one recipient, but `EmailMessage.to` is a tuple (up to 50 recipients on Resend, `resend_provider.py:144`, `:402-403`). A message with a per-recipient unsubscribe URI sent to several recipients would let recipient B unsubscribe recipient A. Whether `service.py` should refuse `list_unsubscribe` with more than one recipient (campaigns send one message per recipient) is an owner decision (section 10).
- `In-Reply-To` and `References` name message ids chosen by the caller. SaaS-OS cannot check that they exist, belong to the same conversation or the same tenant. A caller could use them to attach a message to another thread in the recipient's client. This is a product-level authorisation question and the validation here is syntax only; the risk is low (the recipient's client, not SaaS-OS data, is affected) but should be stated in the consumer guide.

## 7. Outcome classes, idempotency, logging and redaction

- **Outcome classes.** Unchanged. Validation failures raise `InvalidEmailAddressError` before any provider call (as for `Message-ID` today, `service.py:111-112`); a new subclass for header failures would be additive and is an open choice (section 10), but the exception name `InvalidEmailAddressError` already covers `Message-ID` and the idempotency key, so reuse is consistent. Provider outcomes (`EmailNotSentError`, `EmailOutcomeUnknownError`, `EmailProviderError` with `permanent`) are unaffected. A header the provider refuses would surface as Resend `400` or `422` (permanent, `resend_provider.py:155`, `:450-456`) with a fixed reason name from the allow-list of known names (`:160-184`); whether Resend refuses any of these four is not verified. SMTP has no per-header refusal path; a relay refusing the message is classified as today.
- **Idempotency on Resend.** Resend de-duplicates by `Idempotency-Key` and refuses a key reused with a different body (`409 invalid_idempotent_request`, permanent here, `resend_provider.py:434-439`, `docs/ADR/0058-resend-email-provider.md` lines 57-59). The `headers` object is part of the body. So the values must be **identical on every retry of one logical send**: an unsubscribe URL regenerated with a new random component on a retry would turn a safe retry into a permanent `409` (a failure, not a duplicate). The consumer guide must say that the headers are a function of the logical message, derived deterministically from the recipient and campaign, never fresh per attempt. The deterministic serialisation (`sort_keys`) already makes the order of the new entries irrelevant. `idempotency_key` itself is hashed and never becomes a header (`provider.py:47-49`); that stays.
- **SMTP.** No de-duplication exists; a retry after an unknown outcome can deliver twice, as documented (`docs/ADR/0057-deployment-level-email-provider-selection.md` line 52). Headers change nothing here.
- **Logging.** The adapters log nothing today (2.4). The new values must keep that property: they must not appear in any exception (`InvalidEmailAddressError` and `EmailProviderError` carry no value), any log line or `repr`. Recommended: declare the new fields with `repr=False` so `repr(message)` does not print an unsubscribe URL, and extend the canary tests (`tests/core/email/test_resend_provider_unit.py:143-149` pattern) with canary header values. The `httpx` log line contains the Resend URL only (ADR-0058 line 67), not the body.
- **Treatment of the value.** An RFC 8058 URI is a recipient-identifying capability (section 4). The consumer guide should say not to log it, not to put it in audit metadata and not to use the recipient's plain address in it.

## 8. Independence from the open proposals

- Pull request #226 (egress `GET` and `DELETE`) concerns inbound email and sending-domain management (#205, #225). Nothing here depends on it, and nothing there depends on this. Both touch the same two ADRs (0057 and 0058) for documentation; the amendments are separate sections.
- Issue #223 (export `EmailOutcomeUnknownError` and `EmailNotSentError`) was released in v0.9.0 and is the closest precedent for a public email change (section 11, "Version label").

## 9. What could not be verified

- **Resend's server-side behaviour.** Whether Resend accepts exactly `List-Unsubscribe` and `List-Unsubscribe-Post` in `headers` (its documentation page on unsubscribe links, fetched 2026-11-06, shows both as examples), whether it adds, rewrites or reserves any of these names, whether it folds or re-encodes a long value, whether it validates the value, what `400` or `422` it returns for a refused header, and whether its DKIM `h=` tag covers `List-Unsubscribe` and `List-Unsubscribe-Post`. None was exercised: no request was sent. The only live Resend check recorded for this adapter predates this issue and covered the `Message-ID` header path only in general terms (`docs/ADR/0058-resend-email-provider.md` line 85). A live check with an owner-authorised test key and an owner-controlled mailbox is the way to settle this, reading the received message's raw headers and DKIM `h=` tag.
- **Any SMTP relay's DKIM coverage** and whether a relay rewrites or drops list headers. The Mailpit development profile shows headers but signs nothing.
- **Receiver behaviour** with an RFC 2047 encoded-word `List-Unsubscribe` (2.2) and with long `References` chains.
- **The Gmail and Yahoo requirements** quoted in the issue.
- **Behaviour on other Python versions.** The folding and NUL observations were made on Python 3.13.14 with the stdlib default policy. The repository uses Python 3.13; the stdlib's header handling has changed between versions.
- RFC 6376 (DKIM) and the URI RFCs were not read.

## 10. Open questions that only the owner can answer

1. **Whether to do it at all.** Option C (no change) is legitimate; it keeps LeadStack's campaigns off. Do campaign-style headers belong in SaaS-OS's email foundation, given the module's stated minimalism (`provider.py:14-20`)?
2. **Option A or B.** (Section 11 gives a recommendation.)
3. **Names and shapes of the fields**, if A: `list_unsubscribe` as URIs with or without brackets, `list_unsubscribe_one_click` as a boolean or as the header's string, tuples or a small value class.
4. **Recipient count.** Should `service.py` refuse `list_unsubscribe` when `len(to) != 1` (section 6)?
5. **Bounds.** Maximum URI length (2048 characters is the strict egress client's URL limit, `saas_os/infra/egress/client.py`, which may serve as a reference point; it is not an email rule), maximum number of URIs, maximum number of msg-ids and total header length. No RFC rule decides these (section 4).
6. **Error type.** Reuse `InvalidEmailAddressError`, or a new additive subclass.
7. **Adapter re-check.** Should each adapter also refuse CR, LF, NUL and non-ASCII in the new values, because `provider.send()` is public and Resend has no stdlib backstop (2.1, section 3)? This would be new behaviour for these adapters; they check nothing of the message today.
8. **`mailto:` URIs.** Allow `mailto:` with a query (`?subject=`)? The URI grammar needed for that is larger than for plain `mailto:addr`.
9. **The existing `Message-ID` pattern** accepts NUL, controls and non-ASCII (2.1). Tighten it in the same change, in a separate change, or leave it? It is out of scope unless the owner says otherwise, and tightening is a behaviour change for any caller that passes an unusual id.
10. **Live Resend check.** Authorise a live check (as in ADR-0058's 2026-10-25 check) of the four headers and of the received message's DKIM `h=` tag before any release that claims the feature works with Resend?
11. **Vehicle and label** (section 11).
12. **Whether to document a compliance statement.** Recommended: no claim of RFC 8058 compliance, only of well-formed headers.

## 11. Recommendation (separate from the facts above)

**Recommend Option A** (typed, closed fields), subject to the owner's answers in section 10, and only if question 1 is answered "yes".

Reasons: the injection surface is smaller by construction (no caller-chosen name, a boolean instead of the `List-Unsubscribe-Post` string, no mutable mapping); it makes the public surface a reviewed list, matching how this repository already treats the public API (the snapshot test); it needs per-header validation in either option, so B saves nothing there; and the issue asks for four headers, not a general header facility. The cost is one snapshot change per future header, which I consider a feature. If the owner expects many more headers soon (for example `List-Id` or `Precedence`), B with the safeguards of section 5 becomes more attractive; I would still start with A and add fields.

Suggested behaviour (all open until the owner decides):

- `service.py` validates the four fields before any provider call, raising the existing error type with a fixed message and no echo of the value;
- an `https` URI: ASCII printable, no whitespace, no `<`, `>`, `"`, `\`, `,` (commas percent-encoded), no userinfo, a host, bounded length; `mailto:` is the same with a plain address and optional query;
- one-click requires at least one `https` URI;
- each msg-id matches a strict `msg-id` pattern; `In-Reply-To` and `References` each appear at most once, with a bounded count and total length;
- each adapter emits exactly one header per field, in a form that is never folded into an encoded word (SMTP), and merges into the existing `headers` object (Resend);
- the new fields use `repr=False`;
- no claim of RFC 8058 compliance in code or documentation.

**The smallest decision the owner must make** is question 1 and question 2 together: "SaaS-OS carries these four headers as typed fields (A), or does not (C)". Everything else in section 10 can be settled in the implementation pull request's review once that is decided.

### Vehicle

Prefer **an amendment section in ADR-0057 (the message vocabulary and the SMTP adapter) and in ADR-0058 (the Resend request body)**, each recording the owner's decision and its date, over a new ADR. Reasons: both ADRs already own the facts that change (the `Message-ID` header rule, what Resend's body contains), ADR-0058 was itself written as an extension of ADR-0057, and the repository's convention for owner decisions on an accepted ADR is a dated amendment (ADR-0015 is the example). A new ADR is reasonable if the owner wants the allow-list policy recorded once for any future email provider; that would then be cited from both. Either way the module docstring in `provider.py` (the "no unsubscribe-management" sentence) and `docs/CONSUMER-GUIDE.md` section on email need the matching update. This document does not choose or reserve an ADR number.

### Version label

By ADR-0015's rule "`0.Y.0` for a release with a migration, a removed or changed public signature, or a new required deployment step; `0.Y.Z` (Z > 0) for fixes and documentation only", and by the v0.9.0 precedent, which was labelled a minor release and said it "adds public names" (`CHANGELOG.md`, v0.9.0, "Additive public API", issue #223), adding public fields to `EmailMessage` is a **minor release** (the next would be `0.10.0`). The snapshot test classifies a field addition as a changed public entry. The release would list the fields under "Additive public API" with no migration and no new setting. Whether to release at all, when, and the label are the owner's decisions; nothing here tags or releases.

## 12. Acceptance criteria (for the implementation step, if approved)

1. The four fields (names per the owner's decision) exist on `EmailMessage`, are defaulted, appended after `idempotency_key`, and are the only way to set these headers. `metadata` remains unforwarded.
2. A message that sets none of them produces exactly the bytes and requests it produces today (SMTP raw bytes and Resend JSON body unchanged, including the case with only a `message_id`).
3. Validation (before any provider call): each rule of section 11; refusals raise the chosen error with a fixed message that contains no part of the value.
4. SMTP: with all four set, the raw message contains one `List-Unsubscribe`, one `List-Unsubscribe-Post: List-Unsubscribe=One-Click`, one `In-Reply-To`, one `References`; a `List-Unsubscribe` URI longer than the stdlib's folding threshold (more than 78 characters) is present unencoded and unfolded within a line, asserted on the wire bytes received by the real local SMTP responder (`tests/core/email/test_smtp_provider_unit.py` pattern).
5. Resend: the JSON body contains the same entries in `headers` together with `Message-ID` when set; the body is byte-identical across two builds of the same message; two retries of one message carry the same `Idempotency-Key`.
6. No value appears in any exception, any log record at any level, or `repr(message)`.
7. The public API snapshot is rewritten after review (a field-level change to `EmailMessage` only).
8. `docs/CONSUMER-GUIDE.md` and the two ADRs state: what the fields do and do not guarantee (no DKIM or RFC 8058 compliance claim), that the headers must be a deterministic function of the logical message, that the URI is a capability, and that one message with a per-recipient URI should go to one recipient.
9. The full repository validation of CLAUDE.md section 8 passes on the final tree; the live Resend check of question 10 is either done and recorded or listed as not done.

## 13. Test plan, including negative controls

Unit tests (no network) in `tests/core/email/`:

- Acceptance: each header alone and all four together; one and several URIs; `https` only, `mailto` only, both; one-click with and without an `https` URI; a single msg-id and several.
- Refusal, each asserting the error type, the fixed message and that the canary value does not appear in the message, `repr` or `__cause__`: CR, LF, CRLF, NUL, another control character, a space or tab inside a value, non-ASCII, an unterminated or doubled angle bracket, `javascript:`, `http:` (if not allowed), `data:`, `file:`, an https URI with userinfo, a comma inside a URI, an empty value, an over-long value, too many ids, a msg-id without `@`, a duplicate or empty tuple element, and one-click without an `https` URI.
- Provider isolation: the nine existing fields' behaviour is unchanged (existing tests untouched); the Fake provider records the new fields.
- SMTP wire: real local SMTP responder, raw bytes, with a long (more than 78 characters) unbreakable URI (acceptance criterion 4) and a long `References`.
- Resend wire: recorded request body parsed as JSON, `headers` object, determinism, identical key across attempts; a changed header value on a retry under the same key produces the body-mismatch path (the adapter does not special-case it; the test documents it).
- Logging: canary values searched in exceptions and captured logs at DEBUG for both adapters (the `_assert_no_secret` pattern, `test_resend_provider_unit.py:143`).

Negative controls (run once on an isolated change, restore afterwards, never left in the tree; each must fail for the stated reason and not through a setup error):

1. Remove the CR/LF/NUL check on the new values in `service.py` -> the injection parametrisation fails with an unexpected acceptance (`Bcc: ...` appears in the SMTP bytes captured by the real responder).
2. Widen the `https` URI check to allow any scheme -> the `javascript:`, `data:` and `file:` refusal tests fail.
3. Drop the "at least one `https` URI" rule for one-click -> the one-click-without-https test fails.
4. Add a fifth name (or a free-form `Bcc` path) to the emitted headers -> a test that asserts the exact set of header names in both wire formats fails.
5. Remove the `repr=False` or add the value to an error message -> the canary tests fail.
6. In the SMTP adapter, drop the folding handling -> the long-URI wire test fails because the bytes contain `=?utf-8?q?`.
7. Build the `headers` object without sorted keys or with a per-attempt random value -> the determinism and identical-body tests fail.

Existing suites that must stay green: the whole of `tests/core/email`, `tests/core/notifications` email-channel tests and `tests/architecture` (snapshot, layer boundaries, documentation references). The package-boundary tests rewrite package `__init__.py` files and must never run concurrently with another test run.

## 14. Owner decisions

The owner approved Option A on 2026-11-06, together with the answers below, which are the recommendations of section 11 as put to the owner. This section records what was decided; the earlier sections keep the facts and the reasoning. **Implementation is a separate approval**: nothing is built until the owner gives it.

| # | Question (section 10) | Decision |
|---|---|---|
| 1 | Whether to do it at all | Yes: SaaS-OS carries the four headers (Option A). Option C (leave it to the product) is not taken. |
| 2 | Option A or B | **A, typed fields.** No generic `headers` mapping. |
| 3 | Names and shapes | Working names `list_unsubscribe`, `list_unsubscribe_post` (a boolean), `in_reply_to` and `references`; the final names and shapes are settled in the review of the implementation, under the constraint that there is no mutable mapping and no case-folding of header names. |
| 4 | Recipient count | `list_unsubscribe` is refused when the message has more than one recipient, because the URI identifies one person. |
| 5 | Bounds | Conservative and written into the amendment: at most **2048 characters per URI** and at most **20 ids in `References`**. No RFC rule decides these; the numbers are the owner's to change. |
| 6 | Error type | A small additive subclass of the existing invalid-address error, so a caller can tell a header failure from a bad address. |
| 7 | Adapter re-check | Yes: each adapter also refuses CR, LF and NUL in the new values, as defence in depth, because `provider.send()` is public and validates nothing about the message. |
| 8 | `mailto:` URIs | Conservative: the plain form; a query (`?subject=`) is not allowed unless the amendment justifies the larger grammar. |
| 9 | Existing `Message-ID` pattern | Not in this change. Tighten it in a separate small change. |
| 10 | Live Resend check | Not now. Build against the documented behaviour; the product runs the first real send in staging. |
| 11 | Vehicle and label | A dated amendment to ADR-0057 and ADR-0058, not a new ADR. Adding public fields is a minor release (0.10.0) by ADR-0015 and the v0.9.0 precedent; the label is confirmed at the release. |
| 12 | Compliance statement | **Undecided.** The recommendation stands: claim well-formed headers, not RFC 8058 compliance. |

**Required whatever the option.** The SMTP encoded-word defect of section 2.1 (a `List-Unsubscribe` URI longer than about 50 characters is rewritten as an RFC 2047 encoded word and breaks one-click unsubscribe) is fixed in the implementation with a policy that does not fold the value, and is covered by a test.

**What this authorises.** Recording the direction only. The implementation (fields, validation, both adapters, tests, the ADR amendments) needs its own approval after the acceptance criteria of section 12 are read.

**Note (2026-11-07), implementation of issue 224 approved ("approve #224 build").** The working names in row 3 were kept: `list_unsubscribe: tuple[str, ...]` (URIs without angle brackets), `list_unsubscribe_post: bool`, `in_reply_to: tuple[str, ...]` and `references: tuple[str, ...]` (ids with angle brackets), all defaulted and `repr=False`. Two details the table left open were settled in the implementation and are recorded in the ADR-0057 amendment of the same date: `list_unsubscribe` holds at most one `https` and one `mailto` URI (RFC 8058 section 3.1 asks for one HTTPS URI), and a URI must also fit one header line of 998 characters (RFC 5322 section 2.1.1), which is stricter than 2048 for a URI that cannot be folded. Question 12 stays undecided; the documentation claims well-formed headers only.
