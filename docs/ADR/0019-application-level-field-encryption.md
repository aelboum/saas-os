# ADR-0019: Application-level field encryption (`core.crypto`)

Status: Accepted
Date: 2026-09-17
Supersedes / Superseded by: —

## Context

BANK-SEC-01 (the Open Banking security readiness audit) identified finding S-01 (CRITICAL, as an architectural prerequisite): SaaS-OS has no application-level encryption primitive for sensitive values stored in PostgreSQL. `infra/secrets`'s `SecretsProvider` (ADR-0012) answers a different question — "how does the application obtain configuration/secret material" — and is not, and was never intended to be, a mechanism for encrypting *application data* (a future bank OAuth access/refresh token, a provider credential) before it is persisted to a tenant-owned database row. This ADR is BANK-SEC-02: the remediation for S-01 only. It does not implement Open Banking, OAuth, or any specific credential-storage feature — it establishes the primitive a future feature would use.

## Options Considered

### Option A — A narrow `core.crypto` module: `EncryptionService` (AEAD encrypt/decrypt) + `KeyProvider` (key-material abstraction, built on `infra.secrets`) + a versioned ciphertext envelope format

- Advantages: mirrors the pattern already accepted for billing (ADR-0008), identity (ADR-0005), and secrets (ADR-0012) — an interface Core/Product code depends on, with the concrete key-supply mechanism swappable behind it; keeps `SecretsProvider`'s existing, already-audited responsibility unchanged; the ciphertext format's key-version field is designed for S-02 (key rotation) without implementing it now.
- Disadvantages: another small module to maintain; the abstraction is extra design work for a primitive that, as of this ADR, has no production caller yet.

### Option B — Add encrypt/decrypt methods directly onto `SecretsProvider`

- Advantages: one fewer module.
- Disadvantages: merges two different responsibilities the audit explicitly called out as distinct ("how do we obtain configuration secrets" vs. "how do we encrypt application data") — every current `SecretsProvider` consumer would gain an encryption-shaped surface it has no reason to use, and a future non-encryption-capable `SecretsProvider` implementation (e.g. a minimal read-only mount) would be forced to also implement encryption or violate the interface. Rejected: explicitly the design mistake this phase's own directive warned against ("do not merge these responsibilities merely for convenience").

### Option C — Rely on PostgreSQL-native column/transparent encryption (`pgcrypto`, TDE) instead of an application-level primitive

- Advantages: no application code changes when adopted per-column; encryption/decryption happens at the database layer.
- Disadvantages: keys typically live alongside or adjacent to the database itself (weaker key/data separation than an application-boundary design); `pgcrypto`'s `pgp_sym_encrypt`/`decrypt` puts the key in every query that touches the column, which is easy to get wrong and hard to audit; does not naturally support the "encrypt at the API/service boundary, ciphertext everywhere else including logs and backups" property this ADR wants. Rejected for the reasons BANK-SEC-02's own directive states explicitly ("avoid database-native encryption unless the existing architecture specifically requires it").

### Option D — Integrate a cloud KMS (AWS KMS / Azure Key Vault / GCP KMS) or HashiCorp Vault now

- Advantages: strongest key-management posture available.
- Disadvantages: explicitly out of scope for this phase and inconsistent with the deliberately minimal Docker Compose + VPS deployment target (ADR-0010) and the "no cloud-specific secret-management implementation" instruction this phase's directive gives. `KeyProvider` (Option A) is designed so a future KMS-backed implementation is a new adapter, not a redesign.

## Recommendation

Option A.

## Decision

**Accepted.** `core/crypto` is a new Core module (`core/crypto/{__init__,errors,envelope,keys,service}.py`) providing:

1. **`EncryptionService`** (`core/crypto/service.py`) — `encrypt()`/`decrypt()` (bytes) and `encrypt_str()`/`decrypt_str()` (UTF-8 string convenience). Uses AES-256-GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`, from `pyca/cryptography`, already an installed transitive dependency via `PyJWT[crypto]` and now an explicit top-level dependency, `pyproject.toml`) — a standard, widely-reviewed AEAD construction; no custom cryptography is implemented. A fresh 96-bit nonce is generated via `os.urandom()` for every encryption, never reused. `encrypt()`/`decrypt()` accept optional `associated_data: bytes` (AEAD's AAD mechanism) so a caller can bind ciphertext to context (e.g. a tenant id, a credential purpose) — the service itself has no notion of tenants or any specific domain concept; building the AAD bytes is the caller's responsibility.
2. **`KeyProvider`** (`core/crypto/keys.py`) — an ABC (`current_key_version()`, `key_for_version(key_version)`) between `EncryptionService` and however key material is actually supplied. `SecretsBackedKeyProvider` is the one concrete implementation this ADR ships, built on `infra.secrets.get_secrets_provider()` (two secrets: `FIELD_ENCRYPTION_ACTIVE_KEY_VERSION` and `FIELD_ENCRYPTION_KEY_<VERSION>`, base64-encoded 32-byte AES-256 keys) <!-- pragma: allowlist secret --> — never a cloud KMS, Vault, or Docker Secrets integration directly. `SecretsProvider` itself is unmodified and remains unaware that encryption exists; the dependency runs one direction only: `EncryptionService -> KeyProvider -> SecretsProvider`.
3. **A versioned ciphertext envelope** (`core/crypto/envelope.py`): `efv1:<key_version>:<nonce_b64>:<ciphertext_and_tag_b64>` — a plain text string, safe for an ordinary database text column. `efv1` is the *format* version (this module's own parsing/algorithm choice); `key_version` is a non-secret identifier a `KeyProvider` resolves to the actual key. No key material is ever part of the envelope. `decode()` fails closed on anything that is not well-formed or not a supported format version.
4. **Domain exceptions** (`core/crypto/errors.py`): `EncryptionKeyUnavailableError`, `UnknownKeyVersionError`, `MalformedCiphertextError`, `UnsupportedCiphertextVersionError`, `DecryptionAuthenticationError` — every one raised, never a plaintext/default-value fallback. None ever carries plaintext or key material; key *versions* are explicitly not secret and may appear.

**Plaintext handling.** Plaintext is never logged, never included in an exception, never part of the returned ciphertext envelope. This module makes no claim of secure memory zeroization — CPython does not provide that guarantee for ordinary `bytes`/`str` objects, and claiming otherwise would be dishonest about the actual threat model (this phase's own explicit instruction).

**Authorization is a separate concern.** `core.crypto` is not an authorization mechanism. Successful decryption proves only that the caller supplied a resolvable, untampered ciphertext — never that the caller is entitled to the plaintext. Whatever tenant/RBAC boundary already governs the domain object an encrypted value lives on (`core.rbac`, `core.tenancy`'s RLS) continues to apply exactly as before; `EncryptionService` sits inside that boundary, not in place of it.

**Fail closed, unconditionally.** Every failure mode — key unavailable, unknown key version, malformed ciphertext, unsupported format version, AEAD authentication failure — raises. There is no code path from any of these to returning plaintext, a default value, or silently skipping encryption.

**No production data migration performed by this ADR.** As of this ADR, no existing tenant-owned database field is classified as requiring encryption — there is no bank-token table yet, and BANK-SEC-02's own directive explicitly forbids inventing one to demonstrate the primitive. `core/crypto` is implemented and tested (`tests/core/crypto/`) without a production migration; the first real caller (whenever a feature needs to persist a credential-shaped value) selects the specific field(s) and performs its own migration at that time.

## S-02 — Key-Version Lifecycle (BANK-SEC-03, added 2026-09-17)

BANK-SEC-02 (above) established the envelope's `key_version` field and `KeyProvider.key_for_version()`'s ability to resolve an arbitrary version, but deliberately implemented no rotation lifecycle. BANK-SEC-03 closes S-02 at the level this ADR's own directive scopes it to: **a defined, tested key-version lifecycle supporting safe manual rotation** — not automatic rotation, not a production KMS, not re-encryption of existing data. No code in `core/crypto/{envelope,keys,service}.py` changed shape for this — the design already separated "which key encrypts new data" from "which key decrypts existing data" (next paragraph); BANK-SEC-03's real work was proving that separation under rotation with tests (`tests/core/crypto/test_key_rotation_unit.py`) and fixing one latent gap (below).

**The core invariant, and why it already held**: `EncryptionService.encrypt()` calls `KeyProvider.current_key_version()` — the *active* version — and uses that key. `EncryptionService.decrypt()` never calls `current_key_version()` at all; it reads `key_version` out of the ciphertext envelope itself and resolves *that exact version* via `key_for_version()`. Rotating the active version (changing what `current_key_version()` returns) therefore cannot change how an already-existing ciphertext decrypts — there is no code path from "active version changed" to "old ciphertext now resolves a different key." `tests/core/crypto/test_key_rotation_unit.py::test_no_fallback_to_active_key_when_ciphertext_version_is_unavailable` proves the specific negative case directly: active = v2 (available), ciphertext = v1 (retired) — decryption raises `UnknownKeyVersionError`, never silently attempts v2.

**One gap found and fixed by this phase**: `core/crypto/envelope.py::encode()` validated that `key_version` contains no `:` but not that it is non-empty. An empty version would have produced a syntactically well-formed-looking envelope (`efv1::nonce:ciphertext`) that `decode()` would then permanently reject (`MalformedCiphertextError`, empty `key_version` field) — i.e. a misconfigured `KeyProvider` returning `""` could have corrupted a value irrecoverably at the moment of encryption, discovered only later at decrypt time. Fixed by validating non-emptiness in `encode()` itself, so this now fails closed *at `encrypt()`*, before any ciphertext is produced or persisted (`tests/core/crypto/test_key_rotation_unit.py::test_empty_active_version_fails_closed`).

**Rotation procedure** (manual; this ADR does not claim it has been exercised against a real production secrets backend):

1. Generate a new cryptographically random 32-byte key outside the database (e.g. `python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"`).
2. Store it under a new, immutable key-version secret name (e.g. `FIELD_ENCRYPTION_KEY_V2`) via whatever `SecretsProvider` implementation is active (ADR-0012) — never reuse an existing version's secret name for different material.
3. Verify the new key resolves: `KeyProvider.key_for_version("v2")` returns 32 bytes, in a non-production environment first.
4. Change `FIELD_ENCRYPTION_ACTIVE_KEY_VERSION` to `"v2"`.
5. Deploy/reload configuration atomically — `current_key_version()` and `key_for_version()` must change together, not in two separate deploys (an interim state where `FIELD_ENCRYPTION_ACTIVE_KEY_VERSION=v2` but `FIELD_ENCRYPTION_KEY_V2` is not yet set fails closed on the next `encrypt()` call, per the fix above and `test_missing_active_key_fails_closed_on_encrypt_even_with_historical_keys_present` — it does not fall back to v1 or encrypt insecurely, but it does mean new writes fail until both are set together).
6. Verify new encryption produces `efv1:v2:...` envelopes.
7. Verify existing `efv1:v1:...` ciphertext still decrypts (v1's secret must remain configured).
8. Keep v1's key configured and available — do not remove it yet.
9. Monitor for `UnknownKeyVersionError`/`EncryptionKeyUnavailableError` in application logs, which would indicate a value referencing a key version that is no longer resolvable.
10. **Retire v1 only once there is positive evidence no retained ciphertext depends on it** — e.g. every row that could hold a v1-encrypted value has been re-encrypted under v2 (a deliberate future migration, not performed by this ADR) or its own retention period has independently expired and the row itself was deleted. Removing `FIELD_ENCRYPTION_KEY_V1` while any `efv1:v1:...` value still exists makes that value **permanently undecryptable** — this is not a bug to guard against in code (an application-level "is this key still needed" check would require scanning all encrypted data, which this ADR does not implement) but an operational precondition the person performing retirement is responsible for verifying.

**Why automatic key deletion is unsafe, structurally**: `core.crypto` has no inventory of which rows hold which key version — that knowledge lives in whatever future feature actually stores ciphertext (a table this ADR does not create). Deleting a key version's secret is irreversible and has no dependency check available to `core.crypto` itself; automating it would require either scanning encrypted data (expensive, invasive, and still not authoritative without a schema-level "which version" index) or trusting an unverified claim that it's safe. Manual, evidence-based retirement is the correct default until a specific future feature's schema makes an automated check meaningful.

**Why encryption and decryption select keys differently**: encryption has exactly one correct choice — whatever is currently active, because that is what "new data" means. Decryption has exactly one correct choice too, but a different one — whatever the ciphertext itself already committed to, because that is a historical fact about how that specific value was created and cannot change after the fact. Treating these as the same lookup (e.g. "always use the active key") would make rotation itself a data-loss event; treating them as governed by the same rule intentionally is what a rotation-safe design requires.

**What remains explicitly out of scope**: automatic/scheduled rotation, a production KMS/Vault `KeyProvider` implementation, background re-encryption or mass ciphertext rewriting, and any key-retirement automation. These remain deliberately deferred, same as BANK-SEC-02's own original scope line for S-02.

## Security Consequences

- Closes S-01: a sensitive value can now be encrypted at the application/service boundary before it reaches PostgreSQL, rather than relying solely on infrastructure/disk-level encryption outside this repository's control.
- Key material is never colocated with ciphertext (not in the same row, not in the same table, not in the envelope string) — a database compromise alone (backup theft, a leaked `pg_dump`, unauthorized read access) does not yield usable plaintext without also compromising whatever holds `FIELD_ENCRYPTION_KEY_*`.
- **Residual risk, explicitly accepted for now** (unchanged by this ADR, inherited from ADR-0012): key material itself is supplied through `SecretsProvider`'s existing Docker/host production implementation, so a compromised production host that can read the container's injected secrets can read the active encryption key too. This is the same single-VPS, no-external-KMS risk posture ADR-0012 already accepts for all secrets, not a new risk this ADR introduces; a future `KeyProvider` backed by a cloud KMS/Vault (Option D, deferred) would reduce it.
- Encryption is explicit and per-field by design — there is no "encrypt every string column" mechanism, so adopting this primitive for a new sensitive field is always a deliberate, reviewable call site change, not a blanket policy that could silently start (or stop) encrypting something.

## What Would Be Difficult to Change Later

If a future caller stores an `EncryptionService.encrypt()` result without also recording enough context to reconstruct the same `associated_data` at decrypt time, that value becomes permanently undecryptable (AEAD authentication is deliberately unforgiving of this) — this is a correctness contract of AEAD itself, not a defect, but it means any future integration binding ciphertext to AAD must treat that binding as part of its own durable schema. Separately, the two-secret naming convention (`FIELD_ENCRYPTION_ACTIVE_KEY_VERSION` / `FIELD_ENCRYPTION_KEY_<VERSION>`) becomes a de facto external contract once any value is encrypted under it — renaming it later requires a coordinated `SecretsProvider`-level migration, the same one-way-door class ADR-0012 already identifies for its own secret names.

## Related

`docs/ADR/0012-secrets-management.md` (the `SecretsProvider` this module builds on, and the distinct responsibility it deliberately does not take on); `docs/ADR/0008-billing-provider.md` (the provider-abstraction precedent `KeyProvider` follows); `docs/SECURITY.md` §4, §6; the BANK-SEC-01 Open Banking security readiness audit (finding S-01) and BANK-SEC-02 (this remediation)'s own directive, which this ADR's Decision section restates as the binding implementation record.
