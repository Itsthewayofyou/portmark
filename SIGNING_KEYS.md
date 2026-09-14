# Signing Keys And Trust Registry

Portmark signs envelopes with Ed25519 by default. HMAC remains available only as an explicit legacy demo mode and should not be used for production trust domains.

## Signed Envelope Metadata

Each signed `AgentEnvelope` includes:

- `signature_key_id`: selects the public key in the verifier trust registry.
- `signature`: Ed25519 signature over canonical JSON returned by `AgentEnvelope.unsigned_dict()`.

The `signature_key_id` is included in the signed payload. Changing the key ID after signing invalidates the envelope.

## Trust Registry Model

The host verifier uses a `TrustRegistry` containing `TrustedIdentity` records:

- `key_id`: stable ID for the signing key.
- `issuer`: identity allowed to sign envelopes with this key.
- `public_key`: raw 32-byte Ed25519 public key.
- `allowed_audiences`: host IDs this key may target.
- `not_before`: optional activation time.
- `expires_at`: optional expiration time.
- `revoked`: hard-disable flag for compromised or retired keys.
- `usages` (optional): permitted key purposes, e.g. `["envelope"]`, `["audit"]`,
  `["migration"]`, or a combination. Enforced for the `envelope` purpose (envelope verification),
  the `audit` purpose (ordinary audit-head verification), and the `migration` purpose (migration
  handoff verification — a migration handoff is verified with `required_usage="migration"`, so a
  key scoped to audit-only cannot mint migration handoffs). Absent/empty means unrestricted
  (backward compatible), and the host's own self-registered key is unrestricted. A migration key
  therefore needs both `envelope` (to seal the migrated envelope) and `migration` (for the handoff).
- `revoked_at` (optional): the effective epoch time of a revocation (see historical verification
  below). With `revoked=true` and `revoked_at` set, a head signed strictly before that time is
  "valid, key later revoked"; a head at/after it is "signed after revocation".

Verification fails if the key ID is unknown, revoked, inactive, expired, used for the wrong issuer,
used for the wrong audience, lacks the required usage, or the signature bytes do not verify. The
same validity predicate (trusted AND not-revoked AND active AND not-expired) gates admission and
`/readyz`; key-id lookup alone is never treated as "usable".

`not_before`/`expires_at` must be integers (a JSON boolean is rejected, not coerced) and `revoked`
must be a boolean; a duplicate `key_id` in a registry is rejected, not silently collapsed.

## Generate A Key

`portmark keygen` mints the private key and the matching trust registry together, so the
public half a host must load is never hand-assembled:

```bash
eval "$(portmark keygen --issuer user:alice --out-registry trust.json --format env)"
```

That writes `trust.json` (public only, hand this to the host) and exports
`PORTMARK_ED25519_PRIVATE_KEY_B64`, `PORTMARK_SIGNING_KEY_ID`, and `PORTMARK_SIGNING_ISSUER`
as one consistent set. Every exported value is shell-quoted, so a key id or issuer containing
shell metacharacters cannot inject commands when the line is eval'd. **The `env` format is POSIX
sh/bash only** — on PowerShell/cmd, use `--format json` (or `--out-registry`) and set the variables
manually rather than eval'ing this output. Drop `--format env` to get the same material as JSON on
stdout. `--out-registry` refuses to overwrite an existing file unless `--force` is passed. Restrict
which hosts a key may target with one or more `--audience` flags; the default is any.

To generate a signer programmatically instead:

```python
# scripts/key_example.py
from portmark.security import EnvelopeSigner

signer = EnvelopeSigner.generate(
    key_id="host-prod-2026-08",
    issuer="host:prod",
    allowed_audiences=("host:prod",),
)

print(signer.private_key_b64())
print(signer.public_key_bytes().hex())
```

For local CLI use, provide the raw private key through `PORTMARK_ED25519_PRIVATE_KEY_B64`:

```bash
export PORTMARK_ED25519_PRIVATE_KEY_B64="..."
export PORTMARK_SIGNING_KEY_ID="host-prod-2026-08"
export PORTMARK_SIGNING_ISSUER="host:prod"
export PORTMARK_ALLOWED_AUDIENCES="host:prod"
```

Production deployments should load private keys from a secret manager, workload identity provider, HSM, or equivalent key custody system instead of shell environment variables.

## Rotate A Key

1. Generate a new Ed25519 key pair with a new `key_id`.
2. Add the new public key to every destination host trust registry.
3. Deploy signers using the new private key.
4. Keep the old public key trusted until all old envelopes and delegated migrations have expired.
5. Set `expires_at` on the old key to prevent new long-lived trust.
6. Remove or revoke the old key after the maximum envelope lifetime has passed.

`portmark keygen --force --out-registry <file>` merges a new rotation entry into an existing
registry rather than clobbering it, and the merge is **concurrency-safe**: it serializes
read → validate → merge → replace under a sidecar lock (`<file>.lock`) so two simultaneous
rotations cannot lose each other's key, validates the whole existing registry before merging
(a duplicate id already in the file is rejected, not silently collapsed), and fsyncs the parent
directory so the rename survives a crash. The cross-process lock uses `fcntl` on POSIX and
`msvcrt.locking` on Windows — both are released by the OS if the holding process dies, so neither
can leave a stale lock the way an `O_EXCL` lock *file* would. On a platform that offers neither
primitive the write stays crash-atomic but concurrent merges are not serialized.

## Host Audit-Signing Key Must Be Usable At Boot

A host signs every audit head with its own key. `make_host` **fails closed at startup** unless that
key is, in the registry the host verifies audit heads against, currently trusted, active
(`not_before` reached), unexpired, unrevoked, and authorized for the `audit` usage. Readiness only
*reports* a bad key; startup enforcement is what stops a host from admitting a direct request and
returning results whose audit head is invalid from birth. The same check re-runs before every audit
head is signed, so a key that expires mid-process fails the run closed (the checkpoint stays
resumable) rather than writing unverifiable evidence. Legacy HMAC signing has no key lifecycle and is
exempt.

## Revoke A Key

1. Mark the `TrustedIdentity` as `revoked=True` in every verifier registry.
2. Deploy the registry update before accepting more envelopes.
3. Reject or reissue active envelopes signed by the revoked key.
4. Review audit logs for recent envelopes signed with the revoked `key_id`.
5. Generate a replacement key if the issuer still needs to sign envelopes.

Revocation is intentionally checked before signature verification so compromised keys fail with a clear internal cause.

**A running host fails closed on any on-disk registry change and must be restarted to adopt it.**
The signer and the store's audit verifier share one trust source that re-reads the registry file on
every verification: when the file's contents change (a revocation, a rotation, any edit) or the file
is removed, the host rejects admission and audit verification — it does not silently keep trusting
the old registry, and it does not adopt the new, unauthenticated bytes mid-process. So a revocation
takes effect immediately as a *refusal to serve*, and the host must be restarted with the reviewed
new registry to resume. `/readyz` reports not-ready in the same situation. (Authenticated,
versioned hot-reload without a restart is planned; until then, restart is the adopt step.)

**A durable store requires a stable, configured signing key.** Because a generated key changes on
every restart and would orphan previously-signed audit heads, a host backed by a durable store
(SQLite/Postgres) refuses to start unless `PORTMARK_ED25519_PRIVATE_KEY_B64` is set (and the host's
public key is in the trust registry). Ephemeral demo/test hosts may pass
`allow_ephemeral_signing_key=True` to opt out. Generated key ids are derived from the public-key
fingerprint (`ed25519:<digest>`), so two generated keys never share an id.

## Historical Audit Verification (Option B)

Audit heads are signed as `portmark.audit-head.v2`, which carries a signed `signed_at`.
Verification is judged **at signing time**, not against the current clock, so ordinary key
rotation and expiry do not retroactively invalidate a head that was validly signed. The trust
registry is the key archive: keep rotated/expired keys in it (with their `not_before`/`expires_at`/
`revoked`/`revoked_at`) so their historical heads remain verifiable.

`verify-audit` reports a coarse `status` (valid / invalid / unverifiable — drives the CLI exit code)
plus a precise `head_status`:

- `valid` — signed while the key was valid.
- `valid-key-expired` — signed while valid; the key has since expired (still trustworthy).
- `valid-key-revoked` — signed strictly before `revoked_at`; cryptographically valid, but the key
  was **later revoked** — reported prominently, not silently accepted.
- `signed-after-revocation` — signed at/after `revoked_at`, or the key is revoked with no effective
  time — rejected.
- `signed-after-expiry` — signed at/after `expires_at`; the key was already invalid when it signed —
  rejected. (A revocation recorded *later* never upgrades such a head back to accepted.)
- `signed-in-future` — `signed_at` is more than `AUDIT_HEAD_CLOCK_SKEW_SECONDS` (300s) ahead of the
  verifier's clock — rejected. A signer cannot honestly attest a time it has not reached; this is a
  local sanity bound, not proof of existence-before-T (that needs the external witness below).
- `signature-invalid` / `untrusted` / `usage-violation` / `host-mismatch` — rejected.

Validity at signing time is judged in a strict order so a later lifecycle event cannot rehabilitate a
head that was invalid when signed: **malformed/future → before activation → at/after expiry → revocation
timing → since-expiry reporting.** Expiry-at-signing is decided *before* revocation, so a head signed
after the key expired stays `signed-after-expiry` even if the key is revoked afterwards; among heads
that *were* validly signed, a later revocation is reported ahead of a later expiry.

**Legacy v1 policy.** A `portmark.audit-head.v1` head has no attested signing time. It verifies
cryptographically as `valid-legacy-v1` when the key is not revoked; benign expiry/activation are NOT
applied retroactively (there is no signing time to judge against). But a v1 head signed by a key
that is now **revoked** is `revoked-key-legacy-v1` (rejected): without a `signed_at`, pre-compromise
signing cannot be established, so a compromised key's v1 heads cannot be trusted as pre-compromise.

**Limitation (build to it, do not oversell).** `signed_at` is set by the signer, so a *compromised*
key can backdate it. `signed_at` cleanly handles benign expiry/rotation, but on its own it does not
prove a head was signed before compromise. Compromise-sensitive "signed before time T" proof
requires an external witness the attacker cannot backdate (a transparency log / timestamp authority
/ durable remote receipt) — see the deferred transparency-log work.

## Bootstrap Trust

Trust registry distribution is out of scope for the reference runtime, but production systems should:

- Load registry data from a controlled source, not process-local constants.
- Pin issuer identities to public keys and allowed audiences.
- Version registry changes and include the active registry version in audit events.
- Require operator review for new issuers or broader audiences.
- Test rollback before emergency revocation is needed.

## Why Not SPIFFE

SPIFFE/SPIRE is the consensus workload-identity standard, and Portmark deliberately does not use it
as its trust root. The reason is a lifetime mismatch, not a disagreement about the standard.

SPIFFE issues **short-lived credentials for a live workload**, rotated automatically — SPIRE's
defaults are `default_x509_svid_ttl = 6h` and `default_jwt_svid_ttl = 5m`, renewed at roughly half
of their lifetime. That is the correct design for authenticating a running process across a
connection.

Portmark verifies two things, and only one of them is a live connection:

| What | When it is verified | Credential lifetime needed |
| --- | --- | --- |
| Envelope signature | once, on arrival | short is fine |
| **Signed audit head** | **potentially months later, via `portmark verify-audit`** | **must outlive the run** |

The audit head is the constraint. EU AI Act Article 12 record-keeping, enforceable since
2 August 2026, expects tamper-evident logs of agent *actions* retained for at least six months.
Today `verify-audit` resolves a six-month-old signature from a single JSON file. Under rotating
SVIDs the same check requires archiving the exact signing certificate and the trust bundle current
at signing time — signatures made before expiry stay valid, but the material needed to verify them
must be kept, and SPIRE rotates and replaces rather than archiving. That is solvable, and it is
machinery this runtime does not currently need.

The second reason is bootstrap cost. Adopting SPIFFE makes step zero "deploy a SPIRE Server with a
datastore, an Agent on every node, a node attestor, and clock sync," and cross-organisation trust
additionally requires SPIFFE Federation, where adding or removing a trust domain means a
configuration change and restart on every participating deployment. Portmark's premise is a
stranger's agent arriving at your host, which the registry serves with a JSON file and no shared
infrastructure.

**This is an opt-in gap, not a rejection.** The intended design when it is needed: accept a SPIFFE
SVID as an additional identity source for **envelope** verification, while audit heads continue to
use a registry-backed host key. The envelope format does not have to change. The trigger to build
it is a deployment that already runs SPIRE, a need for sub-hour revocation, or more trusted agent
keys than a JSON file can sensibly carry.

Comparison performed 2026-08-31 against spiffe.io documentation of that date.

## Legacy HMAC Mode

Set `PORTMARK_ALLOW_LEGACY_HMAC=unsafe-test-only` and a non-empty
`PORTMARK_SIGNING_KEY` to use the dependency-free HMAC signer for tests or
demos. This mode uses shared secret verification and does not provide
asymmetric workload identity. Do not enable it in production.
