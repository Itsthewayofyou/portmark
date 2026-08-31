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

Verification fails if the key ID is unknown, revoked, inactive, expired, used for the wrong issuer, used for the wrong audience, or the signature bytes do not verify.

## Generate A Key

`portmark keygen` mints the private key and the matching trust registry together, so the
public half a host must load is never hand-assembled:

```bash
eval "$(portmark keygen --issuer user:alice --out-registry trust.json --format env)"
```

That writes `trust.json` (public only, hand this to the host) and exports
`PORTMARK_ED25519_PRIVATE_KEY_B64`, `PORTMARK_SIGNING_KEY_ID`, and `PORTMARK_SIGNING_ISSUER`
as one consistent set. Drop `--format env` to get the same material as JSON on stdout.
`--out-registry` refuses to overwrite an existing file unless `--force` is passed. Restrict
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

## Revoke A Key

1. Mark the `TrustedIdentity` as `revoked=True` in every verifier registry.
2. Deploy the registry update before accepting more envelopes.
3. Reject or reissue active envelopes signed by the revoked key.
4. Review audit logs for recent envelopes signed with the revoked `key_id`.
5. Generate a replacement key if the issuer still needs to sign envelopes.

Revocation is intentionally checked before signature verification so compromised keys fail with a clear internal cause.

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
