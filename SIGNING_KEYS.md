# Signing Keys And Trust Registry

Portable Agent Runtime signs envelopes with Ed25519 by default. HMAC remains available only as an explicit legacy demo mode and should not be used for production trust domains.

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

Generate an Ed25519 signer in Python:

```python
# scripts/key_example.py
from portable_agent.security import EnvelopeSigner

signer = EnvelopeSigner.generate(
    key_id="host-prod-2026-08",
    issuer="host:prod",
    allowed_audiences=("host:prod",),
)

print(signer.private_key_b64())
print(signer.public_key_bytes().hex())
```

For local CLI use, provide the raw private key through `PORTABLE_AGENT_ED25519_PRIVATE_KEY_B64`:

```bash
export PORTABLE_AGENT_ED25519_PRIVATE_KEY_B64="..."
export PORTABLE_AGENT_SIGNING_KEY_ID="host-prod-2026-08"
export PORTABLE_AGENT_SIGNING_ISSUER="host:prod"
export PORTABLE_AGENT_ALLOWED_AUDIENCES="host:prod"
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

## Legacy HMAC Mode

Set `PORTABLE_AGENT_ALLOW_LEGACY_HMAC=1` to use the dependency-free HMAC signer for demos. This mode uses shared secret verification and does not provide asymmetric workload identity. Do not enable it in production.
