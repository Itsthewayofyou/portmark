# Confidential-Computing Attestation

This runtime models confidential-computing attestation as a signed authorization gate before sensitive execution and delegated migration.

## Threat Model

Attestation reduces trust in the destination host before an agent releases sensitive state or migrates work. The relying party needs evidence that a host identity is bound to an approved workload measurement and that the evidence is fresh.

This reference implementation does not encrypt memory against the local Python process and does not verify a hardware TEE quote. Production deployments must replace the mock attestation authority with a platform verifier for the selected TEE, such as a verifier for SEV-SNP, TDX, Nitro Enclaves, or the deployment's equivalent confidential-computing evidence format.

## Evidence Format

`AttestationEvidence` is included in signed permits:

```json
{
  "verifier": "verifier:demo",
  "subject": "host:destination",
  "audience": "host:source",
  "measurement": "measurement:destination",
  "issued_at": 1800000000,
  "expires_at": 1800000060,
  "nonce": "optional-permit-nonce",
  "claims": {},
  "signature_key_id": "demo-attestation-key",
  "signature": "base64url-ed25519-signature"
}
```

The verifier signs the canonical JSON form of every field except `signature`.

## Verification Flow

`AttestationPolicy` verifies:

- the attestation verifier key is trusted, active, and not revoked
- the verifier identity matches the signing key
- the attested subject matches the expected host
- the evidence audience matches the relying party or is explicitly wildcarded
- the evidence is currently valid
- the measurement is in the approved reference-value set
- the nonce matches the permit when a nonce is present
- the evidence signature is valid

For direct execution, the expected subject is the accepting host and the relying party is the permit issuer. For migration, the expected subject is the destination host and the relying party is the source host creating the delegated permit.

## Sealed Storage Decision

The reference runtime treats these values as requiring sealed storage in a production TEE deployment:

- private signing keys
- attestation verifier trust roots
- policy reference measurements
- checkpoints that contain user or agent secrets
- model inputs and outputs that contain sensitive data

The local SQLite store remains a durability backend, not sealed storage. Production deployments should place the database on encrypted storage or use TEE-native sealed storage for sensitive checkpoints, and should keep attestation verifier roots in a managed trust store.

## Residual Risks

Attestation only establishes that a measured workload was approved at the time of evidence creation. It does not remove all host risk, prove application correctness, prevent logic bugs in approved code, or protect data after it is intentionally released to tools, model providers, logs, or external services.
