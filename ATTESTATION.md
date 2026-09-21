# Confidential-Computing Attestation

This runtime models confidential-computing attestation as a signed authorization gate before sensitive execution and delegated migration.

## Threat Model

Attestation reduces trust in the destination host before an agent releases sensitive state or migrates work. The relying party needs evidence that a host identity is bound to an approved workload measurement and that the evidence is fresh.

This reference implementation does not encrypt memory against the local Python process. The built-in authority is a signed test double, not a platform quote verifier. Production deployments must select the target TEE and configure a bounded external verifier for that platform, such as a verifier for SEV-SNP, TDX, Nitro Enclaves, or the deployment's equivalent confidential-computing evidence format.

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
  "quote": "base64url-or-platform-quote",
  "signature_key_id": "demo-attestation-key",
  "signature": "base64url-ed25519-signature"
}
```

The built-in verifier signs the canonical JSON form of every field except `signature`. When an external verifier is configured, `quote` is required and carries the deployment-specific attestation document; `claims` can carry parsed, non-secret quote metadata.

## Verification Flow

`AttestationPolicy` verifies:

- the attestation verifier key is trusted, active, and not revoked when local signed evidence is used
- the verifier identity matches the signing key when local signed evidence is used
- the attested subject matches the expected host
- the evidence audience matches the relying party or is explicitly wildcarded
- the evidence is currently valid
- the measurement is in the approved reference-value set
- the nonce matches the permit when a nonce is present
- the evidence signature is valid when local signed evidence is used
- the configured external verifier accepts the evidence when one is configured

For direct execution, the expected subject is the accepting host and the relying party is the permit issuer. For migration, the expected subject is the destination host and the relying party is the source host creating the delegated permit.

## Production Profile

In the production profile (the default for the ASGI app and the CLI), a host whose policy allows
migration refuses to start, or to reload its policy, unless it has a platform verifier command
(`PORTMARK_ATTESTATION_VERIFIER_COMMAND`), a non-empty approved-measurement set
(`PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS`, comma-separated exact strings), and a migration preflight
command (`PORTMARK_MIGRATION_PREFLIGHT_COMMAND`).

The preflight verifies the destination **before** any migration state is released: the source mints a
fresh challenge, the command returns the destination's evidence over it, and the source verifies that
evidence (`verify_migration_challenge`) before it builds and seals the envelope. Production also turns on
the source-minted migration challenge (`require_migration_challenge`) and reuses the same challenge, so
the destination proves itself a second time in the delivery receipt. An empty measurement set would skip
the allowlist check, and evidence without a fresh challenge can be replayed for another migration. A
host that does not migrate needs none of this. See `DEPLOYMENT.md` for the command contract.

## External Verifier Contract

Configure a verifier with `PORTMARK_ATTESTATION_VERIFIER_COMMAND` or
`--attestation-verifier-command`. The command is parsed into an argv tuple and
executed without a shell. It receives canonical JSON on stdin:

```json
{
  "evidence": {
    "verifier": "verifier:external",
    "subject": "host:destination",
    "audience": "host:source",
    "measurement": "measurement:destination",
    "issued_at": 1800000000,
    "expires_at": 1800000060,
    "nonce": "optional-permit-nonce",
    "claims": {},
    "quote": "platform-quote"
  },
  "expected_subject": "host:destination",
  "relying_party": "host:source",
  "expected_nonce": "optional-permit-nonce",
  "now": 1800000030
}
```

The command must exit 0 and return `{"valid": true}` on stdout. Non-zero exits,
timeouts, malformed JSON, oversized stdout, and any other response reject the
evidence. Local signed evidence and external verification can be combined by
configuring both trusted authorities and an external verifier. The reference
runtime does not ship SEV-SNP, TDX, Nitro, or vendor-specific quote validation
logic; that verifier is deployment-supplied and must own its platform trust
roots.

### Verifier Conformance Kit

Portmark checks the claimed fields (subject, audience, validity window, measurement, nonce) before it
calls the verifier. Those checks are only as good as the verifier's proof that the quote binds the same
values. A verifier that parses the quote but does not compare it with the claims turns each Portmark
check into a check of text that the sender chose. **Run the kit before production use**, and again
after each change to the verifier, its trust roots or the platform:

```bash
PORTMARK_ATTESTATION_VERIFIER_COMMAND='...' portmark attest-conformance --evidence known-good-request.json
```

`--evidence` is one real, known-good request in the stdin shape above, with a fresh quote captured on
the target platform. **The verifier must never have seen that quote before** (capture a new one for
each run). The kit refuses a base whose claims disagree with its own request (exit 2). It
sends the requests to the command directly, through the same shell-free adapter the runtime uses
(empty environment, 2 s timeout, 4 KiB output limit). It does not go through Portmark's own checks,
because they would refuse each bad case before the verifier runs.

| Case | Expect | What changes from the known-good base |
|---|---|---|
| `wrong-subject-first` | reject | claimed subject and `expected_subject`, sent first, while the quote is new |
| `valid` | accept | nothing |
| `wrong-subject` | reject | claimed subject and `expected_subject` |
| `wrong-audience` | reject | claimed audience and `relying_party` (a concrete value, not `*`) |
| `wrong-measurement` | reject | claimed measurement |
| `wrong-nonce` | reject | claimed nonce and `expected_nonce` |
| `stale` | reject | `now` moves past the window, and the claimed window moves with it |
| `malformed-quote-corrupted` | reject | one character in the middle of the quote |
| `malformed-quote-truncated` | reject | the quote is cut in half |
| `malformed-quote-garbage` | reject | the quote is replaced with text that is not a quote |
| `valid-repeat` | accept | nothing: the known-good request is sent again, last |

In every negative case the claims and the request agree, so Portmark's own checks would pass. Only the
quote can show the lie. So the verifier must bind each claimed field to the quote: for example the
report data carries a hash of the subject, audience, nonce and validity window, and the measurement is
compared with the measured value in the quote. Each replacement value differs from the base value, so
no case can send the known-good request by accident.

**The verifier must answer from the request alone.** Every case reuses the base quote, so a verifier
that remembers a quote could pass while it compares no field. The order catches the two forms:

- A verifier that trusts the fields it first sees with a quote, and then refuses other fields with it
  (a first-use association cache), learns the lie in `wrong-subject-first` and accepts it.
- A verifier that refuses a quote it has seen before (a replay cache) refuses `valid` and
  `valid-repeat`.

Replay protection is Portmark's job (permit and challenge nonces), not the verifier's.

The kit also refuses a base with a field of the wrong type (exit 2). The output is one JSON document
with a result per case. Exit 0 means every case passed, and exit 1 means at least one failed.

Limits: the contract has no reason channel, so the kit checks accept or reject only. The order checks
catch memory only when the base quote is new to the verifier: a verifier that learned the true fields
from an earlier request is not caught, so always use a newly captured quote. The kit cannot
forge a quote that the platform signed, so it cannot catch a verifier that skips the quote signature
check but compares the fields. Review that check in the verifier code. The evidence `signature` field
is not sent to the verifier, so the kit does not cover it.

### Preflight Conformance Kit

A host that migrates in the production profile also needs `PORTMARK_MIGRATION_PREFLIGHT_COMMAND` (see
`DEPLOYMENT.md`). This kit is a **readiness check**, not a new security control. At migrate time the
source already verifies every preflight answer before it releases any state, so a broken command fails
closed. The kit shows before production that the whole chain works: the command reaches the
destination, it returns evidence over **each** fresh challenge, and the configured verifier and
approved measurements accept that evidence.

```bash
PORTMARK_MIGRATION_PREFLIGHT_COMMAND='...' PORTMARK_ATTESTATION_VERIFIER_COMMAND='...' \
PORTMARK_ATTESTATION_ALLOWED_MEASUREMENTS='...' portmark --host-id <this host> preflight-conformance --destination <a real destination>
```

Each case mints a new challenge and verifies the answer with `verify_migration_challenge`, the same
check the runtime uses:

| Case | Expect | What it checks |
|---|---|---|
| `first-challenge` | accept | the command attests the destination over a fresh challenge, addressed to this host |
| `second-challenge` | accept | a new challenge gets new evidence (a command that returns saved evidence fails here) |
| `other-destination` | reject | a destination the command cannot honestly attest is refused |

Exit 0 means every case passed, 1 means at least one failed, and 2 means a setting is missing.

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
