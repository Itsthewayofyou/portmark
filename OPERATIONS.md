# Operations Runbook

This runbook covers production operations for the reference runtime.

## Configuration

Runtime configuration can come from environment variables or CLI flags:

- `PORTMARK_HOST_ID` / `--host-id`
- `PORTMARK_ED25519_PRIVATE_KEY_B64`
- `PORTMARK_SIGNING_KEY_ID`
- `PORTMARK_SIGNING_ISSUER`
- `PORTMARK_ALLOWED_AUDIENCES`
- `PORTMARK_TRUST_REGISTRY_PATH` / `--trust-registry-path`
- `PORTMARK_POLICY_PATH` / `--policy-path`
- `PORTMARK_RELOAD_POLICY` / `--reload-policy`
- `PORTMARK_STORE_PATH` / `--store-path`
- `PORTMARK_PROVIDER_ENDPOINT` / `--provider-endpoint`
- `PORTMARK_A2A_TOKEN` / `--a2a-token`
- `PORTMARK_LOG_LEVEL` / `--log-level`
- `PORTMARK_LOG_JSON` / `--log-json`
- `PORTMARK_ENABLE_HSTS` / `--enable-hsts`

## Trust Registry

Trust registries are JSON files:

```json
{
  "identities": [
    {
      "key_id": "issuer-key",
      "issuer": "host:issuer",
      "public_key_b64": "base64url-raw-ed25519-public-key",
      "allowed_audiences": ["host:destination"],
      "not_before": 1800000000,
      "expires_at": 1800086400,
      "revoked": false
    }
  ]
}
```

Use unique key IDs, short key lifetimes, and explicit `allowed_audiences` where possible. For emergency revocation, set `revoked: true`, deploy the trust registry, and restart hosts or use the deployment's config reload mechanism.

## Policy Updates

Policy changes should be reviewed, versioned, and deployed with a rollback plan. Approval tokens are bound to policy hashes, so tokens issued before a policy update will be rejected once hosts reload the new policy.

## Audit Verification

For SQLite-backed hosts, call `SQLiteRuntimeStore.verify_audit_chain(task_id)` during investigations or backup validation. A false result means event sequence, previous hash, or event hash validation failed and the task history should be treated as tampered or corrupted.

## Backup And Restore

Back up these assets together:

- runtime database
- active policy file
- trust registry
- attestation verifier roots
- approval authority roots

Restore them as a consistent set. Restoring an old database with a newer policy is allowed, but old approval tokens may fail policy-hash validation.

## Incident Response

For suspected key compromise:

1. Revoke the signing, attestation, or approval key in the corresponding trust file.
2. Rotate affected private keys.
3. Restart or reload hosts.
4. Search audit logs for the compromised key ID.
5. Re-run audit-chain verification for impacted task IDs.
6. Invalidate outstanding approvals from the compromised approver.

For suspected policy bypass:

1. Preserve the runtime database and logs.
2. Verify audit chains for affected task IDs.
3. Check `agent.accepted` events for policy version and hash.
4. Check approval events for request, approval, denial, expiry, and use.
5. Rotate approval keys if token signing is implicated.
