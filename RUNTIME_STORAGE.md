# Runtime Storage

Portmark persists replay nonces, checkpoints, audit events, and audit heads through the `RuntimeStore` interface in `src/portmark/storage.py`.

## Storage Implementations

- `InMemoryRuntimeStore`: default for tests and dependency-free demos.
- `SQLiteRuntimeStore`: durable local store for single-node deployments.
- `PostgresRuntimeStore`: durable store for multi-host deployments (`pip install "portmark[postgres]"`).

`RuntimeStore` is the supported extension point for production databases. A replacement store must provide the same transaction boundary and observable behavior as `SQLiteRuntimeStore`: nonce consumption, audit append, checkpoint save, and signed audit-head update commit or roll back together; nonce values and `(task_id, sequence)` audit positions must be unique; `audit_head(task_id)` must return the next expected sequence; and `verify_audit_chain(task_id)` must return `False` for missing, incomplete, reordered, relinked, hash-tampered, unsigned, or signature-tampered histories.

Use SQLite from the CLI:

```bash
PYTHONPATH=src python -m portmark.cli --store-path runtime.sqlite demo "research portable agents"
```

Or through the environment:

```bash
export PORTMARK_STORE_PATH=runtime.sqlite
PYTHONPATH=src python -m portmark.cli demo "research portable agents"
```

## Transactional Guarantees

The SQLite store uses `BEGIN IMMEDIATE` for each runtime transaction and configures `PRAGMA busy_timeout = 30000` on store-created connections so concurrent writers wait for the active writer instead of failing immediately with `database is locked`. The host commits or rolls back these operations together:

- Nonce consumption
- New audit events
- Latest checkpoint
- Audit head update

If any write fails, the transaction is rolled back. For example, a duplicate audit event cannot leave behind a consumed nonce without a matching checkpoint and audit head.

## Schema Versions

Each durable store records its schema version and migrates forward on open. A store whose version is
**newer** than the running code fails closed, so an older runtime never writes to an unknown schema.

- **SQLite:** version in `PRAGMA user_version`. Current version: **15** (`SQLITE_SCHEMA_VERSION`).
  Each step runs in ONE `BEGIN IMMEDIATE` transaction together with its `user_version` bump (never
  `executescript()`, which commits first and then runs each statement on its own). A crash leaves the
  complete old version or the complete new one. The version is read inside the write transaction, so
  concurrent first opens queue on SQLite's write lock. Every step is also restart-idempotent: an
  `ADD COLUMN` checks `PRAGMA table_info` first, and the v2 `audit_events` rebuild recognises a
  half-finished copy. So a database left half-migrated by an older runtime also continues.
  `tests/sqlite_schema_versions.json` is the reference schema of every version.
- **PostgreSQL:** version in the single-row `portmark_schema` table. Current version: **13**
  (`POSTGRES_SCHEMA_VERSION`). DDL runs behind a session-level advisory lock and uses
  `ADD COLUMN IF NOT EXISTS`, so concurrent first opens are safe. The Postgres version numbers are
  NOT the same as the SQLite ones; both reach the same current tables below.

SQLite migration steps (each step runs once, in order):

| To | Change |
|---|---|
| 1 | Baseline tables: `consumed_nonces`, `checkpoints`, `audit_events`, `audit_heads`. |
| 2 | `audit_events` rebuilt so hash uniqueness is scoped to `(task_id, hash)`. |
| 3 | `audit_heads` gains `host_id`, `signature_key_id`, `signature` (signed heads). |
| 4 | `checkpoints` gains `generation` and `closed` (compare-and-swap resume, EV-008). |
| 5 | New `migration_outbox` (durable migration delivery). |
| 6 | `audit_heads` gains nullable `signed_at` (NULL = legacy v1 head). |
| 7 | New `migration_receipts`; `migration_outbox` gains `receipt_json`. |
| 8 | `migration_outbox` gains `claimed_by`, `lease_expires_at`, `dead_reason` (lease + dead-letter). |
| 9 | New `task_cancellations` (durable cancellation). |
| 10 | New `tool_effects` + index on `task_id` (effect ledger). |
| 11 | `tool_effects` gains `reconcile_claim_id`, `reconcile_lease_expires_at` (reconcile lease). |
| 12 | New `audit_floor_markers` (Section 10 audit floor; PostgreSQL version 10). |
| 13 | New `time_floor` and `maintenance_log`; nonce expiry and delivery time (Section 12; PostgreSQL version 11). |
| 14 | `checkpoints` gains `owner_issuer`, `owner_subject` (task ownership, PM-001; PostgreSQL version 12). |
| 15 | New `witness_receipts` (EV-013 remote witness; PostgreSQL version 13). |

## Tables

`consumed_nonces`

- `nonce`: primary key
- `subject`, `audience`, `task_id`, `consumed_at`

`checkpoints`

- `task_id`: primary key
- `status`, `checkpoint_json`, `updated_at`
- `generation`: store-owned counter; a resume must present the current value (compare-and-swap)
- `closed`: terminal flag; a closed checkpoint cannot be resumed

`audit_events`

- `(task_id, sequence)`: primary key
- `(task_id, hash)`: unique
- `hash`, `host_id`, `event`, `details_json`, `previous_hash`, `created_at`

`audit_heads`

- `task_id`: primary key
- `head_hash`
- `sequence`: next expected sequence
- `host_id`: host identity that signed the head
- `signature_key_id`: trusted audit-head signing key
- `signature`: signature over task ID, host ID, head hash, sequence (and `signed_at` for v2)
- `signed_at`: attested signing time of a v2 head; NULL for a legacy v1 head
- `updated_at`

`migration_outbox` (source side of a migration)

- `task_id`: primary key
- `destination`, `sealed_envelope_json`, `status` (`pending` / `delivered` / `dead`), `attempt_count`, `created_at`
- `receipt_json`: the destination receipt this host received and verified
- `claimed_by`, `lease_expires_at`: dispatcher lease; `dead_reason`: why a row was dead-lettered

`migration_receipts` (destination side of a migration)

- `task_id`: primary key
- `receipt_json`: the signed receipt this host issued, `created_at`

`task_cancellations`

- `task_id`: primary key; presence means cancelled
- `cancelled_at`

`audit_floor_markers`

- `host_id`: primary key
- `epoch`: the audit floor's current epoch (raised by `floor-reset`)
- `pending`: set while a floor is being created or reset (crash recovery), then cleared
- `updated_at`

`witness_receipts` (EV-013)

- `host_id`: primary key
- `host_seq`, `receipt_hash`: the newest remote-witness receipt this database committed (the next
  advance's `prev`), written in the save transaction
- `receipt_json`: the witness's signed receipt
- `updated_at`

`tool_effects`

- `effect_id`: primary key (host-derived)
- `task_id` (indexed), `tool`, `state` (`prepared` / `started` / `confirmed` / `unknown` / `reconciled`)
- `arguments_json`, `result_json`, `reason`, `created_at`, `updated_at`
- `reconcile_claim_id`, `reconcile_lease_expires_at`: reconcile lease

## Audit Chain Verification

`RuntimeStore.verify_audit_chain_status(task_id)` (and the `verify-audit` CLI) recalculates every
stored audit event hash, checks sequence continuity, compares the stored head to the final event, and
verifies the head signature against the configured trust registry. Unsigned legacy heads and fabricated
internally consistent histories are not `valid`.

- **One snapshot.** The events and the head are read inside ONE read transaction (SQLite: a deferred
  read transaction under WAL; PostgreSQL: `REPEATABLE READ, READ ONLY`). A writer that commits during
  verification cannot make a healthy chain look tampered.
- **Migration anchor.** A migrated task starts from the source's head. The destination records the
  source's signed head in event 0 (`details.migration`): hash, sequence, host, original task ID, key ID,
  and signature. Verification re-checks that source signature against the trust registry, so an auditor
  with only the destination database can re-validate the handoff. `anchor_status` reports `none` (not a
  migration), `verified`, `legacy-anchor` (written before this proof was kept; hash, sequence, and host
  only), or `invalid`. A `legacy-anchor` is `unverifiable` by default (CLI exit 2); the temporary
  compatibility flag `verify-audit --allow-legacy-anchor` accepts a complete one as `valid` without
  reverifying the source proof (see SIGNING_KEYS.md). Partial or malformed anchors are always `invalid`. The source signs its handoff head in the v1 format (no signing time), so if the
  source key is revoked later, the anchor reports `invalid`: it cannot be shown to predate the revocation.
- **What this does not prove.** Verification checks the database against itself and the trust registry.
  It does not know whether a NEWER head once existed: restoring an older, internally consistent database
  still verifies by itself. Rollback detection is the audit floor: a signed file OUTSIDE the database
  (`--audit-floor-path`; see OPERATIONS.md, Audit Floor), checked at start, inside every save
  transaction, and by `verify-audit --audit-floor-path` (`floor_status`).

## Recovery

`RuntimeStore.load_checkpoint(task_id)` returns the most recent committed checkpoint for a task. The host saves checkpoints after accepting an envelope and after each provider decision is applied, so recovery can resume from the last committed externally visible state.

Native stacks, open sockets, threads, and process state are not persisted. Recovery is checkpoint-based only.

## Security Notes

- Replay protection depends on durable nonce uniqueness. Production deployments should use `SQLiteRuntimeStore` or another durable `RuntimeStore`, not `InMemoryRuntimeStore`.
- Audit events are hash chained and sequence checked before insertion. Audit heads are signed after every persisted batch.
- SQLite is suitable for local and single-node deployments. Multi-host deployments should use a transactional database with equivalent uniqueness and isolation guarantees.
