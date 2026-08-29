# Runtime Storage

Portmark persists replay nonces, checkpoints, audit events, and audit heads through the `RuntimeStore` interface in `src/portmark/storage.py`.

## Storage Implementations

- `InMemoryRuntimeStore`: default for tests and dependency-free demos.
- `SQLiteRuntimeStore`: durable local store for production-like runs.

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

## Tables

The current SQLite schema version is stored in `PRAGMA user_version`. Version `3` is the current schema below. Opening a version `0` store runs the baseline table migration, version `1` stores are rebuilt so audit hash uniqueness is scoped to `(task_id, hash)`, version `2` stores gain signed audit-head columns, and newer unsupported versions fail closed so an older runtime does not write to an unknown schema.

`consumed_nonces`

- `nonce`: primary key
- `subject`
- `audience`
- `task_id`
- `consumed_at`

`checkpoints`

- `task_id`: primary key
- `status`
- `checkpoint_json`
- `updated_at`

`audit_events`

- `(task_id, sequence)`: primary key
- `(task_id, hash)`: unique
- `hash`
- `host_id`
- `event`
- `details_json`
- `previous_hash`
- `created_at`

`audit_heads`

- `task_id`: primary key
- `head_hash`
- `sequence`: next expected sequence
- `host_id`: host identity that signed the head
- `signature_key_id`: trusted audit-head signing key
- `signature`: signature over task ID, host ID, head hash, and sequence
- `updated_at`

## Audit Chain Verification

`RuntimeStore.verify_audit_chain(task_id)` recalculates every stored audit event hash, checks local sequence continuity, compares the stored head to the final event, and verifies the stored head signature against the configured trust registry. A migrated task may begin from a previous hash produced by another host; local verification starts from the first stored event's `previous_hash` and then verifies every subsequent link. Unsigned legacy heads and fabricated internally consistent histories return `False`, not `valid`.

## Recovery

`RuntimeStore.load_checkpoint(task_id)` returns the most recent committed checkpoint for a task. The host saves checkpoints after accepting an envelope and after each provider decision is applied, so recovery can resume from the last committed externally visible state.

Native stacks, open sockets, threads, and process state are not persisted. Recovery is checkpoint-based only.

## Security Notes

- Replay protection depends on durable nonce uniqueness. Production deployments should use `SQLiteRuntimeStore` or another durable `RuntimeStore`, not `InMemoryRuntimeStore`.
- Audit events are hash chained and sequence checked before insertion. Audit heads are signed after every persisted batch.
- SQLite is suitable for local and single-node deployments. Multi-host deployments should use a transactional database with equivalent uniqueness and isolation guarantees.
