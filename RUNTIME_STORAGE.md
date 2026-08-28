# Runtime Storage

Portable Agent Runtime persists replay nonces, checkpoints, audit events, and audit heads through the `RuntimeStore` interface in `src/portable_agent/storage.py`.

## Storage Implementations

- `InMemoryRuntimeStore`: default for tests and dependency-free demos.
- `SQLiteRuntimeStore`: durable local store for production-like runs.

Use SQLite from the CLI:

```bash
PYTHONPATH=src python -m portable_agent.cli --store-path runtime.sqlite demo "research portable agents"
```

Or through the environment:

```bash
export PORTABLE_AGENT_STORE_PATH=runtime.sqlite
PYTHONPATH=src python -m portable_agent.cli demo "research portable agents"
```

## Transactional Guarantees

The SQLite store uses `BEGIN IMMEDIATE` for each runtime transaction. The host commits or rolls back these operations together:

- Nonce consumption
- New audit events
- Latest checkpoint
- Audit head update

If any write fails, the transaction is rolled back. For example, a duplicate audit event cannot leave behind a consumed nonce without a matching checkpoint and audit head.

## Tables

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
- `hash`: unique
- `host_id`
- `event`
- `details_json`
- `previous_hash`
- `created_at`

`audit_heads`

- `task_id`: primary key
- `head_hash`
- `sequence`: next expected sequence
- `updated_at`

## Audit Chain Verification

`RuntimeStore.verify_audit_chain(task_id)` recalculates every stored audit event hash and checks local sequence continuity. A migrated task may begin from a previous hash produced by another host; local verification starts from the first stored event's `previous_hash` and then verifies every subsequent link.

## Recovery

`RuntimeStore.load_checkpoint(task_id)` returns the most recent committed checkpoint for a task. The host saves checkpoints after accepting an envelope and after each provider decision is applied, so recovery can resume from the last committed externally visible state.

Native stacks, open sockets, threads, and process state are not persisted. Recovery is checkpoint-based only.

## Security Notes

- Replay protection depends on durable nonce uniqueness. Production deployments should use `SQLiteRuntimeStore` or another durable `RuntimeStore`, not `InMemoryRuntimeStore`.
- Audit events are hash chained and sequence checked before insertion.
- SQLite is suitable for local and single-node deployments. Multi-host deployments should use a transactional database with equivalent uniqueness and isolation guarantees.
