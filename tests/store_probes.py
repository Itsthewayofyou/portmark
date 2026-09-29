"""Ask a runtime store questions through its supported gates, leaving it exactly as it was."""

from __future__ import annotations

from portmark.security import SecurityError


class _ProbeRollback(Exception):
    pass


def nonce_is_consumed(store, nonce: str) -> bool:
    """True iff `nonce` was consumed: consume_nonce refuses it as a replay. The probe's own
    consumption is rolled back, so an unconsumed nonce stays unconsumed."""
    try:
        with store.transaction() as transaction:
            transaction.consume_nonce(nonce, "probe:subject", "probe:audience", "probe-task")
            raise _ProbeRollback
    except _ProbeRollback:
        return False
    except SecurityError as error:
        if "already been consumed" in str(error):
            return True
        raise
