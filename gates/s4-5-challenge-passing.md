# Gates: Section 4 #5 — challenge-passing protocol (Option 1)

Branch `audit-s4-5-challenge-passing` off main `80ce6f5` (#66 merged; NOT stacked).
Finding #5 follow-up: close the replay gap #64 left open. Josh chose Option 1 (receipt-carried,
source-verified fresh challenge) via `artifacts/research/2026-09-15-s4-5-challenge-passing-options.md`.
Test class is `RuntimeTests`. EVIDENCE lines record runs I executed by hand (manual gates).

## The gap
#64 bound migration attestation to `effective.nonce` (the source's INCOMING nonce, chosen upstream)
and the SOURCE's provider produced the "destination attestation". So the evidence isn't fresh w.r.t. a
value the source freshly minted -- a source can present pre-collected evidence. Replay not closed.

## Design (Option 1, advisor-shaped over two passes)
- SOURCE mints a FRESH challenge `C` at migrate time when `AttestationPolicy.require_migration_challenge`
  is set; `C` becomes the delegated permit nonce (inherits digest + receipt `permit_nonce` binding for
  free) and the delegated permit carries `attestation=None` (advisor #1). A `challenge_required` marker
  is set in the sealed migration memory (digest-covered, set pre-seal).
- DESTINATION admission: when the sealed envelope carries `challenge_required`, the host REQUIRES an
  injected `migration_attester` and obtains its OWN evidence over `(challenge=C, audience=source)` BEFORE
  the first `_persist` -- fail CLOSED there if the attester is absent/errors, so nothing persists and the
  source can re-deliver (advisor #2). The evidence rides in the receipt as an OPTIONAL
  `destination_attestation` field (advisor #3: the #62 exact-match shape check allows it present-or-absent).
- SOURCE `settle_migration`: when the sealed row demanded a challenge, REQUIRE the receipt's
  `destination_attestation` and verify it via the source's `attestation_policy` over `C` (subject=dest,
  audience=source, nonce==C, require_nonce). `C` was source-minted => no pre-collected evidence satisfies.
- Both new controls default OFF; a migration with neither behaves byte-identically to today.

- [x] G1: CALIBRATED replay closure. Destination evidence bound to a value the SOURCE did not freshly
  mint (a stale nonce) is REFUSED at settlement; the row stays pending. CALIBRATED: with the settle-time
  challenge check disabled (`if False and ...`) the stale-bound receipt SETTLED ("SecurityError not
  raised"), so the test catches the vulnerability.
  EVIDENCE: test_migration_challenge_evidence_must_bind_source_challenge OK (fix in place); FAILED
  "SecurityError not raised" with the check neutralized, then reverted. (Name states what it asserts:
  the evidence must bind the source-minted challenge; the replay is stale/self-chosen-nonce evidence.)

- [x] G2: freshness -- the source-minted challenge is fresh and distinct per migration, never equal to
  the reused incoming nonce; the attester sees exactly the two per-migration challenges at admission.
  EVIDENCE: test_migration_challenge_is_fresh_per_migration OK.

- [x] G3: default-OFF -- neither `require_migration_challenge` nor a `migration_attester` set => the
  existing migration path (incl. #64's require_migration_nonce reuse) is unchanged. Whole suite green.
  EVIDENCE: full SQLite suite `Ran 361 tests OK (skipped=16)`; no pre-existing migration test changed.

- [x] G4: CALIBRATED stuck-row avoidance -- a destination that admits a `challenge_required` migration
  with NO attester fails admission CLOSED before persist: no checkpoint, no receipt under the namespaced
  id; the source stays pending and re-delivers successfully once an attester is installed. CALIBRATED:
  with the admission fail-closed neutralized the migration admitted with no attester ("SecurityError not
  raised"), then reverted.
  EVIDENCE: test_challenge_required_without_attester_fails_closed_before_persist OK (fix in place);
  FAILED "SecurityError not raised" with the guard neutralized, then reverted.

- [x] G5: challenge-mode delegated permit -- fresh nonce (!= incoming) + `attestation=None` +
  `challenge_required` marker in the migrated state (advisor #1 pin).
  EVIDENCE: test_challenge_mode_delegated_permit_shape OK.

- [x] G6: receipt shape -- optional `destination_attestation` verifies when present; exact-match still
  rejects an unknown field; a VALIDLY-SIGNED receipt with no attestation cannot settle a
  challenge-required row (fail closed, "challenge attestation is required").
  EVIDENCE: test_challenge_receipt_shape_and_missing_evidence OK.

- [x] G7: audience binding -- destination evidence whose audience is NOT the source is refused at
  settlement (attester input carries audience=source).
  EVIDENCE: test_challenge_evidence_wrong_audience_refused OK.

- [x] G7b: flaky attester fails admission CLOSED as a SecurityError (not an uncaught RuntimeError out of
  run(), the EV-010 class), persists nothing, and the source re-delivers once the attester recovers.
  EVIDENCE: test_challenge_flaky_attester_fails_closed_as_security_error OK; host.py wraps attest() ->
  SecurityError("migration challenge attestation failed").

- [x] G7c: documented bound -- challenge mode carries NO permit attestation, so a destination that also
  sets required_for_execution=True refuses (fail CLOSED). Operator picks one attestation mechanism.
  EVIDENCE: test_challenge_mode_incompatible_with_required_execution_attestation OK ("attestation
  evidence is required").

- [x] G8: full suite green -- SQLite AND Postgres; challenge path exercised end-to-end on BOTH backends.
  #5 adds no schema/SQL (attestation rides inside the opaque receipt JSON).
  EVIDENCE: SQLite `Ran 368 tests OK (skipped=16)`; Postgres `Ran 253 tests OK (skipped=8)`;
  test_migration_challenge_end_to_end_on_both_backends OK on sqlite + postgres subtests.

## Auditor round 1 (PR #67) -- 1 Medium + 1 Low, both FIXED

- [x] G11: CALIBRATED -- invalid attester output does not permanently strand a migration (auditor
  Medium). The destination validates its OWN attester's evidence (subject/audience/nonce/temporal, plus
  measurement/signature when its policy is configured) BEFORE persisting, so a semantically-bad output
  (repro: wrong nonce) is never frozen into the keep-first receipt store; nothing persists, and a
  corrected attester then admits + settles. New `AttestationPolicy.check_local_migration_evidence`.
  CALIBRATED: with the pre-persist check neutralized the bad evidence is accepted (admission does NOT
  raise) and would be stored -- reproducing the wedge -- then reverted.
  EVIDENCE: test_challenge_invalid_attester_output_does_not_strand_migration OK (fix in place); FAILED
  "SecurityError not raised" with the check neutralized, then reverted. Source-side check kept as defense
  in depth (test_migration_challenge_evidence_must_bind_source_challenge rewritten to a forged-receipt
  path). Bound: measurement/signature are the SOURCE's authority and validated at the destination only
  when the destination's own policy is configured; a first attester wrong ONLY in a dimension the
  destination cannot evaluate is a persistent misconfiguration (no corrected attester recovers it), not
  the transient wedge the auditor demonstrated.

- [x] G12: attester call is host-bounded (auditor Low, finding 2). The host runs `attest()` on a daemon
  thread with `migration_attester_timeout` (default 5.0s); on timeout admission fails CLOSED (nothing
  persisted). A hung attester leaks a daemon thread but can never hold admission open.
  EVIDENCE: test_challenge_attester_timeout_fails_closed OK ("timed out", nothing persisted, source stays
  pending). `AgentHost._attest_migration_challenge`.

## Auditor round 2 (PR #67) -- 1 Medium + 1 Medium/Low, both FIXED

- [x] G13: CALIBRATED -- the invalid-evidence wedge is closed for ALL dimensions, incl. wrong signing
  key / source-only measurement, which the destination's partial pre-persist check cannot evaluate.
  The destination REGENERATES the receipt attestation on redelivery of an identical envelope (re-runs
  the attester, keeps checkpoint/audit/generation/accepted_at bindings), so a corrected attester's
  evidence replaces a bad first evidence that keep-first storage would otherwise freeze forever.
  CALIBRATED: with redelivery regeneration disabled, redelivery returns the frozen wrong-key receipt and
  settlement still fails (the auditor's WRONG_KEY_PERSISTED repro), then reverted.
  EVIDENCE: test_challenge_wrong_key_evidence_recovers_via_regeneration OK (fix in place); FAILED
  "good == bad receipt" (assertNotEqual) with regeneration neutralized, then reverted. host.py redelivery
  branch + `AgentHost._produce_challenge_evidence` (shared by first admission and regeneration).

- [x] G14: attester calls are bounded -- a stream of deliveries against a hung attester cannot spawn
  unbounded threads. A `BoundedSemaphore(migration_attester_max_inflight=8)` caps concurrent in-flight
  attester calls; excess calls are refused fail-closed ("capacity is exhausted"). A returning call (even
  post-timeout) releases its slot; only truly-hung calls hold slots.
  EVIDENCE: test_challenge_attester_calls_are_bounded_no_thread_explosion OK -- 12 deliveries against a
  3s-hung attester with the bound tightened to 2 grew active threads by <=2 (auditor saw 13 from 12) and
  refused the excess. `AgentHost._attest_migration_challenge` semaphore.

## Auditor round 3 (PR #67) -- 1 Medium, FIXED

- [x] G15: CALIBRATED -- the regenerated receipt is DURABLE. Round-2 regeneration returned a fresh good
  receipt but never persisted it, so a lost ack + later attester outage left the source unable to settle
  (the stored receipt stayed bad, and redelivery could not regenerate with the attester down). Fix: the
  destination atomically OVERWRITES the stored receipt when it regenerates (new `replace_migration_receipt`
  on all three backends -- InMemory/SQLite/Postgres -- single-statement UPDATE, last-write-wins over
  equally-valid receipts; only attestation + signature change, every binding carried over), AND a
  redelivery whose regeneration is unavailable (attester down/failing) FALLS BACK to the stored receipt
  instead of raising. So a previously-regenerated good receipt settles across lost acks / restarts /
  attester outages. First admission still fails closed (no stored receipt to fall back to).
  CALIBRATED: with the durable persist disabled, the store keeps the bad receipt and the post-outage
  redelivery cannot settle (stored attestation != regenerated), then reverted.
  EVIDENCE: test_challenge_regenerated_receipt_is_durable_across_lost_ack_and_attester_outage OK on
  SQLite AND Postgres subtests (auditor round-3 coverage ask -- exercises replace_migration_receipt on
  both durable backends); FAILED "stored != good" with the persist neutralized, then reverted. host.py
  redelivery branch (regenerate->persist->fallback) + storage.py replace_migration_receipt x3.

- [x] G9: Bandit clean (system 1.9.4, the CI version); ruff clean on edited files; security.py cov >=95%.
  EVIDENCE: `bandit 1.9.4` `bandit -r src tests` -> "No issues identified." (0 nosec); `ruff check
  src/portmark/{security,host,factory}.py tests/test_runtime.py` -> "All checks passed!"; coverage
  security.py = 95% (1163 stmts, 61 miss) from the pgvenv6 no-DSN run whose suite reported the SAME
  `OK (skipped=15)` -- skip count matched between the suite run and the coverage run (per-interpreter:
  system-python reports 16, psycopg-installed pgvenv6 reports 15; both legitimate).

- [x] G10: advisor pre-commit go (second vantage) before done.
  EVIDENCE: two advisor passes pre-code (caught the destination-attests-itself framing error, the
  stuck-row cliff, the attestation=None pin, the exact-shape mixed-version concern, the audience input,
  the bound-call requirement); pre-commit pass flagged 3 verification gaps -- ALL FIXED before commit:
  (1) required_for_execution incompatibility now tested (G7c); (2) flaky-attester path now wrapped as
  SecurityError + tested (G7b); (3) coverage skip-count now matched to its suite run (G9). Plus the two
  PR-body items (replay test renamed; #64 supersession stated in the PR body/CHANGELOG).
