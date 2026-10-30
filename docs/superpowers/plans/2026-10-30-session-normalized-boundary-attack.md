# Session-Normalized Boundary Attack Plan

## Goal

Test a distinct offline, session-normalized timing classifier against the
existing A–G invocation boundary on fresh sessions. Keep the previous
control-gate failure as a separate result and do not reuse its held-out data
for attack tuning.

## Frozen protocol

Use `docs/INVOCATION_CONTEXT_ATTACK_PREREG_20261030.md` and
`experiments/configs/invocation-context-attack-20261030.json`. The new seed is
20261032; the study has 30 trials, 4 sessions/trial, 16 operations/session,
and a 100 ms epoch. Sessions 0–1 train and 2–3 test within each trial. A and
B are positive controls; C–G are withheld unless both controls pass.

## Work sequence

1. Add failing tests for robust per-session normalization, tie ranks,
   feature/label separation, whole-session splits, and the control stop rule.
2. Implement a new evaluator without changing the prior frozen evaluator.
3. Run focused tests and the complete Python suite; build the release harness.
4. Collect into a new output directory and record source, binary, host, and
   load metadata.
5. Run the frozen attack. Preserve only controls if the positive gate fails.
6. Add an independent verifier for raw hashes, feature derivation, splits,
   predictions, thresholds, per-trial metrics, and intervals.
7. Report the result and update progress/experiment indexes. Commit and push
   the verifier, raw collection, analysis, and report separately; inspect CI
   after each push.

## Interpretation boundary

This is a fresh but informed follow-up, not a blind replication and not a
real network measurement. A control failure blocks protected comparisons.
Near-chance results are not proofs of privacy or cryptographic security.
