# Invocation Boundary Attack Implementation Plan

## Goal

Measure whether request/response frame lengths and completion timing reveal
which of the two implemented WASM modules ran, using the existing A–G
component-boundary harness. Preserve independent plaintext and encrypt-only
positive controls, and keep private truth out of attacker features.

## Frozen experiment

The protocol and machine-readable configuration are recorded in
`docs/INVOCATION_BOUNDARY_ATTACK_PREREG_20261030.md` and
`experiments/configs/invocation-boundary-attack-20261030.json` before data
collection. The study uses 30 trials, 8 sessions per trial, and 8 offered
operations per session. Sessions 0–3 train each mode-specific classifier;
sessions 4–7 are held out for testing. A and B are positive controls; C–G are
not scored unless both controls pass the preregistered gate.

## Work sequence

1. **Done:** add unit tests for boundary event pairing, strict feature extraction,
   function-label reconstruction, whole-session separation, and the
   positive-control stop gate. Run them and confirm the expected failures.
2. **Done:** implement the evaluator that passes those tests. It discards
   frame payloads and private step/label fields before model fitting.
3. **Done:** focused tests and the complete Python suite passed (262 tests,
   four existing skips).
4. **Done:** build the release harness and collect into a new immutable directory;
   the collector exited 0 and retained host/source metadata.
5. **Done:** run the frozen attack. Plaintext passed; encrypt-only did not
   reach the frozen mean-AUC threshold, so the gate suppressed C–G scoring.
   Attacker predictions and private labels are stored separately.
6. **Done:** independently verify the raw bundle, session split, control gate,
   predictions, metrics, and hashes; write the result report and update
   experiment/status indexes.
7. Commit and push the verifier and result in separate reviewable commits.
   Check hosted CI for each pushed commit.

## Boundaries

This is a local, in-process component-boundary simulation, not a TCP capture,
remote-service measurement, or TEE evaluation. The report must preserve that
limit. No near-chance result is evidence of cryptographic indistinguishability.
