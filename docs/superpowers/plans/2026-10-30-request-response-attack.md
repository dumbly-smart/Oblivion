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

1. Add unit tests for boundary event pairing, strict feature extraction,
   function-label reconstruction, whole-session separation, and the
   positive-control stop gate. Run them and confirm the expected failures.
2. Implement the smallest evaluator that passes those tests. It must discard
   frame payloads and private step/label fields before model fitting.
3. Run focused tests and the complete Python research test suite.
4. Build the release harness, collect into a new immutable directory, and
   record source/binary hashes plus host and software metadata.
5. Run the frozen attack. Retain raw predictions separately from private
   evaluation labels and record all per-trial metrics.
6. Independently verify the collection/analysis bundle, then write the result
   report and update the experiment, status, and progress indexes.
7. Commit and push the preregistration, evaluator, and result in separate
   reviewable commits. Check hosted CI for each pushed commit.

## Boundaries

This is a local, in-process component-boundary simulation, not a TCP capture,
remote-service measurement, or TEE evaluation. The report must preserve that
limit. No near-chance result is evidence of cryptographic indistinguishability.
