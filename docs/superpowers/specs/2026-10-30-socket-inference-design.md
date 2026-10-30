# Socket-Boundary Invocation Inference Design

## Intent

Measure whether a supervised attacker can infer which WASM module ran from
frame sizes and timing observed at the new loopback TCP application boundary.
The study moves the existing six-feature invocation-context attack to a
separate controller/worker process path and uses fresh sessions. The result is
limited to this workload, model, host, and observer; it is not a network or
cryptographic security claim.

## Goals

- Capture controls and protected configurations in separate phases.
- Run plaintext A and encrypt-only B first, and collect C–G only if both
  controls pass the frozen positive-control gate.
- Keep raw ground truth, private instrumentation, and attacker features in
  separate analysis inputs and outputs.
- Reuse the six-feature context classifier unchanged so this study isolates
  the observer boundary rather than tuning the model to prior results.
- Preserve all raw traces, source/binary hashes, host metadata, predictions,
  analysis outputs, and independent verification evidence.

## Non-goals and anti-goals

- No packet capture, remote host, real network, TEE, or hardware-attestation
  evaluation.
- No function-body bytes, labels, step IDs, storage traces, or private worker
  measurements enter the classifier.
- No C–G scoring after either positive control fails; missing protected scores
  are not evidence of privacy.
- No threshold, feature, model, class orientation, or split changes after
  observing this study's results.

## Approaches considered

1. **Repeat the original four-feature frame-size/timing model.** This is
   closest to the first in-process study, but the later six-feature study
   already showed that session normalization and latency rank are relevant.
2. **Move the latest six-feature context model unchanged to the TCP boundary.**
   This preserves the current model and gate while changing the observer
   boundary and using new sessions. It gives the cleanest comparison of
   boundary effects. **Selected.**
3. **Study request presence or dummy detection.** This is a useful, separate
   question, but it changes the target and exposes a different class of
   batching leakage; it should receive its own preregistration.

## Selected protocol

Use `oblivion-harness system-tcp` with 30 trials, four sessions per trial, 16
opportunities per session, a 100 ms epoch, and a fresh deterministic schedule
seed. Collect only A and B first. Analyze and verify their controls. If and
only if both pass, invoke the collector again for C–G in a separate new output
directory. Store the two collections independently and join them only in the
post-collection evaluator.

The harness needs an optional mode-list argument. With no mode list its
existing A–G behavior stays unchanged. The study runner uses exactly the
`A,B` and `C,D,E,F,G` phase subsets; the harness records the selected
canonical modes in each collection. The controller and worker remain separate same-host
processes, and the worker remains loopback-only.

The evaluator pairs request and response events by the worker's public
sequence number, then removes that number and maps the pair to the private
schedule solely for training-label and held-out evaluation joins. For A–D and
F, dummy opportunities have no socket events and are excluded. For E and G,
every opportunity emits a request; dummy cover work runs module 4 and is
labeled as such. The classifier sees only framed request bytes, framed
response bytes, response latency, session-normalized latency, request
interarrival time, and tie-aware latency rank. It never receives raw frame
contents or any truth field.

## Collection and stop behavior

A single runner creates a new bundle directory, collects A/B, runs their
analysis, and checks the gate. A failed gate writes a terminal control-only
result and does not invoke the harness for C–G. A passing gate permits a
second collection into a fresh protected-mode directory, after which the
evaluator scores C–G using the same frozen model. Existing output directories
are never overwritten. Failed partial collections remain labeled incomplete
and are not analyzed as complete trials.

## Implementation choices left to the builder

- Keep mode selection optional in the Rust CLI, preserving the default A–G
  path and its existing tests.
- Implement the phased runner and verifier in Python using the repository's
  locked research dependencies.
- Reuse the existing six-feature extraction/model implementation where the
  interfaces fit; do not duplicate or silently change its frozen behavior.
- Test the control gate with both pass and fail cases, including an assertion
  that the target collector is never called on failure.

## Success criteria

The implementation is successful when a committed preregistration predates
collection; mode-subset collection is bounded and reproducible; A/B controls
are processed before any C–G invocation; the fail path produces no target
data; the pass path uses fresh isolated processes and sessions; an independent
verifier rebuilds hashes, features, splits, predictions, metrics, and the gate;
and the report states exactly which boundary and features were tested.
