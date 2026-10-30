# Socket-Boundary Invocation Context Attack Preregistration

**Frozen:** 2026-10-30, before implementation of the phased collector and
before collection.  
**Status:** no socket-study observations have been collected.

## Research question

At the Oblivion loopback TCP application boundary, can an attacker infer
whether a visible invocation ran the echo module (ID 0) or stateful module
(ID 4) using only frame sizes and timing? Does that attack pass a positive
control on plaintext A and encrypt-only B before protected modes are exposed
to the analysis?

This is a new observer boundary and fresh-data study. It is not pooled with
either in-process invocation study and is not a blind replication because the
selected six-feature model was informed by those earlier studies.

## System and threat boundary

Use `oblivion-harness system-tcp`, which runs a controller and a fresh worker
process per mode/session over a loopback TCP socket. The channel root is
provisioned over inherited stdin. The worker uses the existing A–G registry,
PIR, Wasmtime, storage, response-mask, and fixed-shape paths. The local PIR
servers remain inside the worker; they are not independent operators. The
ORAM observer remains in-process and memory-backed. This is not packet
capture, remote network timing, multi-host non-collusion, or TEE evaluation.

The observer receives `socket-observer.jsonl` request/response rows containing
direction, public sequence number, framed byte count, worker-local monotonic
timestamp, and raw frame body. The classifier is permitted to use only the
framed byte count and timestamp-derived features below. It does not receive
the frame body, even in plaintext mode A. Excluding body bytes narrows the
attack to size/timing and understates the full content leakage of A.

The evaluator uses the private `ground-truth.jsonl` only to align visible
sequence numbers with steps and labels. It strips the alignment key before
model fitting and prediction. The model does not receive mode labels, trial or
session IDs, step IDs, random seeds, dummy/real flags, registry indices,
storage events/addresses/leaves, private executor traces/status, CPU or
memory counters, or response body bytes.

## Modes and workload

The seven modes retain their documented A–G definitions. The frozen
configuration is:

```json
{"version":1,"seed":20261033,"trials":30,"sessions":4,"operations":16,"epoch_ms":100}
```

Each session contains eight dummy opportunities, four echo invocations, and
four stateful invocations, shuffled by the session-specific deterministic
seed. Each selected mode runs in its own fresh worker process. A/B are
collected first in one control collection. The same configuration and
deterministic schedules are used for C–G only after the controls pass, in a
separate fresh protected-mode collection. Within each mode, session pairs are
independent worker processes. Sessions 0–1 train and sessions 2–3 are held
out in every trial; no session is split across the two sets.

For A–D and F, unbatched dummy opportunities emit no invocation and are not
attack samples. In E and G, every opportunity emits an envelope; dummy cover
work executes the stateful module (ID 4) and its visible frame is labeled as
module 4. Thus this is function identity conditional on a visible invocation,
not request-presence or dummy-detection leakage. The E/G test set is imbalanced;
the report must include each class count and majority-class baseline.

## Frozen attacker and features

This is an offline supervised session attack. Training-session labels are the
declared auxiliary knowledge; held-out labels remain unavailable until
predictions have been saved. Pair request/response frames by the public
sequence number inside the evaluator, then remove sequence and private step
before model fitting.

For each visible invocation use exactly these six features:

1. Framed request bytes, including the four-byte length prefix.
2. Framed response bytes, including the four-byte length prefix.
3. `log1p(response_elapsed_ns - request_elapsed_ns)`.
4. Response latency centered by the median of all visible response latencies
   in that session and divided by `max(1, 1.4826 × MAD)`.
5. `log1p(request_interarrival_ns)`; the first request uses its worker-local
   elapsed timestamp from the service observer start.
6. Tie-aware average response-latency rank divided by the number of visible
   invocations in that session.

The latency normalization and rank use unlabeled features from that same
session only. No label or truth-dependent filtering is allowed while deriving
the six features, apart from the private post-capture join that identifies the
visible-invocation samples for evaluation.

Fit one `RandomForestClassifier` per mode with 500 trees, maximum depth 6,
minimum leaf size 2, balanced class weights, one worker, and model seed
`20261220`. Function ID 0 is the positive ROC-AUC class. The fixed
classification threshold is 0.5. Do not choose class direction or tune
features after inspecting held-out predictions.

## Positive controls and stop rule

The runner first collects only A and B. Each control passes if its mean of 30
per-trial ROC-AUC values is at least 0.70 and the lower endpoint of its
two-sided 95% trial-bootstrap interval is greater than 0.50. Use 5,000
bootstrap resamples of the 30 trial units with seed `20261221`.

If either A or B fails, retain and report both controls and the failed gate,
then stop. The runner must not invoke C–G collection, and the analysis must
not emit C–G predictions or scores. If both controls pass, collect C–G in a
separate output root and evaluate them using the unchanged model. Do not lower
the threshold, change the feature set, or use target data to choose the model.

## Metrics

Primary metric: unweighted mean of the 30 per-trial ROC-AUC values.  
Secondary metrics: unweighted mean per-trial balanced accuracy, raw accuracy,
and majority-class accuracy. Report percentile 95% bootstrap intervals over
trial units, per-trial values, class counts, sample counts, and the exact
positive-control decision. A score near chance is not proof of
indistinguishability or cryptographic security.

## Reproducibility and outputs

Frozen config: `experiments/configs/socket-invocation-attack-20261030.json`.  
New bundle root:
`experiments/results/socket-invocation-attack-20261030/`.

The root must be new and the runner must refuse to overwrite it. The bundle
must retain separate A/B control collection, control analysis, optional C–G
collection, final analysis, and independent verification receipt. Record the
frozen configuration and its hash; mode selection; start/end UTC; source
commit and source hashes; release binary hash; Rust/Python/library versions;
OS, CPU and logical-core details; host load; raw file hashes; predictions;
private evaluation labels; per-trial metrics; and analysis output hashes.
Collection metadata must distinguish a complete successful phase from a
failed partial phase. Never rewrite raw traces or replace failed output.

## Known limitations

There are only two target modules and a synthetic deterministic workload. The
observer is worker-side application instrumentation after `accept`, not a
kernel packet timestamp or remote network observer. A and B controls share
the same-host process and scheduler constraints as the targets. The classifier
does not use plaintext body content, although a real observer of A can read
it. The local PIR pair does not establish non-collusion. No result generalizes
beyond the exact observer, host, workload, implementation, and attacker
knowledge. No cryptographic proof, TEE property, or production privacy claim
is tested.
