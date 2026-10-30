# Session-Normalized Invocation Context Attack

## Result

The frozen positive-control gate failed, so the evaluator scored only
plaintext mode A and encrypt-only mode B. A reached mean per-trial ROC AUC
`1.000000` [1.000000, 1.000000]. B reached `0.698958`
[0.668229, 0.731771]. B's interval is above chance, but its mean missed the
preregistered `0.70` threshold by about `0.00104`. The gate therefore failed
exactly as specified. No predictions or scores for C–G were produced.

This is a second, fresh-data invocation study, informed by the earlier
frame-size/timing control shortfall. It is not a blind replication: the
attacker and its features were changed before collecting this independent
session set, and the earlier held-out observations were not reused. Results
from the two protocols are not pooled.

The [raw collection](../experiments/results/invocation-context-attack-20261030/collection/),
[control-only analysis](../experiments/results/invocation-context-attack-20261030/analysis/),
and [independent verification receipt](../experiments/results/invocation-context-attack-20261030/independent-verification.json)
are retained separately. The complete frozen method is in the
[preregistration](INVOCATION_CONTEXT_ATTACK_PREREG_20261030.md), with machine
configuration at
[`invocation-context-attack-20261030.json`](../experiments/configs/invocation-context-attack-20261030.json).

## Frozen method

The experiment used the seven A–G system modes in the local harness. It
collected 30 trials, four sessions per trial, and 16 operation opportunities
per session at 100 ms epochs. Each session contained eight dummy opportunities,
four echo calls, and four stateful calls. The same seeded schedule was paired
across modes. In batched modes E and G, dummy envelopes were actually
dispatched to function ID 4. In unbatched modes, dummy opportunities emitted
no invocation frame and were not samples in this per-visible-request
classifier.

The observer's modeled boundary is the harness's local invocation frame
observer. It sees request and response frame lengths, their event timestamps,
and session boundaries. Trusted analysis pairs frames by a private step ID;
the step ID and frame contents are omitted from model features. This is an
offline supervised session attack: sessions 0–1 train each mode's model, and
sessions 2–3 are held out. Training labels identify echo/function ID 0 and
stateful/function ID 4. Test labels are kept separately until predictions
are saved.

The fixed feature vector is:

1. Request frame bytes.
2. Response frame bytes.
3. `log1p` of response-event time minus request-event time.
4. Response latency centered by the session median and scaled by
   `max(1, 1.4826 × median absolute deviation)`.
5. `log1p` of request interarrival time; the first request uses its timestamp
   from the session observer start.
6. The tie-aware average latency rank divided by visible requests in that
   session.

The per-mode classifier was a 500-tree `RandomForestClassifier`, maximum
depth 6, minimum leaf size 2, balanced class weights, one worker, and seed
`20261220`. Function ID 0 was the positive class, with a fixed 0.5
classification threshold. The primary metric is the unweighted mean of the
30 trial-level ROC AUC values. Confidence intervals are 95% percentile
bootstraps over 30 independent trial units with 5,000 resamples and seed
`20261221`.

The gate required **both** A and B to have mean AUC at least 0.70 and a lower
95% interval endpoint above 0.50. The protected-mode stop rule was frozen
before collection.

## Results

Each control has 480 held-out requests: 240 per function class. Each also has
480 training requests with equal class counts. The held-out majority baseline
is 0.500.

| Mode | Mean ROC AUC [95% CI] | Balanced accuracy [95% CI] | Raw accuracy [95% CI] | Gate |
| --- | ---: | ---: | ---: | --- |
| A: plaintext | 1.000000 [1.000000, 1.000000] | 1.000000 [1.000000, 1.000000] | 1.000000 [1.000000, 1.000000] | Pass |
| B: encrypt-only | 0.698958 [0.668229, 0.731771] | 0.635417 [0.602031, 0.670833] | 0.635417 [0.602031, 0.670833] | Fail: mean AUC below 0.70 |

B's lower confidence bound is above chance, so this attacker detected some
signal in the encrypt-only control on this workload. The gate nevertheless
failed because the preregistered mean-AUC threshold was not met. Since the
gate is a positive control for the comparison, C–G were not scored. Their
missing rows are not evidence that those configurations resisted the attack.

## Collection and independent verification

The release harness was built with
`cargo build --locked --release -p oblivion-harness` (exit 0) before the
collection. The collector exited 0 and ran from 2026-10-30 11:47:17 UTC to
11:55:44 UTC on an Intel Core i7-14650HX with 24 logical CPUs, Linux
7.2.11-arch1-1, Rust 1.99.1, and Cargo 1.99.1. Start/end load averages were
1.928/2.105/2.477 and 1.796/2.121/2.286.

The collection contains 840 mode/session directories, 13,440 private truth
rows, and 4,204 files totaling 56,028,791 bytes. Independent reconstruction
found 960 public invocation observations in each unbatched mode A–D and F,
and 1,920 in each batched mode E and G. The predictions contain only the 960
A/B held-out control observations.

The independent verifier
[`verify_invocation_context_bundle.py`](../research/analysis/verify_invocation_context_bundle.py)
reconstructed the six numeric features from raw request/response frames and
timestamps, refit the declared classifier for A and B, replayed all 960
held-out predictions, and recomputed per-trial metrics and confidence
intervals. It also verified all 4,204 raw-file hashes, the configuration,
four analysis-output hashes, nine source hashes, the release-binary hash,
the test/train session separation, prediction/label separation, and absence
of C–G scores. The receipt records verifier SHA-256
`d3f9073e0b003509e68fc9cbdad76c557e29411afd0a8971a1f97e55db1c29a6`.

Verification commands and observed results:

```sh
cargo build --locked --release -p oblivion-harness
PYTHONPATH=. .venv/bin/python -m unittest \
  research.tests.test_invocation_context_bundle_verifier \
  research.tests.test_invocation_context_attack
# 10 focused tests passed

PYTHONPATH=. .venv/bin/python -m unittest discover -s research/tests
# 272 tests passed; 4 existing tests skipped; exit 0

PYTHONPATH=. .venv/bin/python research/analysis/verify_invocation_context_bundle.py \
  experiments/configs/invocation-context-attack-20261030.json \
  experiments/results/invocation-context-attack-20261030/collection \
  experiments/results/invocation-context-attack-20261030/analysis \
  --receipt experiments/results/invocation-context-attack-20261030/independent-verification.json
# exit 0; checked A/B only, replayed 960 predictions, and verified 4,204 raw hashes
```

No Rust source changed for this study's analysis/verifier increment. The
workspace Rust unit suite, Clippy, formatting gate, and million-operation
ORAM stress tier were not rerun for that increment. No matching GitHub Actions
run was listed for the verifier, data, or analysis commits when checked.

## Reproduction

The retained result paths are immutable. To collect again, use new output
paths; the seeded workload schedule is repeatable, but observed timing values
are not.

```sh
cargo build --locked --release -p oblivion-harness
target/release/oblivion-harness system \
  experiments/configs/invocation-context-attack-20261030.json \
  experiments/results/invocation-context-attack-20261030/collection-NEW

PYTHONPATH=. .venv/bin/python research/analysis/invocation_context_attack.py \
  experiments/configs/invocation-context-attack-20261030.json \
  experiments/results/invocation-context-attack-20261030/collection-NEW \
  experiments/results/invocation-context-attack-20261030/analysis-NEW

PYTHONPATH=. .venv/bin/python research/analysis/verify_invocation_context_bundle.py \
  experiments/configs/invocation-context-attack-20261030.json \
  experiments/results/invocation-context-attack-20261030/collection-NEW \
  experiments/results/invocation-context-attack-20261030/analysis-NEW \
  --receipt experiments/results/invocation-context-attack-20261030/verification-NEW.json
```

## Scope and limitations

This is an in-process component-boundary simulation. It is not packet capture,
TCP observation, a remote-service measurement, or a hardware-TEE evaluation.
The model sees timestamps from the local harness observer, not external
network arrival times. The workload has two function IDs and one supervised
attacker. The result is about this feature set, split, implementation, host,
and workload only. It is not a cryptographic security proof, and the failed
positive-control gate prevents a defense comparison.

The next invocation-privacy study should move to a separately specified
transport observer or another distinct boundary and fresh sessions. Do not
lower the 0.70 gate, tune on either study's held-out observations, or score
C–G from either failed-control bundle.
