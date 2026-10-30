# Invocation Boundary Size and Timing Attack

## Result

**The preregistered control gate did not pass, so protected modes C–G were not
scored.** Plaintext mode A passed with mean ROC AUC 1.000 [1.000, 1.000].
Encrypt-only mode B reached 0.689583 [0.653125, 0.726042]. Its interval is
above chance, but its mean is below the frozen 0.70 threshold. The result is
therefore a control-gate failure under the preregistered rule, not a privacy
result for ORAM or the combined system.

The complete raw collection and control-only analysis are retained under
[`experiments/results/invocation-boundary-attack-20261030/`](../experiments/results/invocation-boundary-attack-20261030/).
The final independent receipt is
[`independent-verification-v2.json`](../experiments/results/invocation-boundary-attack-20261030/independent-verification-v2.json).

## Frozen method

The study was preregistered before collection in
[`INVOCATION_BOUNDARY_ATTACK_PREREG_20261030.md`](INVOCATION_BOUNDARY_ATTACK_PREREG_20261030.md)
with the configuration
[`invocation-boundary-attack-20261030.json`](../experiments/configs/invocation-boundary-attack-20261030.json).
It uses the existing A–G system harness: A plaintext direct storage, B
encrypt-only, C encrypted ORAM, D encrypted PIR, E encrypted batching, F
fixed-deadline execution, and G the combined mechanisms.

The observer is the harness's modeled invocation boundary. It sees request
and response lengths and application event timestamps. The attack receives
only four fields: request bytes, response bytes, response-event minus
request-event latency, and time from the previous visible request. The raw
network observer retains frame contents for audit, but the feature extractor
discards them. It also withholds private step numbers, labels, registry
indices, storage events, executor timings, process counters, and the seed
from the model. The trusted analysis code pairs events by step before removing
that field from the feature matrix.

The target is executed module identity: echo/function ID 0 versus
stateful/function ID 4. In batched modes E and G, dummy cover envelopes are
actually dispatched to function ID 4 and receive that label. Unbatched dummy
opportunities emit no invocation frame and are excluded from this
per-visible-request classification. The study does not evaluate whether an
observer detects missing requests.

The workload used 30 trials, eight independently seeded sessions per trial,
eight operations per session, and a 100 ms epoch. Each session had four dummy,
two echo, and two stateful labels shuffled with a deterministic
session-specific seed. The same hidden label schedule was reused across A–G
within each paired session, and the harness randomized mode order. Sessions
0–3 trained a separate 200-tree random forest per mode; sessions 4–7 were
held out. The attacker is supervised and receives labels only for its
training sessions. Test labels were stored separately and joined after
predictions.

## Control results

There were 480 held-out observations in each control, with 240 examples of
each function class. The majority-class baseline was 0.500 for raw accuracy.
Intervals are 95% percentile bootstraps over 30 trial-level values, using
5,000 resamples.

| Mode | Mean ROC AUC [95% CI] | Balanced accuracy [95% CI] | Raw accuracy [95% CI] | Gate |
| --- | ---: | ---: | ---: | --- |
| A: plaintext | 1.000000 [1.000000, 1.000000] | 1.000000 [1.000000, 1.000000] | 1.000000 [1.000000, 1.000000] | Pass |
| B: encrypt-only | 0.689583 [0.653125, 0.726042] | 0.597917 [0.566667, 0.629167] | 0.597917 [0.566667, 0.629167] | Fail: mean AUC below 0.70 |

The encrypt-only classifier did better than chance on this workload, but it
did not meet the stricter frozen positive-control threshold. The stop rule
was applied as written: the evaluator contains only A and B metrics, and no
predictions or scores for C–G. Do not treat the absent C–G rows as evidence
that those configurations resist this attack.

## Collection and verification

The release harness built with
`cargo build --locked --release -p oblivion-harness` (exit 0). The collection
ran from 2026-10-30 11:23:44 UTC to 11:32:31 UTC on an Intel Core i7-14650HX
with 24 logical CPUs, Linux 7.2.11, Rust 1.99.1, and Cargo 1.99.1. Start/end
load averages were 1.73/2.80/3.03 and 2.94/2.40/2.65. The harness exited 0.
The raw directory contains 1,680 mode-session directories, 13,440 private
truth rows, 8,404 files, and 55,828,544 bytes. Binary and source hashes are in
[`collection-metadata.json`](../experiments/results/invocation-boundary-attack-20261030/collection/collection-metadata.json)
and [`analysis-metadata.json`](../experiments/results/invocation-boundary-attack-20261030/analysis/analysis-metadata.json).

The independent verifier checked all 8,404 raw hashes, 1,680 sessions,
13,440 truth rows, the exact invocation event counts for A–G, all 30 per-trial
metrics for each control, the bootstrap intervals, the fixed control
thresholds, the held-out session IDs, prediction/truth separation, and the
absence of C–G scores. It verified seven Rust source/config files and the
release executable hash. Its five focused verifier tests and the complete
Python research suite passed; the suite ran 262 tests with four existing
skips (exit 0). The source/lock verification covered seven files. No Rust
source changed, so Rust unit tests, Clippy, and the
million-operation ORAM stress tier were not rerun for this increment.

The final commands were:

```sh
cargo build --locked --release -p oblivion-harness
PYTHONPATH=. /home/xtrmn8/oblivion/.venv/bin/python -m unittest research.tests.test_invocation_boundary_attack research.tests.test_invocation_boundary_bundle_verifier
PYTHONPATH=. /home/xtrmn8/oblivion/.venv/bin/python -m unittest discover -s research/tests
PYTHONPATH=. /home/xtrmn8/oblivion/.venv/bin/python research/analysis/verify_invocation_boundary_bundle.py \
  experiments/configs/invocation-boundary-attack-20261030.json \
  experiments/results/invocation-boundary-attack-20261030/collection \
  experiments/results/invocation-boundary-attack-20261030/analysis \
  --receipt experiments/results/invocation-boundary-attack-20261030/independent-verification-v2.json
```

## Reproduction

Use a new collection and analysis directory for any rerun; the retained
outputs are immutable. A rerun with this exact seed repeats the deterministic
label schedule, but observed timings can differ.

```sh
cargo build --locked --release -p oblivion-harness
target/release/oblivion-harness system \
  experiments/configs/invocation-boundary-attack-20261030.json \
  experiments/results/invocation-boundary-attack-20261030/collection-reproduction-NEW
PYTHONPATH=. .venv/bin/python research/analysis/invocation_boundary_attack.py \
  experiments/configs/invocation-boundary-attack-20261030.json \
  experiments/results/invocation-boundary-attack-20261030/collection-reproduction-NEW \
  experiments/results/invocation-boundary-attack-20261030/analysis-reproduction-NEW
PYTHONPATH=. .venv/bin/python research/analysis/verify_invocation_boundary_bundle.py \
  experiments/configs/invocation-boundary-attack-20261030.json \
  experiments/results/invocation-boundary-attack-20261030/collection-reproduction-NEW \
  experiments/results/invocation-boundary-attack-20261030/analysis-reproduction-NEW \
  --receipt experiments/results/invocation-boundary-attack-20261030/verification-reproduction-NEW.json
```

## Limits and next experiment

This is an in-process component-boundary simulation, not a packet capture,
remote service, or network timing study. It covers two modules, a synthetic
workload, and one supervised attacker with four declared features. PIR
workers share the harness process, and the test does not evaluate collusion,
TEE isolation, or exact-seed attackers. The result does not establish
cryptographic indistinguishability or security.

Any follow-up must use a new protocol and fresh output paths. The current
held-out control observations cannot be reused to tune the classifier and
then counted as confirmation. First establish a passing encrypt-only
positive control on an independent collection; only then score protected
modes.
