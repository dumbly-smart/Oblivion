# Profile-only orientation selection for ORAM frequency attacks

This follow-up reanalyzes the retained read-heavy, write-heavy and uniform
eight-address ORAM traces with a predeclared profile-only score-direction
selection rule. It adds no new storage traces. Each result directory retains
the normalized configuration, per-trial compressed predictions, source and
input hashes, JSON report, and AUC plot.

## Method

Each of the 30 trials uses four complete labeled sessions for profiling and
four disjoint complete sessions for testing. For each profile session, the
attacker fits the tag-frequency model on the other three profile sessions and
scores the held-out one. It pools these out-of-fold scores and selects the
score direction with higher profile AUC (ties retain the original direction).
The attacker then fits on all four profile sessions and applies the selected
direction to the four unlabeled target sessions. Target labels enter only the
metric calculation after predictions and scores have been fixed. The ORAM arm
is evaluated only after plaintext and encrypt-only controls each exceed the
preregistered mean-AUC and lower-confidence-bound thresholds.

Intervals are 5,000-resample percentile bootstrap intervals over the 30 trial
metrics. Target sessions remain whole and disjoint from profile sessions.
Reported “raw accuracy” is after profile-only orientation; it is shown beside
the profile-majority baseline because the hot/cold labels are imbalanced.

## Results

| Workload | Mode | AUC after orientation (95% trial interval) | Fixed-direction AUC (95% trial interval) | Balanced accuracy | Raw / profile-majority accuracy | Reversed profile choices |
|---|---|---:|---:|---:|---:|---:|
| 90% reads, skewed | Plaintext | 1.00000 [1.00000, 1.00000] | 1.00000 [1.00000, 1.00000] | 1.00000 | 1.00000 / 0.61693 | 0/30 |
| 90% reads, skewed | Encrypt-only | 1.00000 [1.00000, 1.00000] | 1.00000 [1.00000, 1.00000] | 1.00000 | 1.00000 / 0.61693 | 0/30 |
| 90% reads, skewed | Path ORAM | 0.49909 [0.49106, 0.50726] | 0.49871 [0.49056, 0.50670] | 0.50026 | 0.48314 / 0.61693 | 18/30 |
| 10% reads, skewed | Plaintext | 1.00000 [1.00000, 1.00000] | 1.00000 [1.00000, 1.00000] | 1.00000 | 1.00000 / 0.61569 | 0/30 |
| 10% reads, skewed | Encrypt-only | 1.00000 [1.00000, 1.00000] | 1.00000 [1.00000, 1.00000] | 1.00000 | 1.00000 / 0.61569 | 0/30 |
| 10% reads, skewed | Path ORAM | 0.50653 [0.49657, 0.51666] | 0.48877 [0.47959, 0.49828] | 0.50026 | 0.48913 / 0.61569 | 18/30 |
| 50/50 reads, uniform | Plaintext | 1.00000 [1.00000, 1.00000] | 1.00000 [1.00000, 1.00000] | 1.00000 | 1.00000 / 0.74681 | 0/30 |
| 50/50 reads, uniform | Encrypt-only | 1.00000 [1.00000, 1.00000] | 1.00000 [1.00000, 1.00000] | 1.00000 | 1.00000 / 0.74681 | 0/30 |
| 50/50 reads, uniform | Path ORAM | 0.49374 [0.48298, 0.50437] | 0.50462 [0.49385, 0.51519] | 0.50120 | 0.46484 / 0.74681 | 17/30 |

All positive controls pass. The ORAM AUC intervals include 0.5, and the
oriented raw accuracies remain below the profile-majority baseline. The
write-heavy arm demonstrates why a fixed score direction can land below
chance: profile-only selection moves its mean AUC from 0.48877 to 0.50653.
This is a measured effect of this scorer and validation rule on these finite
workloads, not proof of an attacker’s optimal ability or of privacy. Four
profile sessions make direction selection noisy; many other sequence,
timing, scheduler, and joint-feature attacks remain untested.

## Reproduction

```sh
.venv/bin/python -m unittest research.tests.test_oram_frequency_orientation
.venv/bin/python -m research.analysis.oram_frequency_selected \
  --config experiments/configs/oram-isolated-eight-address-write-heavy.json \
  --raw experiments/results/oram-isolated-eight-address-write-heavy-20261024 \
  --output experiments/results/oram-write-heavy-frequency-oriented-new
```

The committed reports are in
[`read-heavy`](../experiments/results/oram-read-heavy-frequency-oriented-20261024/),
[`write-heavy`](../experiments/results/oram-write-heavy-frequency-oriented-20261024/),
and [`uniform`](../experiments/results/oram-uniform-frequency-oriented-20261024/).
Use a new output directory for each rerun.
