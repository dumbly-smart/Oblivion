# Policy-aware interval attack on CSPRNG autoscaling transcripts

This analysis evaluates a deterministic policy-aware feature transform on the
retained 30-trial OS-CSPRNG scaler transcript. It adds no workload or timing
measurements. The attack observes only public per-epoch instance counts,
scale-up/down and cold-start counts, plus public scaler and noise parameters.

The analysis was preregistered in
[`scaler-csprng-policy-interval-attack-20261024.json`](../experiments/configs/scaler-csprng-policy-interval-attack-20261024.json)
before the final run. In each trial, the first four whole sessions train the
attacker and the other four are held out. Classifiers predict intensity or hot
pool from public per-epoch features; the interval variant appends conservative
lower/upper/width bounds for each pool's included arrivals. Target labels are
used only after predictions are fixed. No public-seed replay is attempted for
the CSPRNG arm.

## Interval construction

For a non-saturated scale-up, the visible target count bounds the measured
signal through the public `ceil(signal * service / (epoch * utilization))`
rule. A no-scale-up epoch gives a censored upper bound; at maximum capacity,
the signal is treated as unbounded except for the public simulator request
limit. The known EWMA recurrence is inverted with interval arithmetic. The
noise draw itself is unknown, so the attacker expands the noisy-count interval
by the configured finite support `[-K, K]`, where `K` is the public geometric
cap. Inconsistent/downscale transitions are kept uninformative rather than
assigned a guessed count.

These intervals are conservative deterministic transforms of the same public
count transcript. The attack uses centroid and 64-tree random-forest
classifiers trained on independent profile sessions; it is not a Bayesian or
optimal likelihood attack.

## Results

All **28** naïve positive controls (both classifiers, public and interval
features, all workload/task combinations) exceeded the preregistered 0.60
balanced-accuracy threshold; observed control balanced accuracy ranged from
0.799 to 0.983. Every protected-arm interval-feature versus public-feature
paired 95% trial-bootstrap interval for the difference includes zero.

| Workload | Task | Model | Public features BA [95% CI] | Policy intervals BA [95% CI] |
|---|---|---|---:|---:|
| Uniform | Intensity | Centroid | 0.525 [0.450, 0.595] | 0.535 [0.461, 0.607] |
| Uniform | Intensity | Forest | 0.503 [0.443, 0.562] | 0.510 [0.452, 0.570] |
| Zipf | Intensity | Centroid | 0.494 [0.434, 0.553] | 0.501 [0.440, 0.562] |
| Zipf | Intensity | Forest | 0.492 [0.436, 0.550] | 0.487 [0.428, 0.548] |
| Zipf | Hot pool | Centroid | 0.541 [0.482, 0.602] | 0.553 [0.485, 0.622] |
| Zipf | Hot pool | Forest | 0.544 [0.492, 0.598] | **0.562 [0.514, 0.608]** |
| Diurnal | Intensity | Centroid | 0.515 [0.450, 0.579] | 0.503 [0.440, 0.564] |
| Diurnal | Intensity | Forest | 0.550 [0.490, 0.609] | 0.538 [0.471, 0.602] |
| Diurnal | Hot pool | Centroid | 0.519 [0.459, 0.579] | 0.538 [0.487, 0.590] |
| Diurnal | Hot pool | Forest | 0.514 [0.464, 0.565] | 0.525 [0.479, 0.574] |
| Burst | Intensity | Centroid | 0.506 [0.450, 0.559] | 0.507 [0.451, 0.557] |
| Burst | Intensity | Forest | 0.522 [0.477, 0.567] | 0.505 [0.460, 0.550] |
| Burst | Hot pool | Centroid | 0.573 [0.498, 0.649] | **0.575 [0.509, 0.640]** |
| Burst | Hot pool | Forest | **0.559 [0.501, 0.613]** | **0.560 [0.501, 0.615]** |

Four of the 28 protected classifier results have unadjusted intervals whose
lower endpoint is just above 0.5. Two concern hot-pool inference under Zipf
and burst workloads; burst-hot forest performance is also above chance with
the public features alone. Because the analysis includes multiple
workload/task/model comparisons, those individual intervals are exploratory.
The paired feature differences do not show a reliable improvement from the
interval transform. The results do show that a limited profile-trained
classifier can retain a possible hot-function signal under these tested
synthetic conditions. They do not prove a general attack, negate the
mechanism's scoped DP claim, or establish privacy.

## Reproduction and artifacts

```sh
.venv/bin/python -m unittest \
  research.tests.test_scaler_interval \
  research.tests.test_scaler_seed_replay
.venv/bin/python -m research.analysis.scaler_seed_replay \
  experiments/results/scaler-dp-discrete-csprng-20261024-v2 \
  experiments/results/scaler-dp-policy-interval-csprng-attack-20261024 \
  --study-config experiments/configs/scaler-csprng-policy-interval-attack-20261024.json
```

The [retained report and artifacts](../experiments/results/scaler-dp-policy-interval-csprng-attack-20261024/)
include the config/source/raw-input hashes, all trial metrics, paired
differences, and regenerated plot; prediction arrays are not retained. CIs are unadjusted percentile bootstrap
intervals over 30 independent trial clusters. The result covers only these
simulator observables and workloads; latency, sampler CPU/timing, errors,
billing, network traffic, hardware scheduling and runtime integration remain
outside the tested observer.
