# Event-level Laplace autoscaler study

## Status and scope

This is a simulator experiment, not a deployed autoscaler. It introduces an
optional `dp_laplace` policy while leaving the existing five-policy campaign
as the default. The experiment's public view is deliberately limited to epoch,
per-pool instance counts, scale-up/down counts, and cold-start launches. It
does not cover response timing, errors, billing, worker scheduling, the Rust
runtime, or a joint system transcript.

The report distinguishes a conditional mechanism-design argument from an
actual DP release. The simulator uses deterministic NumPy randomness and
publishes the experiment seed. The seed and its derivation are public, so an
attacker who follows the code can reproduce the nominal noise. **The retained
experiment has no formal DP guarantee.** Near-chance results from the selected
classifier do not repair that failure and are not evidence of cryptographic
or differential privacy.

## Mechanism-design argument

Let `H = ceil(duration / epoch)` be a public, fixed number of releases, and
let each epoch produce an EWMA arrival vector `s_t` across the public function
pools. The adjacency relation adds or removes exactly one `Request` record
from the whole fixed-horizon workload. One such record affects one pool's
arrival count in one epoch. With EWMA coefficient `alpha` in `(0, 1]`, its
contribution to that pool is at most `alpha * (1-alpha)^k` at later release
`k`; thus the per-release vector has L1 sensitivity at most one. Each release
adds independent coordinate-wise Laplace noise with scale `H / epsilon`.
The Laplace mechanism is therefore `epsilon/H` for that release, and basic
sequential composition over the fixed `H` releases gives the declared
event-level `epsilon`, `delta = 0` bound for the noisy signal transcript.

Capacity selection is deterministic post-processing: clip the noisy value at
zero, convert it to the requested capacity, cap at the configured maximum,
and only scale up. The controller does not add the true queue to this signal
and does not retire workers. Consequently the listed public count, scale-up,
and cold-start fields are functions of the noisy signals and public state;
request-dependent worker-busy state cannot affect those fields. This boundary
does not include measurements outside the simulator's declared observer.

The argument is conditional on ideal independent Laplace draws hidden from
the observer. The experiment's PRNG seed is part of the public configuration,
and the per-session PRNG seed is deterministically derived from it by public
code. The output is consequently deterministic given public experiment
parameters and workload class identifiers. A secure, hidden production RNG,
finite-precision sampler analysis, and an end-to-end observer contract have
not been implemented.

The adjacency is request-level, not user-level. A user issuing `m` requests
can incur up to the corresponding group-privacy composition; no per-user
contribution bound is enforced. Replacement/move adjacency is not claimed.
Variable horizons, externally visible queue state, latency, errors, billing,
and the full runtime transcript are outside the argument. The legacy `noisy`
policy remains engineering noise without a formal privacy analysis.

## Reproduction

From the repository root, run the selected test and create fresh output
directories:

```sh
.venv/bin/python -m unittest research.tests.test_scaler
.venv/bin/python -m research.simulation.run \
  experiments/configs/scaler-dp-event-20261024.json \
  experiments/results/scaler-dp-event-reproduction
.venv/bin/python scripts/regenerate_scaler.py \
  experiments/results/scaler-dp-event-reproduction \
  experiments/results/scaler-dp-event-reanalysis
.venv/bin/python -m research.simulation.run --plot-only \
  experiments/results/scaler-dp-event-reproduction
```

The checked-in configuration uses seed `20261024`, 30 independent trials,
eight whole sessions per trial, four synthetic workload families, six
policies, two public function pools, a 20-epoch horizon, and `epsilon = 1`.
This means 5,760 policy/session simulations and 20 vector releases per
simulation. The configured scale is 20.0 per pool and epoch (`epsilon/H =
0.05`). The output directory must not already exist.

Raw public transcripts, private lifecycle records, and private workload labels
are separate files. `artifact-sha256.json` hashes the files produced by a run;
the report separately records config and source hashes, seed, trial count,
runtime, software versions, host details, and Git revision. Gzip metadata is
fixed, and a test requires identical raw bytes for repeated runs with the same
configuration and seed. `regenerate_scaler.py` verifies raw session coverage,
strict public/private schemas, lifecycle consistency, and stored source hashes
before rebuilding summaries and plots without re-running the simulator.

The measured run is retained in
[`experiments/results/scaler-dp-event-20261024/`](../experiments/results/scaler-dp-event-20261024/).
Its independently regenerated summary and plots are in
[`experiments/results/scaler-dp-event-20261024-rebuilt/`](../experiments/results/scaler-dp-event-20261024-rebuilt/).
Both directories contain `artifact-sha256.json`; the raw inputs are unchanged
during reanalysis.

The freshly captured raw file SHA-256 values are:

| File | SHA-256 |
| --- | --- |
| `observer.jsonl.gz` | `37e1f716102a955d2825c161ae85c12157ad0e9d753c8d93e078af676670838e` |
| `private.jsonl.gz` | `5027904fe3701b051e932732d39b1b49ea34a45791f7b1da1a00ca19fe4ca6ac` |
| `workloads-private.jsonl.gz` | `132d854e1e372a64e2af2c735a5e3de062095768ecb5dd7a7f83fa6bc85c9e3c` |

The independently regenerated report has 1,260 trial/task/policy rows and 42
summaries. Its summary object matches the runner report exactly, and all
manifest entries and source hashes were checked against file bytes.

## Attack protocol and controls

The attack is the existing known-policy diagonal nearest-centroid classifier.
For each trial, the first four whole sessions profile and the other four
sessions test. The features are current, previous, and cumulative per-pool
instance counts, scale events, and cold-start counts. The attacker is told the
workload family and policy, and the public function-pool identities. Truth
labels and request lists remain in separate files. There are 30 independent
trial clusters; intervals bootstrap trials, not correlated epochs or sessions.
The intensity task is a binary low/high demand regime; the hot-pool task is
evaluated only for non-uniform workloads.

The naive policy is the positive control. All seven task-specific controls
passed the predeclared `balanced_accuracy > 0.60` criterion:

| Workload | Task | Naive balanced accuracy |
| --- | --- | ---: |
| Uniform | Intensity | 0.9833 |
| Zipf | Intensity | 0.9775 |
| Zipf | Hot pool | 0.8454 |
| Diurnal | Intensity | 0.9292 |
| Diurnal | Hot pool | 0.8521 |
| Burst | Intensity | 0.8796 |
| Burst | Hot pool | 0.8650 |

## Results

The table reports the `dp_laplace` rows from the saved report. Intervals are
equal-weight, independent-trial 95% bootstrap intervals. Instance-seconds,
p99, and SLO violation are simulator outputs, not measured service
performance. The cost field uses the experiment's hypothetical configured
price and is not a provider quote.

| Workload | Task | Balanced accuracy [95% CI] | Instance-seconds | Mean session p99 (s) | SLO violations | Meets 1% SLO filter |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Uniform | Intensity | 0.508 [0.449, 0.563] | 267.38 | 0.659 | 1.30% | No |
| Zipf | Intensity | 0.562 [0.501, 0.625] | 266.06 | 0.803 | 1.94% | No |
| Zipf | Hot pool | 0.489 [0.430, 0.551] | 266.06 | 0.803 | 1.94% | No |
| Diurnal | Intensity | 0.518 [0.462, 0.572] | 268.61 | 0.803 | 2.16% | No |
| Diurnal | Hot pool | 0.541 [0.495, 0.583] | 268.61 | 0.803 | 2.16% | No |
| Burst | Intensity | 0.493 [0.434, 0.550] | 263.49 | 0.479 | 0.74% | Yes |
| Burst | Hot pool | 0.513 [0.460, 0.570] | 263.49 | 0.479 | 0.74% | Yes |

Six intervals include the 0.50 balanced-chance baseline. Zipf intensity's
unadjusted interval begins at 0.501, a marginal result across multiple tasks
and workloads; it is not presented as significant evidence. The selected
classifier is intentionally modest. The DP policy's scale-up-only behavior leaves
roughly 263–269 instance-seconds in these synthetic runs and does not meet the
1% SLO filter for three of four workloads. These results do not establish an
improved privacy/cost trade-off.

## Public-seed replay attack

The follow-up attacker regenerates the per-session Laplace stream from the
public experiment seed, public trial/session/workload identifiers, and the
published seed derivation. It combines those values with public instance and
scale-up transitions to invert the capacity quantizer. The inverse is
censored when a pool does not scale up or reaches its capacity cap. It never
uses private request lists; profile labels train the classifier, and target
labels are read only for scoring.

All fourteen task-specific naive controls passed the same `> 0.60`
criterion across the centroid and forest variants. The table compares public
features and seed replay using the same 30 held-out trial clusters. The forest
uses 64 trees, maximum depth 6, and minimum leaf size 4, fixed before this
post-hoc run.

| Workload | Task | Centroid public | Centroid replay | Forest public | Forest replay [95% CI] |
| --- | --- | ---: | ---: | ---: | ---: |
| Uniform | Intensity | 0.508 | 0.519 | 0.541 | 0.553 [0.484, 0.618] |
| Zipf | Intensity | 0.562 | 0.526 | 0.543 | 0.531 [0.472, 0.595] |
| Zipf | Hot pool | 0.489 | 0.498 | 0.515 | 0.514 [0.459, 0.573] |
| Diurnal | Intensity | 0.518 | 0.533 | 0.519 | 0.518 [0.454, 0.580] |
| Diurnal | Hot pool | 0.541 | 0.512 | 0.539 | 0.520 [0.465, 0.578] |
| Burst | Intensity | 0.493 | 0.542 | 0.529 | 0.563 [0.506, 0.619] |
| Burst | Hot pool | 0.513 | 0.508 | 0.510 | 0.518 [0.458, 0.581] |

The burst-intensity forest-replay interval excludes 0.50 at its unadjusted
lower bound (0.506); the other six replay intervals include chance. This is
one nominal result among multiple workloads, tasks, and attacks, without
multiple-comparison correction. It is a modest indication of workload
inference in this simulator, not a broad attack or a privacy theorem.
Capacity quantization and maximum clipping still discard information. A
regression test also constructs adjacent empty/one-request workloads with the
same public seed and observes different transcripts, demonstrating that this
deterministic seeded release is not constant over that adjacent pair.

Recreate the post-hoc evaluation from retained raw data:

```sh
.venv/bin/python -m research.analysis.scaler_seed_replay \
  experiments/results/scaler-dp-event-20261024 \
  experiments/results/scaler-dp-seed-replay-reproduction
```

The 42-summary report is retained in
[`experiments/results/scaler-dp-seed-replay-20261024/`](../experiments/results/scaler-dp-seed-replay-20261024/).
Its input hashes identify the public transcript and separately held-out
labels used by the evaluation harness. Positive and target predictions are
summarized by independent trial; no target labels enter features or model
fitting. The report SHA-256 is
`8828a3a8ae2607c13a2be63782f5a6e0bbd79d17e8d2ec060686cd9af4d1ddae`.

## Epsilon and cost sweep

Rebuild the paired budget sweep from its configuration with:

```sh
.venv/bin/python -m research.analysis.scaler_epsilon_sweep \
  experiments/configs/scaler-dp-epsilon-sweep-20261024.json \
  experiments/results/scaler-dp-epsilon-sweep-reproduction
```

The retained run uses 30 trials, eight whole sessions, and four synthetic
workload families at each of ε ∈ {0.5, 1, 2, 4}. It reuses identical private
workload/session streams across budgets. The public-feature forest and the
known-seed replay forest were evaluated separately; all 28 naive positive
controls exceeded the predeclared 0.60 threshold. Each confidence interval
below is a percentile bootstrap over 30 independent trial clusters, without
correction for the many workload/task comparisons.

| ε | Laplace scale | Uniform intensity | Zipf intensity | Diurnal intensity | Burst intensity | Mean simulated instance-seconds | Mean SLO violation |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.5 | 40 | 0.506 [0.428, 0.578] | 0.520 [0.451, 0.589] | 0.490 [0.438, 0.541] | 0.573 [0.508, 0.640] | 281.22 | 0.0152 |
| 1 | 20 | 0.553 [0.484, 0.618] | 0.531 [0.472, 0.595] | 0.518 [0.454, 0.580] | 0.563 [0.506, 0.619] | 266.39 | 0.0154 |
| 2 | 10 | 0.556 [0.495, 0.619] | 0.573 [0.510, 0.640] | 0.576 [0.509, 0.639] | 0.532 [0.480, 0.584] | 226.69 | 0.0174 |
| 4 | 5 | 0.625 [0.552, 0.697] | 0.643 [0.583, 0.704] | 0.660 [0.593, 0.724] | 0.606 [0.558, 0.655] | 163.54 | 0.0224 |

The accuracy entries are balanced accuracy for the forest seed-replay
intensity task; intervals are unadjusted 95% trial-cluster bootstrap
intervals. Mean simulated instance-seconds and SLO rate are unweighted
averages across the four synthetic families. They are simulator outputs,
not provider cost or live-service performance. Higher ε generally made
intensity easier to infer while lowering simulated instance-seconds and
raising SLO violations, but the classifier results are not monotone at every
step and do not establish a universal privacy/cost law. At ε=4 all four
unadjusted intervals exclude 0.5. Public deterministic randomness invalidates
any formal DP guarantee for these artifacts, regardless of classifier score.

Raw traces, per-run reports, plots, source/config hashes, and the root
manifest are retained in
[`scaler-dp-epsilon-sweep-20261024`](../experiments/results/scaler-dp-epsilon-sweep-20261024/).
The report SHA-256 is
`dcaa4818ef0e0859f2812ea6051ba9b99c277eeddc3c515e9f6504cf0a823260`.

## OS-CSPRNG sampling path

The runner accepts top-level `"dp_noise_source": "os_csprng"`. In that mode,
each `dp_laplace` pool/tick samples a 52-bit word through Python's
`secrets.randbits` and applies an open-interval inverse-CDF transform. The
default `seeded_experiment` mode remains unchanged and reproducible; it exists
for experiments, not as a private release. The report marks CSPRNG runs as
non-reproducible from the public seed and distinguishes their randomness
source. Raw reanalysis preserves this distinction.

The seed-replay evaluator inspects this setting and omits its known-seed
attacker for `os_csprng` traces; it evaluates only public-feature models there.
The naïve arm remains a positive control. This avoids attributing a
reconstructed seed stream to a transcript generated from OS entropy.

This is a research sampler, not a DP implementation: finite word support,
binary64 rounding and the transformation have not been analyzed as a discrete
mechanism, so the report makes no formal guarantee even when the OS CSPRNG is
used. The retained event/epsilon studies still use seeded randomness and do
not characterize this new path; their classifier results must not be
attributed to it. The separate 30-trial CSPRNG campaign below passes its
positive controls, but a formally analyzed discrete mechanism and independent
cryptographic review remain open.

### CSPRNG attack campaign

Recreate the sampled transcript and its attack analysis with:

```sh
.venv/bin/python -m research.simulation.run \
  experiments/configs/scaler-dp-csprng-20261024.json \
  experiments/results/scaler-dp-csprng-reproduction
.venv/bin/python -m research.analysis.scaler_seed_replay \
  experiments/results/scaler-dp-csprng-reproduction \
  experiments/results/scaler-dp-csprng-analysis-reproduction
```

Because the noise is drawn from OS entropy, reruns reproduce the design and
analysis, not the raw noise samples. The 30-trial, eight-session, four-family
campaign uses the same seeded workload/session streams as the ε=1 seeded arm.
The forest public-feature attack results are:

| Workload | Task | Naïve positive control | CSPRNG `dp_laplace` [95% CI] |
| --- | --- | ---: | ---: |
| Uniform | Intensity | 0.979 | 0.518 [0.466, 0.571] |
| Zipf | Intensity | 0.937 | 0.552 [0.490, 0.612] |
| Zipf | Hot pool | 0.827 | 0.498 [0.433, 0.565] |
| Diurnal | Intensity | 0.930 | 0.542 [0.487, 0.600] |
| Diurnal | Hot pool | 0.799 | 0.491 [0.435, 0.551] |
| Burst | Intensity | 0.893 | 0.468 [0.395, 0.542] |
| Burst | Hot pool | 0.840 | 0.462 [0.377, 0.547] |

All 14 naïve centroid/forest controls exceeded 0.60. All seven forest
intervals are unadjusted 95% trial-cluster bootstrap intervals and include
0.50; results are limited to the declared count/event features and workload
classes, and do not establish a privacy guarantee. The report also retains
centroid results, all controls, and the plot at
[`scaler-dp-csprng-attack-20261024-plotted`](../experiments/results/scaler-dp-csprng-attack-20261024-plotted/).
The raw transcript, config, and runner report are at
[`scaler-dp-csprng-20261024`](../experiments/results/scaler-dp-csprng-20261024/).
The attack report SHA-256 is
`f030c7f9fb7a9d42de34e7bfb295b9eb1e68e9535e3bfc7b283cb9cd3a9b3fd1`.

## Next work

1. Review/audit the separate OS-CSPRNG path and replace its finite-precision
   transform with a formally analyzed discrete mechanism.
2. Specify user-level adjacency through a bounded per-user contribution and
   account for composition across users, epochs, pools, and deployments.
3. Test stronger policy-aware inversion and temporal classifiers against the
   capacity censoring, and report their limits with positive controls.
4. Evaluate whether scheduled scale-down can be added as public post-processing
   without exposing busy state, and measure the resulting cost/SLO trade-off.
5. Revisit the claim against a complete scheduler/network/runtime observer
   before connecting any mechanism to the invocation path.
