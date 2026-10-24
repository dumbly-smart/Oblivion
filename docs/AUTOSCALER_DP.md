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
classifier is intentionally modest. A public-seed-aware attacker, a
policy-aware inverse controller, or a stronger temporal model is not included
in this empirical comparison. The DP policy's scale-up-only behavior leaves
roughly 263–269 instance-seconds in these synthetic runs and does not meet the
1% SLO filter for three of four workloads. These results do not establish an
improved privacy/cost trade-off.

## Next work

1. Implement a production-like sampler backed by cryptographically secure,
   non-public randomness, while keeping deterministic randomness isolated to
   experiments and tests.
2. Specify user-level adjacency through a bounded per-user contribution and
   account for composition across users, epochs, pools, and deployments.
3. Add a seed-aware positive-control attacker and an inverse-controller
   attack, then report how much of the nominal noise is recoverable from the
   public transcript.
4. Evaluate whether scheduled scale-down can be added as public post-processing
   without exposing busy state, and measure the resulting cost/SLO trade-off.
5. Revisit the claim against a complete scheduler/network/runtime observer
   before connecting any mechanism to the invocation path.
