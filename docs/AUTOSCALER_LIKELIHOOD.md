# Known-policy autoscaler likelihood attack

This preregistered study tests whether an attacker with labeled whole-session
profiles can infer workload intensity or the hot function from a DP
autoscaler's public instance-count trace. The fresh source run used the OS
CSPRNG, 30 independent trials, eight sessions per trial, and four synthetic
workload families. Four complete sessions per trial train the attack; four
disjoint sessions are targets. The selected unit and held-out split are
recorded in the [attack config](../experiments/configs/scaler-csprng-likelihood-attack-20261024.json)
and the [source run config](../experiments/configs/scaler-dp-likelihood-csprng-20261024.json).

## Attack and observer

For each candidate task class, the attacker estimates a per-epoch,
per-function Poisson arrival rate from the labeled profile requests, with
Gamma(0.5, 0.5) rate smoothing. The same class-conditional likelihood model
is first tested on a plaintext positive control that reveals exact per-pool
counts. For DP targets, the attack receives only public instance counts and
public scaler parameters. It applies a bootstrap particle filter over hidden
Poisson arrivals, the exact finite PMF of the capped difference-of-geometric
noise, EWMA smoothing, capacity quantization, and the no-downscale transition
rule. Each target's labels are used only after its prediction is fixed.

The primary metric is balanced accuracy over whole target sessions, averaged
within 30 independent trials. The attack arm is evaluated only if every
plaintext control has mean balanced accuracy at least 0.60 and its
trial-bootstrap 95% interval has a lower endpoint above 0.50. All seven
workload/task controls passed with balanced accuracy 1.000 [1.000, 1.000].
The particle filter used 512 particles; all 840 DP target sessions were
scored, all 1,680 class likelihoods were finite, and no session had both
candidate likelihoods non-finite.

## Results

| Workload | Task | Plaintext count control | DP instance trace |
|---|---|---:|---:|
| Uniform | Intensity | 1.000 [1.000, 1.000] | 0.658 [0.592, 0.725] |
| Zipf | Intensity | 1.000 [1.000, 1.000] | 0.617 [0.525, 0.708] |
| Zipf | Hot function | 1.000 [1.000, 1.000] | 0.567 [0.492, 0.642] |
| Diurnal | Intensity | 1.000 [1.000, 1.000] | 0.608 [0.516, 0.708] |
| Diurnal | Hot function | 1.000 [1.000, 1.000] | 0.575 [0.492, 0.667] |
| Burst | Intensity | 1.000 [1.000, 1.000] | 0.717 [0.617, 0.808] |
| Burst | Hot function | 1.000 [1.000, 1.000] | 0.525 [0.458, 0.592] |

Intervals are percentile bootstrap intervals over the 30 trial-level scores.
Four protected intervals exclude 0.50 before any multiple-comparison
adjustment: uniform, Zipf, diurnal, and burst intensity. These are exploratory
results across seven tested cells, not a general attack guarantee. They show
that this profile-trained model retained intensity signal in several tested
synthetic workloads under this bounded observer. They neither invalidate the
mechanism's scoped request-level approximate-DP claim nor establish that
claim; workload inference is not a test of neighboring-dataset privacy.

The filter uses a finite Monte Carlo likelihood estimate conditioned on its
recorded particle count and seed. It fits independent per-pool rates from a
small profile and omits parameter-estimation and particle Monte Carlo
uncertainty from the trial bootstrap. It is not an optimal attack or an
independent sampler audit. Results do not cover latency, sampler timing,
errors, billing, network traffic, scheduler metadata, identity-level
adjacency, or multi-deployment composition.

## Artifacts and reproduction

The fresh synthetic source run retains the public observer, private
workload-label/driver inputs, component metrics, configs, and plots in
[`scaler-dp-likelihood-csprng-20261024`](../experiments/results/scaler-dp-likelihood-csprng-20261024/).
The [final attack bundle](../experiments/results/scaler-csprng-likelihood-attack-20261024-v3/)
includes predictions, trial scores, the plot, and an artifact hash manifest.
Re-running the attack against the retained source artifacts reproduced both
`report.json` and `predictions.json` byte for byte.

```sh
.venv/bin/python -m research.simulation.run \
  experiments/configs/scaler-dp-likelihood-csprng-20261024.json \
  experiments/results/scaler-dp-likelihood-csprng-new
.venv/bin/python -m research.analysis.scaler_likelihood \
  experiments/results/scaler-dp-likelihood-csprng-new \
  experiments/results/scaler-csprng-likelihood-new \
  --study-config experiments/configs/scaler-csprng-likelihood-attack-20261024.json
```
