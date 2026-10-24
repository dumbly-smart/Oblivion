# Autoscaling research simulation

This independent post-MVP experiment implements the roadmap's simulator for privacy, cold starts, cost, and queueing. It does not change the Rust execution pipeline or provision cloud resources. The optional `dp_laplace` policy has a narrowly scoped mechanism-design analysis, but the published seeded experiment itself has **no differential privacy guarantee**. The trusted executor assumption remains the runtime threat model; this simulation examines the scheduler's public capacity transcript separately.

## Reproduce

From the repository root, using the existing Python environment:

```sh
.venv/bin/python -m unittest discover -s research/tests -p 'test_*.py'
.venv/bin/python -m research.simulation.run experiments/configs/scaler-paper.json experiments/results/scaler-reproduction
.venv/bin/python -m research.simulation.run experiments/configs/scaler-prewarm2.json experiments/results/scaler-prewarm2-reproduction
.venv/bin/python -m research.simulation.run --plot-only experiments/results/scaler-reproduction
```

Output directories must be new. The two configurations each specify **30 independent trials, eight independently generated sessions per trial, four workload families, and five policies**. Repeating a configuration reproduces simulated records and metrics; wall time, creation time, command, and host provenance naturally differ. No public cloud dataset was fetched or implicitly attributed to this synthetic experiment.

## Model and implementation plan

The experiment consists of independently inspectable parts: `research/simulation/scaler.py` implements workloads, event queues, policies, and the attack; `research/simulation/run.py` runs balanced independent sessions, separates public/private records, evaluates inference, records provenance, and regenerates plots; `scripts/regenerate_scaler.py` validates retained raw lifecycles and refits the attack from the public/private split; `research/tests/test_scaler.py` exercises timing, admission, billing, policies, boundaries, and end-to-end reproduction. Gzip metadata is fixed for raw output files, so identical seeded runs produce byte-identical raw files.

The development sequence was queue mechanics and failure tests, policy and workload implementation, observer-only profiling, trial-level evaluation, then the two reproducible experiments. Tests initially failed because the simulator module was missing. A later end-to-end test exposed plotting a nonexistent hot-function task for a uniform-only experiment; plotting now skips absent tasks.

Events are held in a heap ordered by time, event priority, then insertion sequence. At equal timestamps, completions precede readiness, arrivals, control ticks, and the horizon. Each publicly named function pool has a FIFO waiting queue and function-affine instances. An instance serves one request at a time; service duration is fixed and identical across function identities. New instances become ready after the configured cold-start duration; no request bypasses that delay. Initial instances are explicitly prewarmed and ready at time zero. There is no sampled or fabricated response latency: each completion follows actual readiness, queue waiting, and service events.

Instances are billed while booting, ready, idle, busy, or finishing retirement. Billing integrates live instance count over every interval between events. Scale-down removes idle instances first; busy instances finish their request before disappearing. Retiring workers do not accept new requests. Total physical instances, including retirement, remain capped per pool. Queue admission is bounded per pool; excess arrivals drop. Control runs after the first full epoch and every epoch thereafter, including the public final boundary.

The observation horizon does not drain unfinished requests. Completed-request p95/p99 are reported alongside unfinished and dropped counts. **Every dropped or unfinished request counts as an SLO violation**, as does every completed request whose latency exceeds the configured SLO. This conservative accounting prevents a policy from looking good by leaving difficult requests unfinished. Reported latency aggregates are means of per-session quantiles, not pooled request quantiles. Cold-start metrics count instance launches, rather than claiming every launch serves a request.

## Policies

All policies receive the same generated arrivals, initial capacity, maximum capacity, service duration, queue limit, and cold-start cost within a configuration.

| Policy | Controller |
| --- | --- |
| `naive` | Last epoch's arrivals plus current waiting queue, converted to desired capacity using service time and utilization target. |
| `ewma` | EWMA of epoch arrivals plus current waiting queue. |
| `quantized` | EWMA plus waiting queue, rounded up to capacity quanta; scale-down waits for consecutive low-target ticks. |
| `fixed` | Retains the configured prewarmed pool throughout the horizon, independent of arrivals. This is a constant fixed schedule, the simplest schedule variant. |
| `noisy` | EWMA arrival signal plus independent Laplace noise clipped at zero, then adds the true waiting queue and converts to capacity. |
| `dp_laplace` | Adds calibrated Laplace noise to the per-pool EWMA vector, clips at zero, and scales from that signal alone. It never downsizes, so queue/busy-state-dependent retirement cannot change the declared public count/launch transcript. |

For the legacy reactive policies, desired capacity is `ceil((arrival_signal + waiting_requests) * service / (epoch * target_utilization))`, capped at maximum capacity. This is a stated engineering heuristic. It deliberately exposes residual leakage through queue feedback. The legacy `noisy` scale is a tunable engineering input and has no adjacency/sensitivity/composition analysis. Fixed capacity can still miss the latency SLO; its identical capacity transcript is not a statement about response traffic, queues, billing to external users, or the complete runtime transcript.

The separate [`event-level Laplace study`](AUTOSCALER_DP.md) fixes the horizon and uses `H = ceil(duration / epoch)` releases. For add/remove-one-request adjacency, one request changes one pool's EWMA by at most one at any release; independent Laplace noise with scale `H / epsilon` therefore gives epsilon pure-DP by basic composition for the declared count/event transcript **under ideal independent hidden randomness**. Queue feedback and downscaling are excluded from this policy's observation boundary. This is a mechanism-design argument, not a guarantee for the saved experiment: the simulator records a public deterministic seed, so an attacker who follows the public seed derivation can reproduce its noise. The saved artifact has no formal DP guarantee. The claim is event-level, not user-level, and excludes latency, errors, billing, and the rest of the runtime transcript.

## Workloads and import

Each session uses independently seeded Poisson arrival counts and uniform arrival times within each epoch. Intensity is a balanced low/high latent session regime (2 or 12 requests/s at the base rate), not a label derived from observed capacity. Each trial's profiling and target halves contain every intensity/hot combination. Across policies, workload seeds and requests match exactly; policy noise uses a separate seed from workload generation.

| Family | Arrival rate | Function probabilities |
| --- | --- | --- |
| Uniform | Constant low/high rate | Uniform; no hot-function label is evaluated. |
| Zipf | Constant low/high rate | Rank probabilities proportional to rank^-1.8; the chosen hot function receives rank one. |
| Diurnal | Base rate × `(1 + 0.7 sin(2πt/horizon))` | Same Zipf popularity. One compressed synthetic cycle, not a measured day. |
| Burst | Base rate × 3 during 35–55% of horizon; × 0.5 otherwise | Same Zipf popularity. |

To add an imported workload, supply a sorted CSV with exactly `time,function` columns, times in simulation seconds within the configured horizon, and valid numeric pool IDs. Add `{"path":"path/to/trace.csv","provenance":"source, collection method, license or synthetic origin"}` to the configuration's `imports` array. Input bytes receive a SHA-256 digest in the report. Imported data is validated and simulated for performance under each policy, but **has no inference score**: repeating the same trace does not create independent labeled profiling and target sessions. Synthetic hot-class claims must not be transferred to an imported trace without an independently justified labeling protocol.

## Attacker and inference

The passive observer gets, for every public epoch, per-pool live instance counts, scale-up events, completed scale-down events, and cold-start launches. Pool names and the scaling policy are public. It receives no request identities, private labels, arrival counts, queue state, response latency, service completion times, or private billing metrics. The schema rejects extra fields. It observes the entire session persistently; feature vectors include current, previous, and cumulative average public counts/events.

The attacker profiles separately for each workload family, policy, and trial. A diagonal nearest-centroid classifier fits labeled independent profiling sessions, then predicts held-out epochs from different sessions. The intensity task identifies the binary latent session demand regime. The popularity task identifies the hot public function pool only where the generator actually creates a hot pool. Labels are constant within a session, so inference at successive epochs is correlated; this is not a claim of arbitrary changing per-epoch demand reconstruction.

The report gives accuracy, balanced accuracy, majority accuracy, and balanced-majority baseline. Target halves are balanced by class; balanced chance is 0.5. Profiling labels are permitted attacker auxiliary knowledge; held-out labels enter scoring only. Four profiling sessions and four target sessions per trial are disjoint. All session results share that trial's learned model, so **confidence intervals bootstrap equal-weight independent trial means**, never individual correlated epoch predictions or target sessions. There are 5,000 percentile resamples and 30 independent trial clusters in each recorded experiment.

Naive reactive scaling is the positive control. The report records whether each task's balanced accuracy exceeds 0.6; failed controls are retained explicitly rather than interpreted as privacy. The chosen profiler is intentionally modest and may miss nonlinear or other temporal information. A low score bounds neither a stronger attacker nor information leakage. No mutual information or calibrated confidence claim is made.

## Artifacts and interpretation

Each run stores:

- `config.json`: exact experiment parameters.
- `observer.jsonl.gz`: public count/event transcripts with trial/session/workload/policy identifiers.
- `workloads-private.jsonl.gz`: workload seeds, latent labels, true epoch arrival counts, and raw arrivals.
- `private.jsonl.gz`: actual per-request arrival/start/completion/drop records and performance metrics for each policy.
- `report.json`: source/config hashes, Python/dependency/host provenance, raw per-trial metrics, summaries, confidence intervals, imported-trace provenance, positive controls, and Pareto membership.
- `pareto-intensity.png` and `pareto-hot.png`: latency/cost and cost/inference plots, regenerable from the saved report alone.

Cost is instance-seconds multiplied by the configurable **hypothetical** price 0.00001 per instance-second. It is not a provider price quote and excludes memory tiers, egress, billing granularity, and minimum charges. Measured hardware provenance describes the machine running the simulation, not hardware calibration of simulated service or cold-start times.

Three-axis Pareto membership minimizes mean session p99 latency, instance-seconds, and attack balanced accuracy using point estimates. A second frontier minimizes cost and attack accuracy among policies whose mean SLO violation rate is at most 1%; dotted lines connect that frontier in plots. Crosses mark policies exceeding this SLO threshold. When no policy meets it, the SLO-constrained frontier is empty. These frontiers do not establish statistically significant dominance.

## Verification and measured results

The Python research suite passed **158 tests with four existing fixture skips**, including the autoscaler mechanisms, selected-policy raw regeneration, positive controls, byte-for-byte reproducibility of seeded gzip traces, centroid/forest public-seed replay attacks, the paired epsilon-sweep driver, and the separate finite-precision OS-CSPRNG sampling path. The prior five-policy campaigns remain the default when `policies` is omitted; optional policy lists are carried through the runner and raw-data reanalysis. CSPRNG sampling is not a formal DP implementation and has not yet had a standalone attack study.

Recorded artifacts are `experiments/results/scaler-paper-30-final/` (one prewarmed instance per pool) and `experiments/results/scaler-prewarm2-30-final/` (two). Each contains 35 policy/task/workload summaries and all raw runs. The final experiments took approximately 17.2 and 17.1 wall seconds on the recorded Intel Core i7-14650HX host. Simulation time remains independent of that execution speed.

All seven naive positive controls passed in each experiment. Their balanced accuracies ranged from 0.823–0.980 with one prewarmed instance, and 0.833–0.970 with two. Selected **uniform-workload intensity inference** results:

| Initial instances per pool | Policy | Instance seconds | Mean session p99 (s) | Balanced accuracy [95% trial CI] | SLO violation rate |
| --- | --- | --- | --- | --- | --- |
| 1 | Naive | 63.85 | 1.443 | 0.980 [0.969, 0.989] | 11.74% |
| 1 | EWMA | 62.58 | 0.968 | 0.980 [0.973, 0.985] | 1.81% |
| 1 | Quantized | 93.05 | 0.586 | 0.897 [0.876, 0.918] | 0.96% |
| 1 | Fixed | 40.00 | 2.622 | 0.500 [0.500, 0.500] | 34.29% |
| 1 | Noisy | 65.83 | 1.649 | 0.955 [0.944, 0.967] | 9.83% |
| 2 | Fixed | 80.00 | 0.420 | 0.500 [0.500, 0.500] | 0.93% |
| 2 | Quantized | 93.87 | 0.439 | 0.850 [0.830, 0.872] | 0.96% |

Fixed capacity produces the same public count/event transcript regardless of workload in this model; the attack's 0.5 score follows that restricted observation, rather than a claim about the entire system. One prewarmed instance per pool is cheaper and has lower measured attack accuracy than naive in the nominal leakage/cost plane, but violates the SLO frequently. Prewarming two instances per pool improves uniform latency at higher cost; it does not solve bursts. For example, under the burst workload fixed-two capacity has mean session p99 3.818 seconds and 27.95% SLO violations. EWMA and noise remain readily distinguishable to the selected attacker. There is no universal policy improvement across these workloads and SLO constraints, and none is fabricated to satisfy the roadmap's hoped-for acceptance outcome.

Only uniform/quantized in the first configuration and uniform/fixed in the second configuration meet the stated mean <=1% SLO-violation filter. Other workload/task frontiers under that filter are empty. Full precision values, all hot-function results, queue/cold-start/drop metrics, hypothetical costs, and confidence intervals are in the reports. The plot color and inference axes report attack performance, not a formal amount of information leaked.

## Limits and follow-up

This is a model with seeded arrivals, two known function pools, constant service times, simple cold starts, fixed control epochs, bounded queues, and no real resource contention. It does not model compilation, module caching, host memory, ORAM cost distributions, network congestion, autoscaler API failures, malicious scheduling, user presence, billing granularity, tenancy, or hardware side channels. Direct scheduler queue visibility would reveal more than the chosen observer; it is explicitly excluded from this attack experiment. The runtime does not gain a privacy-aware autoscaler by running this simulation.

Useful subsequent experiments would calibrate service/cold-start distributions from separately measured runtime samples, obtain licensed real traces with documented provenance, test stronger policy-aware classifiers, vary noise/quantum/hysteresis/utilization and horizon, and compare additional prewarming schedules. Those extensions require fresh independent trials and updated observation contracts. Noise without an adjacency definition, sensitivity bound, and composition accounting must continue to be described as engineering noise.

The optional DP policy, retained raw results, and public-seed replay attack are documented separately in [`AUTOSCALER_DP.md`](AUTOSCALER_DP.md); do not read its ideal-randomness theorem as a guarantee for this seeded simulation.
