# Individual-server PIR target timing and query distribution

`experiments/results/pir-target-timing-20261023/` evaluates the roadmap's individual-server query-distribution and target-timing checks, P03/P11, for the project's actual two-server XOR PIR. This is an empirical three-target experiment with a measured plaintext positive control, followed by protected observations. It is scoped to one noncolluding server's exported query bytes and local answer duration.

## Reproduction and observer scope

```sh
.venv/bin/python -m unittest research.tests.test_pir_timing
.venv/bin/python scripts/evaluate_pir_timing.py \
  --config experiments/configs/pir-target-timing-30.json \
  --output experiments/results/pir-target-timing-new
```

Tests require the release exporter (`cargo build --locked --release -p oblivion-pir --example target_timing`), or an explicit `OBLIVION_PIR_TIMING_BIN`. The runner builds it, checks source stability across compilation, copies an immutable executable into the result directory's ignored `bin/`, snapshots sources and writes hardware/configuration/source/executable provenance before starting measurements. After-run provenance records executable and source hashes again. The artifact manifest covers raw streams, source snapshots, reports and plots, excluding ignored binaries. Frozen executable hashes remain in provenance. Fresh directories preserve historical results.

The attacker receives only `session`, `step`, `server_ns`, `query_bytes`, and `visible_index`. Session and step align records and enforce whole-session splits; they are excluded from model features. For protected PIR, `visible_index` is always null, and `query_bytes` contains only server 0's own first query share. The observer does not receive the second share, server 1's answer timing, recovery, generation time, target labels, target seed or an arrival-time trace. Truth labels/index and client generation/recovery/oracle status reside in separate private streams. The exporter never serializes the second query share.

For the plaintext control, the exporter performs an actual direct-index record lookup and exposes that index plus measured lookup duration. Its complete observations are collected and its independently profiled classifier must exceed chance before protected collection starts. No target-correlated latency is invented. All measured answers, protected and plaintext, are compared byte for byte with a complete 64-byte record oracle. Each session constructs fresh separately owned server databases and excludes an untimed warm-up.

## Experiment and classifier

Each geometry has 128 or 1,024 records, each 64 bytes. The requested indices are `[0, N/2, N-1]`. Every session contains 96 queries, 32 per target in a shuffled order. Each of 30 trials has two complete profiling sessions and two disjoint complete target sessions: 192 profiling and 192 held-out observations. This yields 11,520 observations per geometry/mode, including 5,760 held-out predictions. Across both geometries and control/protected modes there are 46,080 measured requests, each verified by the oracle. The public reproducibility seed schedules the private label order; it is not supplied to the model or represented as a protocol observable. Cryptographic query randomness comes from the actual `QueryPair::generate` OS source, with no seeded replacement.

`research/attacks/pir_timing.py` exposes `PirTimingAttack.fit(trace, aux)` and `run(trace, aux)` using the shared `PredictionResult` interface. It enforces exact observer and auxiliary schemas, fixed query shape, valid session/step identities and disjoint profiling/target sessions. The only profiling auxiliary knowledge is labeled complete profiling sessions. Target auxiliary knowledge names the target sessions and cannot contain target labels. Unknown/private fields are rejected. Each feature mode/trial fits a fresh scikit-learn random forest with 64 trees, maximum depth five, minimum leaf size three, all candidate features, one thread and a model seed independent of the workload seed.

The four feature modes are joint (own query byte values, log answer duration, and visible index), timing only, share only and visible index only. The last mode is a constant null-index negative control for protected PIR. All modes use the same whole-session split. Scores are uncalibrated tree class proportions; `confidence` is deliberately absent. Balanced accuracy has chance 1/3, and balanced target counts also make the majority baseline 1/3. Intervals bootstrap 30 independently fitted trial balanced accuracies with 5,000 resamples, rather than treating all queries as independent model fits.

Server answer p50/p95/p99 are computed within each trial/target from genuine local timing samples and then summarized across trials. Query-bit diagnostics use only the observed first share, with separate target labels available solely for evaluation. They report each bit's one frequency and the three requested bit positions' frequencies. These are marginal diagnostics with many comparisons, without a global acceptance threshold or claim that nonsignificance proves equality of full distributions.

## Observed results

The campaign completed 46,080 oracle-checked requests. The plaintext control's held-out balanced accuracy was 1.000 for each geometry, with trial-bootstrap interval [1.000, 1.000], before protected collection began. Both geometries had all 30 independent fitted-model trials and four distinct sessions per trial. Frozen executable and source hashes matched before/after measurement. Collection/analysis ran from 2026-10-22 20:42:13 to 20:42:49 UTC (2026-10-23 local date).

| Records | Joint accuracy, 95% trial CI | Timing only, 95% trial CI | Share only, 95% trial CI | Constant index control |
|---:|---:|---:|---:|---:|
| 128 | 0.3398 [0.3250, 0.3542] | 0.3233 [0.3118, 0.3335] | 0.3333 [0.3198, 0.3470] | 0.3333 |
| 1,024 | 0.3318 [0.3201, 0.3439] | 0.3292 [0.3168, 0.3408] | 0.3361 [0.3238, 0.3498] | 0.3333 |

All these protected accuracy intervals include balanced chance (1/3). This bounded classifier did not demonstrate target inference above chance from the specified local observations. The intervals and positive control describe this experimental setup; they do not establish a zero-leakage result.

Mean per-trial server 0 p95 durations, by requested index `[0, N/2, N-1]`, were `[1.645, 1.644, 1.648]` µs for N=128 and `[8.797, 8.811, 8.822]` µs for N=1,024. Individual trial distributions and p50/p95/p99 intervals are retained in the report; shared-host noise contributes visible tail variation. `pir-target-timing.png` plots these duration summaries alongside held-out inference accuracy.

Each target has 3,840 observed first-share samples per geometry, counting both profiling and target sessions for the descriptive marginal diagnostics. The mean one-bit frequencies averaged over all positions ranged from 0.49845 to 0.50113 for N=128 and 0.49976 to 0.50015 for N=1,024. Across every position/target the observed extremes were 0.47448–0.52734 and 0.46953–0.52891 respectively. These ranges contain many finite-sample comparisons; no full-distribution equivalence claim follows. The report retains all bit-position frequencies and the three requested positions separately.

## Exact marginal argument and limits

`QueryPair::generate` fills the first vector with fresh OS-random bytes, independently of the requested index. For a fixed requested index, the second vector is the first vector XOR a fixed unit vector. XOR with a fixed vector is a bijection, so under an ideal uniform first-vector model either **individual** server's query has the same uniform distribution for every target. The implementation uses OS cryptographic randomness; this experiment does not independently certify that randomness or prove cryptographic security.

This argument concerns the individual query share, not local machine timing, the whole network trace or colluding servers. The second share is excluded from this observer: obtaining both shares would identify the requested point by XOR. The timing experiment concerns the three stated targets, two small geometries, this mask-scan implementation and exported local observables. Finite held-out classifier accuracy near chance cannot prove uniform full-joint distributions or rule out other classifiers, larger target sets, long-range timing, microarchitectural channels or network observers. A measured accuracy above chance must be reported even if it contradicts the intended privacy outcome. The plaintext control checks the pipeline's ability to exploit its visible index; it does not certify universal attack strength.
