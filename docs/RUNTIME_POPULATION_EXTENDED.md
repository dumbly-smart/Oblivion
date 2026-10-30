# Extended full-path open-loop load

This follow-up raises the per-process offer count beyond the retained
[64-offer study](RUNTIME_POPULATION.md). The preregistered configuration is
[`runtime-population-extended-20261024.json`](../experiments/configs/runtime-population-extended-20261024.json).
Its primary metric is the fraction of **offered** requests that miss the
250 ms SLO or are dropped. Each of 30 trials per profile is a fresh executor
process. Profile order is shuffled from the declared seed.

The benchmark uses the actual local path: bounded admission, authenticated
invocation envelopes, two PIR server requests, stateful Wasmtime execution,
and 16 actual ORAM reads plus 16 actual ORAM writes per admitted invocation.
The client oracle validates successful outputs and state; the analyzer checks
the expected 128 storage events per completed offer. Both profiles ran all
30 trials successfully. Source-tree and copied executable fingerprints
matched before and after measurement. Reanalysis from the compressed raw
trial archive reproduced `analysis.json` byte for byte.

## Results

Intervals are 95% percentile bootstrap intervals over 5,000 resamples of 30
whole-process trial statistics. Latency quantiles are computed per process
before summarizing across trials. Offered-load SLO failure counts both drops
and admitted requests exceeding 250 ms; admitted latency excludes dropped
offers.

| Profile | Offers per trial (total) | Admitted / dropped per trial | Drop fraction | Offered SLO failures | Completions/s | Admitted p95 / p99 ms | Executor CPU s | Sampled peak RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 128 offers, 150 ms interval, queue 2 | 128 (3,840) | 128 / 0 | 0% [0%, 0%] | 0% [0%, 0%] | 6.684 [6.684, 6.684] | 101.381 [101.185, 101.590] / 103.456 [103.089, 103.863] | 1.249 [1.209, 1.290] | 25.642 [25.573, 25.714] |
| 256 offers, 25 ms interval, queue 2 | 256 (7,680) | 66 / 190 | 74.22% [74.22%, 74.22%] | 99.22% [99.22%, 99.22%] | 9.913 [9.910, 9.916] | 300.601 [300.425, 300.754] / 302.050 [301.786, 302.345] | 0.478 [0.461, 0.495] | 25.638 [25.566, 25.715] |

The steady profile admitted every offer at 6.68 offers/s. At 40 offered
offers/s the process completed about 9.91/s, dropped 74.22% of offers, and
99.22% of offers either dropped or missed the SLO. This demonstrates
overload behavior for these two local schedules; it is not a general server
capacity estimate. The degenerate bootstrap intervals for admission and SLO
rates reflect identical outcomes in all 30 processes, not uncertainty over
other workloads, hosts, or schedules.

## Limits

All clients and services run on one shared host with a single open-loop
producer per process. WASM is precompiled before readiness, so these trials
do not measure compilation cold starts. CPU is sampled from process ticks,
and periodic RSS sampling may miss short peaks or double-count shared pages.
No network transport, multi-host contention, provider billing, autoscaler,
or real multi-user population was measured. The SLO denominator includes
dropped offers by design.

## Reproduction

The artifact manifest covers the raw archive, config, launch records,
provenance, analysis, and plot. To regenerate the analysis from the retained
raw data:

```sh
mkdir -p /tmp/oblivion-runtime-extended
tar -xzf experiments/results/runtime-population-extended-20261024/raw-trials.tar.gz \
  -C /tmp/oblivion-runtime-extended
.venv/bin/python -m research.analysis.open_loop \
  --runtime /tmp/oblivion-runtime-extended
```

To collect fresh processes, use a new output directory:

```sh
.venv/bin/python scripts/benchmark_open_loop.py \
  experiments/configs/runtime-population-extended-20261024.json \
  --mode runtime \
  --runtime-output experiments/results/runtime-population-extended-new \
  --batch-output /tmp/oblivion-runtime-no-batch
```

See the [retained summary, figure, provenance, and raw archive](../experiments/results/runtime-population-extended-20261024/).
