# Preregistered isolated two-address ORAM leaf/timing replication

**Status:** frozen before collection. Planned output:
`experiments/results/oram-isolated-two-address-replication-20261026/`.

## Question

Does the possible leaf-plus-timing signal in the historical two-address
experiment reproduce when a fixed temporal attacker observes only bucket
identifiers, fixed-shape bytes, and bucket-handler time measured inside a
separate service process, using fresh workload streams and fresh ORAM states?

This directly repeats the historical 75/25 logical-address distribution
(`docs/ORAM_LEAF_TIMING.md`) with the new isolated-service measurement boundary.
It reuses the existing temporal classifier; it is not an independent
implementation of the attack. It is one synthetic local replication, not a
remote timing study or a cryptographic security test.

## Frozen design

The machine-readable configuration is
[`oram-isolated-two-address-replication-20261026.json`](../experiments/configs/oram-isolated-two-address-replication-20261026.json).
It fixes 30 trials, eight independently initialized sessions per trial, four
whole profiling sessions and four disjoint whole target sessions, 128 measured
operations per session, eight warm-up accesses, a 16-block Path ORAM, 64-byte
blocks and bucket capacity four. Each measured workload independently samples
addresses 0 and 1 with probabilities 0.75 and 0.25; address 0 is the positive
class. Reads occur with probability 0.5, with no Markov persistence. The
deterministic seed is 20261041, distinct from the earlier preregistered runs.
Each trial/session has a unique deterministic workload stream, paired exactly
across plaintext, encrypt-only and Path ORAM. ORAM leaves, keys and nonces use
OS cryptographic randomness.

The fixed temporal random forest receives visible bucket identifiers, total
bytes per logical access, bucket-handler-only service time and the existing
short-window temporal features. It receives no logical-address or read/write
labels while fitting or predicting. The first four sessions are labeled
profiling data; the remaining four sessions are unlabeled at prediction time
and held out whole. Target labels are used only to score predictions.

## Primary metric and stopping rule

The sole primary metric is mean per-access ROC AUC over 30 fitted trials. Its
95% interval is the percentile bootstrap over the 30 per-trial AUCs with 5,000
resamples. Chance is AUC 0.5. Balanced accuracy, raw accuracy, the
profile-majority predictor and per-trial values are secondary descriptive
metrics. Plaintext and encrypt-only controls are evaluated first; each must
have mean AUC at least 0.80 and a bootstrap lower bound above 0.50. If either
control fails, do not interpret the ORAM result. An ORAM interval excluding
0.50 is a signal for this attacker/workload only. An interval containing 0.50
is inconclusive and is not evidence of security.

No workload, metric, classifier, feature, seed, CPU assignment or threshold
will be changed after inspecting a mode result. Any failed or interrupted run
will be retained and described without replacing it under this output path.

## Timing isolation and environment

Every mode uses the existing separate local bucket-service process.
`service_ns` starts after fixed-length request decoding and ends before
fixed-length response encoding. It includes the in-memory bucket handler and
excludes controller work, pipe waiting, parsing, response encoding and trace
file output. The service process is pinned to logical CPU 0; the experiment
driver is pinned to logical CPU 2 using `taskset`. The host reports CPUs 0 and
1 as SMT siblings on physical core 0, and CPU 2 as a different core. These
affinity masks prevent the driver from consuming CPU 0 directly, but do not
reserve the service core or exclude interrupts, kernel work, unrelated host
processes, SMT/frequency/thermal effects or scheduler noise. Host snapshots at
run and mode boundaries and the service child’s effective affinity are
retained. This is process/CPU affinity isolation on one shared host, not a TEE
or remote-network timing measurement.

Before collection, the isolated harness tests must pass and both release
examples must build. No local tests or other repository benchmark will run
concurrently with collection. Retain configuration, raw observer/private
traces, source/binary/configuration hashes, predictions, host observations,
paired-schedule checks and analysis output. If positive controls or integrity
checks fail, record the failure without changing the design.

## Collection command

```sh
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
cargo build --locked --release -p oblivion-store --example oram-measure
cargo build --locked --release -p oblivion-store --example oram-control
taskset -c 2 .venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-two-address-replication-20261026.json \
  --output experiments/results/oram-isolated-two-address-replication-20261026
```
