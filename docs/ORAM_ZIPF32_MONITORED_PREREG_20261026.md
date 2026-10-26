# Preregistered monitored Zipf-32 ORAM replication

**Status:** preregistered after the first Zipf-32 result, before this repeat's
collection. The follow-up was prompted by the first run's missing
collection-time load observation. It is a separate replication and will not be
pooled with the first run for its primary result.

## Frozen configuration

The machine-readable configuration is
[`oram-isolated-zipf32-monitored-replication-20261026.json`](../experiments/configs/oram-isolated-zipf32-monitored-replication-20261026.json).
It is byte-for-byte equivalent in workload and analysis settings to the first
[Zipf-32 configuration](../experiments/configs/oram-isolated-zipf32-replication-20261026.json),
except that its deterministic workload seed is 20261033 instead of 20261032.
It retains 32 addresses with `p(i) proportional to (i+1)^(-1.15)`, hot set
0–3, hot probability mass 0.5868, 256 measured operations per session, 16
warmup accesses, a 35% read probability, zero Markov persistence, 30 trials,
and eight sessions per trial.

The same fixed temporal classifier and four-session profile/four-session
target split will be used. The sole primary metric remains mean per-trial ROC
AUC with a 5,000-resample percentile bootstrap over 30 trial AUCs. Plaintext
and encrypt-only controls must each have mean AUC at least 0.80 and a lower
95% interval bound above 0.50 before ORAM is evaluated. A failed control makes
the defense result inconclusive. No classifier, feature, workload, threshold,
or metric will be changed after inspecting outcomes.

The corrected collector will save UTC snapshots immediately before and after
each mode. Each snapshot records platform, CPU model, logical CPU count, the
collector process's allowed CPU set, and 1/5/15-minute load averages where
available. The separate bucket-service process records its own effective CPU
mask per session. These boundary samples are context for each mode, not a
continuous record of host contention during every operation.

## Rationale and scope

This is a fresh-seed repeat of the same workload because the first run's host
report omitted the CPU description and did not capture instantaneous load.
It checks whether the first near-chance estimate is reproducible with better
host-context logging. The first result remains published separately with its
deviation. A second near-chance result would still not prove
indistinguishability. Neither run evaluates remote networking, a hardware
TEE, other classifier families, or production workloads.

## Collection command

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-zipf32-monitored-replication-20261026.json \
  --output experiments/results/oram-isolated-zipf32-monitored-replication-20261026 \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```
