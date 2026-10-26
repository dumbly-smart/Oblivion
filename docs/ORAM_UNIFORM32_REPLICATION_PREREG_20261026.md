# Preregistered uniform-32 ORAM timing replication

**Status:** preregistered before collection. The machine-readable
[configuration](../experiments/configs/oram-isolated-uniform32-replication-20261026.json)
uses a fresh deterministic workload seed, 20261034.

## Question

Does the fixed temporal leaf/timing classifier infer membership in a
publicly-profiled half of the logical address space when addresses are
accessed uniformly, and does Path ORAM reduce inference compared with
plaintext and encrypt-only controls? This checks whether results from the
Zipf-skewed workload depend on address popularity. It is a bounded synthetic
study, not a general security claim.

## Workload and observer

Each of 30 trials has eight independent sessions of 256 measured accesses
over 32 logical blocks, with 16 independent warmups per session. Every logical
address has probability 1/32. Addresses 0–15 form the hot label and 16–31 the
cold label, giving exactly 0.5 configured mass to each group. Read probability
is 0.35; accesses are independent (`address_persistence = 0`). The same
seeded address and read/write schedules are run in all three modes. The
bucket-service handler time is recorded by the isolated local service
process; the service is not CPU-pinned.

Use the existing `TemporalLeafTimingAttack` without tuning. Each trial trains
on four complete sessions and scores on four disjoint complete sessions. The
observer features are the same visible bucket identifiers, fixed bytes,
handler-only service times, tag-frequency history, recent tags/timings, and
short-window summaries used in prior preregistered runs. Private labels are
excluded from fitting and prediction.

## Primary metric and decision rule

The sole primary metric is mean per-trial ROC AUC over 30 trials, with a
5,000-resample percentile bootstrap over the 30 trial values. Plaintext and
encrypt-only controls are run first; each must reach mean AUC at least 0.80
and a lower 95% interval bound above 0.50. If either fails, the ORAM result is
inconclusive and is not evaluated as a defense. Otherwise, score Path ORAM
once with the same fixed classifier. No post-result tuning, feature changes,
or workload changes are allowed.

The collector records start/end run metadata and before/after snapshots for
each mode, including platform, CPU model/count, effective CPU set, and load
averages when supported. These are coarse mode-boundary observations; they do
not quantify load at every access. Retain all raw files, predictions, hashes,
process metadata, and the report. An interval containing 0.50 is a bounded
failure to resolve this particular signal, not a proof of
indistinguishability.

## Collection command

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-uniform32-replication-20261026.json \
  --output experiments/results/oram-isolated-uniform32-replication-20261026 \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```
