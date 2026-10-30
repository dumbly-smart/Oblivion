# Independent ORAM leaf/timing replication: Markov workload B

This is the independent workload replication frozen in
[the preregistration](ORAM_SIGNAL_REPLICATION_20261026_B_PREREG.md) and
[machine-readable configuration](../experiments/configs/oram-isolated-signal-replication-20261026-b.json).
It reuses the fixed attack implementation; it is not an independent
reimplementation of the classifier.

## Results

The primary metric was mean per-access ROC AUC over 30 fitted trials. Intervals
are 95% percentile bootstraps over trial AUCs with 5,000 resamples. Both
positive controls exceeded their preregistered mean-AUC threshold of 0.80 and
had lower intervals above 0.50, so Path ORAM was evaluated.

| Mode | Mean AUC (95% trial-bootstrap interval) | Mean balanced accuracy (95% interval) | Profile-majority accuracy |
|---|---:|---:|---:|
| Plaintext | 1.0000 [1.0000, 1.0000] | 0.9999 [0.9998, 1.0000] | 0.5368 |
| Encrypt-only | 1.0000 [1.0000, 1.0000] | 0.9998 [0.9994, 1.0000] | 0.5368 |
| Path ORAM | 0.5021 [0.4803, 0.5242] | 0.4999 [0.4850, 0.5159] | 0.5368 |

The Path ORAM AUC interval contains 0.50. This study did not distinguish the
two hot addresses from the six cold addresses with this attacker on this
workload. It does not prove privacy or rule out other features, attacks,
workloads, or host observations.

## Workload and observer

The fresh workload used eight addresses with configured refresh weights
`[0.25, 0.18, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05]`, two hot addresses
`{0, 1}`, 80% probability of retaining the prior address, and 60% read
probability. Across the 30,720 measured operations, observed adjacent address
retention was 82.39%, hot-address frequency was 43.36%, and reads were 60.04%.
The seed was `20261027`. Workload schedules were identical across plaintext,
encrypt-only and ORAM; each trial used four complete profiling sessions and
four disjoint target sessions.

The attacker saw bucket/leaf identifiers, aggregate fixed-shape bytes per
access, isolated bucket-handler time, and the preregistered short temporal
features. The observer-side timer includes the in-memory bucket handler after
request decoding and before response encoding. It excludes ORAM controller
work, pipe waiting, decoding, encoding and trace output. Private workload labels
were kept separate. This is a local process-isolation measurement, not a
remote-network or TEE study.

## Reproducibility and limits

The preregistration and configuration were pushed in commit `33572f40` before
collection. The report pins the analysis, attack, configuration and release
binary hashes. Post-run verification recomputed all five source/binary hashes,
all 1,440 raw compressed trace hashes, and all 240 paired trial/session
schedules. The 1,440 raw traces and 90 prediction files are retained in
[`trace-data.tar.gz`](../experiments/results/oram-isolated-replication-20261026-b/trace-data.tar.gz),
which preserves their `raw/` and `predictions/` paths. The audit and archive
hash are in `verification.json`; report, plot and host observation are in the
[result directory](../experiments/results/oram-isolated-replication-20261026-b/).
All nine isolated-timing harness tests passed before collection.

Inspect the stored sessions by extracting into a fresh directory:

```sh
mkdir -p /tmp/oram-isolated-replication-20261026-b
tar -xzf experiments/results/oram-isolated-replication-20261026-b/trace-data.tar.gz \
  -C /tmp/oram-isolated-replication-20261026-b
```

The service used a separate child process for each session. No repository test
or benchmark was active during collection, but the shared host was not idle:
load averages were 3.78/4.68/6.00 before and 7.71/6.30/6.46 after collection
on a 24-logical-CPU Intel Core i7-14650HX machine. CPU affinity was not pinned.
Host scheduling noise could reduce power to detect small timing effects, so
the result remains workload-specific and process-isolated rather than
quiet-host evidence.

Reproduce with:

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-signal-replication-20261026-b.json \
  --output /tmp/oram-isolated-replication-20261026-b-reproduced \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```
