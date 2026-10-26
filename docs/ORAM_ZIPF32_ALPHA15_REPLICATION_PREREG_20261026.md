# Preregistered higher-skew 32-address ORAM timing replication

**Status:** protocol and configuration committed before data collection.
The machine-readable [configuration](../experiments/configs/oram-isolated-zipf32-alpha15-replication-20261026.json)
uses fresh deterministic workload seed `20261035`.

## Question and scope

Does the fixed temporal leaf/timing classifier infer membership in the four
most popular logical addresses when the public workload follows a steeper
32-address Zipf distribution, and does Path ORAM reduce that inference versus
plaintext and encrypt-only controls? The probability of address `i` is
proportional to `(i+1)^(-1.5)`. Addresses 0–3 have configured probability mass
about 0.7389; workload entropy is about 3.10 bits. This condition deliberately
increases concentration relative to the earlier Zipf-32 workload. It is one
synthetic local workload and cannot establish general privacy.

## Workload and observer

Each of 30 trials has eight independent sessions, each with 16 independent
warmup and 256 measured operations over 32 logical blocks. Address draws are
independent, reads occur with probability 0.35, and the same seeded address
and read/write schedules are replayed across plaintext, encrypt-only, and
Path ORAM. The service is the separate local bucket handler. It records
visible bucket identifiers, fixed message sizes, and handler-only timing;
pipe wait, request parsing, response encoding, and Path ORAM controller work
are excluded. No service CPU affinity is requested.

Use the existing frozen `TemporalLeafTimingAttack`. Each trial trains on four
whole, labeled profiling sessions and predicts on four disjoint, unlabeled
target sessions. No feature or model tuning is permitted after collection.

## Primary metric and controls

The sole primary metric is mean per-trial ROC AUC over 30 trials, with a
5,000-resample percentile bootstrap over those trial values. Plaintext and
encrypt-only controls run first; both must reach mean AUC at least 0.80 and a
lower 95% interval bound above 0.50. If either control fails, the defense
result is inconclusive and must not be evaluated as a success. If controls
pass, evaluate Path ORAM once using the same frozen classifier and features.
The interval containing 0.50 is a bounded failure to resolve this signal,
not proof of indistinguishability.

Record source/config/binary fingerprints, all raw traces, predictions,
paired schedules, process metadata, and host snapshots immediately before
and after every mode. Report host load only as coarse snapshots, not as
per-access measurements. Repeated runs reproduce the seeded workload, not OS
cryptographic randomness or exact timing.

## Collection command

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-zipf32-alpha15-replication-20261026.json \
  --output experiments/results/oram-isolated-zipf32-alpha15-replication-20261026 \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```
