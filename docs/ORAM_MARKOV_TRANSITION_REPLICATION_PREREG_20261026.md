# Preregistered independent ORAM transition-attack replication

**Status:** attack, workload, split, and primary metric are specified before
collection. This is a fresh-seed independent collection from the earlier
Markov-locality study and its exploratory transition analysis.

## Question and workload

Can a one-step profile transition attacker predict whether the next logical
access is to hot address 0 in a locality-heavy workload, and does Path ORAM
reduce this inference versus plaintext and encrypt-only controls? The
machine-readable [configuration](../experiments/configs/oram-markov-transition-replication-20261026.json)
uses fresh seed `20261036`. There are eight addresses with base probabilities
0.35, 0.20, 0.15, 0.10, 0.08, 0.05, 0.04, and 0.03; each subsequent access
retains the previous address with probability 0.85 or refreshes from that
base distribution. The read probability is 0.70. Each of 30 trials contains
eight independent sessions with 8 warmup and 128 measured operations.
Address and operation schedules are paired across modes, while ORAM state and
cryptographic randomness are fresh for each session.

## Frozen attacker and split

Use the existing `MarkovTransitionAttack` without tuning. It maps the
immediately preceding visible bucket/leaf identifier to the next hot/cold
label using labeled profiling sessions with one prior pseudo-observation.
The first target operation uses the profile class prior. The target's current
identifier and all target labels are excluded from prediction. Four whole
sessions per trial are used for profile and four disjoint whole sessions for
scoring. The visible input is the fixed-size observer record containing bucket
identifier and handler-only time; this attack uses the preceding identifier
only. It is a simple lookup, not a reproduction of a published attack.

The transition lookup is the primary attack for this preregistration. The
separately preregistered temporal random-forest result produced by the
collector is auxiliary context and does not alter the transition attack,
features, split, or decision rule.

## Metric and positive controls

The sole primary metric is mean per-trial ROC AUC with a 5,000-resample
percentile bootstrap over 30 trial values. Evaluate plaintext and encrypt-only
controls first. Both must have mean AUC at least 0.80 and a lower 95% interval
bound above 0.50. If either fails, preserve outputs, mark this attack
inconclusive, and do not score ORAM as a defense result. If both pass, evaluate
Path ORAM once using the same frozen attack. Report class prevalence,
balanced and raw accuracy, and the profile-majority baseline alongside the
primary metric. An interval containing 0.50 is a bounded failure to resolve
this signal, not evidence of indistinguishability.

## Provenance and limits

Retain raw observer and private-driver traces, prediction files, paired
schedules, configuration, source/binary hashes, host snapshots, and trial
metrics. Timing is measured inside the local bucket-service handler and
excludes pipe wait, Path ORAM controller work, parsing, response encoding, and
trace writing. The runner is not CPU-pinned or isolated. This is a synthetic
local experiment, not remote-network timing, a TEE evaluation, or a security
proof. The same captured sessions support both the temporal primary collector
analysis and this preregistered secondary attack; the transition score is not
an independent data collection from that temporal result.

## Collection and analysis

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-markov-transition-replication-20261026.json \
  --output experiments/results/oram-markov-transition-replication-20261026 \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
.venv/bin/python -m research.analysis.oram_markov_transition_attack \
  --protocol-status preregistered-secondary \
  --raw experiments/results/oram-markov-transition-replication-20261026/raw \
  --config experiments/configs/oram-markov-transition-replication-20261026.json \
  --output experiments/results/oram-markov-transition-replication-20261026/transition-attack
```
