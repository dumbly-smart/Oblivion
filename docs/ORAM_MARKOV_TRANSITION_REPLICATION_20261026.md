# Independent Markov transition-attack replication

This fresh-seed study followed the
[preregistration](ORAM_MARKOV_TRANSITION_REPLICATION_PREREG_20261026.md)
and [configuration](../experiments/configs/oram-markov-transition-replication-20261026.json).
It reuses the already implemented one-step `MarkovTransitionAttack` on a new
collection, while separately retaining the collector's temporal random-forest
analysis. The [collector report](../experiments/results/oram-markov-transition-replication-20261026/report.json),
[transition attack report](../experiments/results/oram-markov-transition-replication-20261026/transition-attack/report.json),
[raw traces and prediction archive](../experiments/results/oram-markov-transition-replication-20261026/trace-data.tar.gz),
[host observations](../experiments/results/oram-markov-transition-replication-20261026/host-observation.json),
[process metadata](../experiments/results/oram-markov-transition-replication-20261026/process-metadata.json),
[raw hash manifest](../experiments/results/oram-markov-transition-replication-20261026/raw-session-sha256.json),
[verification record](../experiments/results/oram-markov-transition-replication-20261026/verification.json),
[artifact hashes](../experiments/results/oram-markov-transition-replication-20261026/artifact-sha256.json),
and both [temporal](../experiments/results/oram-markov-transition-replication-20261026/auc.png)
and [transition](../experiments/results/oram-markov-transition-replication-20261026/transition-attack/attack-auc.png)
figures are retained.

## Workload and attack

The fresh seed was 20261036. The workload had eight logical addresses with
base probabilities 0.35, 0.20, 0.15, 0.10, 0.08, 0.05, 0.04, and 0.03;
address 0 was hot. Each subsequent operation retained the previous address
with probability 0.85, otherwise refreshing from the base distribution.
There were 30 trials, eight fresh sessions per trial, eight warmups and 128
measured operations per session, and a 70% read rate. The same seeded address
and read/write schedule was replayed across all modes.

The predeclared attack uses only the immediately preceding visible bucket or
leaf identifier. Labeled complete sessions estimate the next hot/cold label
for each previous tag, with one prior pseudo-observation; the first access
uses the profile class prior. Four sessions profile the lookup and four
independent sessions are scored per trial. The sole primary metric is mean
per-trial ROC AUC with a 5,000-resample bootstrap over 30 trial scores.

## Transition attack results

| Mode | Mean AUC (95% trial-bootstrap interval) | Balanced accuracy | Raw accuracy | Profile-majority accuracy |
| --- | ---: | ---: | ---: | ---: |
| Plaintext | 0.9198 [0.9144, 0.9253] | 0.9173 | 0.9244 | 0.6188 |
| Encrypt-only | 0.9198 [0.9144, 0.9253] | 0.9173 | 0.9244 | 0.6188 |
| Path ORAM | 0.5013 [0.4916, 0.5106] | 0.4990 | 0.5962 | 0.6188 |

Both positive controls passed before the transition attack evaluated ORAM.
The ORAM AUC interval includes 0.50. Raw ORAM accuracy is below the profile-
majority baseline. This attack did not resolve hot-address inference on this
workload; it does not prove indistinguishability or exclude other attacks.

As auxiliary context, the collector's separately specified temporal random
forest scored ORAM AUC 0.5062 [0.4780, 0.5348], with both direct-address
controls at approximately 1.000. This was not the transition attack's primary
metric and does not change its decision rule.

## Provenance and interpretation

This is a fresh collection independent of the earlier Markov study. The
transition lookup was specified before this collection, but it shares the
captured sessions with the temporal classifier and is therefore a
preregistered secondary analysis of the same collection, not an independent
collection from that primary analysis. The attack is a simple lookup, not a
published-attack reproduction.

The post-collection audit verified all 1,440 raw hashes, 240 paired trial and
session schedules, source/config/binary fingerprints, and all 90 transition
prediction files by recomputing their metrics from saved predictions and
private target labels. The classifier fitting itself was not independently
reimplemented. The archive SHA-256 is
`6a76326985e85ef6ec6fe6de5770849d03d578bba0ab74ff8fa7079595c3a202`.

Timing is measured inside the local isolated bucket-service handler; it
excludes pipe wait, Path ORAM controller work, parsing, response encoding,
and trace writing. The host is shared and unpinned. This is not remote timing,
a TEE evaluation, or a security proof.
