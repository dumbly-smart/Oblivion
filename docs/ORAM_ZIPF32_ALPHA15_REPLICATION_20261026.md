# Higher-skew Zipf-32 ORAM timing replication

This fresh-seed study followed its
[preregistration](ORAM_ZIPF32_ALPHA15_REPLICATION_PREREG_20261026.md) and
[machine-readable configuration](../experiments/configs/oram-isolated-zipf32-alpha15-replication-20261026.json).
Retained artifacts include the [collector report](../experiments/results/oram-isolated-zipf32-alpha15-replication-20261026/report.json),
[raw trace and prediction archive](../experiments/results/oram-isolated-zipf32-alpha15-replication-20261026/trace-data.tar.gz),
[host observations](../experiments/results/oram-isolated-zipf32-alpha15-replication-20261026/host-observation.json),
[process metadata](../experiments/results/oram-isolated-zipf32-alpha15-replication-20261026/process-metadata.json),
[raw SHA-256 manifest](../experiments/results/oram-isolated-zipf32-alpha15-replication-20261026/raw-session-sha256.json),
[verification record](../experiments/results/oram-isolated-zipf32-alpha15-replication-20261026/verification.json),
[artifact hashes](../experiments/results/oram-isolated-zipf32-alpha15-replication-20261026/artifact-sha256.json),
and [AUC figure](../experiments/results/oram-isolated-zipf32-alpha15-replication-20261026/auc.png).

## Workload and primary metric

The study used seed 20261035 and 32 addresses with probability proportional
to `(i+1)^(-1.5)`. The top four addresses have 0.7389 probability mass;
Shannon entropy is about 3.10 bits. Each of 30 trials had eight fresh sessions,
with 16 warmup and 256 measured operations per session and a 35% read rate.
A fixed temporal random forest trained on four labeled whole sessions and
predicted four disjoint sessions. The sole primary metric was mean per-trial
ROC AUC with a 5,000-resample bootstrap over trial values. Timing came from
the local isolated bucket-service handler.

## Results

| Mode | Mean per-trial AUC (95% trial-bootstrap interval) | Balanced accuracy | Profile-majority accuracy |
| --- | ---: | ---: | ---: |
| Plaintext | 1.0000 [1.0000, 1.0000] | 0.9989 | 0.7380 |
| Encrypt-only | 1.0000 [1.0000, 1.0000] | 0.9987 | 0.7380 |
| Path ORAM | 0.4997 [0.4913, 0.5073] | 0.4997 | 0.7380 |

Both preregistered positive controls passed. The ORAM interval includes 0.50,
and raw accuracy is below the profile-majority baseline for this imbalanced
label distribution. Under this fixed attack, no hot-versus-cold signal was
resolved. This result does not prove indistinguishability, exclude other
attackers or establish cryptographic security.

## Host and integrity observations

The collector reported Intel Core i7-14650HX, 24 allowed logical CPUs, and
load averages sampled at each mode boundary. Around ORAM they were
0.92/1.01/0.66 before and 1.30/1.09/0.69 after. No CPU pinning or host
isolation was used; these samples are not per-access load measurements.

An independent post-collection check verified all 1,440 raw file hashes,
240 paired trial/session schedules, 90 saved predictions and all 90 prediction
metrics recomputed from their target labels. The classifier fitting itself
was not independently reimplemented. Source, configuration, and executable
fingerprints are retained in the report. The raw-and-prediction archive
SHA-256 is `b7d21857c6021744b8c7e7417ec47e74248c92b572f8172cc3b4571c5f680cd5`.

## Reproduction and limits

The preregistration contains the exact build and collection command. Repeated
runs reproduce seeded workloads, not operating-system cryptographic
randomness or exact timing. This is synthetic local handler timing, not remote
network timing or TEE evaluation. It excludes pipe wait, request parsing,
response encoding, and Path ORAM controller work. The result applies only to
the configured workload, observer, and attack.
