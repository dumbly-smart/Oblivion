# Monitored Zipf-32 ORAM timing replication

This independent fresh-seed run followed its
[preregistration](ORAM_ZIPF32_MONITORED_PREREG_20261026.md) and
[configuration](../experiments/configs/oram-isolated-zipf32-monitored-replication-20261026.json).
The result includes the corrected
[report](../experiments/results/oram-isolated-zipf32-monitored-replication-20261026/report.json),
[original collector report](../experiments/results/oram-isolated-zipf32-monitored-replication-20261026/report-initial-collector.json),
[raw session hashes](../experiments/results/oram-isolated-zipf32-monitored-replication-20261026/raw-session-sha256.json),
[archive](../experiments/results/oram-isolated-zipf32-monitored-replication-20261026/trace-data.tar.gz),
[AUC figure](../experiments/results/oram-isolated-zipf32-monitored-replication-20261026/auc.png),
[host observations](../experiments/results/oram-isolated-zipf32-monitored-replication-20261026/host-observation.json),
[process metadata](../experiments/results/oram-isolated-zipf32-monitored-replication-20261026/process-metadata.json),
[verification record](../experiments/results/oram-isolated-zipf32-monitored-replication-20261026/verification.json),
and [artifact hashes](../experiments/results/oram-isolated-zipf32-monitored-replication-20261026/artifact-sha256.json).

## Workload and primary metric

The workload and analysis settings match the first Zipf-32 experiment; only
the deterministic seed changed from 20261032 to 20261033. Each of 30 trials
had eight sessions of 256 operations, 16 warmups, a 32-address
`p(i) proportional to (i+1)^(-1.15)` distribution, addresses 0–3 hot, and a
35% read probability. Four whole sessions trained the fixed temporal random
forest and four disjoint sessions were scored. The sole primary metric was
mean per-trial ROC AUC with a 5,000-resample trial bootstrap. Plaintext and
encrypt-only controls were evaluated before Path ORAM.

## Results

| Mode | Mean per-trial AUC (95% trial-bootstrap interval) | Balanced accuracy | Profile-majority accuracy |
| --- | ---: | ---: | ---: |
| Plaintext | 1.0000 [1.0000, 1.0000] | 0.9999 | 0.5850 |
| Encrypt-only | 1.0000 [1.0000, 1.0000] | 0.9999 | 0.5850 |
| Path ORAM | 0.5052 [0.4995, 0.5109] | 0.5044 | 0.5850 |

Both controls passed the frozen gate (mean AUC at least 0.80; lower interval
bound above 0.50). The ORAM interval includes 0.50. Its mean is slightly above
chance, but this result does not resolve hot-versus-cold inference under the
predeclared attack. It does not prove indistinguishability or rule out other
signals.

The first Zipf-32 result was 0.5003 [0.4929, 0.5073]. These two runs are
reported separately: this follow-up was initiated after the first run exposed
a missing collection-time host record, and no pooled effect estimate was
preregistered.

## Host observations and integrity

The corrected collector recorded platform, Intel Core i7-14650HX model,
logical CPU count, allowed CPU set, and load average immediately before and
after each mode. The process-level allowed CPU mask was `0-23`; there was no
pinning or host isolation. Load averages varied from 4.31/4.14/3.61 before
plaintext to 3.33/3.92/3.55 after ORAM. These are mode-boundary samples, not
continuous per-operation measurements.

The collector initially wrote 960 raw hashes because it computed the manifest
before ORAM capture. The original report is retained unchanged as
`report-initial-collector.json`. The corrected `report.json` and separate raw
hash manifest add SHA-256 values for all 1,440 raw observer/private files; no
trace, prediction, or model result was changed. The post-collection correction
is recorded in the report. All 240 paired trial/session schedules, all 90
prediction files, the 720 session-child process records, and every saved
prediction metric were independently checked. The stored prediction metrics
were recomputed from the target labels; classifier fitting was not
independently reimplemented. The archive SHA-256 is
`0192c071339874a7c2126cf3ec8d29843e96a3f6d7cdad46c7277fb105a46bcd`.

## Reproduction and limits

The collection command is in the
[preregistration](ORAM_ZIPF32_MONITORED_PREREG_20261026.md). Repeated runs
reproduce the logical address and operation schedules, not OS cryptographic
randomness or exact timing. The timing interval is local bucket-handler time;
it excludes pipe waiting, request parsing, response encoding, and Path ORAM
controller work. This is not remote network timing, TEE evaluation, or a
security proof.
