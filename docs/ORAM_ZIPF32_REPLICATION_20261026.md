# 32-address Zipf ORAM timing replication

This experiment followed the frozen [preregistration](ORAM_ZIPF32_REPLICATION_PREREG_20261026.md) and [configuration](../experiments/configs/oram-isolated-zipf32-replication-20261026.json). The result directory contains the raw and prediction [archive](../experiments/results/oram-isolated-zipf32-replication-20261026/trace-data.tar.gz), [report](../experiments/results/oram-isolated-zipf32-replication-20261026/report.json), [AUC figure](../experiments/results/oram-isolated-zipf32-replication-20261026/auc.png), [process metadata](../experiments/results/oram-isolated-zipf32-replication-20261026/process-metadata.json), [verification record](../experiments/results/oram-isolated-zipf32-replication-20261026/verification.json), [host observation](../experiments/results/oram-isolated-zipf32-replication-20261026/host-observation.json), and [artifact hashes](../experiments/results/oram-isolated-zipf32-replication-20261026/artifact-sha256.json).

## Frozen workload and attacker

Each of 30 trials used eight independent sessions with 256 operations/session and 16 independent warmup operations. The 32-address distribution was `p(i) proportional to (i+1)^(-1.15)`; addresses 0–3 were hot, with configured mass 0.5868. Read probability was 0.35 and access persistence was zero. Four complete sessions trained the fixed temporal random forest; four disjoint sessions were scored. The model used visible bucket IDs and fixed-size observer messages, handler-only service timing, within-session tag frequency, recent tag/timing history, and short-window summaries. Private logical addresses and write labels were excluded from model inputs.

The same deterministic logical schedule was used in plaintext, encrypt-only, and Path ORAM modes. Each service child was a separate process. The bucket handler interval excluded pipe waiting, request parsing, response encoding, and Path ORAM controller work. All service children had effective CPU mask `0-23`; no CPU pinning or host isolation was used.

## Results

The primary metric was mean per-trial ROC AUC, with a percentile bootstrap interval over 30 complete trials.

| Mode | Mean per-trial AUC (95% trial-bootstrap interval) | Balanced accuracy | Profile-majority accuracy |
| --- | ---: | ---: | ---: |
| Plaintext | 1.0000 [1.0000, 1.0000] | 0.9995 | 0.5880 |
| Encrypt-only | 1.0000 [1.0000, 1.0000] | 0.9992 | 0.5880 |
| Path ORAM | 0.5003 [0.4929, 0.5073] | 0.5028 | 0.5880 |

Both controls met the preregistered gate: mean AUC at least 0.80 and lower interval bound above 0.50. Therefore ORAM was evaluated. Its primary interval includes 0.50, and its raw accuracy is below the profile-majority baseline. For this fixed classifier and synthetic workload, the run did not resolve hot-versus-cold inference from the declared feature set. This is not a proof of indistinguishability and says nothing about other workload families, attackers, scheduler-visible signals, remote timing, or TEE side channels.

## Integrity and execution caveat

An independent audit verified all 1,440 per-file SHA-256 values, all 240 paired trial/session schedules, the eight-session train/test split, 256 operations per session, and the source, configuration, and binary hashes. It recomputed every saved AUC, accuracy, and balanced-accuracy value from the retained predictions and private target labels. It did not independently reimplement classifier fitting. The archive contains 1,440 compressed raw observer/private files and 90 prediction files; the archive SHA-256 is `bb4a81c14c70c7f6648324d8c1c5c212bc006b01890b51ccccc7a09a2c597c85`. The process-metadata array was emitted in outer-trial order; the companion file adds outer-trial/session indices from that preserved order.

The experiment report's CPU description is empty, and the collector did not record instantaneous host load during collection. The retained host snapshot was taken after the run and cannot characterize collection-time contention. This is a deviation from the preregistered host-observation plan and limits interpretation of timing noise and statistical power. The measured child CPU mask and Linux platform are retained, but this must not be described as a quiet-host result.

## Reproduction

The capture command, using fresh runtime randomness and a new output directory, is listed in the [preregistration](ORAM_ZIPF32_REPLICATION_PREREG_20261026.md). Workload addresses and operation types are seeded; cryptographic randomness and exact service timing are intentionally not reproducible. To verify the retained archive, extract `trace-data.tar.gz` in the result directory and compare every raw path against `report.json`'s `raw_session_sha256` map. The detailed checks and verified source hashes are retained in `verification.json`.
