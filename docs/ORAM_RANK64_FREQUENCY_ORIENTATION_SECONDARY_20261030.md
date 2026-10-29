# Rank-64 ORAM frequency-only secondary analysis

**Status:** completed as a post-hoc secondary analysis. This reuses the exact
sessions from the rank-64 temporal leaf/timing study after that study's result
was known. It is not an independent replication, new sample, or cryptographic
security result.

## Question and boundary

This analysis asked whether a tag-frequency-only classifier can identify hot
versus cold logical addresses from the visible tag stream. It uses the same
30-trial rank-64 Zipf/Markov workload as the primary study: 64 addresses, hot
set 0–7, 512 measured operations per session, eight sessions per trial, and
four labeled profile sessions disjoint from four target sessions. The original
paired address/read-write schedules and all raw sessions were reused without
recollection or exclusion.

The scoring rule receives visible tag identities and labeled profile-session
counts. It does not use timing, byte counts, operation identity, private
logical addresses, or target labels. Score direction is selected by
leave-one-profile-session-out validation on the four labeled profile sessions;
the scorer is then fitted on those four sessions and applied to the four
targets. Private target labels are read only after predictions are produced,
for evaluation.

The plan was committed before this secondary analysis in
[`ORAM_RANK64_FREQUENCY_ORIENTATION_SECONDARY_PLAN_20261030.md`](ORAM_RANK64_FREQUENCY_ORIENTATION_SECONDARY_PLAN_20261030.md).
It pins the runner, attack/orientation source, raw study report, and workload
configuration. The run used source revision `80678c6d` and the original
configuration
[`oram-isolated-rank64-markov-replication-20261030.json`](../experiments/configs/oram-isolated-rank64-markov-replication-20261030.json).

## Results

| Mode | Mean target AUC | 95% trial-bootstrap interval | Fixed-direction AUC | Balanced accuracy | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: |
| Plaintext | 1.000000 | [1.000000, 1.000000] | 1.000000 | 1.000000 | 1.000000 |
| Encrypt-only | 1.000000 | [1.000000, 1.000000] | 1.000000 | 1.000000 | 1.000000 |
| Path ORAM | 0.496447 | [0.491316, 0.501515] | 0.503477 | 0.497667 | 0.498112 |

Both leaky controls exceeded the frozen gate (mean AUC at least 0.80 and
95% interval lower bound above 0.50), so the ORAM arm was evaluated. The
profile-only orientation was reversed in 14 of 30 ORAM trials. ORAM's
fixed-direction AUC was 0.503477 [0.498123, 0.508641], and its balanced
accuracy was 0.497667 [0.493352, 0.502003].

The mean target hot-class prevalence was 0.491357. Across trials, the mean
evaluation-only target-majority accuracy reference was 0.516227; a constant
profile-majority prediction achieved 0.502913 mean accuracy. These baselines
show why raw accuracy alone is not a useful privacy conclusion here. The AUC
interval includes 0.50, so the analysis is inconclusive for this scorer,
workload, split, and observer. The successful controls establish that this
scorer detects the deliberately leaky controls; they do not establish that it
is an optimal attacker.

The 95% percentile intervals resample the 30 independent trial-level AUCs
5,000 times with seed `20261231`. No feature changes, target-label orientation,
trial exclusions, or post-result tuning were performed. Do not pool these
numbers with the primary temporal random-forest AUC: this analysis reuses the
same sessions and is a different post-hoc scorer, not independent sample
evidence.

## Evidence and verification

The secondary output directory is
[`oram-rank64-frequency-orientation-secondary-20261030/`](../experiments/results/oram-rank64-frequency-orientation-secondary-20261030/).
It contains the run configuration and report, all 90 compressed target
prediction artifacts, the orientation plot, and
[`independent-verification.json`](../experiments/results/oram-rank64-frequency-orientation-secondary-20261030/independent-verification.json).
The verifier independently checked all 1,440 raw-session hashes against the
complete configured file set, the frozen plan's source/configuration hashes,
all 90 prediction files, all 90 per-trial metric rows, and all three
5,000-resample bootstrap summaries. It confirmed the prediction artifacts do
not contain private target labels. The receipt records the verifier source
hash and the raw report hash.

The runner's existing prediction schema includes the profile-selected
orientation sign in addition to target session IDs, score vectors, and
predicted classes. This is a small output-schema deviation from the plan's
strict wording; the sign is derived from profile labels only and the verifier
rejects any other unexpected prediction fields. No target label or private
logical address is present in a prediction artifact.

The previous successful verification receipt is preserved as
`independent-verification-v1.json`; the canonical receipt reruns the verifier
after it was strengthened to require the complete raw-session set and report
the target-majority baseline.

## Reproduction

The retained output directory is immutable. A repeat needs a new output path:

```sh
.venv/bin/python -m research.analysis.oram_frequency_selected \
  --config experiments/configs/oram-isolated-rank64-markov-replication-20261030.json \
  --raw experiments/results/oram-isolated-rank64-markov-replication-20261030 \
  --output experiments/results/oram-rank64-frequency-orientation-secondary-NEW

.venv/bin/python -m research.analysis.oram_frequency_secondary_verifier \
  --output experiments/results/oram-rank64-frequency-orientation-secondary-NEW \
  --raw experiments/results/oram-isolated-rank64-markov-replication-20261030 \
  --config experiments/configs/oram-isolated-rank64-markov-replication-20261030.json
```

The first command applies the positive-control gate before the ORAM arm. The
second checks raw integrity, source provenance, target-only predictions,
private-label-derived metrics, and the bootstrap calculations. Read the
frozen plan and the
[primary study report](ORAM_RANK64_MARKOV_REPLICATION_20261030.md) before
interpreting either result.
