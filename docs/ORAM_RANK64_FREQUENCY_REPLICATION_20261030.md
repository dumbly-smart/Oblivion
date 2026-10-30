# Fresh-seed rank-64 frequency-attack replication

**Status:** completed as a preregistered fresh-session replication under a
changed temporal-locality parameter. The protocol was frozen before data
collection. The attack family and experiment design were informed by the
earlier post-hoc result, so this is not a blind replication. The new sessions
are independently seeded and are not pooled with the earlier study.

## Protocol and workload

The preregistered question was whether the profile-only tag-frequency attack
would retain its positive-control performance and near-chance ORAM result
when address persistence increased from 0.40 to 0.60. The configuration keeps
the 64-address Zipf-like distribution, hot set 0–7, 55% read probability,
64-byte blocks, Path ORAM `Z=4`, and 512 measured operations plus 32 warmups
per session. It uses seed `20261102`, 30 trials, and eight separately
initialized sessions per trial. Sessions 0–3 are complete labeled profiles;
sessions 4–7 are disjoint targets.

The frozen protocol is
[`ORAM_RANK64_FREQUENCY_REPLICATION_PREREG_20261030.md`](ORAM_RANK64_FREQUENCY_REPLICATION_PREREG_20261030.md),
and the machine configuration is
[`oram-isolated-rank64-frequency-replication-20261030.json`](../experiments/configs/oram-isolated-rank64-frequency-replication-20261030.json).
The scorer uses visible tag identity and counts in profile sessions only. It
does not use timing, byte counts, read/write identity, private logical
addresses, or target labels. Score orientation comes from
leave-one-profile-session-out validation; target labels are used only after
prediction for evaluation. The primary metric is the mean trial-level target
ROC AUC, with 5,000 trial-bootstrap resamples and seed `20261303`.

The collector's temporal random-forest positive controls ran first. Both
controls scored AUC 1.000, so it captured the ORAM arm. The frequency-only
analysis then independently passed its own plaintext and encrypt-only control
gate before scoring the ORAM arm. Each control gate required mean AUC at least
0.80 and a 95% lower confidence bound above 0.50.

## Frequency-only results

| Mode | Mean target AUC | 95% trial-bootstrap interval | Fixed-direction AUC | Balanced accuracy | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: |
| Plaintext | 1.000000 | [1.000000, 1.000000] | 1.000000 | 0.999344 | 0.999349 |
| Encrypt-only | 1.000000 | [1.000000, 1.000000] | 1.000000 | 0.999344 | 0.999349 |
| Path ORAM | 0.502248 | [0.498132, 0.506253] | 0.499121 | 0.500468 | 0.498128 |

The ORAM fixed-direction AUC interval was [0.495014, 0.503117], and balanced
accuracy was [0.497184, 0.503694]. Orientation was reversed in 16 of 30 ORAM
trials. The 95% AUC interval includes 0.50, so the experiment is inconclusive
for this frequency scorer and workload; it does not demonstrate
indistinguishability or cryptographic security.

The mean target hot-class prevalence was 0.492952. The evaluation-only
target-majority accuracy reference was 0.518083, while a constant prediction
based on the profile majority achieved 0.504508 mean accuracy. ORAM raw
accuracy was 0.498128. Balanced accuracy and AUC account for the class
imbalance more directly than raw accuracy.

The collector's separate temporal random-forest analysis measured Path ORAM
AUC 0.501172 [0.495693, 0.506969] and balanced accuracy
0.502394 [0.497443, 0.507930]. Its plaintext and encrypt-only AUC controls
were also 1.000. This is a separate attack result on the same new sessions;
do not pool it with the frequency-only scores or with the earlier 0.40
persistence study.

## Evidence and integrity

The raw collection is retained in
[`oram-isolated-rank64-frequency-replication-20261030/`](../experiments/results/oram-isolated-rank64-frequency-replication-20261030/).
The frequency-only report, 90 prediction artifacts, figure, and independent
verification are in
[`oram-rank64-frequency-replication-20261030/`](../experiments/results/oram-rank64-frequency-replication-20261030/).

The collector verifier checked 1,440 raw files, 240 paired schedules, 720
observer sessions, 720 private sessions, 90 trial predictions, five
source/binary hashes, and the collector's bootstrap interval. The frequency
verifier independently confirmed that its input manifest matches the
collector's manifest, checked the complete configured raw file set and all
1,440 hashes, verified 90 target-only prediction artifacts, and recomputed
all 90 trial metric rows and bootstrap summaries. Both manifests name the
same 1,440 raw files. Their canonical manifest digests and the two report
digests are preserved in the
[`collector-manifest-crosscheck.json`](../experiments/results/oram-rank64-frequency-replication-20261030/collector-manifest-crosscheck.json)
receipt. Neither verification found target truth fields in a prediction
artifact.

The run used source revision `b5f4d8c1`, a local Intel Core i7-14650HX with 24
logical CPUs, and Linux 7.2.11. The driver was restricted to CPU 2 and the
bucket service to CPU 0. Load averages at collection start were
2.295/2.195/2.057; at end they were 2.999/2.411/2.142. The measured timing
boundary remains the local bucket-handler interval; this frequency scorer
does not consume timing values.

The plan pins the workload and analysis sources. The collector independently
records its executable hashes: `oram-measure` SHA-256
`d09d3714b6123fb4fcaf657df6d18d842258e72ece11ccd55ca99bd9c4781c20`, and
`oram-control` SHA-256
`9cd9cea2cd8a86db8ac254cda0aaa7816f65a9ca54694b4d933e730398587c3b`. The
collector report SHA-256 is
`11c31bf494b952e6d9e9630b519edffcafb2f85ba468a5476439d82ca2b2162a`; the
frequency report SHA-256 is
`7369df1806e0053aba3e1e8ba3b72c52d8542503ad215513669b96d38fe16628`.

## Reproduction

The retained output paths are immutable. For a repeat, use a new seed and new
output paths, update and commit a separate preregistration first, then run the
collector, frequency analysis, and both independent verifiers as described in
the frozen plan. The commands in that plan intentionally use the original
output names and must not be rerun against those existing paths.

This study supports only a narrow empirical statement about one attack, one
64-address workload, a changed persistence value, one host, and the declared
local observer. The processes are not a TEE, and no result here is a general
privacy guarantee.
