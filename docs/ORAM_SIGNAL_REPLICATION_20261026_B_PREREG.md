# Independent ORAM leaf/timing replication: Markov workload B

**Status:** frozen before collection. Planned output:
`experiments/results/oram-isolated-replication-20261026-b/`.

## Question

Does the fixed temporal leaf/timing attacker distinguish two hot logical
addresses from six cold addresses under a fresh Markov-locality workload, when
the observer receives bucket identifiers, fixed-shape byte counts, and handler
time measured inside a separate bucket-service process?

This independently varies the workload seed, hot set, address weights,
retention probability, and read/write mix from the 2026-10-25 preregistered
study. It reuses the existing attack implementation and is not an independent
implementation of the classifier. It tests one synthetic workload and does not
establish remote timing or cryptographic indistinguishability.

## Frozen design

The machine-readable configuration is
[`oram-isolated-signal-replication-20261026-b.json`](../experiments/configs/oram-isolated-signal-replication-20261026-b.json).
It fixes 30 trials, eight independent controller sessions per attack trial,
four complete profiling sessions and four disjoint target sessions, 128
measured operations per session, eight warm-up accesses, 32 blocks, 64-byte
blocks, and bucket capacity four. The eight-address refresh distribution is
`[0.25, 0.18, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05]`. Addresses `0` and `1`
are the hot class. On each operation, the Markov generator retains the prior
logical address with probability `0.80`; otherwise it samples the configured
distribution. Reads occur with probability `0.60`.

The workload seed is `20261027`; each trial/session receives a distinct
deterministic workload stream, paired exactly across plaintext, encrypt-only,
and Path ORAM modes. Warm-up uses its separate deterministic stream. ORAM
leaves, encryption keys and nonces use OS cryptographic randomness. The
classifier is the existing fixed random forest (128 trees, depth 8, minimum
leaf size 5, balanced class weights, model seed 1907). It receives visible
bucket/leaf identifiers, total bytes per logical access, isolated
bucket-handler time, and the existing short temporal features. It receives no
logical-address or read/write labels during fit or prediction. Profiling and
target data are split by complete sessions.

## Primary metric and decision rules

The sole primary metric is mean per-access ROC AUC across the 30 fitted trials.
The 95% interval is a percentile bootstrap over the 30 trial AUCs with 5,000
resamples. Chance is AUC `0.5`. Accuracy, balanced accuracy, and
profile-majority accuracy are secondary descriptive results.

Plaintext and encrypt-only controls run and score first. Each must have mean
AUC at least `0.80` and a bootstrap lower bound above `0.50`; otherwise the
study stops without evaluating Path ORAM. A Path ORAM interval excluding 0.50
is treated as a detectable signal for this specific attack and workload. An
interval containing 0.50 is inconclusive for this experiment, not evidence of
security. No workload, feature, classifier, threshold, or metric will be
changed after inspecting results.

## Observer and isolation boundary

All three modes use a separate local bucket-service process. Recorded
`service_ns` is measured after fixed-length request decoding and before
fixed-length reply encoding. It includes the in-memory bucket handler and
excludes controller work, pipe waiting, request decoding, response encoding,
and trace-file output. Attacker-visible traces and private driver labels stay
in separate directories. No other repository benchmark or correctness workload
will run concurrently during collection. This is process isolation on one
host, not a TEE or remote-network timing measurement.

The existing isolated-trace harness tests must pass before collection. The run
uses a new output directory and retains configuration, raw session hashes,
code/binary hashes, machine/runtime metadata, paired-schedule verification,
and elapsed time. If controls or integrity checks fail, report the failure
without substituting another workload.
