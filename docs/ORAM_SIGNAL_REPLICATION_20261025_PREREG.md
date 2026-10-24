# Independent ORAM leaf/timing replication: preregistration

**Status:** frozen before collection. The corresponding raw output path is
`experiments/results/oram-isolated-replication-20261025-v3/`.

## Question

Can the fixed temporal leaf/timing classifier distinguish the hot logical
address from cold addresses under a fresh eight-address skew and a 70% read
workload, when its observer receives only bucket identifiers, fixed-shape
bytes, and service time measured inside a separate bucket-service process?

This is a workload-specific replication and extension of the two-address
study. It is not a test of every ORAM leakage function, a remote timing study,
or evidence of cryptographic indistinguishability.

## Frozen design

The machine-readable configuration is
[`oram-isolated-signal-replication-20261025.json`](../experiments/configs/oram-isolated-signal-replication-20261025.json).
It fixes 30 trials, eight independent controller sessions per attack trial,
four complete profiling sessions and four disjoint target sessions, 128
measured operations per session, eight warm-up accesses, 32 blocks, 64-byte
blocks, and bucket capacity four. Each session initializes a new Path ORAM
state and a separate bucket-service child process. The measured address
probabilities are `0.35, 0.20, 0.15,
0.10, 0.08, 0.05, 0.04, 0.03` for addresses `0..7`. Address `0` is the hot
class; addresses `1..7` are cold. The read probability is `0.70`.

The workload seed is `20261026`; each trial and session receives a distinct
deterministic workload stream, paired exactly across plaintext, encrypt-only,
and Path ORAM modes. The existing harness uses a separate warm-up stream.
Cryptographic randomness and ORAM position-map leaves continue to use the
operating-system CSPRNG. No configuration or attack threshold will be changed
after inspecting mode results.

The classifier is fixed to the existing random forest
(`128` trees, depth `8`, minimum leaf size `5`, balanced class weights, model
seed `1907`). It receives visible bucket/leaf identifiers, total bytes per
logical access, isolated bucket-handler time, and the existing fixed short
temporal features. It receives no logical-address or read/write labels during
fit or prediction. Profiling and target data are split by complete sessions.

## Primary metric and decision rules

The sole primary metric is the mean per-access ROC AUC across the 30 fitted
trials. Its 95% interval is a percentile bootstrap over those 30 trial AUCs
with 5,000 resamples. Chance is AUC `0.5`. The workload's profile-majority
accuracy, balanced accuracy, and per-trial scores are secondary descriptive
results.

Plaintext and encrypt-only controls run and score first. Each must have mean
AUC at least `0.80` and a bootstrap lower bound above `0.50`; otherwise the
study stops without evaluating Path ORAM. A control pass validates this attack
and workload pairing only. An ORAM interval containing `0.50` is reported as
failure to distinguish in this experiment, never as a proof of privacy.

## Observer and isolation boundary

All three modes use a separate local bucket-service process. The recorded
`service_ns` is measured after fixed-length request decoding and before
fixed-length reply encoding. It includes the in-memory bucket handler; it
excludes controller work, pipe waiting, request decoding, response encoding,
and trace-file output. The attacker-visible trace and private driver labels
remain in separate directories. No other benchmark or correctness workload
will run concurrently during collection. This is process isolation on one
host, not a TEE or a remote-network timing measurement.

The fixed harness and analysis tests must pass before collection. The run will
use a new output directory; the report will retain configuration, raw-session
hashes, code/binary hashes, machine and runtime metadata, paired-schedule
verification, and elapsed time. If controls fail or integrity checks fail,
the outcome will be reported without substituting a different workload.
