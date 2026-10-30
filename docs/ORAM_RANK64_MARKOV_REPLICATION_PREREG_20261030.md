# Preregistered independent 64-address ORAM leaf/timing replication

**Status:** workload, attacker, split, primary metric, positive-control gate,
and stop rules are fixed before the study-specific tests, release builds, and
data collection. Planned output:
`experiments/results/oram-isolated-rank64-markov-replication-20261030/`.

## Question and scope

Does the already implemented temporal leaf/timing attacker distinguish a
hot-address class from a cold-address class under a fresh, larger,
lower-skew Markov workload when it sees only fixed-shape storage events and
bucket-handler timing? This is an independent workload/session collection;
the classifier is reused unchanged. It is not an independent implementation
of the attacker, a remote-network timing experiment, or a security proof.

The study isolates workload generalization from attack tuning. It keeps the
same three configurations, attack implementation, fixed feature set,
session-level split, and positive-control gate used by earlier replications.
Only the workload distribution, address-space size, operation count, seed,
temporal retention probability, and read/write mix are changed as recorded in
the machine-readable configuration.

## Frozen workload

The authoritative configuration is
[`oram-isolated-rank64-markov-replication-20261030.json`](../experiments/configs/oram-isolated-rank64-markov-replication-20261030.json).
It uses 30 attack trials, eight independent sessions per trial, 512 measured
operations and 32 warm-up reads per session, 64 logical blocks, 64-byte
blocks, and bucket capacity four. Each trial has four complete profiling
sessions followed by four disjoint target sessions.

Addresses 0 through 63 are sampled from the normalized rank distribution
`p(i) ∝ 1/(i+1)^0.85`; the probabilities stored in the configuration are
rounded to 15 decimal places. Addresses 0 through 7 are the hot class and
addresses 8 through 63 are cold. The hot class has base probability mass
`0.486319785106612`, before finite-session variation. Each logical operation
retains the preceding address with probability `0.40`; otherwise it samples
from the configured base distribution. Reads occur with probability `0.55`.

The deterministic workload seed is `20261030`. Each trial/session receives a
distinct deterministic workload stream, and the address and read/write
schedules are paired exactly across plaintext, encrypt-only, and Path ORAM.
Warm-up uses a separate stream. Path ORAM position-map leaves and runtime
cryptographic keys/nonces use operating-system randomness and are fresh for
each session. The controls use the same workload schedules. Their direct
service addresses intentionally expose the logical address; encrypt-only
protects record contents while retaining that address leakage.

## Frozen attacker and auxiliary knowledge

Use the existing `TemporalLeafTimingAttack` unchanged: a random forest with
128 trees, maximum depth 8, minimum leaf size 5, balanced class weights,
random state 1907, and one worker. For each mode and trial, it receives the
four labeled profile sessions from that same mode, then predicts the four
disjoint target sessions without their labels. This explicitly gives the
attacker labeled auxiliary examples from the target configuration; the
positive controls demonstrate that the fixed pipeline can exploit direct
address leakage under this workload.

Features are limited to the visible final-path bucket identifier, fixed
bytes per logical access, bucket-handler-only service time, within-session
identifier frequency, recent identifier repetition, the previous four
visible identifiers and their times, and short 4/8/16-operation windows.
The classifier may calculate unsupervised frequency/window features over a
whole unlabeled target session. Logical addresses, read/write labels, and
ground-truth hot/cold labels are never supplied during target prediction;
labels are used only for profiling and scoring.

## Primary metric and decision rules

The sole primary metric is mean per-target-operation ROC AUC across the 30
trial-level fits for each mode. Its 95% interval is a percentile bootstrap
over those 30 trial AUCs with 5,000 resamples. The AUC bootstrap uses the
collector's deterministic seed `20261077` (`workload seed + 47`). Chance is
0.5. Raw accuracy, balanced accuracy, profile-majority accuracy, observed
class prevalence, and each trial's AUC are secondary descriptive results.

Run and score plaintext and encrypt-only first. Both controls must have mean
AUC at least `0.80` and a bootstrap lower bound above `0.50`. If either fails,
preserve the partial output, mark the attack inconclusive, and do not capture
or evaluate Path ORAM. If both pass, evaluate Path ORAM once. An ORAM interval
excluding `0.50` in either direction is a detectable association under the
fixed score orientation and this attacker/workload. An interval containing
`0.50` is inconclusive for this study, not evidence of indistinguishability.
No configuration, seed, feature, classifier, threshold, split, metric, or
decision rule will be changed after examining a mode result.

## Observer, process isolation, and host conditions

Every mode uses a separate local bucket-service process. `service_ns` starts
after fixed-length request decoding and stops before fixed-length reply
encoding. It includes the in-memory bucket handler and excludes controller
work, pipe wait, framing, and trace-file output. The controller is pinned to
logical CPU 2; bucket-service children are pinned to logical CPU 0 and their
effective affinity is verified from process metadata. On the host observed at
preregistration, `lscpu -e` maps CPU 0 to physical core 0 and CPU 2 to physical
core 1; the scaling governor reports `powersave`. These affinities do not
reserve cores or exclude interrupts, sibling-thread activity, kernel work,
frequency/thermal changes, other processes, or scheduler noise. If either CPU
is unavailable or the configured service mask is not applied, stop without
changing the frozen CPU assignment.

Run no other repository test, benchmark, or data collection during capture.
The collector records CPU model, process-allowed CPUs, and load averages
before and after each mode. Also retain `lscpu -e`, the governor values, the
kernel/platform version, and the output of `taskset -pc` for the driver and
each service child where available. This is local process and affinity
isolation on one shared host, not a TEE, reserved-core guarantee, or remote
timing measurement.

## Integrity and stop rules

Run the focused trace-schema/session-split tests, build both release examples,
and run the isolated-service integration tests against those newly built
binaries before collection. The collector must verify identical private
address/read-write schedules across all three modes, fixed-shape request and
response lengths, one observed service child per session, and the configured
service CPU mask. It records the configuration, code and binary SHA-256 values,
raw observer/private-file hashes, predictions, trial summaries, host snapshots,
Git revision/status, and elapsed time. Observer traces and private driver
labels remain in separate directories.

The output path must not already exist. An interrupted or failed run is
preserved as-is; any later attempt uses a new output path and a separately
preregistered seed. A control-gate failure, schedule mismatch, malformed
trace, hash mismatch, or missing affinity evidence prevents an ORAM defense
claim. Do not replace a failed control or discard a failed mode.

## Collection commands

```sh
.venv/bin/python -m unittest research.tests.test_oram_isolated_replication
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m unittest research.tests.test_oram_isolated_timing
taskset -c 2 .venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-rank64-markov-replication-20261030.json \
  --output experiments/results/oram-isolated-rank64-markov-replication-20261030 \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```

The collector runs positive controls before Path ORAM and refuses to overwrite
the output directory. Preserve its raw output unchanged. A report will be
written only from the resulting data; this preregistration itself contains no
results.
