# Preregistered ORAM Zipf-16 Markov Leaf/Timing Replication

**Status:** frozen before running the study's tests, builds, or data collection.
Planned output: `experiments/results/oram-isolated-zipf16-markov-replication-20261028/`.
Frozen source commit: `9dcd83a30835b4fce03abfe1fbff679d0363deee`.

## Question

Does the previously observed possible ORAM leaf/timing signal generalize to a
fresh, larger hot/cold address universe with temporal locality when a fixed
attacker observes only isolated bucket identifiers, fixed-size traffic and
bucket-handler timing? This is an independent workload replication using the
existing fixed attacker, not an independent implementation of that attacker.
It is a local synthetic experiment, not a remote timing study or a security
proof.

## Frozen workload and geometry

The machine-readable configuration is
[`oram-isolated-zipf16-markov-replication-20261028.json`](../experiments/configs/oram-isolated-zipf16-markov-replication-20261028.json).
It specifies 30 trials, eight independently initialized sessions per trial,
four complete profiling sessions and four disjoint target sessions, 256
measured operations per session, 16 independent warm-up accesses, and a
32-block Path ORAM with 64-byte blocks and bucket capacity four. The active
logical-address universe has 16 addresses. Its fixed base probabilities are
the normalized Zipf distribution `p(rank) ∝ 1/rank^1.10`, rounded in the
configuration to 15 decimal places; addresses 0–2 define the hot class (base
probability mass 0.582703085089245), and addresses 3–15 are cold. At each
operation the prior address is retained with probability 0.65; otherwise a
fresh address is sampled from that base distribution. Reads occur with
probability 0.80. The workload seed is 20261028, distinct from the previously
recorded studies. Each trial/session receives a unique deterministic stream,
paired exactly across plaintext, encrypt-only and Path ORAM. ORAM state,
leaves, keys and nonces remain fresh cryptographic randomness.

## Attacker and sole primary metric

Use the existing frozen `TemporalLeafTimingAttack` without tuning: 128-tree
random forest, maximum depth 8, minimum leaf size 5, balanced class weights,
random state 1907 and one worker. Features are only visible bucket IDs,
fixed bytes per logical access, bucket-handler-only time, tag frequency and
short-window histories. The attack receives four labeled complete profiling
sessions and four disjoint unlabeled target sessions per trial. Private logical
addresses and operation types are excluded from fitting and prediction;
labels are used only for scoring.

The sole primary metric is mean per-access ROC AUC over 30 fitted trials. The
95% interval is the percentile bootstrap over the 30 trial-level AUCs with
5,000 resamples. Chance is 0.5. Balanced accuracy, raw accuracy, profile
majority accuracy, class prevalence and per-trial metrics are secondary
descriptive results. Plaintext and encrypt-only controls run and score before
ORAM; each control must have mean AUC at least 0.80 and a 95% bootstrap lower
bound above 0.50. If either control fails, the run is inconclusive and ORAM
must not be evaluated or interpreted as a defense. An ORAM interval excluding
0.50 is evidence only for this attacker and workload; an interval including
0.50 is not evidence of security.

The choice is to reuse the already validated attacker and paired-session
pipeline while changing the address universe, skew/locality combination,
read mix, geometry and seed. Adding or tuning another classifier would answer
a different question and increase researcher degrees of freedom.

## Isolation, integrity and stopping

Each mode uses the separate local bucket-service process. Handler timing starts
after fixed-length request decoding and ends before fixed-length response
encoding; it includes in-memory bucket handling and excludes controller work,
pipe waiting, parsing, encoding and trace writes. Pin the service to logical
CPU 0 and the driver to CPU 2 using `taskset`. At preregistration, the current
host allows CPUs 0–23; `lscpu` reports CPU 0 on core 0 and CPU 2 on core 1.
These affinities do not reserve either core or exclude interrupts, kernel work,
unrelated processes, SMT/frequency/thermal effects or scheduler noise. Record
run/mode host snapshots and each service child's effective CPU mask. This is
process-affinity isolation on one shared host, not a TEE or remote-network
measurement.

Before collection, run both focused ORAM harness test modules and build both
release examples. Collect only after these gates pass, with no other local
tests or repository benchmarks running concurrently. Preserve configuration,
raw private-driver and public-observer traces, predictions, output hashes,
source/binary/config hashes, host observations and paired-schedule checks. A
failed or interrupted output directory is retained and never overwritten. No
seed, workload, feature, model, primary metric, threshold or CPU assignment is
changed after inspecting a mode result.

## Collection command

```sh
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
cargo build --locked --release -p oblivion-store --example oram-measure
cargo build --locked --release -p oblivion-store --example oram-control
taskset -c 2 .venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-zipf16-markov-replication-20261028.json \
  --output experiments/results/oram-isolated-zipf16-markov-replication-20261028
```
