# ORAM rank-64 Zipf/Markov replication — results

This report follows the frozen [preregistration](ORAM_RANK64_MARKOV_REPLICATION_PREREG_20261030.md)
and [machine-readable configuration](../experiments/configs/oram-isolated-rank64-markov-replication-20261030.json).
Collection ran from 2026-10-29 22:51:21 UTC to 22:53:36 UTC (2026-10-30
local time), against source revision `e7813b99887ce537cd04607aa258949c53e160d7`.
The result bundle records the exact source and release-binary SHA-256 values.

## Result

The fixed temporal leaf/timing classifier cleared both preregistered positive
controls before Path ORAM was run. Mean trial AUCs and 95% percentile-bootstrap
intervals are:

| Mode | Mean ROC AUC | 95% trial-bootstrap interval | Mean balanced accuracy | Profile-majority accuracy |
| --- | ---: | ---: | ---: | ---: |
| Plaintext | 1.000000 | [1.000000, 1.000000] | 1.000000 | 0.502913 |
| Encrypt-only | 1.000000 | [1.000000, 1.000000] | 1.000000 | 0.502913 |
| Path ORAM | 0.502474 | [0.496502, 0.508492] | 0.503593 | 0.502913 |

The plaintext and encrypt-only controls each exceed the preregistered mean-AUC
threshold of 0.80, and each bootstrap lower bound exceeds 0.50. The fixed
attacker therefore detected the deliberately exposed logical-address signal.
For Path ORAM, the primary interval contains 0.50. This result is inconclusive
for this classifier, workload, host, and bucket-handler timing boundary. It
does not demonstrate indistinguishability, rule out a smaller association, or
establish cryptographic security. The score direction was not changed after
observing the ORAM result.

The hot class was addresses 0–7. Across the 61,440 held-out observations, its
realized prevalence was 49.14%; the realized read fraction was 55.09%. The
profile-majority accuracy of 50.29% is reported as a baseline for each mode.
The same private address and read/write schedules were used in all three
modes.

## Frozen workload and attacker

Each of 30 trials used eight fresh sessions, with four complete profiling
sessions and four disjoint target sessions. Each session contained 32 warm-up
reads followed by 512 measured operations over 64 logical blocks of 64 bytes
each; Path ORAM used bucket capacity `Z = 4`. Addresses followed the
normalized rank distribution `p(i) ∝ 1/(i+1)^0.85`; the hot set's configured
base mass was 0.486320. The Markov step retained the preceding address with
probability 0.40, and reads were requested with probability 0.55. The
deterministic workload seed was `20261030`; each trial/session used a distinct
stream. ORAM leaves and runtime cryptographic keys/nonces used operating
system randomness.

The unchanged attacker was a one-worker random forest with 128 trees, maximum
depth 8, minimum leaf size 5, balanced class weights, and random state 1907.
For each mode/trial, it received four labeled profile sessions and predicted
the four different target sessions without their labels. Its inputs were the
visible final-path bucket identifier, fixed bytes per logical access,
bucket-handler service time, within-session identifier frequency, recent
repetition, the prior four visible identifiers and times, and 4/8/16-operation
window features. Private logical addresses, operation types, and hot/cold
labels were used only by the driver and for scoring. They were not included in
attacker features or prediction artifacts.

The primary metric was the mean of 30 per-trial ROC AUCs. The 95% interval was
the percentile bootstrap over those 30 trial values using 5,000 resamples and
seed `20261077`. The [independent verifier](../research/analysis/verify_oram_isolated_bundle.py)
recomputed all per-trial AUCs from the saved predictions and private driver
labels, then regenerated the configured bootstrap interval.

## What the observer measured

Each session ran a separate local bucket-service process. For ORAM, each
logical access emitted seven bucket reads and seven writes: 14 fixed-shape
events, each with a 316-byte bucket payload. The request and response frames
were each 325 bytes in all three modes. `service_ns` measured the in-memory
bucket handler after fixed-length request decoding and before fixed-length
reply encoding. It excludes client cryptography, ORAM path computation, pipe
waiting, request decoding, response encoding, and trace-file output. This is
process-isolated local component timing, not end-to-end or remote-network
timing.

The driver was restricted to logical CPU 2 and the bucket service to logical
CPU 0. The preregistration preflight mapped those CPUs to separate physical
cores (CPU 0/core 0 and CPU 2/core 1); both governors reported `powersave`.
The host was a 24-logical-CPU Intel Core i7-14650HX running
`Linux-7.2.11-arch1-1-x86_64-with-glibc2.44`. The collector recorded driver
allowed CPUs as `[2]`, every service child's allowed mask as `0`, and
per-mode load averages. The one-, five-, and fifteen-minute load averages at
run start were 2.208, 2.704, and 2.841; at run end they were 2.160, 2.451, and
2.724. These CPUs were not reserved, and host scheduling, interrupts,
frequency changes, and other processes remain possible. External `taskset
-pc` output per PID was not retained; the collector's effective affinity
metadata is the recorded per-process mask evidence.

## Integrity and test status

The result directory retains 1,440 gzip-compressed raw observer/private files,
90 prediction files, configuration, report, host snapshots, process metadata,
and the AUC plot. The independent [verification record](../experiments/results/oram-isolated-rank64-markov-replication-20261030/independent-verification-v5.json)
checked all 1,440 raw hashes, 240 paired trial/session schedules, 720 private
and 720 observer sessions, 720 service-process records, 90 prediction trials,
and all five source/binary hashes. The raw schedules, fixed byte lengths,
path shapes, CPU masks, profile/target separation, saved metrics, and
bootstrap intervals passed. The final bundle occupies approximately 18 MiB.

Verification records `independent-verification-v1.json` through `v3.json` are
retained as earlier validation iterations and are superseded by v5. A v4
attempt wrote no result: a later workspace-wide example build had replaced
the two captured ORAM binaries. Rebuilding the exact preregistered
`oblivion-store` examples restored both binaries to their recorded hashes;
v5 then verified the full source/binary manifest. No raw observations or
predictions were changed or recollected during these checks.

Before collection, the nine session/split tests passed, both release examples
built, and the three isolated-service tests passed. After the study, the
complete research Python suite passed 246 tests with four skips. Its initial
run had five setup failures because the worktree did not yet contain unrelated
release examples and the separate ORAM reference binary; after building the
workspace examples and the locked reference workspace, the full suite passed.
The serial Rust workspace tests and warning-denied Clippy had also passed for
the unchanged Rust source revision; the million-operation ORAM stress tier
was not run in this increment.

The output directory is immutable evidence. Reproduction requires the frozen
configuration and a new output path; the collector refuses to overwrite an
existing directory. From a fresh checkout, build the two examples, run the
collection command from the preregistration, then use a new verification
output filename, for example:

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
taskset -c 2 .venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-rank64-markov-replication-20261030.json \
  --output experiments/results/oram-isolated-rank64-markov-replication-REPRO
.venv/bin/python -m research.analysis.verify_oram_isolated_bundle \
  --bundle experiments/results/oram-isolated-rank64-markov-replication-REPRO \
  --output experiments/results/oram-isolated-rank64-markov-replication-REPRO/independent-verification.json
```

This is an empirical result for one synthetic rank-64 workload and one fixed
attacker. It is neither an ORAM proof nor evidence about other workload
families, attacks, hosts, network observers, or trusted-executor leakage.
