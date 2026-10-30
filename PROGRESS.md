# Project progress snapshot

**Updated:** 2026-10-30. Rust runtime source remains `24ded25d` on
`codex/oblivion-research-platform`; the rank-64 study ran at `e7813b99`, and
the independent bundle verifier/tests were added in `d5d90054`. The frequency
secondary plan and verifier/tests were pushed in `80678c6d` and `22bb0024`.
The study protocol/config was frozen in `d5847766` before collection. The chronological record is
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md), and the full
requirement audit is [docs/REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md).

## Current state

Oblivion is a functioning local Rust research prototype. It integrates a
fixed-shape epoch path, two-server XOR PIR, bounded Wasmtime execution, staged
Path ORAM state, signed registry rows, a separate attack harness, and optional
local or remote durability. This does not complete every extension in the
fourteen-week roadmap and does not make the system production-safe. Processes
and Wasmtime simulate a trusted-executor boundary; neither is a hardware TEE.

The latest Rust runtime change bounds concurrent remote mTLS connection handling:
four fixed TLS/frame workers share a queue capped at sixteen accepted sockets,
with a five-second I/O deadline that includes queue wait. SQLite operations
remain serialized through one connection. A full queue closes the newly
accepted connection. Per-certificate/per-slot token buckets default to 100
requests per second with burst 200. They reset on restart and do not cover TCP
accepts, TLS handshakes, IP-level limits, or multiple witness instances.
The latest research tooling adds independent verifiers for isolated ORAM
bundles, frequency analyses, and the rank-64 transition analysis. These
validate raw hashes, paired schedules where applicable, fixed event/frame
shape, process masks, target-only predictions, trial metrics, and bootstrap
statistics.

The first optional invocation-boundary size/timing study completed on the
local A–G component harness. Its independent verifier checked 8,404 raw-file
hashes, 1,680 session directories, and 13,440 truth rows. Plaintext A passed
at AUC 1.000; encrypt-only B scored 0.6896 [0.6531, 0.7260], below the frozen
0.70 gate, so C–G were withheld. The [report](docs/INVOCATION_BOUNDARY_ATTACK_20261030.md)
documents the result and local measurement boundary.

A second, informed follow-up collected fresh sessions and added six
session-normalized size/timing features. A again passed at AUC 1.000; B scored
0.69896 [0.66823, 0.73177], just below the unchanged 0.70 threshold. The
evaluator withheld C–G. A separate verifier reconstructed features from raw
observer frames, replayed all 960 control predictions, and checked 4,204 raw
file hashes. The full Python suite passed 272 tests with four existing skips;
the release harness built. Both studies use the local in-process observer,
not real network arrival times. See the [follow-up report](docs/INVOCATION_CONTEXT_ATTACK_20261030.md).

## Loopback transport implementation

The A–G component harness now has a separate `system-tcp` path that runs each
mode/session through a fresh worker process over loopback TCP. Its bounded
four-byte frame codec, inherited-pipe channel bootstrap, socket observer, and
actual registry/PIR/WASM/storage execution are covered by focused tests; all
seven mode response oracles passed. The socket observer is an application
boundary trace, not packet capture. Its local PIR pair and memory-backed ORAM
remain inside the worker. Full workspace format and warning-denied Clippy
passed; the initial serial full workspace test passed 203 tests with zero
failures and one ignored million-operation ORAM stress test. Follow-up review
hardening now rejects mode-incompatible frame prefixes before body reads and
uses one absolute 30-second deadline per frame. The latest serial full
workspace run passed 206 tests with zero failures and one ignored stress test.
No new attack result is claimed for these traces.
See [the protocol](docs/PROTOCOL.md), [the architecture](docs/ARCHITECTURE.md),
and [next steps](docs/NEXT_STEPS.md).

## Latest measurement

The latest completed independent ORAM leaf/timing study is the preregistered
2026-10-30 rank-64 Zipf/Markov replication. Plaintext and encrypt-only controls
scored mean ROC AUC 1.0000; Path ORAM scored 0.502474 with a 95%
trial-bootstrap interval [0.496502, 0.508492]. The interval includes chance:
the result is inconclusive for the fixed classifier, workload, host, and
handler-only timing boundary. It is not a security proof. The complete raw
bundle, source/binary hashes, independent verification, plot, preregistration,
and interpretation are indexed in [REPORTS.md](REPORTS.md).

A separate post-hoc frequency-only tag attack reused those same rank-64
sessions. Plaintext and encrypt-only controls both scored AUC 1.000; the ORAM
scorer measured 0.496447 [0.491316, 0.501515], inconclusive for this attack
and workload. It is not an independent replication. Its frozen analysis plan,
raw report/predictions, result interpretation, and independent verification
are linked from [REPORTS.md](REPORTS.md).

A preregistered fresh-seed replication then increased Markov address
persistence to 0.60 and collected 30 new trials. Both the collector's temporal
attacker controls and the frequency attack's controls passed. The frequency
scorer measured ORAM AUC 0.502248 [0.498132, 0.506253], with an interval
including chance. It is independent session evidence for this changed
workload, not a blind replication or a security proof. Its two verified
bundles and report are linked in [REPORTS.md](REPORTS.md).

The latest ORAM attack evaluation used a fresh seed and address persistence
0.80 for a preregistered one-step transition lookup. Its plaintext and
encrypt-only controls passed at AUC 0.898148 [0.895392, 0.900593]; Path ORAM
scored 0.502017 [0.497459, 0.506447]. The interval includes chance and mean
raw accuracy is below the profile-majority baseline. Its independent verifier
checked 1,440 raw files and 90 target-only prediction files and recomputed
trial metrics and intervals. The attack shares collection sessions with the
temporal study, uses no target-label features, and is not a published-attack
reproduction. See its [preregistration and report](docs/ORAM_RANK64_TRANSITION_REPLICATION_20261030.md).

The completed persistent SSE journal benchmark ran 30 trials at each of 64,
257, 1,024, and 4,093 postings, with five fresh-process reopens per index. Its
application-level encrypted journal-byte amplification ranged from 84.037× to
244.754×. This is not SQLite/WAL or physical storage write amplification; see
[the result report](docs/SSE_JOURNAL_BENCHMARK_20261028_RESULT.md).

## Verification status

For unchanged Rust source `24ded25d`, `cargo fmt --all --check`,
`cargo clippy --locked --workspace --all-targets -- -D warnings`, and a fresh
`cargo test --locked --workspace -- --test-threads=1` rerun all exited 0. The
workspace suite passed with one intentionally ignored million-operation ORAM
stress test. Before that rerun, one full suite had exited 101 when
`oblivion-server/tests/pipeline.rs::sse_metadata_discovery_precedes_real_mixed_invocation`
received a `Timeout` during a 100 ms invocation. Its retained fixture was
`/tmp/oblivion-sse-demo-6450479058385519197`; the private execution record
reported about 86.1 ms of work and a 100.29 ms response elapsed time. The
focused test then passed six sequential executions, and the full serial suite
passed on rerun. This narrows the observation to an intermittent failure but
does not establish its cause. No deadline, retry, or test threshold was
changed. The million-operation stress tier, Python suite, and hosted CI have
not been run for this source revision.

The full research Python suite most recently passed 252 tests with four skips
after adding the transition-bundle verifier; its four focused tests also
passed. The full validation script and million-operation ORAM stress tier have
not been run for this increment. Earlier Python suites passed 246 tests with
four skips after building all workspace examples and the separate locked
ORAM reference workspace. Its first run had five setup failures caused by
absent release binaries in that worktree; no test failed after prerequisites
were built. The focused study suite passed 9 tests and the isolated-process
suite passed 3; the primary bundle verifier's six focused tests also passed.
For the frequency-verifier increment, a fresh suite passed 252 tests with
four skips, including six focused tests for that verifier. Earlier gate
results remain valid only for their recorded revisions. See the per-commit evidence in
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

## Latest ORAM study

The rank-64 Zipf/Markov handler-timing study completed after the preregistration
and configuration were committed in `d5847766`:

- [Preregistration](docs/ORAM_RANK64_MARKOV_REPLICATION_PREREG_20261030.md)
- [Configuration](experiments/configs/oram-isolated-rank64-markov-replication-20261030.json)
- [Results](docs/ORAM_RANK64_MARKOV_REPLICATION_20261030.md)
- [Raw bundle and independent verification](experiments/results/oram-isolated-rank64-markov-replication-20261030/)
- [Post-hoc frequency-only result and verification](docs/ORAM_RANK64_FREQUENCY_ORIENTATION_SECONDARY_20261030.md)
- [Fresh-seed frequency replication, preregistration, and two verified bundles](docs/ORAM_RANK64_FREQUENCY_REPLICATION_20261030.md)
- [Fresh-seed transition attack replication and final verification](docs/ORAM_RANK64_TRANSITION_REPLICATION_20261030.md)

Its 30-trial positive controls passed at AUC 1.000; Path ORAM scored 0.502474
[0.496502, 0.508492]. Independent verification matched 1,440 raw hashes,
all 240 paired schedules, 90 prediction trials, and the captured executable
hashes. The output is immutable; a reproduction requires a new preregistered
seed and directory. The next active experiment should measure a separate
externally visible request/response boundary under a frozen protocol.

## Implemented components

- `oblivion-store`: Path ORAM with fixed encrypted buckets, memory and bounded
  file backends, trusted map/stash state, freshness checks, checkpoints, and a
  separate million-operation oracle tier.
- `oblivion-pir` and `oblivion-server`: fixed-record XOR PIR, authenticated
  worker transport, two worker processes, signed registry validation, and a
  local multi-component demo. PIR privacy requires that the two servers do
  not collude; the local process topology does not establish this assumption.
- `oblivion-exec` and `oblivion-batcher`: Wasmtime fuel/resource limits,
  fixed-size invocation and response envelopes, bounded scheduling, dummy
  work, and staged fixed-count ORAM state accesses.
- `oblivion-registry` and `oblivion-anchor`: signed fixed-size catalog records,
  local SQLite/Unix anchoring, and an optional single mTLS witness for catalog,
  SSE, checkpoint, and invocation freshness operations.
- `oblivion-sse`: constrained GGM-inspired search, persistent encrypted client
  journals, and explicit search-pattern/result-volume leakage documentation.
- `oblivion-harness` and `research/`: observer/label-separated traces,
  positive-control attacks, trial-level analysis, reproducible reports, and
  an autoscaling simulator rather than a production scaler.

## Remaining work in the active sequence

1. Preserve the historical 100 ms pipeline timeout record for source
   `24ded25d`; its original host-specific cause is not established. A separate
   current-head mixed-function test failure was traced to its three-client
   correctness workload occasionally crossing the default 100 ms runtime
   deadline. That test now requests 250 ms explicitly; the production default,
   runtime deadline behavior, and retry policy are unchanged.
2. Preregister a distinct inference study over the new loopback socket trace
   before collecting targets. Freeze its attacker view, whole-session split,
   positive-control threshold, primary metric, and output schema. Score C–G
   only if both plaintext A and encrypt-only B pass the same frozen gate.
3. Continue the remaining work in [docs/NEXT_STEPS.md](docs/NEXT_STEPS.md),
   preserving the threat model and reporting data- or hardware-dependent
   extensions as unimplemented where appropriate.

Known boundaries remain: no hardware TEE or attestation; no proof that PIR
servers do not collude; a single trusted witness can be rolled back and sees
checkpoint handles that contain snapshot keys; SSE is not backward-private;
the autoscaler is a simulator; and measured attacks cover only their declared
features and workloads.
