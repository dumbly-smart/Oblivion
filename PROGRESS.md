# Project progress snapshot

**Updated:** 2026-10-30. **Source revision tested:** `24ded25d` on
`codex/oblivion-research-platform`; verification was rerun after the
documentation-only commits `d5847766` and `e2b85646`. The active study
protocol/config commit is `d5847766`, pushed to `origin`. This snapshot
describes source commit `24ded25d`; the chronological record is
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md), and the full
requirement audit is [docs/REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md).

## Current state

Oblivion is a functioning local Rust research prototype. It integrates a
fixed-shape epoch path, two-server XOR PIR, bounded Wasmtime execution, staged
Path ORAM state, signed registry rows, a separate attack harness, and optional
local or remote durability. This does not complete every extension in the
fourteen-week roadmap and does not make the system production-safe. Processes
and Wasmtime simulate a trusted-executor boundary; neither is a hardware TEE.

The latest source change bounds concurrent remote mTLS connection handling:
four fixed TLS/frame workers share a queue capped at sixteen accepted sockets,
with a five-second I/O deadline that includes queue wait. SQLite operations
remain serialized through one connection. A full queue closes the newly
accepted connection. Per-certificate/per-slot token buckets default to 100
requests per second with burst 200. They reset on restart and do not cover TCP
accepts, TLS handshakes, IP-level limits, or multiple witness instances.

## Latest measurement

The newest completed independent ORAM leaf/timing study is the preregistered
2026-10-28 Zipf-16/Markov replication. Plaintext and encrypt-only controls both
scored mean ROC AUC 1.0000; Path ORAM scored 0.4968 with a 95% trial-bootstrap
interval [0.4864, 0.5072]. The interval includes chance. This is an
inconclusive result for one classifier, workload, host, and isolated handler
timing boundary, not a security proof. Its preregistration, raw bundle,
verification, and report are indexed in [REPORTS.md](REPORTS.md).

The completed persistent SSE journal benchmark ran 30 trials at each of 64,
257, 1,024, and 4,093 postings, with five fresh-process reopens per index. Its
application-level encrypted journal-byte amplification ranged from 84.037× to
244.754×. This is not SQLite/WAL or physical storage write amplification; see
[the result report](docs/SSE_JOURNAL_BENCHMARK_20261028_RESULT.md).

## Verification status

For source commit `24ded25d`, `cargo fmt --all --check`,
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

The million-operation ORAM stress tier and Python suite were not rerun for
`24ded25d`. Earlier passing results remain valid only for their recorded
revisions. See the per-commit evidence in
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

## Current ORAM study preparation

A fresh rank-64 Zipf/Markov workload and isolated bucket-handler timing study
have a frozen preregistration and machine-readable configuration, committed
and pushed before study-specific testing, building, or data collection in
`d5847766`:

- [Preregistration](docs/ORAM_RANK64_MARKOV_REPLICATION_PREREG_20261030.md)
- [Configuration](experiments/configs/oram-isolated-rank64-markov-replication-20261030.json)

Its focused test, release build, and data collection have not run. Collection
must wait until the workspace test failure is understood and both positive
controls pass. Use the new output directory
`experiments/results/oram-isolated-rank64-markov-replication-20261030/`.

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

1. Keep the intermittent 100 ms pipeline timeout visible as unresolved; the
   focused repetitions and full serial rerun passed, but they did not identify
   its cause. Capture host-load and per-phase diagnostics if it recurs, without
   changing runtime limits or adding retries.
2. Recheck the study-specific focused test and release build, then run the
   frozen positive controls first. Collect the protected condition only if
   both controls pass and the study's prerequisites remain satisfied.
3. Verify the retained raw bundle independently, record environment and source
   hashes, and add the result (including any inconclusive outcome) to
   `REPORTS.md`, `PROGRESS.md`, and the detailed implementation status.
4. Continue the remaining work in [docs/NEXT_STEPS.md](docs/NEXT_STEPS.md),
   preserving the threat model and reporting data- or hardware-dependent
   extensions as unimplemented where appropriate.

Known boundaries remain: no hardware TEE or attestation; no proof that PIR
servers do not collude; a single trusted witness can be rolled back and sees
checkpoint handles that contain snapshot keys; SSE is not backward-private;
the autoscaler is a simulator; and measured attacks cover only their declared
features and workloads.
