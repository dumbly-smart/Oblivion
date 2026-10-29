# Project progress snapshot

**Updated:** 2026-10-29. This is a snapshot; the chronological and source-sensitive record is [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md), and the complete requirement-by-requirement record is [docs/REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md).

## Current state

Oblivion is a functioning Rust research prototype with a selected local end-to-end process path and a substantial collection of component and system experiments. The selected-scope audit reports the required local source gate and hosted source gate passing on their recorded revisions. The full project is **not complete as a production system or as every possible extension in the fourteen-week research roadmap**. Results from historical source revisions remain attached to those revisions and should not be described as current-head validation without rerunning the gate.

Recent commits are being delivered on `codex/oblivion-research-platform` in small increments. The 2026-10-28 ORAM data/report was pushed in commit `03f04b76` after its preregistration commit `1cc21e3b`. The SSE benchmark verifier and standard-library SVG renderer were pushed separately in `1e5a3b75`. The remote mTLS witness service and standalone SSE adapter were pushed in `7db12546` and `b758d0d4` respectively. The remote signed-registry catalog client and CAS integration were pushed in `a2f1281f`; runtime worker mTLS configuration and its end-to-end test were pushed in `1befc5c2`. Standalone remote ORAM checkpoint support was pushed in `a3201105`, followed by the fixed-width/version-2 wire correction in `2b79f0e4`; the expanded witness trust boundary is recorded below and in the security docs. Certificate-to-slot authorization was added in `cfd1a04d`. Runtime remote invocation anchoring was implemented and pushed as `7bee2666`; its serial workspace test, Clippy and formatting results are recorded below.

The post-commit lost-reply case was covered in source commit `4e66221d` and
pushed separately. The new mTLS fault test confirmed the receipt and checkpoint
after a committed finish reply was dropped; the serial workspace suite passed
188 tests, warning-denied Clippy and formatting passed, and no benchmark or
Python suite was run for this test-only increment. The test's exact boundary
and the remaining full-process fault coverage are in
[the implementation status](docs/IMPLEMENTATION_STATUS.md).

Source commit `12c2dd03` adds a real mTLS SSE stale-writer test: the remote
witness rejects a second client opened at an old generation, and a fresh client
recovers and completes the winning pending request. The full serial workspace
suite passed 189 tests with one ignored ORAM stress test; warning-denied Clippy,
formatting, and whitespace checks passed. Benchmarks, the Python suite, and
hosted CI were not run for this test-only change.

## Latest experiment

The 30-trial preregistered ORAM leaf/timing replication completed with both leaky positive controls first and successful:

| Mode | Mean ROC AUC | 95% trial-bootstrap interval |
| --- | ---: | ---: |
| Plaintext baseline | 1.0000 | [1.0000, 1.0000] |
| Encrypt-only baseline | 1.0000 | [1.0000, 1.0000] |
| Path ORAM | 0.4968 | [0.4864, 0.5072] |

Each trial had eight fresh sessions, with disjoint four-session profiling and target sets. The classifier did not reproduce the earlier possible weak timing signal under this workload and isolated handler timing boundary. The interval includes chance. The result is **inconclusive for broader privacy**: it does not exclude smaller effects, alternate workloads/attackers/hosts, end-to-end timing, or other observer views.

The report, frozen preregistration, config, raw traces, hashes, predictions, verifier output, host metadata, and figure are indexed in [REPORTS.md](REPORTS.md) and detailed in [the study report](docs/ORAM_ZIPF16_MARKOV_REPLICATION_20261028.md).

The preregistered persistent SSE journal benchmark also completed: 30 trials at each of 64, 257, 1,024, and 4,093 postings, with five fresh-process recovery opens per index. Mean application journal-byte amplification ranged from 84.037× to 244.754×, while mean index-build time ranged from 3.316 s to 242.889 s. These are local measurements of encrypted application journal frames, not physical or SQLite/WAL write amplification. See the [result report](docs/SSE_JOURNAL_BENCHMARK_20261028_RESULT.md) and raw bundle.

## Implemented and evidenced

- Nine Rust workspace crates: store, PIR, executor, batcher, server, harness, SSE, signed registry, and local anchor service.
- Encrypted Path ORAM with in-memory and bounded file storage, fresh remapping, a trusted position map/stash, integrity/freshness checks, full checkpoints/restore, and a million-operation oracle tier.
- Fixed-record two-server XOR PIR with full scans; a bounded authenticated transport and process-backed worker integration; signed function rows in the demo.
- Wasmtime execution with actual example functions, bounded resources, staged storage access, fixed class I/O, and externally shaped error handling.
- Authenticated fixed-shape epoch envelopes, bounded batching, dummy work, and an actual mixed component demo.
- A separate Python/Rust measurement stack with public observer features separate from ground truth, attacks with controls, trial-cluster uncertainty, raw artifacts, and reproducible plots.
- Constrained GGM-inspired SSE with a persistent-client journal adapter, and an autoscaler simulator with explicitly bounded privacy-mechanism studies.
- Optional local checkpoint/catalog/invocation anchoring, with rollback and key-custody limits documented.
- An optional remote mTLS witness for persistent SSE journals, signed-registry catalog activation, standalone Path ORAM checkpoints, and runtime invocation receipts/checkpoints. Invocation runtime selects either a local Unix anchor or a remote witness through complete, mutually exclusive settings. The witness receives the 88-byte snapshot secret handle and exact response, so it is trusted with snapshot confidentiality and sees receipt contents. Snapshot files remain local, and remote mode has no distributed writer lease or host failover.
- A 30-trial persistent SSE journal size/recovery benchmark runner and completed collection using the real SQLite-backed Unix anchor and fresh recovery processes. The verifier checks all 120 trial/size samples and the retained output includes raw rows, SVG, and checksums.

See the [requirements matrix](docs/REQUIREMENTS_MATRIX.md) for exact requirement-level evidence and explicit partial/unfinished items.

## Validation status

On source commit `7bee2666`, the pinned serial workspace command
`cargo test --locked --workspace -- --test-threads=1` passed 187 tests; its
million-operation Path ORAM stress test is intentionally ignored by default.
The dedicated release command
`cargo test --locked --release -p oblivion-store million_operation_oracle -- --ignored --exact`
also passed (88.76 s). Workspace warning-denied Clippy,
`cargo fmt --all --check`, and `git diff --check` passed. The 24-test server pipeline suite includes a
real mTLS witness process, signed stateful WASM invocation, encrypted snapshot
recovery after witness restart, exact response replay, a later state update,
and replay of an older receipt without checkpoint rollback. Startup rejects
partial/conflicting remote configuration. No performance benchmark or Python
suite was run locally for this Rust-only integration. Hosted run
[40824696959](https://github.com/dumbly-smart/Oblivion/actions/runs/40824696959)
passed Rust quality and analysis; the workflow's separate stress job was
skipped, and the dedicated release stress command passed locally.

The latest ORAM run's focused Python checks passed 12 tests, both release measurement examples built, and an independent verifier rechecked the frozen output hashes, paired session schedules, CPU metadata, trial means, bootstrap intervals, and disjoint splits. See the result report.

The selected-scope serial Rust/Python/stress gate and hosted CI were recorded as passing on their documented earlier source revision. The runtime mTLS worker increment also passed a fresh pinned serial workspace suite and warning-denied Clippy locally. Hosted run [40758604155](https://github.com/dumbly-smart/Oblivion/actions/runs/40758604155) passed all three jobs for code commit `1befc5c2`, including the million-operation ORAM stress oracle; exact local evidence is in [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md). This evidence is not a substitute for a fresh whole-repository run on every later commit.

For the remote-witness increment, a fresh serial `cargo test --locked --workspace -- --test-threads=1` run exited 0, with every enabled workspace test passing, including mTLS service authentication, outage handling, service restart, slow-drip deadline enforcement, and rejection of a restored application journal when the witness retains a newer head. The million-operation ORAM stress test remains intentionally ignored in this default command. Workspace warning-denied Clippy, formatting, and whitespace checks pass. The earlier CPU-contention timeout remains historical evidence. The venv Python suite's prior 240-test result is unchanged because this increment does not modify Python. Details are in [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

For source commit `a3201105`, the pinned serial command
`taskset -c 21 cargo test --locked --workspace -- --test-threads=1` completed
with all enabled tests passing; the million-operation ORAM stress test remains
ignored by this default suite. Whole-workspace warning-denied Clippy and
formatting passed. The new mTLS integration test stores a real ORAM checkpoint,
restarts the witness, restores and reads actual data, advances the CAS, and
rejects the stale controller. Hosted run
[40809388355](https://github.com/dumbly-smart/Oblivion/actions/runs/40809388355)
passed Rust quality, the million-operation ORAM stress oracle, and analysis on
the exact source SHA. Concurrent run
[40809398937](https://github.com/dumbly-smart/Oblivion/actions/runs/40809398937)
also passed Rust quality and analysis, with the stress job skipped by workflow
concurrency. No performance benchmark was run for this adapter. See the
appended `a3201105` record in [implementation status](docs/IMPLEMENTATION_STATUS.md).

Follow-up source commit `2b79f0e4` changes the remote protocol to version 2 and
encodes the 88-byte snapshot handle as a fixed 176-character hex field, so the
serialized length no longer depends on secret byte values. Version-1 peers are
rejected. The anchor all-targets suite passed 44 tests; whole-workspace
warning-denied Clippy and formatting passed. Hosted checks for this follow-up
are pending. See its separate implementation-status entry.

The independent benchmark verifier has 8 passing Python tests and successfully revalidated the full report at source revision `5fe4f603`; the report's checksums pass. The verifier commit is pushed separately from the raw result commit.

On source commit `cfd1a04d`, the versioned mTLS certificate-to-slot policy
passed the full serial Rust workspace suite, warning-denied workspace Clippy,
formatting, whitespace validation, CLI help inspection, and the changed-doc
link check (328 relative links across 12 files). The default test run leaves
the million-operation ORAM stress case intentionally ignored. Hosted runs
[40813595940](https://github.com/dumbly-smart/Oblivion/actions/runs/40813595940)
and [40813584568](https://github.com/dumbly-smart/Oblivion/actions/runs/40813584568)
were still in progress when this snapshot was written.

Correctness test integration uses one Rust test thread because these fixtures have real deadlines and can be delayed by local CPU contention. Benchmark concurrency and production deadlines have not been silently changed to make tests pass.

## Remaining limits and work

1. **No TEE:** process isolation and Wasmtime are not hardware confidentiality. TEE, attestation, host-root defense, and hardware side channels need supported hardware and a separate design/review.
2. **PIR assumption:** the two servers must not collude; the current process topology does not enforce independent operators.
3. **Freshness root:** local catalog, checkpoint, invocation-receipt, and local SSE freshness rely on the local SQLite anchor and key remaining trusted. A privileged database rollback can undo them. Standalone SSE, signed-registry, Path ORAM checkpoint, and runtime invocation clients can instead use one independent mTLS witness; rolling back, compromising, or losing that witness removes its freshness guarantee. For ORAM checkpoints and runtime invocation receipts, the witness sees the snapshot key and can decrypt snapshots it can access. The witness validates the configured client CA and then applies a versioned SHA-256 DER leaf-certificate-to-slot allowlist; policy changes require restart. Per-slot request quotas and rate limits remain unimplemented. Runtime remote receipts now work, but host-independent writer fencing, replicated rollback resistance, and hardware anti-rollback remain research/deployment work.
4. **Execution leakage:** fixed resource-access count and frame shapes do not make CPU work constant-time. Scheduling, cache behavior, completion time, deadlines, active failures, participation, and host-level resource observations remain.
5. **SSE:** constrained GGM-inspired construction is not a complete Diana implementation. Search equality, result volume, timing, and historical capability/linkability leak; no backward privacy is claimed. The persistent journal cost is measured. A standalone mTLS witness detects application-host journal rollback under its single-operator trust assumption; witness rollback resistance, replicated acknowledgment, and runtime integration remain.
6. **Autoscaling:** the subsystem is a simulator, not provisioning. Mechanism arguments depend on declared adjacency, bounded horizon, sampler, and observer; public seeded artifacts are not DP releases.
7. **Evaluation coverage:** each experiment evaluates specified features, workload, classifier, and host boundary. Run fresh controlled-host replications and explore other workload and attacker families; do not generalize near-chance studies.
8. **Production readiness:** no cryptographic audit, formal composition theorem for the complete system, remote deployment capacity/cost calibration, or general transactional external side-effect guarantee.

## Next engineering sequence

1. Keep the root contributor/architecture/report/progress/explanation guides consistent with the canonical technical docs.
2. Before multiple remote workers are supported, design a host-independent writer-fencing protocol; compare a single trusted witness against a genuinely replicated rollback-resilient register. The witness commit-then-drop-reply case now has a focused mTLS request-handler test.
3. Continue the bounded SSE implementation only with a written leakage target, positive controls, and explicit search/update/recovery failure behavior.
4. Continue bounded independent ORAM replication only with a frozen protocol, passed controls, new sessions, and an available host whose noise/provenance limitations are recorded.
5. Run current-source local and hosted validation after meaningful code changes; update this snapshot with exact revision, commands, results, and any failures.

No item in this snapshot turns the prototype into an audited or production-safe system. The roadmap remains the authority for the broader research program.
