# Project progress snapshot

**Updated:** 2026-10-28. This is a snapshot; the chronological and source-sensitive record is [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md), and the complete requirement-by-requirement record is [docs/REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md).

## Current state

Oblivion is a functioning Rust research prototype with a selected local end-to-end process path and a substantial collection of component and system experiments. The selected-scope audit reports the required local source gate and hosted source gate passing on their recorded revisions. The full project is **not complete as a production system or as every possible extension in the fourteen-week research roadmap**. Results from historical source revisions remain attached to those revisions and should not be described as current-head validation without rerunning the gate.

Recent commits are being delivered on `codex/oblivion-research-platform` in small increments. The 2026-10-28 ORAM data/report was pushed in commit `03f04b76` after its preregistration commit `1cc21e3b`. The SSE benchmark verifier and standard-library SVG renderer were pushed separately in `1e5a3b75`.

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
- A 30-trial persistent SSE journal size/recovery benchmark runner and completed collection using the real SQLite-backed Unix anchor and fresh recovery processes. The verifier checks all 120 trial/size samples and the retained output includes raw rows, SVG, and checksums.

See the [requirements matrix](docs/REQUIREMENTS_MATRIX.md) for exact requirement-level evidence and explicit partial/unfinished items.

## Validation status

The latest ORAM run's focused Python checks passed 12 tests, both release measurement examples built, and an independent verifier rechecked the frozen output hashes, paired session schedules, CPU metadata, trial means, bootstrap intervals, and disjoint splits. See the result report.

The repository's selected-scope serial Rust/Python/stress gate and hosted CI were recorded as passing on their documented earlier source revision. That is valuable historical evidence but is not a substitute for a fresh whole-repository run on every later commit. The root guides and benchmark preregistration have local link/diff checks; those do not rerun or replace cryptographic and runtime correctness.

For the current journal-benchmark implementation, the fresh real-anchor/fresh-process integration test and all 21 SSE crate tests pass; workspace formatting and warning-denied Clippy pass. A fresh serial `cargo test --locked --workspace -- --test-threads=1` run exited 0, with every enabled workspace test passing; the million-operation ORAM stress test remains intentionally ignored in this default command. The earlier CPU-contention timeout and its isolated pass remain historical evidence, not the current result. The venv Python suite also passed 240 tests with four skips. Details are in [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

The independent benchmark verifier has 8 passing Python tests and successfully revalidated the full report at source revision `5fe4f603`; the report's checksums pass. The verifier commit is pushed separately from the raw result commit.

Correctness test integration uses one Rust test thread because these fixtures have real deadlines and can be delayed by local CPU contention. Benchmark concurrency and production deadlines have not been silently changed to make tests pass.

## Remaining limits and work

1. **No TEE:** process isolation and Wasmtime are not hardware confidentiality. TEE, attestation, host-root defense, and hardware side channels need supported hardware and a separate design/review.
2. **PIR assumption:** the two servers must not collude; the current process topology does not enforce independent operators.
3. **Freshness root:** the local SQLite anchor and key rely on OS access controls. A privileged database rollback can undo version, receipt, and journal freshness. A remote/hardware rollback-resistant anchor remains research/deployment work.
4. **Execution leakage:** fixed resource-access count and frame shapes do not make CPU work constant-time. Scheduling, cache behavior, completion time, deadlines, active failures, participation, and host-level resource observations remain.
5. **SSE:** constrained GGM-inspired construction is not a complete Diana implementation. Search equality, result volume, timing, and historical capability/linkability leak; no backward privacy is claimed. The persistent journal cost is now measured; distributed acknowledgment and rollback-resistant freshness remain.
6. **Autoscaling:** the subsystem is a simulator, not provisioning. Mechanism arguments depend on declared adjacency, bounded horizon, sampler, and observer; public seeded artifacts are not DP releases.
7. **Evaluation coverage:** each experiment evaluates specified features, workload, classifier, and host boundary. Run fresh controlled-host replications and explore other workload and attacker families; do not generalize near-chance studies.
8. **Production readiness:** no cryptographic audit, formal composition theorem for the complete system, remote deployment capacity/cost calibration, or general transactional external side-effect guarantee.

## Next engineering sequence

1. Keep the root contributor/architecture/report/progress/explanation guides consistent with the canonical technical docs.
2. Specify a freshness source that survives privileged rollback before claiming anti-rollback. Compare a separately administered witness with a replicated rollback-resilient register, and state the required operator/failure assumptions.
3. Continue the bounded SSE implementation only with a written leakage target, positive controls, and explicit search/update/recovery failure behavior.
4. Continue bounded independent ORAM replication only with a frozen protocol, passed controls, new sessions, and an available host whose noise/provenance limitations are recorded.
5. Run current-source local and hosted validation after meaningful code changes; update this snapshot with exact revision, commands, results, and any failures.

No item in this snapshot turns the prototype into an audited or production-safe system. The roadmap remains the authority for the broader research program.
