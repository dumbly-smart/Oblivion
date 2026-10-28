# Project progress snapshot

**Updated:** 2026-10-28. This is a snapshot; the chronological and source-sensitive record is [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md), and the complete requirement-by-requirement record is [docs/REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md).

## Current state

Oblivion is a functioning Rust research prototype with a selected local end-to-end process path and a substantial collection of component and system experiments. The selected-scope audit reports the required local source gate and hosted source gate passing on their recorded revisions. The full project is **not complete as a production system or as every possible extension in the fourteen-week research roadmap**. Results from historical source revisions remain attached to those revisions and should not be described as current-head validation without rerunning the gate.

Recent commits are being delivered on `codex/oblivion-research-platform` in small increments. The new 2026-10-28 ORAM data/report was pushed in commit `03f04b76` after its preregistration commit `1cc21e3b`.

## Latest experiment

The 30-trial preregistered ORAM leaf/timing replication completed with both leaky positive controls first and successful:

| Mode | Mean ROC AUC | 95% trial-bootstrap interval |
| --- | ---: | ---: |
| Plaintext baseline | 1.0000 | [1.0000, 1.0000] |
| Encrypt-only baseline | 1.0000 | [1.0000, 1.0000] |
| Path ORAM | 0.4968 | [0.4864, 0.5072] |

Each trial had eight fresh sessions, with disjoint four-session profiling and target sets. The classifier did not reproduce the earlier possible weak timing signal under this workload and isolated handler timing boundary. The interval includes chance. The result is **inconclusive for broader privacy**: it does not exclude smaller effects, alternate workloads/attackers/hosts, end-to-end timing, or other observer views.

The report, frozen preregistration, config, raw traces, hashes, predictions, verifier output, host metadata, and figure are indexed in [REPORTS.md](REPORTS.md) and detailed in [the study report](docs/ORAM_ZIPF16_MARKOV_REPLICATION_20261028.md).

## Implemented and evidenced

- Nine Rust workspace crates: store, PIR, executor, batcher, server, harness, SSE, signed registry, and local anchor service.
- Encrypted Path ORAM with in-memory and bounded file storage, fresh remapping, a trusted position map/stash, integrity/freshness checks, full checkpoints/restore, and a million-operation oracle tier.
- Fixed-record two-server XOR PIR with full scans; a bounded authenticated transport and process-backed worker integration; signed function rows in the demo.
- Wasmtime execution with actual example functions, bounded resources, staged storage access, fixed class I/O, and externally shaped error handling.
- Authenticated fixed-shape epoch envelopes, bounded batching, dummy work, and an actual mixed component demo.
- A separate Python/Rust measurement stack with public observer features separate from ground truth, attacks with controls, trial-cluster uncertainty, raw artifacts, and reproducible plots.
- Constrained GGM-inspired SSE with a persistent-client journal adapter, and an autoscaler simulator with explicitly bounded privacy-mechanism studies.
- Optional local checkpoint/catalog/invocation anchoring, with rollback and key-custody limits documented.

See the [requirements matrix](docs/REQUIREMENTS_MATRIX.md) for exact requirement-level evidence and explicit partial/unfinished items.

## Validation status

The latest ORAM run's focused Python checks passed 12 tests, both release measurement examples built, and an independent verifier rechecked the frozen output hashes, paired session schedules, CPU metadata, trial means, bootstrap intervals, and disjoint splits. See the result report.

The repository's selected-scope serial Rust/Python/stress gate and hosted CI were recorded as passing on their documented earlier source revision. That is valuable historical evidence but is not a substitute for a fresh whole-repository run on every later commit. The current Markdown guides need link/format checks; a docs-only update does not rerun cryptographic or runtime correctness.

Correctness test integration uses one Rust test thread because these fixtures have real deadlines and can be delayed by local CPU contention. Benchmark concurrency and production deadlines have not been silently changed to make tests pass.

## Remaining limits and work

1. **No TEE:** process isolation and Wasmtime are not hardware confidentiality. TEE, attestation, host-root defense, and hardware side channels need supported hardware and a separate design/review.
2. **PIR assumption:** the two servers must not collude; the current process topology does not enforce independent operators.
3. **Freshness root:** the local SQLite anchor and key rely on OS access controls. A privileged database rollback can undo version, receipt, and journal freshness. A remote/hardware rollback-resistant anchor remains research/deployment work.
4. **Execution leakage:** fixed resource-access count and frame shapes do not make CPU work constant-time. Scheduling, cache behavior, completion time, deadlines, active failures, participation, and host-level resource observations remain.
5. **SSE:** constrained GGM-inspired construction is not a complete Diana implementation. Search equality, result volume, timing, and historical capability/linkability leak; no backward privacy is claimed. Measure persistent journal write amplification/recovery and address distributed acknowledgment/freshness limits.
6. **Autoscaling:** the subsystem is a simulator, not provisioning. Mechanism arguments depend on declared adjacency, bounded horizon, sampler, and observer; public seeded artifacts are not DP releases.
7. **Evaluation coverage:** each experiment evaluates specified features, workload, classifier, and host boundary. Run fresh controlled-host replications and explore other workload and attacker families; do not generalize near-chance studies.
8. **Production readiness:** no cryptographic audit, formal composition theorem for the complete system, remote deployment capacity/cost calibration, or general transactional external side-effect guarantee.

## Next engineering sequence

1. Keep the root contributor/architecture/report/progress/explanation guides consistent with the canonical technical docs.
2. Follow [docs/NEXT_STEPS.md](docs/NEXT_STEPS.md): measure persistent SSE journal write amplification and recovery latency across increasing index sizes; preserve fresh raw evidence and controls.
3. Specify a freshness source that survives privileged rollback before claiming anti-rollback. Evaluate a hardware or independently administered anchor only where supported.
4. Continue bounded independent ORAM replication only with a frozen protocol, passed controls, new sessions, and an available host whose noise/provenance limitations are recorded.
5. Run current-source local and hosted validation after meaningful code changes; update this snapshot with exact revision, commands, results, and any failures.

No item in this snapshot turns the prototype into an audited or production-safe system. The roadmap remains the authority for the broader research program.
