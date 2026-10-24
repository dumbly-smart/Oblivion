# Foundation and Path ORAM implementation plan

Historical implementation sequence. Updated status is in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and the full acceptance mapping in [REQUIREMENTS_MATRIX.md](REQUIREMENTS_MATRIX.md). Later increments now include generic encrypted PIR, staged multi-client execution, file/checkpoint APIs, ephemeral GGM SSE, genuine reference PIR and autoscaler experiments. The dated decisions below describe their original stage rather than the current completion boundary.

Goal: a functioning tested encrypted block store before PIR and execution integration.
Spec: ../Oblivion_ Research Roadmap and Build Plan (1).md and ARCHITECTURE.md.
Execution: inline in the supplied checkout, preserving user files; ordinary implementation and tests are explicitly authorized. No publishing or merging is requested.

## Constraints and review focus

Stable Rust 2024; Z=4 default; secure runtime randomness; fixed block/bucket lengths; trusted executor simulation only. Review partial writes, replayed ciphertext, duplicate blocks, invalid geometry/allocation bounds, and lost trusted state. No restart guarantee or constant-time controller guarantee.

## Tasks

- [x] Foundation + correctness: create workspace and failing tests for zero initialization and a seeded plaintext-oracle workload. Implement `Config`, `Backend`, `MemoryBackend`, `PathOram` with typed errors. Test command: `cargo test -p oblivion-store`.
- [x] Adversarial behavior: write corruption/replay/backend failure, invalid input, shape and re-encryption tests before implementation. Enforce bounded geometry, authenticated bucket location/version, poison-on-uncertain-state behavior. Test invariant correctness throughout randomized workloads.
- [x] Stress and measurement: add an ignored million-operation oracle test; an executable benchmark emits separate observer, private and metadata files, reads and writes latency percentiles, bandwidth, stash and state sizes. Add seeded multi-trial leaf-distribution analysis, with clear statistical limits.
- [x] Quality and documentation: run fmt, clippy all targets, workspace tests, release stress as feasible, benchmark smoke and statistical analysis. Add CI, reproducibility commands, security assumptions, actual status and precise next actions.
- [x] Advance to PIR only after the block store passes its relevant checks; retain the MVP dependency order.

Progress, actual results and deviations are recorded in IMPLEMENTATION_STATUS.md.

## Next implemented increment: PIR and executor

PIR tests precede the implementation: fixed-shape recovery and collusion identity, malformed dimensions, 10,000 x 1 KiB retrieval, broad per-bit distribution diagnostics, two independent server subprocesses, and unavailable server behavior. The localhost plaintext wire is an explicit experimental simplification and does not protect both shares from a joint network observer.

Executor tests precede implementation: five actual WAT modules (copy, sum, iterative Fibonacci, noncryptographic checksum, and stateful increment), real ORAM host I/O, fixed input/output classes, fuel exhaustion, guest trap, memory allocation/growth failures, bad input, invalid modules, and wall-clock epoch interruption. Class validation bounds allocations and module count/bytes. Compilation occurs before invocation measurements. A dedicated engine ticker interrupts guest code; synchronous host I/O must itself be bounded, and is not preemptible by Wasmtime epochs. Fuel is charged separately for host calls. Responses are padded to the class deadline with measured jitter remaining. This in-process executor library is not yet the promised process-isolated executor service.

## Epoch implementation decision

Envelopes have a 20-byte authenticated public header (magic/version/direction/epoch/participant), 128 encrypted payload bytes, and a 16-byte tag. HKDF separates request and response keys. Move-only endpoints enforce strictly increasing sending epochs and reject receiving replays. Nonces derive from participant and epoch under ephemeral session keys. Durable state and key provisioning across services remain pending.

One bounded pending request per participant enforces backpressure. Fixed emission deadlines advance independently of load. Missing participants get random ciphertext cover; authentication failure must trigger equivalent downstream dummy work. The queue itself does not establish end-to-end indistinguishability, and its missing-slot list describes public participation, not real/dummy identity.

## Current completion boundary

The initial store plan and subsequent PIR/executor/batcher/process integration/component-attack increments have executed evidence in IMPLEMENTATION_STATUS.md. Hosted CI, general multi-client composition and the full research evaluation remain pending; the complete roadmap is not marked complete. No branch integration/publication was requested.
