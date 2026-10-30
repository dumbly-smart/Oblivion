# Completion plan: generalized privacy pipeline

The user's request authorizes continuous implementation of the remaining roadmap. Work continues in the supplied checkout without discarding the original untracked research/source artifacts. Existing checks/results are historical evidence, not evidence for later edits. The complete roadmap and docs/NEXT_STEPS.md remain the specification.

## Current increment: fixed storage schedule

Protected execution will prefetch a public, bounded state working set through actual ORAM reads, execute guest storage calls against a trusted staged snapshot, then write every working-set block through ORAM at a public commit phase. Every invocation, invalid input, unknown module and guest trap receives the same successful-backend operation count and read/commit phase structure. Failed guest work discards staged mutations. A failed physical commit still invalidates the ORAM controller; it is not a durable atomic transaction.

This deliberately trades bandwidth O(M log N) for compositional clarity, where M is the public working-set size. It retains actual encrypted Path ORAM and does not label plaintext server storage oblivious. Trusted staging is bounded by the class memory budget. Classes publish working-set size, host-call budget, guest fuel/memory, I/O and deadlines. A trusted namespace maps guest addresses into enrolled user or reserved dummy state, preventing guests from reading dummy counters.

Read/commit phases start independently of guest completion; the commit boundary is half the public deadline. Guest epochs use the remaining compute phase. Slow storage, scheduler jitter, resource/billing observations and deadline misses remain measured residual leakage. The trusted process has no TEE guarantee. The unpadded baseline keeps direct storage calls for positive controls.

Interfaces: add BlockStorage::blocks(); public Namespace(first, blocks); Class::state_blocks; Executor::execute_scheduled(id,input,storage,namespace,started). Keep existing execute and execute_unpadded_baseline callers working. Existing Host imports operate on the staged namespace, not the physical backend. Stateful guest ABI stays unchanged.

- [ ] Add failing real-ORAM tests comparing copy, arithmetic, stateful, input error, trap and fuel failure physical transcripts; test writes followed by trap do not persist, namespace bounds and dummy isolation.
- [ ] Implement staged prefetch/commit with bounded allocations and typed status, preserving observer/private separation. Verify all relevant tests.
- [ ] Generalize worker to enrolled clients, namespaced real/dummy state, mixed functions, explicit slot/epoch checks, bounded I/O/startup/shutdown and end-to-end phase deadline.
- [ ] Replace five-record encrypted PIR adapter with generic fixed-geometry authenticated transport; independent worker owns that change and its tests.
- [ ] Extend joint observer capture and A–G process evaluations, independent sessions and trial-cluster inference; retain successful positive controls.
- [ ] Implement durable authenticated snapshots with explicit trusted freshness anchor and fault semantics; do not claim rollback protection without an external anchor.
- [ ] Complete SSE implementation after source-backed design verification and stabilized generalized MVP, then advanced PIR/attacks and autoscaler simulator.
- [ ] Run database/epoch/workload sweeps and reproducible metric/Pareto figures; run local quality gates, review and hosted CI if authenticated environment permits.

Independent SSE source verification runs concurrently with runtime implementation; it does not substitute for later implementation/tests. Every result and remaining limitation will be recorded in IMPLEMENTATION_STATUS.md as tasks complete.
