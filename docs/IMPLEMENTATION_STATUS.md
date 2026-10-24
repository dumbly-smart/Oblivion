# Implementation and evidence status

**Selected-scope acceptance:** the [serial local gate](../experiments/results/validation-20261023-serial/commands.json) passed all ten commands, including 91 core Rust tests, one reference test, 120 Python tests without skips and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-serial/metadata.json) match: `a83d606782f63e9f5c9f8b95a3c80b299f57da30c916de670f61751e8068becc`. All three jobs in [hosted run 39971009249](https://github.com/dumbly-smart/Oblivion/actions/runs/39971009249) for `ade31d2c` passed. The selected roadmap software and empirical deliverables, local gate and hosted source gate are accepted within the documented boundaries. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery; no merge is claimed. Subsequent closing Markdown-only checks are accessible on the PR and do not create a new unfinished source requirement.

The later failed [historical run 39969711451](https://github.com/dumbly-smart/Oblivion/actions/runs/39969711451) remains preserved: Rust failed while analysis/stress passed, and its specific cause remains unproved. [Three-arm scheduling diagnostics](PIPELINE_TEST_SCHEDULING.md) reproduced authenticated timeouts under CPU contention: pinned two-CPU parallel tests had two timeouts, the same serial suite passed, and one CPU with 16 competitors produced an actual 218 ms Timeout with both PIR operations and 128 storage events. Correctness suites explicitly use `--test-threads=1`; production budgets, benchmark concurrency and retry behavior are unchanged.

After adding the isolated ORAM service and fresh timing study, the current
source passed all ten commands in
[`validation-20261025-oram`](../experiments/results/validation-20261025-oram/commands.json).
The before/after source fingerprints match. The gate covered workspace and
reference formatting, clippy, tests and builds; 133 Python tests with four
existing skips; and the million-operation ORAM oracle. The Python validator
also supplied freshly built ORAM binaries to the isolated-process integration
tests.

Updated 2026-10-23. The selected pipeline and later bounded research artifacts now have evidence in [the requirements matrix](REQUIREMENTS_MATRIX.md) and [completion audit](COMPLETION_AUDIT.md). The selected artifacts and earlier passing gates are recorded. PR #1 is the review artifact while latest validation closure is held; no production-security or merge claim follows. TrustedExecutor is simulated by ordinary processes, without a hardware TEE or attestation.

## Implemented system

Seven Rust crates implement encrypted Path ORAM, two-server XOR PIR, Wasmtime execution, authenticated epoch batching, process orchestration, trace generation and constrained GGM SSE. The current process path supports one to four clients, all five actual functions, disjoint user/dummy state, SSE metadata discovery, encrypted PIR, independent output/counter oracles and fixed 164-byte invocation/response envelopes.

Protected execution reads eight blocks at the public 25 ms phase and commits eight at 50 ms. Guest failures discard staged mutations; uncertain backend failure can poison partially written state. At eight logical blocks an invocation emits 128 actual bucket events of 316 bytes, with O(M log N) bandwidth for public working-set M. Trusted drivers prepare encrypted responses/private instrumentation before the 100 ms publication wait. Clients prepare requests before their public epoch. Slot starts are epoch arrival plus slot × 100 ms. OS scheduling and work overruns remain visible.

The current response reader timestamps completion immediately after `read_exact`, before channel handoff and later client decryption/oracle/logging. Public pipe timing and separate private client latency are not interchangeable. The process demo remains ephemeral. Separate bounded file/checkpoint recovery authenticates full snapshots and rekeys against a trusted latest handle; it does not implement durable invocation acknowledgments, whole-anchor replay protection or persistent SSE.

The built-in demo's real/dummy/function schedule is public given its code, real percentage and epoch. It validates correctness/topology, not anonymity against an adversary who knows that schedule. Research datasets keep workload labels/seeds outside each declared attack input; public cadence, classes, batch size and geometry remain known. Encryption cannot hide an identity already determined by auxiliary knowledge.

## Accepted bounded measurements

| Evidence | What actually ran | Result and boundary |
| --- | --- | --- |
| [Joint A–G/ablations](SYSTEM_EXPERIMENTS.md) | 30 fitted-model trials; 1,920 observations/mode on actual libraries | Final G balanced accuracy 33.40% [32.29,34.51], chance 33.33%. Declared summary-feature attacker, not every host observation |
| [Execution/errors](EXECUTION_EVALUATION.md) | Five functions plus three failures, 30 trials, visible-selector control first | Protected eight-class accuracy 11.67% [9.38,13.75], chance 12.5%; 960 protected output/status checks, fixed frames/storage shapes; saved earlier binary |
| [Actual trace validation](TRACE_VALIDATION.md) | 100k ORAM accesses/workload and 30 scoped encrypted PIR captures | 1.4M bucket events/workload; 3,000 verified PIR retrievals, 6,000 streams, 61,363 packets and zero reported drops. Unvalidated packet classifier excluded |
| [ORAM leaf+timing](ORAM_LEAF_TIMING.md) | Independent profile/target sessions and 30 fitted trials | Balanced accuracy 50.70% [49.80,51.62]; AUC 0.511 [0.501,0.521] is a possible weak signal, retained with unadjusted/multiple-metric caveats |
| [Individual-server PIR timing](PIR_TARGET_TIMING.md) | 46,080 oracle-checked requests at two geometries; real visible-index control first | Protected joint/timing/share intervals include three-class chance; only own share/local answer time, not collusion or network timing |
| [SSE methods](SSE_ATTACKS.md), [inference](ADVANCED_ATTACKS.md), [chosen updates](UPDATE_LINKABILITY.md) | Actual encrypted postings/capabilities and 30 trial clusters | Six bounded SSE-facing methods and successful controls; equality/volume/later authorization still leak; not faithful published attack reproductions |
| [Real corpus/drift](CORPUS_EVALUATION.md) | Licensed UCI text associations, genuine SSE/dummy padding, 30 conditional resamples | Likelihood 64.35% matched auxiliary → 36.35% strongest document drift; padded 38.88%. Synthetic queries; shared corpus across resamples |
| [Presence/intersection](PRESENCE_EVALUATION.md) | Actual authenticated batcher frames with virtual epochs | Online-only fixed-rate clients remain identifiable under the explicit semantic beacon. Always-participating endpoints leave eight candidates; no packet-timing claim |
| [Geometry/stash](GEOMETRY_EVALUATION.md) | 42 cells × 30 trials; 138,240 ORAM accesses / 2,880 PIR queries | Genuine full-record oracles, payload/map/stash accounting and histograms; observed maxima are not rare-overflow bounds or remote RSS |
| [Matched Path/Circuit reference](CIRCUIT_ORAM_REFERENCE.md) | Genuine MobileCoin 2.3.0 implementations; 61,440 timed accesses / 193,920 full-record checks | Matched unencrypted trusted heap, 30 trials/cell, separate GPL workspace. Not core Path ORAM replacement or network/TEE comparison |
| [Square-root PIR](SQRT_PIR.md) | Actual packed-row queries/recovery; 5,760 checked retrievals | Smaller queries, potentially much larger answers; all padded bytes still scanned. Private column, non-colluding servers, no symmetric-PIR claim |
| [SimplePIR reference](SIMPLEPIR_REFERENCE.md) and [100k summary](../experiments/results/simplepir-100k-20261023/summary.json) | Genuine pinned Go/C SimplePIR and matched XOR, 30 setups each; 100,020 queries/scheme | Every full eight-byte output matches. Real hint/setup/online accounting; within-setup outcomes dependent, no worst-case LWE failure theorem |
| [Executor resources/CPU](EXECUTOR_RESOURCES.md) | Separate original resource and direct-CPU campaigns, each 180 processes / 2,160 calls | Setup/compile, first/warm, public classes, process/thread invocation CPU and success/failure denominators. Wall padding is not CPU waste |
| [Extended open loop](RUNTIME_BENCHMARKS.md) | 180 fresh processes / 5,760 offers, six load/queue cells | Queue/drop/admitted latency/SLO tradeoffs retained; 32 offers/trial do not establish population tails or production capacity |
| [Integrated epochs](EPOCH_SYSTEM_EVALUATION.md) | Final reader-thread pipe campaign: 360 process trees / 2,160 verified calls | 12 cells × 30; strict public/private separation, 1,080 real/1,080 dummy successes, 2,955 artifact hashes; scoped provenance differences below |
| [Joint batching load](BATCH_LOAD_EVALUATION.md) | 720 independent processes; 30 fitted models/mode, 180 held-out targets/mode | Actual plaintext control 100%; AEAD protected 28.33% [22.78,33.89] against 33.33%. Same 22 public features/metric; two failed forest controls retained |
| [Repeated faults](FAULT_CAMPAIGN.md) | Seven assertion-bearing fixtures × 30, 210 launches | All assertions pass for stated scenarios. Original ENOSPC/truncated-publication attempt remains excluded/incomplete, not silently overwritten |
| [Autoscaler](AUTOSCALER.md) | Five policies, four synthetic workloads, two 30-trial simulator campaigns | Nominal cost/privacy/SLO panels and failed burst objectives retained; hypothetical prices, no real provisioning or DP |
| [Attack API](ATTACK_INTERFACE.md) | 13 registered adapters with common PredictionResult and strict schemas | Uncalibrated confidence remains absent. Adapter availability is not extra experimental evidence |
| [Actual demo](DEMO.md) | Three-client mixed SSE/PIR/WASM/ORAM run | 24 calls, 12 real, all five functions, 24 metadata queries and 3,072 storage events; MP4/terminalcast/raw records. Public deterministic schedule, not privacy evidence |

The final A–G report's per-real API p95/p99 are 100.159/100.200 ms; opportunity wall time 116.268 ms and goodput 4.3004/s include the stated initial wait/oracle/logging scope. Accounted payload is 82,484 bytes/real at 50% dummy load. A/E/G nominal three-axis membership uses explicitly hypothetical executor-wall/egress prices. Neither provider calibration nor universal statistical dominance is claimed or required to possess the stated plots.

## Chronology and provenance limits

The stopped 18-trial `system-30-20261021/` pilot has an incorrect measurement/oracle boundary and is excluded. The genuine earlier corrected system run retains possible conditional function inference 54.58% [50.21,59.17]. Later encrypted preparation/publication changes and fresh data do not erase that result.

The first integrated epoch campaign mixed private instrumentation into an observer-named file and is excluded from attacker input. The second separates fields but timestamps client consumption after channel handoff. Only `epoch-system-pipe-timestamps-20261023/` claims the reader-thread pipe boundary. Its immutable binary/source copies are authoritative: 251 live checkout fingerprints matched the snapshot; 109 reflect an unrelated PIR timing example's Clippy edit. Later checked default-wrapper input bounds/regressions differ from the measured tree but do not change the measured valid `demo-sweep` path or reader. No false global before/after checkout equality is asserted.

The two failed batch-load forest controls never generated protected data. Original source snapshots/retrospective provenance explicitly retain their missing terminal/start-time proof limitation. The final class-centroid campaign writes durable source/config/binary/hardware provenance before measurement and verifies hashes afterward. Older 10 ms/two-ORAM-operation demos remain historical; current protected calls use sixteen logical accesses and 100 ms classes.

## Validation and delivery gates

Historical `validation-20261022-frozen/` has five zero exits and matching source fingerprints, including 53 Python checks with one explicit optional skip and a separate million-operation stress tier. It does not validate later additions. All three jobs in [historical hosted run 39969191581](https://github.com/dumbly-smart/Oblivion/actions/runs/39969191581) for `d80f258c` passed on the earlier locally verified source. Those green records and the later failed hosted run remain preserved. The new explicit serial correctness-test policy changed CI/validator inputs; validation-20261023-serial and hosted ade31d2c/39971009249 subsequently passed, as recorded above. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is the review artifact; no merge is claimed.

Two ten-command local attempts remain preserved and unaccepted as complete gates. `validation-20261023-final/` has nine zero exits and a workspace harness Timeout. `validation-20261023-current-source/` passes workspace tests but its 112-test Python run has one authenticated `demo-sweep` invocation failure; its private cause was not retained and remains unknown. A deterministic Timeout regression does not establish that historical cause.

The fresh [verified local gate](../experiments/results/validation-20261023-verified/commands.json) passed all ten commands: 90 core Rust tests, one reference test, 119 Python tests with all four runtime fixtures and no skips, both workspaces' quality/build checks, and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-verified/metadata.json) match; that historical gate passed for its recorded source. The default validator builds core release fixtures and the separate GPL reference, runs both workspaces' gates, enables all four Python runtime fixtures and executes million-operation stress. The ten-command local pass applies to that recorded source identity; it does not substitute for final-head hosted CI.

The research-only `demo-sweep` now retains authenticated masked runtime failures, including their timing, CPU and completed interface work, while successful outputs still require full independent oracles. Legacy `demo`/`demo-sse` stay strict; budgets, reader timestamps and retry behavior are unchanged. Primary CPU/byte cost per real success is a ratio of sums that includes zero-success trials' costs; unknown partial PIR-byte costs, undefined totals and bootstrap draws are explicit, with no unconditional finite interval when a draw is undefined. Historical completed campaigns had zero runtime errors and were not rerun or rewritten. See [the post-measurement policy](EPOCH_SYSTEM_EVALUATION.md#post-measurement-runtime-error-retention).

[The figure reproduction audit](FIGURE_REPRODUCTION.md) now records raw-derived regeneration of all eight required main figures and the supplemental three-axis/SLO plot without ignored measurement executables. Both autoscaler campaigns rebuild from four raw/config files rather than cached reports; audited numerical reports and PNG bytes matched, and accepted inputs stayed unchanged. The serial local and hosted source gates are accepted; subsequent closing Markdown-only checks are accessible on PR #1.

Selected implementation/evaluation and the serial local/hosted source gates are accepted within their bounded scope. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery on `codex/oblivion-research-platform`; no main merge is claimed. Hardware isolation, formal DP, recursive/native Circuit storage, DPF/native single-server runtime selection, persistent/backward-private SSE and durable application acknowledgments remain explicitly unselected extensions/deployment obligations. Human P1–P12 study and mutable bibliography/course listings are context, not machine-proof software gates.

## Optional follow-up: isolated ORAM timing

The ORAM measurement example now has an opt-in child-process bucket service.
A fresh 30-trial study passed plaintext and encrypt-only positive controls and
measured ORAM AUC 0.502 [0.491, 0.513] with a declared primary metric and
whole-session split. Raw event and private label hashes were independently
verified; the initial unpaired run is marked superseded. See the
[replication report](ORAM_TIMING_REPLICATION.md). Larger address/operation
universes and network timing remain open.

## Optional follow-up: real query content

A 30-trial MIMICS-Click token-workload evaluation now uses the real constrained
GGM SSE implementation. Exact-count and unpadded positive controls pass;
padding reduces the measured count-volume attack to the profile-majority range
on the evaluated 12.2%-coverage subset. Aggregate-only output and source
provenance are retained in
[the human-query report](HUMAN_QUERY_EVALUATION.md). The source has no
arrival-frequency or temporal data and licensing terms remain ambiguous, so
this is not a representative search-traffic study.
