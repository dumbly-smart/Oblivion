# Oblivion research report

**Selected-scope acceptance:** the [serial local gate](../experiments/results/validation-20261023-serial/commands.json) passed all ten commands, including 91 core Rust tests, one reference test, 120 Python tests without skips and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-serial/metadata.json) match: `a83d606782f63e9f5c9f8b95a3c80b299f57da30c916de670f61751e8068becc`. All three jobs in [hosted run 39971009249](https://github.com/dumbly-smart/Oblivion/actions/runs/39971009249) for `ade31d2c` passed. The selected roadmap software and empirical deliverables, local gate and hosted source gate are accepted within the documented boundaries. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery; no merge is claimed. Subsequent closing Markdown-only checks are accessible on the PR and do not create a new unfinished source requirement.

The later failed [historical run 39969711451](https://github.com/dumbly-smart/Oblivion/actions/runs/39969711451) remains preserved: Rust failed while analysis/stress passed, and its specific cause remains unproved. [Three-arm scheduling diagnostics](PIPELINE_TEST_SCHEDULING.md) reproduced authenticated timeouts under CPU contention: pinned two-CPU parallel tests had two timeouts, the same serial suite passed, and one CPU with 16 competitors produced an actual 218 ms Timeout with both PIR operations and 128 storage events. Correctness suites explicitly use `--test-threads=1`; production budgets, benchmark concurrency and retry behavior are unchanged.

23 October 2026. This report covers completed, bounded experiments and the current implementation. The [design summary](DESIGN_SUMMARY.md), [related work](RELATED_WORK.md) and [requirements matrix](REQUIREMENTS_MATRIX.md) separate the system design, scientific context and remaining acceptance work. The selected implementation/evaluation artifacts exist with documented limits; the final serial local and hosted source gates are accepted as recorded above, and no security theorem is claimed.

## Research question and implemented system

Can private registry lookup, oblivious state, fixed execution shape and cover traffic reduce useful invocation inference, and what costs or residual channels remain? Oblivion implements actual XOR PIR, encrypted Path ORAM, constrained GGM SSE, Wasmtime execution and authenticated epoch batching. It measures selected attacks rather than deriving a single privacy score for the whole system.

The runtime assumes a trusted client/executor. Processes simulate that boundary; there is no hardware TEE or attestation. A host administrator can inspect executor memory. XOR PIR requires non-colluding servers, even when their links are encrypted. Fixed message sizes and public storage phases do not hide all timing, cache, resource, billing, presence or active-failure observations.

The current process demo enrolls one to four clients, optionally discovers functions through actual SSE, verifies all five real function outputs and separates user/dummy state. Protected execution stages eight blocks and performs eight actual ORAM reads plus eight writes per invocation. Guest failures discard staged changes; interrupted physical commit can still poison the store. This bandwidth-for-shape choice costs O(M log N), with public working-set size M. [Runtime integration](RUNTIME_INTEGRATION.md) records passing scoped process tests and exact failure semantics. Store checkpoint recovery is separately authenticated against an external trusted handle and rekeys on restore; it does not implement durable invocation acknowledgments or whole-anchor replay protection.

## Method and evidence policy

Workloads use fixed logical seeds while cryptographic randomness comes from the OS. Public observer traces, authorized profiling knowledge and private target truth are separate. Classifiers fit on complete profiling sessions and evaluate disjoint target sessions. Independent fitted-model trials, not correlated queries, are bootstrap units. Positive controls must succeed before interpreting defenses. These choices reduce identifiable experimental errors but cannot rule out stronger adversaries or distribution shift. Public mechanism parameters are always known. The built-in demo's deterministic function/real-dummy schedule is public given its code, configured percentage and epoch, so that demo is correctness/topology evidence rather than anonymity against a schedule-aware observer. Experiment seeds/ground truth are reproducible research-driver inputs excluded from the declared runtime attack arguments; encryption is not claimed to hide an identity already fixed by auxiliary knowledge.

Recorded artifacts include configurations, source hashes, toolchains and host/provenance. Measurements use a shared host without CPU isolation. Payload counts are not packet captures; in-process algorithm times are not network latency; simulated time is not hardware calibration. Historical 2026-10-20 runs remain evidence about their saved source version, not every subsequent edit. This report cites scoped checks as recorded by their owners and does not claim to have rerun every suite or observed hosted CI.

## 1. Component access and traffic inference

The historical [30-trial component dataset](../experiments/results/leakage-30trials-20261020/) has eight independent sessions per trial and 128 observations per session. A rank attacker knows a two-label 75%/25% popularity order and sees persistent storage tags or ORAM leaves. A separate decision stump profiles application response size/local latency for balanced echo versus Fibonacci. These are deliberately simplified attacks, not faithful reproductions of the cited published methods.

| Mode | Accuracy | Balanced accuracy | Accuracy 95% trial-bootstrap interval |
| --- | --- | --- | --- |
| Frequency, plaintext/encrypt-only controls | 100% | 100% | 100–100% |
| Frequency, ORAM | 69.84% | 49.87% | 69.38–70.26% |
| Traffic, unpadded control | 100% | 100% | 100–100% |
| Traffic, padded | 49.91% | 49.91% | 49.35–50.48% |

The frequency majority baseline is **74.48%**, so interpreting its 69.84% defended accuracy against a raw 50% baseline would mislead. The traffic baseline is 50%. The results support reduced inference for these features under these workloads. They do not establish indistinguishability of the entire process path, traps or five-way function identity. [Attack figure](../experiments/results/leakage-30trials-20261020/analysis/attack-controls.png). The initial smoke session-bootstrap analysis is explicitly superseded by trial-cluster reanalysis.

## 2. Forward-private updates still leak searchable volume

The [new SSE experiment](SSE_ATTACKS.md) uses the real bounded GGM implementation, eight keywords, independently sampled public/target corpora, an independent labeled public query profile and two held-out target sessions per trial. Thirty trials preserve the shared corpus/profile as one uncertainty cluster. The count attacker compares observed posting counts with auxiliary corpus counts; a separate rank method exploits stable search-tag frequencies using unlabeled target-session observations.

The positive control intentionally matches target/public counts while still executing real encrypted SSE. The defended volume experiment inserts actual encrypted dummy postings until every keyword has 96 postings; the server returns them and the trusted client authenticates/filters them. It does not merely replace observer sizes with constants.

| Attacker/mode | Accuracy [95% trial interval] | Balanced accuracy | Top-three |
| --- | --- | --- | --- |
| Count, exact-count control | 98.88% [97.81, 99.77] | 97.41% | 100.00% |
| Count, ordinary SSE | 51.67% [43.07, 60.00] | 48.14% | 93.78% |
| Count, padded SSE | 21.69% [20.42, 22.97] | 12.99% | 57.58% |
| Search-tag frequency, all three modes | 32.24% [26.93, 37.37] | 35.23% | 64.43% |

The authorized profile-majority baseline is 21.69%; uniform eight-way chance is 12.5%. Padding reduces count recovery to its prior-based baseline but leaves equality-based recovery unchanged. Mean returned postings increase from 36.81 to 96, **2.61×**, with approximately **2.59×** JSON response bytes. These figures exclude update transport and container memory. Static index-build padding is not a general dynamic volume-hiding protocol.

The [report/raw provenance](../experiments/results/sse-attacks/report.json) and [figure](../experiments/results/sse-attacks/sse-attacks.png) preserve costs and uncertainty. Eight scoped Python tests and Rust example build/clippy passed as recorded in the experiment documentation. The earlier 100,000-operation plaintext oracle and retained-capability challenge validate separate construction properties. The later bounded likelihood, iterative-assignment and chosen-update methods are reported separately below; none is a faithful published SAP/IHOP/file-injection reproduction. Synthetic stable distributions, small vocabulary and absent timing features limit generalization.

## 3. ORAM size and state costs

The [size study](../experiments/results/oram-size-30-20261021/summary.json) runs 30 fresh controllers per geometry with 256-byte logical blocks. Its latency statistic is the **mean of per-trial read/write p95 values**, with trial-bootstrap intervals; it is neither a pooled p95 nor network latency.

| Blocks | Mean trial p95, µs [95% interval] | Bucket bytes/access | Maximum observed stash |
| --- | --- | --- | --- |
| 16 | 46.33 [46.10, 46.58] | 10,840 | 3 |
| 64 | 65.43 [64.88, 66.37] | 15,176 | 5 |
| 256 | 84.99 [83.72, 86.89] | 19,512 | 4 |
| 1,024 | 106.32 [103.73, 109.29] | 23,848 | 8 |

[Size figure](../experiments/results/oram-size-30-20261021/oram-size.png). Actual full-path work rises with depth. These are observed stash maxima, not failure bounds. Trusted metadata remains O(N), and size formulas exclude allocator/temporary memory. The later [actual trace validation](TRACE_VALIDATION.md) now includes 100,000 measured accesses each for repeated/uniform workloads, 1.4M physical bucket events/workload, compressed originals and streaming integrity checks. Leaf-count homogeneity has unadjusted p 0.2089; the minimum Holm-adjusted p across the script's 11-test family is 0.748. There is one fresh session/workload, not a cross-session independence proof. The separately recorded million-operation oracle establishes correctness evidence for its configuration, not a proof of obliviousness.

## 4. Genuine SimplePIR comparison

The [reference experiment](SIMPLEPIR_REFERENCE.md) imports a genuine pinned upstream implementation with real database-dependent hint generation. Thirty fresh processes per scheme each run 16 measured queries after warm-up; all **960 measured outputs** across both schemes match a full eight-byte oracle. The matched database is **10,000 eight-byte records**, separate from the XOR component's 10,000 × 1 KiB experiment.

| Mean online component | SimplePIR | Two serial XOR servers |
| --- | --- | --- |
| Server work | 11.57 µs | 201.97 µs |
| Sum of query/answer/recovery calls | 613.20 µs | 207.92 µs |
| 95% interval for that sum's mean | 600.48–626.50 µs | 202.73–213.20 µs |

The faster SimplePIR server kernel does not make the total online sum faster at this geometry: client work dominates. Setup adds shared-matrix/hint work and **2,170,880 payload bytes**, versus 2,120 online bytes/query. Under the stated uncompressed matrix accounting it amortizes below XOR's 2,516 online bytes/query after 5,483 queries. Timing excludes transport, authentication, process startup and compilation. Packed Go/C matrices versus Rust record containers and shared-host effects limit algorithmic conclusions. [Saved summary](../experiments/results/simplepir-reference-small-20261020/summary.json).

The later [100k-query campaign](../experiments/results/simplepir-100k-20261023/summary.json) completes 100,020 genuine SimplePIR retrievals and 100,020 matched XOR retrievals over 30 setups each, all with complete eight-byte outputs correct. Queries sharing a matrix/hint are dependent; the saved IID-query and setup-event intervals are conditional reference calculations, not worst-case LWE failure guarantees. This supplements rather than relabels the earlier 960-query timing comparison. [Square-root PIR](SQRT_PIR.md) separately checks 5,760 actual matrix-packed retrievals: at 10,000 eight-byte records payload falls from 2,516 to 1,626 bytes, but with 1,024-byte records rises from 4,548 to 204,826 bytes. All padded bytes still undergo a full scan.

## 5. Autoscaler privacy/cost/SLO tradeoffs

The [simulator](AUTOSCALER.md) executes five policies and four seeded workload families with actual event-queue waiting/readiness/completion logic. Its public observer sees per-pool capacity and scaling/cold-start events, not direct queue/arrival/completion data. A policy-aware profiler fits on separate sessions; 30 independent trial means determine intervals. Costs use a hypothetical price, with no cloud deployment or DP claim.

For uniform intensity inference, naive balanced accuracy is 0.980 with one initial worker per pool. Fixed capacity attains 0.500 in this restricted view, but one worker has mean session p99 **2.622 s** and **34.29%** SLO violations. Two fixed prewarmed workers reduce uniform p99 to **0.420 s** and violations to **0.93%**, with 80 instance-seconds instead of 40. Bursts still yield **3.818 s** p99 and **27.95%** violations. Dropped and unfinished requests count as SLO violations rather than disappearing from the metric.

[One-worker report](../experiments/results/scaler-paper-30-final/report.json), [two-worker report](../experiments/results/scaler-prewarm2-30-final/report.json), [cost/privacy figure](../experiments/results/scaler-prewarm2-30-final/pareto-intensity.png). There is no universal SLO-feasible policy improvement. Nominal Pareto membership uses mean points and is not statistically significant dominance. Independent runtime calibration, broader adversaries and real licensed arrivals remain future work.

## 6. Final joint A–G and publication-boundary evaluation

[SYSTEM_EXPERIMENTS.md](SYSTEM_EXPERIMENTS.md) records the completed final `system-fixed-publication-30-20261022/` campaign: 30 independent fitted-model trials, four whole sessions/trial and 16 opportunities/session, for 1,920 observations/mode and 13,440 across A–G. Modes execute actual libraries: A plaintext, B encrypt-only, C ORAM, D PIR, E batching, F padded executor and G combined. Disabled-layer variants supply the ablation comparison. Separate real process-G tests and demo validate topology; this in-process campaign is not packet capture or a measurement of every host interface.

The joint attacker trains on independent profiling sessions, then sees declared interface-summary features with no private target labels. Actual payload ciphertexts and physical storage traces are retained, but this classifier does not exploit every byte/sequence or host cache/billing/resource observation. A successful plaintext positive control precedes interpretation. The report retains independent fitted-trial intervals and chance/majority references.

| Final G score | Mean | 95% trial interval | Relevant baseline |
| --- | --- | --- | --- |
| Three-class balanced accuracy | 33.40% | 32.29–34.51% | 33.33% |
| Ordinary three-class accuracy | 48.96% | 47.81–50.00% | Majority 50% |
| Real/dummy accuracy | 50.83% | 47.81–53.54% | 50% |
| Real/dummy AUC | 0.5318 | 0.4883–0.5720 | 0.5 |
| Conditional real-function accuracy | 48.96% | 45.83–52.29% | 50% |

A–D attain balanced accuracy 100%, E 97.36% and F 98.89% in this model. The combined layer's bounded result is favorable for these features, whereas individual layers retain useful signals. Neither the finite intervals nor the simple attacker establish full-system indistinguishability.

The final driver uses `prepare_scheduled` to complete private execution after fixed 25/50 ms read/commit phases, then prepares response encryption and instrumentation before waiting for the 100 ms public publication deadline. Clients similarly prepare encrypted frames before emitting at the public epoch; server slots use epoch-arrival plus slot-index × 100 ms starts. The standalone padded executor API remains available. Work overruns and publication lateness are separately recorded; OS wakeups retain nonzero lateness, so this is not exact-time or constant-time execution.

Pooled per-real API p95/p99 are **100.159/100.200 ms**. Mean opportunity wall time is **116.268 ms**, and real goodput is **4.3004/s** when including initial epoch wait and trusted oracle/logging overhead. Accounted payload is **82,484 bytes/real request** at 50% dummy load. These boundaries differ from API service latency and external captured wire traffic. Illustrative cost uses 0.00001 units/executor-wall-second plus 0.1 units/GiB response egress, not a verified cloud price sheet. Three-axis mean-point Pareto membership is A/E/G; it is nominal membership under this finite campaign and price model, not statistically significant universal dominance.

[Final report](../experiments/results/system-fixed-publication-30-20261022/joint-report.json), [latency/privacy](../experiments/results/system-fixed-publication-30-20261022/latency-privacy.png), [bandwidth/privacy](../experiments/results/system-fixed-publication-30-20261022/bandwidth-privacy.png), [cost/attack](../experiments/results/system-fixed-publication-30-20261022/cost-attack.png), [ablation comparison](../experiments/results/system-fixed-publication-30-20261022/ablation-attacks.png).

The stopped `system-30-20261021/` pilot contains 18 trials with an incorrect measurement/oracle boundary and is excluded from acceptance. The completed `system-30-corrected-20261021/` run is retained as earlier-version evidence: G conditional real-function accuracy **54.58% [50.21,59.17]** suggested possible client-arrival coupling and multiple-comparison effects. Final encrypted preparation/publication changes and a fresh output directory address that observed concern; the favorable final campaign does not erase the negative result. Measured immutable binary/source hashes identify each version. A Git HEAD recorded later during metadata writing is not treated as a launch-time source authority.

## 7. Actual offered load and controlled update association

The [runtime benchmark record](RUNTIME_BENCHMARKS.md) reports 30 fresh processes each at underload and overload, eight independently scheduled offers/process and a bounded queue of two. All 60 processes exited successfully with no authenticated invocation errors or recorded execution deadline misses. Underload admits 8/8 with mean admitted E2E **100.641 ms [100.614, 100.673]**. Overload admits 3/8, drops **62.5%**, and raises admitted E2E to **191.411 ms [191.328, 191.503]**; **75%** of all offered requests violate the 250 ms SLO when drops are included. Admission explicitly reveals demand; this command has no fixed-cover claim.

[Offered-load figure](../experiments/results/runtime-open-loop-current/offered-load.png). Admitted service remains near 100.56 ms; overload queueing causes the difference. With only three admitted overload requests/trial, its interpolated p99 is not a well-resolved population tail. Reported CPU counters are coarse Linux process ticks, and sampled RSS can miss peaks/count shared pages repeatedly. First/subsequent invocations use precompiled modules and do not measure cold compilation. These limits preclude treating this short workload as a full production capacity or cost study.

The batching component separately completed **270 fresh-process trials**: 30 at each combination of 2/10/25 ms periods and 0/50/100% real traffic, eight clients and 32 epochs. All **69,120 actual AEAD frames** preserve eight 164-byte frames per batch. In the 0%-real cells, mean queue waits are **1.005 / 5.033 / 12.636 ms**, against ideal E/2 values **1 / 5 / 12.5 ms**. [Raw-derived analysis](../experiments/results/batch-epoch-current/analysis.json) and [epoch figure](../experiments/results/batch-epoch-current/batching-overhead-vs-epoch.png). Planned arrival phases are uniform; measured actual arrival/emission lateness accounts for timer jitter. This is actual queue/timer/encryption work, with no downstream WASM/PIR/ORAM invocation in that component experiment. Fixed batch shape across ratios is not a statistical timing-indistinguishability test.

The [controlled chosen-update experiment](UPDATE_LINKABILITY.md) uses 30 independent real SSE setups and an encrypted stable-tag control. Before the next authorized search, the control associates 240/240 chosen updates with prior opaque queries, while GGM yields 0/240 direct matches; seeded permutation guessing scores **15.83% [10.42, 21.25]**, versus 12.5% uniform chance. After the next search both associate 240/240. [Report](../experiments/results/update-linkability-30-20261021/report.json) and [figure](../experiments/results/update-linkability-30-20261021/update-linkability.png). This demonstrates delayed association under a narrow capability/address adversary, not a faithful published file-injection reproduction or complete active-security proof.

## 8. Stronger bounded inference, real packets and delivery artifacts

[Offline SSE inference](ADVANCED_ATTACKS.md) combines actual observed query equality/posting counts with a separate public corpus and labeled query profile. Over 30 trial clusters, separable likelihood assignment reaches **94.43% [91.02,97.50]** on the exact-count control, **80.52% [72.45,87.53]** on independently sampled SSE and **33.80% [28.15,39.17]** after real posting padding. Iterative Markov assignment reaches 75.55% ordinary and 30.96% padded; the exact bounded objective comparator reaches 75.81% and 28.57%. Better optimization need not recover more labels under model mismatch. At most eight keywords permit exact enumeration; these methods and exhaustive top-three rankings are not scalable faithful SAP/IHOP reproductions. The [attack interface](ATTACK_INTERFACE.md) now exposes 13 registered adapters and exposes six SSE-facing bounded methods without inventing calibrated confidence or extra experimental evidence.

[Execution/error evaluation](EXECUTION_EVALUATION.md) separately executes five actual functions plus trap, fuel and memory failures. A visible-selector control first achieves 100%; the protected eight-class centroid achieves **11.67% [9.38,13.75]** versus 12.5% chance. All 960 protected observations pass full output/status checks, carry 164-byte directional AEAD requests/responses and generate 128 actual bucket events each. This earlier executable's measurement includes response encryption after its padded executor API; its exact timing boundary and approximately 100.124 ms mean response time are retained rather than attributed to the final driver's later publication mitigation.

[Actual PIR capture](TRACE_VALIDATION.md) uses only the two dynamically owned encrypted loopback listener ports in each of 30 fresh sessions. It contains **3,000 oracle-verified retrievals, 6,000 complete streams and 61,363 packets**. All aggregate/component capture drop counters are explicitly zero and agree with decoded packet totals. Query/answer application frames are 53/180 bytes, while observed TCP frame lengths are 66/74/119/246. Original pcaps and compressed ORAM traces have verified integrity hashes. A packet centroid classifier lacking a validated leaky control was removed; historical exploratory outputs are preserved but excluded from privacy acceptance. Current packet results establish structural accounting only.

The [local demo recording](DEMO.md) visualizes an actual three-client mixed-function SSE/PIR/WASM/ORAM subprocess: 24 calls, 12 real invocations, all five functions, 24 SSE queries and 3,072 storage events. MP4, terminalcast, raw logs, provenance and representative frames are retained. It is a data-driven recording artifact, not a privacy experiment or hardware-isolation demonstration.

[Recorded validation commands](../experiments/results/validation-20261022-current/commands.json) exited zero for formatting, warning-denied workspace Clippy, workspace tests, Python discovery and explicit million-operation stress. The Python record has 42 checks and one optional Rust smoke skip; stress test time is 41.44 seconds. Source changed during that campaign, so final frozen-source gates must be rerun and hosted CI must be observed separately. Authorized small commits/pushes use `codex/oblivion-research-platform`, without a main merge.

## 9. Later bounded acceptance studies

The [licensed corpus study](CORPUS_EVALUATION.md) uses UCI SMS document associations and real SSE posting/dummy exports. Thirty resamples are conditional on the same deduplicated public corpus, not 30 independently collected corpora. IID likelihood recovery is 64.35% with matched auxiliary documents, 36.35% with strongest spam-enriched document drift and 38.88% under fixed padding. Queries are synthetic. Auxiliary text is disjoint from target; the two held-out drift views may share documents with each other.

The [presence study](PRESENCE_EVALUATION.md) is a negative result under explicit semantic-beacon knowledge: online-only fixed-rate participants remain identifiable. Always-participating endpoints are a different operational configuration. [Leaf+timing inference](ORAM_LEAF_TIMING.md) also retains possible weak ORAM AUC 0.511 [0.501,0.521], although balanced accuracy 50.70% [49.80,51.62] crosses chance. Multiple reported metrics and shared historical timing limit interpretation; neither result is hidden by a global favorable privacy score.

[Individual-server PIR timing](PIR_TARGET_TIMING.md) completes 46,080 full-record checks at two geometries, with visible-index controls first and separate own-share/timing feature models. Protected intervals include three-class chance. [Geometry/stash work](GEOMETRY_EVALUATION.md) covers 42 cells × 30 trials, 138,240 ORAM accesses and 2,880 PIR queries, with actual payload/map/stash accounting. [Matched Circuit/Path reference](CIRCUIT_ORAM_REFERENCE.md) adds 61,440 measured accesses and 193,920 complete-record comparisons on genuine upstream implementations. That GPL benchmark uses matched unencrypted trusted heap and does not replace or directly time-compare the core encrypted Path ORAM.

[Executor CPU/resource measurements](EXECUTOR_RESOURCES.md) complete 180 fresh processes and 2,160 actual calls per campaign, separating setup/compile, first/warm calls, public classes, wall padding, process/thread CPU and success/failure denominators. [Extended offered load](RUNTIME_BENCHMARKS.md) adds 180 processes and 5,760 offers across six interval/queue cells. Overload drops and latency/SLO failures remain explicit; finite 32-offer trials do not establish population tails or deployment capacity. [Repeated faults](FAULT_CAMPAIGN.md) complete 210 assertion-bearing launches across seven scenarios, while preserving the original ENOSPC/truncated-publication attempt as incomplete evidence.

The [joint batch-load experiment](BATCH_LOAD_EVALUATION.md) runs 720 independent actual-timer processes with public wire bytes, timing, sizes, destinations and slots. Two failed forest controls never proceed to protected collection. A new fixed-public-unit class-centroid model, validated only on controls, then scores 100% on its fresh plaintext control and 28.33% [22.78,33.89] on genuine AEAD-protected 0/50/100% load, versus 33.33% chance. It uses the same 22 features in both modes and no target labels in fitting. This small model can miss nonlinear signals; the result is not a proof of timing equivalence.

The [final integrated epoch campaign](EPOCH_SYSTEM_EVALUATION.md) completes 360 process-tree trials and 2,160 independently verified invocations across participants 1/2, periods 200/400 ms and three real fractions. Its reader timestamps immediately after `read_exact`, before channel handoff/private consumer work; public and private rows remain separate. All 360 retained raw directories reanalyze exactly and 2,955 original artifact hashes verify. Earlier mixed-instrumentation and client-consumer-timestamp campaigns stay scoped to their original boundaries. The final immutable binary/source copy is authoritative: live checkout fingerprints include an unrelated PIR example edit, and later default-wrapper guard changes are explicitly separate. No global checkout-equality claim is made.

## Interpretation and accepted scope

The results demonstrate distinct tradeoffs: selected component signals decrease while search equality, presence, possible weak ORAM timing and active failures remain; larger matrix responses can offset query savings; reference kernels can lose on client-inclusive cost; and demand-independent scaling/large queues can violate SLOs. Completed investigations retain undesirable results rather than manufacturing privacy or universal dominance.

[The completion audit](COMPLETION_AUDIT.md) maps the original MVP, seven layers, numbered benchmark/threat-model requirements and later milestones. Nominal Pareto/SLO panels, explicit hypothetical prices, trusted payload memory accounting and selected synthetic arrival traces satisfy their stated bounded artifact scopes without inventing extra production criteria. Human study and bibliography context remain distinct from software gates. TEE/DP/recursive/native Circuit/DPF/native runtime PIR/persistent-backward SSE and durable application semantics remain unselected extensions.

The research-only `demo-sweep` now retains authenticated masked runtime failures, including their timing, CPU and completed interface work, while successful outputs still require full independent oracles. Legacy `demo`/`demo-sse` stay strict; budgets, reader timestamps and retry behavior are unchanged. Primary CPU/byte cost per real success is a ratio of sums that includes zero-success trials' costs; unknown partial PIR-byte costs, undefined totals and bootstrap draws are explicit, with no unconditional finite interval when a draw is undefined. Historical completed campaigns had zero runtime errors and were not rerun or rewritten. See [the post-measurement policy](EPOCH_SYSTEM_EVALUATION.md#post-measurement-runtime-error-retention).

Two ten-command local attempts remain preserved and unaccepted as complete gates. `validation-20261023-final/` has nine zero exits and a workspace harness Timeout. `validation-20261023-current-source/` passes workspace tests but its 112-test Python run has one authenticated `demo-sweep` invocation failure; its private cause was not retained and remains unknown. A deterministic Timeout regression does not establish that historical cause.

The fresh [verified local gate](../experiments/results/validation-20261023-verified/commands.json) passed all ten commands: 90 core Rust tests, one reference test, 119 Python tests with all four runtime fixtures and no skips, both workspaces' quality/build checks, and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-verified/metadata.json) match; that historical gate passed for its recorded source.

All three jobs in [hosted run 39971009249](https://github.com/dumbly-smart/Oblivion/actions/runs/39971009249) for `ade31d2c` passed. The selected roadmap software and empirical deliverables, local gate and hosted source gate are accepted within the documented boundaries. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery; no merge is claimed. Subsequent closing Markdown-only checks are accessible on the PR and do not create a new unfinished source requirement. No production-security or global-indistinguishability claim follows.

[The figure reproduction audit](FIGURE_REPRODUCTION.md) now records raw-derived regeneration of all eight required main figures and the supplemental three-axis/SLO plot without ignored measurement executables. Both autoscaler campaigns rebuild from four raw/config files rather than cached reports; audited numerical reports and PNG bytes matched, and accepted inputs stayed unchanged. The serial local and hosted source gates are accepted; subsequent closing Markdown-only checks are accessible on PR #1.
