# Requirements and evidence matrix

Audited 2026-10-23 against the complete supplied [research roadmap](../Oblivion_%20Research%20Roadmap%20and%20Build%20Plan%20%281%29.md), the original project instructions summarized in the build/completion plans, current source, component documentation and saved result records. This document does not change those requirements.

**Complete** means the bounded artifact/behavior exists with the cited evidence; it does not mean the full system is secure. **Partial** means some required implementation/evidence exists, with the missing part stated. **Not verified** means no accepted execution/artifact is established here. **Extension** means an explicitly unselected stretch/deployment property; **Context** marks human learning or bibliography work, not a software gate. **Gate pending** means current validation or delivery has not been accepted. Source/test presence is not a passing test execution. Optional extensions remain explicitly tracked. A hoped-for experimental result is not a license to manufacture a positive outcome.

## Evidence provenance

| ID | Authoritative artifact | Evidence boundary |
| --- | --- | --- |
| V20 | `experiments/results/validation-20261020/final-commands.json` and referenced logs | Historical zero exits for fmt/clippy/workspace/Python. 29 ordinary Rust tests passed, stress ignored; four Python tests. Does not validate later code |
| O20 | `experiments/results/oram-{uniform,same,analysis}-20261020/` | Three trials each, 64 × 256-byte blocks, 1,000 measured accesses/trial; diagnostics/plot and payload/state formulas |
| P20 | `experiments/results/pir-30trials-20261020/` | 30 × 16 queries, 10,000 × 1 KiB; in-process algorithm benchmark, no wire throughput |
| D20 | `experiments/results/demo-{0,50,100}-final-20261020/` | Earlier one-client/stateful, two ORAM accesses per invocation, 20 ms epochs/10 ms class; eight invocations/run |
| L20 | `experiments/results/leakage-30trials-20261020/analysis/` and raw parent directory | Actual component attacks with positive controls and independent session/trial intervals; historical source |
| S20 | `docs/SSE_IMPLEMENTATION.md`, `crates/oblivion-sse/src/lib.rs` tests, example `measure` | Recorded eight release tests and 100,000-operation oracle; measured challenge/example described in docs. Large JSONL generated on demand, not committed raw result suite |
| R20 | `experiments/results/simplepir-reference-small-20261020/` | Genuine pinned SimplePIR, 30 fresh processes/scheme × 16 measured queries, 10,000 eight-byte records, real setup and full-output checks |
| A20 | `experiments/results/scaler-{paper-30-final,prewarm2-30-final}/` | Independent 30-trial simulator runs, public/private/raw records and plots; hypothetical costs, no deployment or DP |
| V22 | `experiments/results/validation-20261022-current/commands.json` and `0.log`–`4.log` | Five zero exits: fmt, warning-denied workspace clippy, workspace tests, Python discovery (42 checks, one explicit optional Rust smoke skip), separate million-operation stress (41.44 s test time). Source changed during this campaign; final frozen-source gates must be rerun |
| T22 | `TRACE_VALIDATION.md`, `leaf-100k-current/`, `pir-capture-current/` under results | Actual 100k/access workload pair and 30 encrypted PIR capture sessions; immutable binary/raw integrity checks; structural diagnostics only |
| X22 | `EXECUTION_EVALUATION.md`, `experiments/results/execution-timing-30-20261021/` | 30 trial clusters, eight execution/error classes; visible-selector control first, fixed actual envelopes/ORAM; saved source version |
| H22 | `ADVANCED_ATTACKS.md`, `experiments/results/inference-sse/`, `UPDATE_LINKABILITY.md` | Bounded offline likelihood/iterative/exact methods and chosen-update association, real SSE observations, successful controls; not faithful paper reproductions |
| J22 | `SYSTEM_EXPERIMENTS.md`, corrected and fixed-publication system result directories | Actual A–G and disabled-layer campaigns; chronology and observed inference retained. Final publication-boundary mechanism differs from the earlier corrected run |
| D22 | `DEMO.md`, `docs/artifacts/demo-demo-recording-20261022/` | Actual local mixed-function/SSE process run visualized as MP4 and terminalcast; not a screen recording or privacy experiment |
| VF22 | `experiments/results/validation-20261022-frozen/` | Five zero exits; identical before/after source hash; 53 Python checks with one optional skip. Applies to that revision, not later additions |
| C23 | `CORPUS_EVALUATION.md`, `experiments/results/corpus-real-frozen-20261023/` | Licensed UCI text, 30 conditional split resamples, real SSE/dummy padding, matched and spam-enriched auxiliary corpora; fixed synthetic query prior. Frozen executable verified before/after |
| B23 | `PRESENCE_EVALUATION.md`, original presence raw and independent-ties-Wilson analysis | 60 actual-batcher virtual-clock trials; strong explicit semantic beacon; intermittent fixed-rate presence remains identifiable. No packet-timing claim |
| G23 | `GEOMETRY_EVALUATION.md`, `experiments/results/geometry-20261022/` | 42 geometry cells × 30 trials; 138,240 ORAM accesses, 2,880 PIR queries; genuine stash traces/full-record oracles; in-process payload/timing scope |
| LT23 | `ORAM_LEAF_TIMING.md`, `oram-leaf-timing-20261023/` | 30 profiled trial clusters; possible weak ORAM AUC 0.511 [0.501,0.521] retained, not a privacy pass |
| PT23 | `PIR_TARGET_TIMING.md`, `pir-target-timing-20261023/` | 46,080 oracle-verified requests, 30 fits/geometry/mode, own-share/local-time observer and control first |
| SQ23 | `SQRT_PIR.md`, `sqrt-pir-20261023/` | Genuine packed-row variant, 5,760 checked retrievals; full scans and potentially larger responses |
| R23 | `simplepir-100k-20261023/summary.json` | 100,020 checked SimplePIR queries and 100,020 matched XOR queries, 30 setups each; no observed failures, dependent outcomes within setup |
| CR23 | `CIRCUIT_ORAM_REFERENCE.md`, `circuit-reference-20261023/` | Genuine separately licensed Path/Circuit reference, 61,440 measured accesses / 193,920 full-record oracle checks; matched unencrypted heap scope |
| CPU23 | `EXECUTOR_RESOURCES.md`, `executor-cpu-20261023/` | 180 fresh processes / 2,160 calls, direct process/thread CPU, first/warm/setup and three public resource classes |
| RT23 | `RUNTIME_BENCHMARKS.md`, `runtime-extended-30-20261023/` | 180 process trials / 5,760 offered requests, six load/queue cells, drops and finite-run tails retained |
| FT23 | `FAULT_CAMPAIGN.md`, `fault-campaign-30-20261023-retry/` | 210 assertion-bearing launches; all seven scenarios × 30 pass; original ENOSPC attempt retained |
| BL23 | `BATCH_LOAD_EVALUATION.md`, `batch-load-centroid-20261023/` | 720 independent processes; 30 fits/mode; control 100%, protected 28.33% [22.78,33.89] against 33.33%; two failed forest controls retained |
| EP23 | `EPOCH_SYSTEM_EVALUATION.md`, `epoch-system-pipe-timestamps-20261023/` | 360 process-tree trials / 2,160 oracle-checked invocations; reader-thread pipe timestamps, separate private rows, immutable binary and scoped checkout differences |
| SRC | Current component paths/test names below | Source presence alone is not executed validation; V22 and per-run source versions remain explicit |

Historical validation stays versioned. Two ten-command local attempts remain preserved and unaccepted as complete gates. `validation-20261023-final/` has nine zero exits and a workspace harness Timeout. `validation-20261023-current-source/` passes workspace tests but its 112-test Python run has one authenticated `demo-sweep` invocation failure; its private cause was not retained and remains unknown. A deterministic Timeout regression does not establish that historical cause.

The fresh [verified local gate](../experiments/results/validation-20261023-verified/commands.json) passed all ten commands: 90 core Rust tests, one reference test, 119 Python tests with all four runtime fixtures and no skips, both workspaces' quality/build checks, and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-verified/metadata.json) match; this local gate is accepted.

Hosted run 39968400558 for `1d741580` is green. The latest pushed `d80f258c` has run 39969191581 in progress as of this refresh; final-head hosted acceptance remains pending. [Draft PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is available for review. Earlier green runs 39931999451/39921151648 and locally corrected Clippy failure 39921929791 remain historical evidence. No merge is claimed. Source snapshots and immutable measured executable hashes identify experiments independently of later Git HEAD/live-checkout fingerprints.

## Foundation, trust and documentation

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| F01 | Preserve original checkout/user artifacts; coherent Rust workspace and lockfile | Complete | Root `Cargo.toml`, `Cargo.lock`; seven real crates. Pre-existing `graft/` preserved |
| F02 | Explicit threat model A/B/C and trust boundaries | Complete | `THREAT_MODEL.md`, `SECURITY_ASSUMPTIONS.md`: TrustedExecutor simulated with processes; no hardware TEE |
| F03 | Assets, adversary, leakage functions, residual channels and diagram | Complete | `THREAT_MODEL.md`, `ARCHITECTURE.md`; storage/network/scheduler/billing observations distinguished |
| F04 | AEAD, HKDF separation, OS entropy and nonce lifecycle | Complete | Store/batcher/PIR/SSE source; assumptions record ephemeral invocation sessions and rekeyed store restore |
| F05 | Observer schema excluding plaintext secrets/labels; distinct truth/private data | Complete | `PROTOCOL.md`; store events, harness datasets, simulator strict public schema; runtime private files must remain private |
| F06 | CI configured and running | Final-head gate pending | Local validation-20261023-verified passed ten commands with matching source digests. Hosted 1d741580/39968400558 is green; latest d80f258c/39969191581 is in progress. [Draft PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) exists; final-head CI/review remain pending. Both failed local attempts stay preserved. |
| F07 | Reproducible commands, exact dependencies/config/seeds and provenance | Complete | Locked dependencies, per-run configuration/seeds and source/executable fingerprints; T22/X22/J22 preserve exact measurement boundaries. Postmeasurement source snapshots are explicitly labeled |
| F08 | P1–P12 probability/security games/crypto/GGM/LWE/DP/systems/WASM/stats preparation | Context | Assumptions/construction notes are documented. Human reading and interview understanding are not machine-verifiable software gates; no claim certifies those competencies. |
| F09 | Verify primary literature and licenses for implemented methods | Complete, scoped | Construction docs verify the methods actually used; UCI corpus, pinned MIT SimplePIR and separate GPL Path/Circuit reference have explicit provenance/licenses. Broader roadmap courses/venues/unverified bibliography remain context, not blanket verified citations. |
| F10 | Final README, design/writeup, report, related work, talk/demo video/public artifact | Gate pending | Required documents, figures and actual local MP4/terminalcast exist; `COMPLETION_AUDIT.md` maps scope. Current local validation is accepted; draft PR #1 exists; final-head hosted CI and review remain open. |

## L1: Diana-inspired constrained GGM SSE (§2, week 9)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| S01 | Actual constrained GGM PRF, client keyword state and encrypted server posting map | Complete | `crates/oblivion-sse/src/lib.rs`, `SSE_DESIGN.md`; HMAC tree, exact prefix cover, independent value keys; labeled Diana-inspired, no theorem-port claim |
| S02 | 100,000 random add/search operations equal plaintext oracle | Complete | S20 recorded release suite; seeded oracle includes duplicate IDs/retries/rotation; rerun current source before certifying edits |
| S03 | Written adversary retains every past search token/capability | Complete | S20 retained-node tests/challenge, including lost search responses; positive controls prematurely release root or stable update tag |
| S04 | Report retained-capability link challenge vs chance and uncertainty | Complete, bounded | S20: 400 balanced challenges, 202/400 guesses with Wilson interval; zero fresh addresses derived before and 400 after authorization. Together with the written capability/transcript argument, this meets the specified narrow adversary experiment; it is not a new general SSE theorem. |
| S05 | Exact server-side update/search leakage logs | Complete | `--example measure -- PATH` exports real request/response capabilities/addresses; S20 parsed 13,161 events; no plaintext ID/keyword field. Generated large transcript not retained as committed raw record |
| S06 | Update/search cost vs result count and storage blowup | Complete, bounded | S20 and SSE attack exports report actual update/search timings, 56 cryptographic bytes/posting, logical update bytes and genuine padded-result cost. Container/RSS accounting and deployment throughput are not claimed by these payload measurements. |
| S07 | Forward-privacy transcript argument and explicit residual equality/volume/timing | Complete | `SSE_DESIGN.md` assumptions/leakage argument; computational claim conditioned on GGM/PRF and counters, no byte-histogram proof |
| S08 | Ephemeral state loss, exact pending retry and counter safety | Complete | No restore/key-import API; tests stale-counter negative fixture and idempotent retries. Persistence is deliberately unsupported |
| S09 | Metadata index integrated with actual function discovery/invocation | Complete | `RUNTIME_INTEGRATION.md`: actual `demo-sse` prepare/search/verify drives mixed PIR/WASM/ORAM; scoped server suite passed 4 unit/14 integration tests and clippy. Search timing/volume remain outside padded class |
| S10 | Deletions/backward privacy and Janus design sketch | Complete sketch; implementation extension | `EXTENSION_NOTES.md` provides the source-backed backward-privacy contrast/design sketch allowed by the roadmap simplification. Actual deletions/Janus remain unselected extensions. |
| S11 | Persistent SSE client journal, antirollback and multiwriter reservation | Extension | No persistent SSE deployment is supported; ephemeral state and exact pending retries are implemented. Do not infer persistent safety from forward-private updates. |

## L2: Path ORAM (§3, weeks 2–3)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| O01 | Rust Path ORAM, Z=4, AEAD fixed buckets, fresh writes, client map/stash | Complete | `crates/oblivion-store/src/oram.rs`, `crates/oblivion-store/src/config.rs`; encryption is implemented in `oram.rs`; reads and writes remap with OS randomness |
| O02 | Memory/file Backend abstraction | Complete | `src/backend.rs`, `tests/recovery.rs::file_backend_bounds_and_truncated_files`; bounded real file I/O |
| O03 | Million random operations match plaintext oracle | Complete | V22 release stress explicitly ran 1,000,000 operations over 256 blocks in 41.44 seconds; ordinary suite deliberately ignores this tier |
| O04 | Stash histogram/max and invariants | Complete | G23 36 N/width/Z/workload cells × 30 controllers with genuine private histograms and fixed observer checks; maximum observed stash seven. Finite occupancy observations do not establish rare overflow bounds |
| O05 | 100,000 repeated-address versus uniform-address chi-square/KS/independence diagnostics | Complete | T22: actual 100,000 accesses each for repeated and uniform workloads, 1.4M physical events each; compressed originals, chi-square/discrete-KS/permutation diagnostics and limitations retained in `TRACE_VALIDATION.md` |
| O06 | Fixed server messages and measured 2·Z·(log N+1) payload blowup | Complete | `tests/adversarial.rs::fixed_shape_and_fresh_ciphertext_for_reads_and_writes`, O20; ciphertext/metadata overhead explicitly counted at bucket interface |
| O07 | p50/p99, bandwidth, trusted map/stash payload overhead | Complete, bounded | G23 provides 36-cell latency, payload, storage, stash histograms and trusted metadata accounting. Allocator/process/remote RSS are excluded explicitly, not silently required as a second memory experiment. |
| O08 | Stronger leaf+timing classifier for address or operation inference | Complete investigation; weak signal retained | LT23 tests two-record inference using leaves/tags, size, time and frequency, with controls and whole-session splits. ORAM AUC 0.511 [0.501,0.521] is a possible weak signal; arbitrary addresses/operation inference and all hardware channels are not certified. |
| O09 | Integrity, bucket substitution/replay and failure semantics | Complete | `tests/adversarial.rs`, trusted versions/location AEAD, poison on uncertain reads/writes |
| O10 | Durable authenticated state and recovery | Complete bounded checkpoint API | File/checkpoint recovery validates complete snapshots and rotates keys against a trusted latest handle. External anchor publication and durable invocation acknowledgments are separate unselected deployment obligations, not claims of the process demo. |
| O11 | Recursive map, multi-controller/shared-writer protocol | Extension | Roadmap stretch work; current trusted position map/version state is O(N) and one controller serializes operations. |
| O12 | Circuit ORAM benchmark reference and eviction design note | Complete, reference scope | CR23 executes genuine matched MobileCoin Path/Circuit implementations: 61,440 measured operations and 193,920 full-record checks. Separate GPL workspace, unencrypted trusted heap, no replacement of core encrypted Path ORAM; eviction/recursion contrasts documented. |

## L3: Registry PIR (§4, week 4 and week 10)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| P01 | Actual two-server XOR selection shares/full scans/recovery | Complete | `crates/oblivion-pir/src/lib.rs`, retrieval/process tests; separate server-owned state |
| P02 | Correct 10,000 × 1 KiB retrieval | Complete | `tests/retrieval.rs::ten_thousand_kib_records`, P20; current secure TCP/process tests cover same geometry |
| P03 | Individual-server query uniformity for varied indices | Complete, bounded | PT23: exact uniform-share/bijection rationale plus own-share bit diagnostics and independent target inference; protected intervals include chance. Finite diagnostics do not prove full timing equivalence or protect colluding servers. |
| P04 | Fixed query/answer sizes, GB/s/full-scan throughput | Complete | G23 six-cell count/width full-scan curve, 30 fresh-state trials each, fixed share/answer payloads; T22 separate encrypted transport. Reported rates explicitly in-process, not network/production capacity |
| P05 | Generic encrypted geometry-bound transport and failure/replay tests | Complete | `src/secure.rs`, `tests/secure_transport.rs`, `tests/secure_processes.rs`, `PIR_TRANSPORT.md`; plaintext CLI explicitly retained for experiments |
| P06 | Authenticated registry/module selection | Complete bundled prototype | Trusted bundled registry/module pins are checked in the process path. Dynamic independent signing/publication and registry rollback policy remain deployment extensions. |
| P07 | Square-root communication variant; DPF optional | Complete square-root variant | SQ23 implements genuine row-packed two-server XOR queries with private column recovery, fixed shape, bounds and 5,760 full-record checks. DPF remains optional. Server scans are still linear; square layout can increase total bytes. |
| P08 | Genuine SimplePIR reference on matched DB, real hint/setup | Complete | R20 pinned commit/license and original upstream correctness log; actual 10,000 eight-byte DB, 960 measured oracle checks |
| P09 | Single-server runtime option or native toy implementation | Extension; reference alternative implemented | The roadmap allows genuine reference benchmarking instead of reimplementation. R20/R23 execute pinned SimplePIR; no native LWE construction or runtime selection option is claimed. |
| P10 | 100,000-query LWE failure experiment and hint/communication accounting | Complete, bounded | R23: 100,020 SimplePIR outputs and 100,020 matched XOR outputs all correct over 30 setups each, actual hint/setup/online accounting and amortization. Queries sharing a setup are not 100k independent setup trials; no worst-case LWE failure bound. |
| P11 | Target query timing and database-size throughput curves | Complete, bounded | PT23: 46,080 measured requests at 128/1,024 records, independent profiles/targets, control first and local-time/share feature ablations. G23 supplies count/record-width scan curves. No remote network-timing theorem. |

## L4: Fixed-shape WASM (§5, week 5)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| E01 | Actual Wasmtime runtime and five varied functions | Complete | `examples/wasm-functions/`, executor execution tests; copy/sum/Fibonacci/checksum/stateful |
| E02 | Fuel, memory, fixed I/O, host charge/count, epochs, no WASI | Complete | `crates/oblivion-exec/src/lib.rs`, `host.rs`, execution tests; guest limits do not cap all host/JIT memory |
| E03 | Uniform successful/error/trap response sizes and deadline targets | Complete | `tests/execution.rs`, protected error bodies; deadline target is engineering mechanism with measured overrun flag |
| E04 | Five-class/function timing+size classifier, trap indistinguishability | Complete | X22: five successful functions plus trap/fuel/memory failures, 30 fitted-model trials, leaky selector control first; protected eight-class accuracy 11.67% [9.38,13.75] vs 12.5% chance. Bounded feature test, not a theorem |
| E05 | General guest-independent storage count and public phase schedule | Complete | `tests/storage_schedule.rs::protected_functions_and_failures_have_identical_storage_structure`; M reads/M writes, staged traps discarded; physical failures outside equal-shape condition |
| E06 | Namespaced user/dummy state, no cross-client access | Complete | `tests/storage_schedule.rs::namespaces_prevent_guest_cross_client_and_dummy_accesses`, process mixed-client test |
| E07 | Padded/actual overhead, waste, per-core throughput and first/warm/setup split | Complete, bounded | CPU23 plus original resource campaign: three public classes × two modes × 30 processes, 2,160 calls per campaign. Direct invocation process/thread CPU, engine/compile stages, first/warm calls, wall padding and success/failure denominators are separate; no guest-only or production billing claim. |
| E08 | Billing/cache/memory.grow/host timing confidentiality | Residual/non-goal | Sandboxing/fuel are not constant-time execution or confidentiality against the trusted host. Explicit residual observations, not an unsupported completed security property. |
| E09 | Hardware TEE provisioning, attestation and side-channel defenses | Extension | Ordinary processes simulate TrustedExecutor; actual TEE/attestation deployment is not selected or claimed. |

## L5: Epoch batching (§6, week 6)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| B01 | Exactly one fixed real/dummy request per enrolled slot, bounded queues/fixed emission | Complete | `crates/oblivion-batcher/`, `tests/epochs.rs`; missing slot cover is random ciphertext handled as dummy downstream |
| B02 | Same-size authenticated real/dummy envelopes and replay rejection | Complete | Batcher tests, directional 164-byte frames; unknown epoch/slot/duplicate handling |
| B03 | 0/50/100% load joint observer distribution tests | Complete, bounded | BL23: actual timer/queue and full plaintext-control vs AEAD wire, 720 separate processes, 30 fits/mode. Joint 22-feature control 100%, protected 28.33% [22.78,33.89]; two failed forest controls preserved. Not a timing-equivalence proof. |
| B04 | Latency, goodput/dummy and integrated epoch/batch curves | Complete, bounded | 270 timer component trials establish random-phase E/2 queue delay; EP23 adds 360 genuine full-pipeline trials across participants 1/2, periods 200/400 ms and real ratios 0/50/100. Private-ready, arrival and reader-pipe boundaries are distinct. |
| B05 | Presence/intersection inference under online/offline participation | Complete | B23 successful 30/30 control and fixed-rate-online recovery at both availability rates; always-participating eight-candidate counterfactual. Explicit semantic-beacon knowledge, independent tie seed, whole-trial Wilson intervals |
| B06 | Active drop/delay/skip/duplicate robustness | Complete, bounded | FT23 repeats seven real assertion-bearing fault fixtures 30 times each: bootstrap/partial/EOF, duplicate/skipped/late epochs, tamper, lost PIR child and response backpressure. Failures remain visible; no general availability/exactly-once guarantee. |
| B07 | DP-noised batching, epsilon/delta and composition | Extension | Explicit optional variant cut from selected fixed-rate prototype. No formal DP or composition guarantee is claimed. |

## L6: Privacy-aware autoscaling (§7, week 12)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| A01 | Actual event simulator, five required policies and synthetic Zipf/diurnal/burst workloads | Complete | `research/simulation/scaler.py`, `run.py`; A20 and 13 recorded simulator tests |
| A02 | Public instance/cold-start observer infers load/hot class with policy knowledge | Complete | A20 separate profiling/targets, restricted schema, naive positive controls, trial-cluster intervals; latent load regime rather than arbitrary time-varying load |
| A03 | Instance-seconds, p99, attacker score for each policy and Pareto plots | Complete | A20 35 policy/task/workload summaries/run, raw records, two plots; price 0.00001/instance-second is hypothetical |
| A04 | At least one policy dominates naive on leakage/cost plane | Complete nominal comparison; SLO target limited | A20 shows fixed-capacity nominal leakage/cost improvements for stated workloads and prices, with poor burst/SLO behavior retained. The roadmap does not require universal SLO-feasible statistically significant dominance. |
| A05 | Burst sensitivity and identity-independent fixed-capacity cold starts | Complete, simulation scope | A20 compares four workload families and fixed prewarmed capacity with actual simulator waiting/readiness/cold-start events. Burst SLO failures are explicit; no measured cloud cold-start distribution or real worker pool is claimed. |
| A06 | Real prewarmed runtime pool / Kubernetes | Extension | Fixed initial capacity is implemented in the selected simulator. Real runtime provisioning is optional; Kubernetes is explicitly outside the roadmap scope. |
| A07 | Synthetic or licensed real arrival trace input | Complete selected synthetic study | The roadmap permits synthetic Zipf/diurnal/burst inputs when no verified real trace is imported. A20 records those inputs; a validated CSV importer exists. A future external trace requires separate source/license provenance. |
| A08 | Formal privacy for noisy policy | Extension | Noise remains an engineering policy input; no adjacency, sensitivity, epsilon/delta or composition guarantee is claimed. |

## L7: Attacks and evaluation (§8, weeks 7/11)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| H01 | Actual trace mechanisms and common attack/auxiliary API | Complete | 13 registered adapters, including leafTiming, pirTargetTiming and batchLoad; common PredictionResult, strict schemas and no invented calibrated confidence. Separate studies establish experimental evidence. |
| H02 | Frequency attack and unpadded traffic classifier, positive controls | Complete | L20 raw files/reports, strict observer-only schema, controls exceed relevant baseline |
| H03 | One SSE attack for MVP | Complete | `SSE_ATTACKS.md`, `experiments/results/sse-attacks/report.json`: actual count/volume and stable-tag frequency attacks, exact-count control, genuine encrypted dummy padding, 30 trial clusters and eight scoped Python tests |
| H04 | Cash-style count attack | Complete | `SSE_ATTACKS.md`: bounded transparent count baseline on actual encrypted index, independent auxiliary corpus and successful exact-count control; not a faithful full Cash reproduction |
| H05 | Oya–Kerschbaum-style MLE attack | Complete | `ADVANCED_ATTACKS.md`, H22: offline separable likelihood assignment on actual SSE exports with positive control, independent query profile and 30 trial clusters; not a faithful Oya–Kerschbaum reproduction |
| H06 | IHOP-lite | Complete | `ADVANCED_ATTACKS.md`, H22: bounded iterative linear-assignment Markov model and exact eight-keyword comparator; objective checks and positive controls; explicitly not faithful IHOP |
| H07 | File injection against non-forward-private baseline | Complete | `UPDATE_LINKABILITY.md`: actual chosen encrypted updates versus stable-tag control, 30 trial clusters, before/after next authorization. Bounded association experiment, not a faithful general published file-injection reproduction |
| H08 | Accuracy, top-k, ROC and bootstrap CIs | Complete | L20 binary ROC/AUC; H22/X22 multiclass accuracy, balanced accuracy, top-three and whole-trial intervals. Binary ROC is not invented for multiclass permutation inference |
| H09 | Positive-control-first, fixed seeds and one-command reproducibility | Complete | Component, SSE, execution and joint analyses gate interpretation on successful leaky controls. Unvalidated packet classifier removed and historical outputs excluded in T22; adapters do not create fresh evidence |
| H10 | No train/test related-session leakage; proper uncertainty clustering | Complete | L20 independent profiling/target sessions and equal-weight whole-trial bootstrap; original smoke session bootstrap explicitly superseded |
| H11 | Realistic document corpus and auxiliary-knowledge sensitivity | Complete, bounded | C23 licensed text associations, 30 conditional resamples and paired drift intervals. All auxiliary documents are disjoint from target; baseline and drift pools are disjoint, while two drift views may overlap each other. Queries remain synthetic IID, not real human searches. |
| H12 | MI estimate if bits are reported | Not applicable | No empirical bits or zero-bit claim is reported; chosen attack success and uncertainty are the privacy metrics. An MI estimator is conditional future work. |

## Integration, benchmarks, ablations and final delivery (§9–11)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| I01 | Actual client → batcher → PIR → padded WASM → ORAM process path | Complete | `crates/oblivion-server/src/pipeline.rs`, process oracle tests; D20 historical executions |
| I02 | Several clients, all five functions, isolated state and equal storage shapes | Complete | V22 process tests and D22 recorded `demo-sse`: three clients, 24 actual calls, all five functions, 12 real calls, 24 metadata queries, 3,072 storage events; output/counter oracles |
| I03 | Joint observer classifier on all supported interfaces with leaky positive control | Complete | J22 final 30-trial actual A–G declared interface-summary model: G balanced accuracy 33.40% [32.29,34.51], chance 33.33%; controls first, private labels excluded, full payload/physical traces retained. Host/cache/billing and stronger full-sequence models remain outside this bounded acceptance |
| I04 | A plaintext, B encrypt-only, C ORAM, D PIR, E batching, F padded executor, G combined | Complete | J22 actual common-workload A–G libraries and raw observer/truth/metrics; process G separately verified. This is in-process system evidence, not TCP capture or every host interface |
| I05 | Turn each layer off individually and measure effect | Complete | J22 actual per-layer disabled paths, common-workload ablation reports and `ablation-attacks.png`; timing/provenance versions remain distinct |
| M01 | End-to-end quantiles, layer timing, open-loop and 30+ runs | Complete, bounded | RT23 adds six load/queue cells, 180 fresh processes and 5,760 offers; component/stage first/warm/setup studies and trial intervals identify measurement boundaries. Finite 32-offer runs do not estimate asymptotic capacity or prove population tail bounds. |
| M02 | Client/server/server interface bytes per real request and blowup | Complete interface accounting | T22 captures actual encrypted PIR packets; J22/EP23 count actual invocation, registry and bucket-interface frames. Storage backend payload is not mislabeled network traffic, and aggregate application bytes are not every deployment packet. |
| M03 | CPU/request, padding, memory and throughput/goodput | Complete, bounded | CPU23 directly measures invocation process/thread CPU and success/failure denominators, setup CPU and child RSS; RT23/EP23 report actual goodput/dummy work and whole-process resource scope. Wall padding is not called CPU waste. Post-measurement research error retention charges failed/zero-success trial costs by ratios of sums and exposes undefined bootstrap denominators. |
| M04 | Cost/million from explicit price assumptions, time and egress | Complete illustrative accounting | J22 uses declared hypothetical executor-wall/egress prices; A20 uses stated instance-second prices. These meet the explicit-assumption comparison without pretending to be verified provider billing/current prices. |
| M05 | Epoch, batch, dummy, resource/deadline, storage/PIR and scaling sweeps | Complete selected axes | EP23 supplies 12 integrated cells; CPU23 three public resource classes; G23 42 storage/PIR cells; A20 five policies/workload/prewarm variants. Confounded resource-class changes and finite host-specific cells are disclosed, not a universal factorial search. |
| M06 | Bursts/epoch skips/drops and bounded lifetimes | Complete, bounded | RT23 load/admission/drop/SLO records, A20 bursts and FT23 210 fault launches plus queue/process tests. Negative overload and active-failure observations remain part of the result. |
| M07 | Latency/privacy figure and CIs | Complete | J22 `latency-privacy.png`, reported trial intervals and public measurement contract; broad external load/capacity frontier remains separate |
| M08 | Bandwidth/privacy and cost/attack-success figures | Complete | J22 `bandwidth-privacy.png` and `cost-attack.png` from common-workload actual counters with declared hypothetical prices |
| M09 | ORAM-size and batching-epoch figures | Complete | `oram-size-30-20261021/summary.json`/`oram-size.png`: 30 trials per 16/64/256/1024 blocks. `batch-epoch-current/analysis.json`/`batching-overhead-vs-epoch.png`: 270 actual timer/AEAD trials across 2/10/25 ms and 0/50/100% real; component scopes explicitly bounded |
| M10 | Before/after attack and ablation figures | Complete | L20 controls, H22 inference figure, J22 `ablation-attacks.png` and raw-derived reports; unsuccessful defenses retained |
| M11 | Autoscaler cost/privacy figure | Complete | A20 `pareto-hot.png`, `pareto-intensity.png`, raw reports/plot-only regeneration |
| M12 | Three-axis Pareto, fixed-SLO panels and extremes | Complete nominal analysis | J22 common-workload A–G extremes and mean-point three-axis membership plus CIs; A20 cost/privacy and SLO-feasibility panels. Universal statistical dominance or provider calibration is not asserted or an extra required acceptance criterion. |
| M13 | Report/design/threat/related work/demo/public branch delivery | Gate pending | Documents and recorded actual demo exist; `COMPLETION_AUDIT.md` maps original scope. Current local validation is accepted; draft PR #1 exists; final-head hosted CI and review remain pending, with no merge claimed. |

## Scope and acceptance rules

Weeks 1–8 are a coherent prioritized milestone, but the user's continuation request retains the later roadmap. Cuttable/optional items above remain visible rather than silently removed. The roadmap's reading lists, interview questions, research groups/courses/venues are learning/context material, not executable software acceptance; their mutable dates/affiliations and unverified appendix require fresh verification before external citation. No audit here revalidates those external listings.

Current scientific limits are mandatory: no host-memory confidentiality without actual isolation, no XOR PIR privacy under server collusion, no DP from arbitrary noise, no backward privacy from forward-private SSE, no durable invocation semantics from store snapshots alone, no whole-anchor replay protection from AEAD, and no cryptographic proof from statistical non-rejection. All experimental acceptance conditions report what occurred even when the desired result fails.

## Remaining acceptance and extensions

The implementation and selected empirical-artifact rows now have bounded evidence, including Circuit reference, square-root PIR, 100k SimplePIR correctness, timing attackers, real-corpus drift, presence, CPU/resource/load/fault and integrated pipe-epoch studies. This is not an unconditional full-roadmap or security-completion claim. The current local quality gate is accepted; final-head hosted CI and draft PR review remain acceptance work. The first local gate has a harness Timeout; the next has one Python authenticated sweep error of unknown private cause. Both remain preserved; the fresh verified ten-command local result is accepted, while final-head hosted CI/PR review remain open. [The figure reproduction audit](FIGURE_REPRODUCTION.md) now records raw-derived reports/figures without ignored executables; this does not substitute for final-head hosted CI/PR review.

Possible weak ORAM timing inference, complete semantic-beacon presence recovery, burst/overload SLO failures, increased matrix-PIR response traffic and historical instrumentation/control failures remain visible outcomes. An investigation can be complete while a desirable privacy/performance target is unmet. See `COMPLETION_AUDIT.md` for the primary numbered roadmap crosswalk and explicit human-context versus selected-software boundaries.

Hardware TEE/attestation, formal DP, recursive maps, a native Circuit replacement, DPF/native single-server runtime selection, persistent/backward-private SSE, real cloud provisioning and durable application acknowledgments are unselected extensions or deployment obligations. Genuine Circuit reference and square-root PIR are implemented and must not still be listed as absent optional work. No external-anchor or public-demo known-schedule limitation is silently converted into a completed confidentiality claim.
