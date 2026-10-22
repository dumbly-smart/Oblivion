# Requirements and evidence matrix

Audited 2026-10-23 against the complete supplied [research roadmap](../Oblivion_%20Research%20Roadmap%20and%20Build%20Plan%20%281%29.md), the original project instructions summarized in the build/completion plans, current source, component documentation and saved result records. This document does not change those requirements.

**Complete** means the bounded artifact/behavior exists with the cited evidence; it does not mean the full system is secure. **Partial** means some required implementation/evidence exists, with the missing part stated. **Not verified** means no accepted execution/artifact is established here, including work currently being implemented. Source/test presence is not a passing test execution. Optional extensions remain explicitly tracked. A hoped-for experimental result is not a license to manufacture a positive outcome.

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
| SRC | Current component paths/test names below | Source presence alone is not executed validation; V22 and per-run source versions remain explicit |

The separate million-operation release stress execution (1,000,000 operations, 256 blocks, periodic invariants; 41.61 seconds) is recorded in the earlier implementation history. V22 records a later repeat; VF22 records a matching-source repeat. The first hosted Rust and stress jobs passed; Python fixture setup failed and has been fixed, with a corrected full hosted run pending. All result source hashes/configs identify launch-time versions; today's source must not inherit their measurements automatically.

## Foundation, trust and documentation

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| F01 | Preserve original checkout/user artifacts; coherent Rust workspace and lockfile | Complete | Root `Cargo.toml`, `Cargo.lock`; seven real crates. Pre-existing `graft/` preserved |
| F02 | Explicit threat model A/B/C and trust boundaries | Complete | `THREAT_MODEL.md`, `SECURITY_ASSUMPTIONS.md`: TrustedExecutor simulated with processes; no hardware TEE |
| F03 | Assets, adversary, leakage functions, residual channels and diagram | Complete | `THREAT_MODEL.md`, `ARCHITECTURE.md`; storage/network/scheduler/billing observations distinguished |
| F04 | AEAD, HKDF separation, OS entropy and nonce lifecycle | Complete | Store/batcher/PIR/SSE source; assumptions record ephemeral invocation sessions and rekeyed store restore |
| F05 | Observer schema excluding plaintext secrets/labels; distinct truth/private data | Complete | `PROTOCOL.md`; store events, harness datasets, simulator strict public schema; runtime private files must remain private |
| F06 | CI configured and running | Partial | First hosted run 39847355406: Rust and million-op stress passed; Python failed on missing release fixtures. Workflow now builds them; corrected hosted outcome pending |
| F07 | Reproducible commands, exact dependencies/config/seeds and provenance | Complete | Locked dependencies, per-run configuration/seeds and source/executable fingerprints; T22/X22/J22 preserve exact measurement boundaries. Postmeasurement source snapshots are explicitly labeled |
| F08 | P1–P12 probability/security games/crypto/GGM/LWE/DP/systems/WASM/stats preparation | Partial | Construction and statistical assumptions documented. Human reading/understanding is not established by tests |
| F09 | Verify primary literature and licenses before claiming faithful methods | Partial | Path ORAM/Wasmtime/RustCrypto and SSE design sources recorded; R20 pins/license genuine reference. Full roadmap appendix and attack/dataset checks remain |
| F10 | Final README, 2–3 page design/writeup, report, related work, talk/demo video/public artifact | Partial | README, `DESIGN_SUMMARY.md`, `RESEARCH_REPORT.md`, `RELATED_WORK.md`, and actual local MP4/terminalcast in `DEMO.md` exist; final frozen-source gates, hosted CI and public delivery acceptance remain |

## L1: Diana-inspired constrained GGM SSE (§2, week 9)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| S01 | Actual constrained GGM PRF, client keyword state and encrypted server posting map | Complete | `crates/oblivion-sse/src/lib.rs`, `SSE_DESIGN.md`; HMAC tree, exact prefix cover, independent value keys; labeled Diana-inspired, no theorem-port claim |
| S02 | 100,000 random add/search operations equal plaintext oracle | Complete | S20 recorded release suite; seeded oracle includes duplicate IDs/retries/rotation; rerun current source before certifying edits |
| S03 | Written adversary retains every past search token/capability | Complete | S20 retained-node tests/challenge, including lost search responses; positive controls prematurely release root or stable update tag |
| S04 | Report preauthorization link challenge vs chance and uncertainty | Partial | S20 400 balanced challenges, 202/400 guesses with Wilson interval, 0 fresh addresses derived before and 400 after authorization; narrow capability adversary only, no full leakage-abuse security proof |
| S05 | Exact server-side update/search leakage logs | Complete | `--example measure -- PATH` exports real request/response capabilities/addresses; S20 parsed 13,161 events; no plaintext ID/keyword field. Generated large transcript not retained as committed raw record |
| S06 | Update/search cost vs result count and storage blowup | Partial | S20 sample timings, 56 cryptographic bytes/posting, 73 logical update bytes; full container/RSS, repeated trials and integrated benchmark absent |
| S07 | Forward-privacy transcript argument and explicit residual equality/volume/timing | Complete | `SSE_DESIGN.md` assumptions/leakage argument; computational claim conditioned on GGM/PRF and counters, no byte-histogram proof |
| S08 | Ephemeral state loss, exact pending retry and counter safety | Complete | No restore/key-import API; tests stale-counter negative fixture and idempotent retries. Persistence is deliberately unsupported |
| S09 | Metadata index integrated with actual function discovery/invocation | Complete | `RUNTIME_INTEGRATION.md`: actual `demo-sse` prepare/search/verify drives mixed PIR/WASM/ORAM; scoped server suite passed 4 unit/14 integration tests and clippy. Search timing/volume remain outside padded class |
| S10 | Deletions/backward privacy and Janus design sketch | Partial | `EXTENSION_NOTES.md` supplies source-backed backward-privacy contrast/design sketch; no deletion/backward-private implementation claimed |
| S11 | Persistent SSE client journal, antirollback and multiwriter reservation | Not verified | Extension necessary for persistent deployment; no supported persistence, no reset-counter restore claim |

## L2: Path ORAM (§3, weeks 2–3)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| O01 | Rust Path ORAM, Z=4, AEAD fixed buckets, fresh writes, client map/stash | Complete | `crates/oblivion-store/src/oram.rs`, `crates/oblivion-store/src/config.rs`; encryption is implemented in `oram.rs`; reads and writes remap with OS randomness |
| O02 | Memory/file Backend abstraction | Complete | `src/backend.rs`, `tests/recovery.rs::file_backend_bounds_and_truncated_files`; bounded real file I/O |
| O03 | Million random operations match plaintext oracle | Complete | V22 release stress explicitly ran 1,000,000 operations over 256 blocks in 41.44 seconds; ordinary suite deliberately ignores this tier |
| O04 | Stash histogram/max and invariants | Complete | G23 36 N/width/Z/workload cells × 30 controllers with genuine private histograms and fixed observer checks; maximum observed stash seven. Finite occupancy observations do not establish rare overflow bounds |
| O05 | 100,000 repeated-address versus uniform-address chi-square/KS/independence diagnostics | Complete | T22: actual 100,000 accesses each for repeated and uniform workloads, 1.4M physical events each; compressed originals, chi-square/discrete-KS/permutation diagnostics and limitations retained in `TRACE_VALIDATION.md` |
| O06 | Fixed server messages and measured 2·Z·(log N+1) payload blowup | Complete | `tests/adversarial.rs::fixed_shape_and_fresh_ciphertext_for_reads_and_writes`, O20; ciphertext/metadata overhead explicitly counted at bucket interface |
| O07 | p50/p99, bandwidth, trusted memory and stash overhead | Partial | G23 36-cell latency/payload/storage/stash/trusted-metadata sweep plus O20. Payload excludes allocator/oracle/process memory; full remote/RSS accounting remains separate |
| O08 | Stronger leaf+timing classifier for address or operation inference | Partial | L20 frequency attack sees leaf tags only; general address/operation timing classifier remains unverified; J22 now provides the separately bounded joint-system feature result |
| O09 | Integrity, bucket substitution/replay and failure semantics | Complete | `tests/adversarial.rs`, trusted versions/location AEAD, poison on uncertain reads/writes |
| O10 | Durable authenticated state and recovery | Partial | `src/oram/recovery.rs`, `tests/recovery.rs`, `STORAGE_RECOVERY.md`: complete snapshots and fresh-key restore. External anchor publication and durable application ack protocol absent; whole-anchor replay unsolved |
| O11 | Recursive map, multi-controller/shared-writer protocol | Not verified | Explicit later extensions; trusted map/version state remains O(N), one serialized controller |
| O12 | Circuit ORAM benchmark reference and eviction design note | Partial | `EXTENSION_NOTES.md` gives reviewed eviction/recursive-map comparison boundaries; no Circuit ORAM implementation or measured reference comparison |

## L3: Registry PIR (§4, week 4 and week 10)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| P01 | Actual two-server XOR selection shares/full scans/recovery | Complete | `crates/oblivion-pir/src/lib.rs`, retrieval/process tests; separate server-owned state |
| P02 | Correct 10,000 × 1 KiB retrieval | Complete | `tests/retrieval.rs::ten_thousand_kib_records`, P20; current secure TCP/process tests cover same geometry |
| P03 | Individual-server query uniformity for varied indices | Partial | `bit_marginals_do_not_depend_on_requested_index`; per-bit diagnostic is not an exhaustive joint-distribution or timing test |
| P04 | Fixed query/answer sizes, GB/s/full-scan throughput | Complete | G23 six-cell count/width full-scan curve, 30 fresh-state trials each, fixed share/answer payloads; T22 separate encrypted transport. Reported rates explicitly in-process, not network/production capacity |
| P05 | Generic encrypted geometry-bound transport and failure/replay tests | Complete | `src/secure.rs`, `tests/secure_transport.rs`, `tests/secure_processes.rs`, `PIR_TRANSPORT.md`; plaintext CLI explicitly retained for experiments |
| P06 | Authenticated registry/module selection | Partial | Process recovered-record pins bind trusted bundled records; independent signing/dynamic publication and rollback policy not implemented |
| P07 | √n communication/DPF variant | Not verified | Roadmap additional scheme; current query vector is ceil(N/8), server scan linear |
| P08 | Genuine SimplePIR reference on matched DB, real hint/setup | Complete | R20 pinned commit/license and original upstream correctness log; actual 10,000 eight-byte DB, 960 measured oracle checks |
| P09 | Single-server runtime option or native toy implementation | Not verified | R20 is a genuine reference adapter, not a server runtime replacement or independent LWE implementation |
| P10 | 100,000-query LWE failure experiment, database/hint/communication sweeps | Partial | R20 checks 480 SimplePIR measured outputs, setup/online payloads and amortization; no 100,000-query run or broad DB sweep |
| P11 | Target-independent query timing and full database-size throughput curves | Not verified | Full scan implementation is present, but dedicated timing inference/scaling experiments not established |

## L4: Fixed-shape WASM (§5, week 5)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| E01 | Actual Wasmtime runtime and five varied functions | Complete | `examples/wasm-functions/`, executor execution tests; copy/sum/Fibonacci/checksum/stateful |
| E02 | Fuel, memory, fixed I/O, host charge/count, epochs, no WASI | Complete | `crates/oblivion-exec/src/lib.rs`, `host.rs`, execution tests; guest limits do not cap all host/JIT memory |
| E03 | Uniform successful/error/trap response sizes and deadline targets | Complete | `tests/execution.rs`, protected error bodies; deadline target is engineering mechanism with measured overrun flag |
| E04 | Five-class/function timing+size classifier, trap indistinguishability | Complete | X22: five successful functions plus trap/fuel/memory failures, 30 fitted-model trials, leaky selector control first; protected eight-class accuracy 11.67% [9.38,13.75] vs 12.5% chance. Bounded feature test, not a theorem |
| E05 | General guest-independent storage count and public phase schedule | Complete | `tests/storage_schedule.rs::protected_functions_and_failures_have_identical_storage_structure`; M reads/M writes, staged traps discarded; physical failures outside equal-shape condition |
| E06 | Namespaced user/dummy state, no cross-client access | Complete | `tests/storage_schedule.rs::namespaces_prevent_guest_cross_client_and_dummy_accesses`, process mixed-client test |
| E07 | Padded/actual overhead, waste, per-core throughput and warm/cold split | Partial | Component actual/padded timings exist; broad runtime CPU/waste/warm/cold throughput evaluation pending |
| E08 | Hidden billing/cache/memory.grow/host timing | Not verified | Documented residual leakage; sandboxing and fuel are not data-oblivious/constant-time execution |
| E09 | Hardware TEE provisioning, attestation and side-channel defenses | Not verified | Optional deployment extension; simulated TrustedExecutor boundary only |

## L5: Epoch batching (§6, week 6)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| B01 | Exactly one fixed real/dummy request per enrolled slot, bounded queues/fixed emission | Complete | `crates/oblivion-batcher/`, `tests/epochs.rs`; missing slot cover is random ciphertext handled as dummy downstream |
| B02 | Same-size authenticated real/dummy envelopes and replay rejection | Complete | Batcher tests, directional 164-byte frames; unknown epoch/slot/duplicate handling |
| B03 | 0/50/100% load observer distribution tests | Partial | D20 historical single-client runs; current fixed structure/multi-client tests exist. Statistical full joint size/time/destination comparison required |
| B04 | Latency ≈ E/2+processing, goodput/dummy and epoch curves | Partial | `RUNTIME_BENCHMARKS.md`: 270 actual batching trials quantify E/2 queue delay and real/dummy counts ; 60 process offered-load trials quantify admitted throughput/drops. No shared integrated epoch-vs-system-goodput sweep claimed |
| B05 | Presence/intersection inference under online/offline participation | Complete | B23 successful 30/30 control and fixed-rate-online recovery at both availability rates; always-participating eight-candidate counterfactual. Explicit semantic-beacon knowledge, independent tie seed, whole-trial Wilson intervals |
| B06 | Active drop/delay/skip/duplicate robustness | Partial | Queue/replay/server-loss component tests exist; full multi-client fault campaign and timing evidence pending |
| B07 | DP-noised batching, ε/δ and T-epoch composition | Not verified | Explicit optional variant cut from MVP. Fixed-rate batching and simulator noise do not imply DP |

## L6: Privacy-aware autoscaling (§7, week 12)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| A01 | Actual event simulator, five required policies and synthetic Zipf/diurnal/burst workloads | Complete | `research/simulation/scaler.py`, `run.py`; A20 and 13 recorded simulator tests |
| A02 | Public instance/cold-start observer infers load/hot class with policy knowledge | Complete | A20 separate profiling/targets, restricted schema, naive positive controls, trial-cluster intervals; latent load regime rather than arbitrary time-varying load |
| A03 | Instance-seconds, p99, attacker score for each policy and Pareto plots | Complete | A20 35 policy/task/workload summaries/run, raw records, two plots; price 0.00001/instance-second is hypothetical |
| A04 | At least one policy dominates naive on leakage/cost plane | Partial | Fixed-one has nominal lower cost/inference but poor SLO; no universal SLO-feasible dominance. Negative outcomes retained; statistical significance not established |
| A05 | Burst sensitivity and bounded identity-independent cold starts | Partial | A20 burst and fixed-capacity observations; realistic runtime calibration/cold-start identity distributions absent |
| A06 | Real prewarmed runtime pool knob / Kubernetes | Not verified | Runtime knob is optional; simulator fixed initial capacity is implemented. Kubernetes explicitly out of roadmap scope |
| A07 | Verified real trace importer/provenance/licensing | Partial | Validated CSV importer/hash/provenance support; recorded runs are seeded synthetic, no external dataset fetched |
| A08 | Formal privacy for noisy policy | Not verified | Noise is engineering input with raw queue feedback, no ε/δ, adjacency/sensitivity or composition guarantee |

## L7: Attacks and evaluation (§8, weeks 7/11)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| H01 | Trace-driven actual mechanisms and attack/prediction/auxiliary-knowledge interface | Complete | `ATTACK_INTERFACE.md`: ten real adapters, including trace-level presence intersection; common predictions/confidence/metadata and strict JSON schemas; twelve adapter checks. Experiment evidence remains separate |
| H02 | Frequency attack and unpadded traffic classifier, positive controls | Complete | L20 raw files/reports, strict observer-only schema, controls exceed relevant baseline |
| H03 | One SSE attack for MVP | Complete | `SSE_ATTACKS.md`, `experiments/results/sse-attacks/report.json`: actual count/volume and stable-tag frequency attacks, exact-count control, genuine encrypted dummy padding, 30 trial clusters and eight scoped Python tests |
| H04 | Cash-style count attack | Complete | `SSE_ATTACKS.md`: bounded transparent count baseline on actual encrypted index, independent auxiliary corpus and successful exact-count control; not a faithful full Cash reproduction |
| H05 | Oya–Kerschbaum-style MLE attack | Complete | `ADVANCED_ATTACKS.md`, H22: offline separable likelihood assignment on actual SSE exports with positive control, independent query profile and 30 trial clusters; not a faithful Oya–Kerschbaum reproduction |
| H06 | IHOP-lite | Complete | `ADVANCED_ATTACKS.md`, H22: bounded iterative linear-assignment Markov model and exact eight-keyword comparator; objective checks and positive controls; explicitly not faithful IHOP |
| H07 | File injection against non-forward-private baseline | Complete | `UPDATE_LINKABILITY.md`: actual chosen encrypted updates versus stable-tag control, 30 trial clusters, before/after next authorization. Bounded association experiment, not a faithful general published file-injection reproduction |
| H08 | Accuracy, top-k, ROC and bootstrap CIs | Complete | L20 binary ROC/AUC; H22/X22 multiclass accuracy, balanced accuracy, top-three and whole-trial intervals. Binary ROC is not invented for multiclass permutation inference |
| H09 | Positive-control-first, fixed seeds and one-command reproducibility | Complete | Component, SSE, execution and joint analyses gate interpretation on successful leaky controls. Unvalidated packet classifier removed and historical outputs excluded in T22; adapters do not create fresh evidence |
| H10 | No train/test related-session leakage; proper uncertainty clustering | Complete | L20 independent profiling/target sessions and equal-weight whole-trial bootstrap; original smoke session bootstrap explicitly superseded |
| H11 | Realistic corpus and auxiliary-knowledge sensitivity | Complete | C23 real licensed document associations and three disjoint auxiliary population views, 30 conditional split resamples and paired intervals. Queries remain synthetic IID; no human query or chronological-drift claim |
| H12 | Classifier/nonparametric MI lower-bound estimate if bits reported | Not verified | No bits/zero-leakage claim or completed MI estimator; attack success is the reported empirical quantity |

## Integration, benchmarks, ablations and final delivery (§9–11)

| ID | Requirement | Status | Evidence / remaining condition |
| --- | --- | --- | --- |
| I01 | Actual client → batcher → PIR → padded WASM → ORAM process path | Complete | `crates/oblivion-server/src/pipeline.rs`, process oracle tests; D20 historical executions |
| I02 | Several clients, all five functions, isolated state and equal storage shapes | Complete | V22 process tests and D22 recorded `demo-sse`: three clients, 24 actual calls, all five functions, 12 real calls, 24 metadata queries, 3,072 storage events; output/counter oracles |
| I03 | Joint observer classifier on all supported interfaces with leaky positive control | Complete | J22 final 30-trial actual A–G declared interface-summary model: G balanced accuracy 33.40% [32.29,34.51], chance 33.33%; controls first, private labels excluded, full payload/physical traces retained. Host/cache/billing and stronger full-sequence models remain outside this bounded acceptance |
| I04 | A plaintext, B encrypt-only, C ORAM, D PIR, E batching, F padded executor, G combined | Complete | J22 actual common-workload A–G libraries and raw observer/truth/metrics; process G separately verified. This is in-process system evidence, not TCP capture or every host interface |
| I05 | Turn each layer off individually and measure effect | Complete | J22 actual per-layer disabled paths, common-workload ablation reports and `ablation-attacks.png`; timing/provenance versions remain distinct |
| M01 | End-to-end p50/p95/p99 and layer timing, warm-up excluded, open-loop, 30+ runs | Partial | `RUNTIME_BENCHMARKS.md`: 30 fresh-process trials at each of two offered loads, actual queued service/oracle and trial intervals. Eight offers/trial produce weak tail resolution; complete broad load/latency campaign still required |
| M02 | Measured client/server/server wire bytes per real request and plaintext blowup | Partial | T22 genuine encrypted PIR pcap/streams; J22 framed invocation/registry/storage accounting and blowup. No global packet capture across every deployment interface |
| M03 | CPU-seconds/request, padding waste, RSS and throughput/goodput | Partial | `RUNTIME_BENCHMARKS.md` records admitted throughput, queue waits, drops, coarse process CPU ticks and sampled aggregate RSS across 60 trials; no isolated high-resolution CPU or cloud billing guarantee |
| M04 | Cost/million from explicit price assumptions, instance-seconds and egress | Partial | J22 explicit hypothetical worker/egress accounting and cost/million; A20 instance-second prices. Neither is measured provider billing or a verified current cloud price sheet |
| M05 | Sweeps: epoch, batch, dummy ratio, fuel/deadline, ORAM Z/block size, DB/PIR and scaling | Partial | G23 covers N/Z/block widths/workload and PIR N/record widths; batching epoch/real ratio and scaler prewarm variants measured. Executor resource-class and wider runtime sweeps in progress; integrated participant/deadline axes remain |
| M06 | Robustness under bursts/epoch skips/drops, bounded process lifetimes | Partial | Simulator bursts and component fault checks; active runtime robustness additions require current execution records |
| M07 | Latency/privacy figure and CIs | Complete | J22 `latency-privacy.png`, reported trial intervals and public measurement contract; broad external load/capacity frontier remains separate |
| M08 | Bandwidth/privacy and cost/attack-success figures | Complete | J22 `bandwidth-privacy.png` and `cost-attack.png` from common-workload actual counters with declared hypothetical prices |
| M09 | ORAM-size and batching-epoch figures | Complete | `oram-size-30-20261021/summary.json`/`oram-size.png`: 30 trials per 16/64/256/1024 blocks. `batch-epoch-current/analysis.json`/`batching-overhead-vs-epoch.png`: 270 actual timer/AEAD trials across 2/10/25 ms and 0/50/100% real; component scopes explicitly bounded |
| M10 | Before/after attack and ablation figures | Complete | L20 controls, H22 inference figure, J22 `ablation-attacks.png` and raw-derived reports; unsuccessful defenses retained |
| M11 | Autoscaler cost/privacy figure | Complete | A20 `pareto-hot.png`, `pareto-intensity.png`, raw reports/plot-only regeneration |
| M12 | Three-axis Pareto frontier and fixed-latency-SLO panel; include extremes | Partial | A20 nominal Pareto/SLO panels and J22 common-workload extremes/figures exist; broad calibrated three-axis runtime frontier and robust significance remain incomplete |
| M13 | Full report/design threat model v2/related work/demo video/public delivery | Partial | Research/design/threat/related-work docs and D22 actual MP4/terminalcast exist. Small component commits are pushed to `codex/oblivion-research-platform`; final frozen-source/hosted CI and public delivery acceptance remain |

## Scope and acceptance rules

Weeks 1–8 are a coherent prioritized milestone, but the user's continuation request retains the later roadmap. Cuttable/optional items above remain visible rather than silently removed. The roadmap's reading lists, interview questions, research groups/courses/venues are learning/context material, not executable software acceptance; their mutable dates/affiliations and unverified appendix require fresh verification before external citation. No audit here revalidates those external listings.

Current scientific limits are mandatory: no host-memory confidentiality without actual isolation, no XOR PIR privacy under server collusion, no DP from arbitrary noise, no backward privacy from forward-private SSE, no durable invocation semantics from store snapshots alone, no whole-anchor replay protection from AEAD, and no cryptographic proof from statistical non-rejection. All experimental acceptance conditions report what occurred even when the desired result fails.

## Remaining mandatory acceptance and optional extensions

The implemented pipeline, six bounded SSE-facing attacks, uniform adapter API, required component/ablation figure artifacts, 100k ORAM diagnostics, actual PIR packets, eight-class execution experiment and local demo recording now have evidence. This does not close every roadmap row. Mandatory gaps still include realistic licensed corpus/auxiliary-knowledge sensitivity (H11), presence/intersection inference (B05), broad parameter and load/fault campaigns (M01/M05/M06), detailed warm/cold/resource and PIR throughput studies (E07/P11), full stash/geometry analysis (O04/O07), and calibrated three-axis/SLO frontier interpretation (M12). Final frozen-source validation, hosted CI and public delivery remain explicit gates. Desired positive outcomes, including universal SLO-feasible scaler dominance, cannot be manufactured into completion.

Hardware TEE/attestation, formal DP, recursive/Circuit ORAM, DPF/√n PIR, native single-server PIR, persistent/backward-private SSE and durable application acknowledgments are separately tracked extensions or deployment requirements. Their absence must not be substituted for, or used to conceal, the mandatory empirical gaps above. Faithful publication reproductions and complete literature/dataset verification remain unclaimed; implemented bounded approximations are named precisely.
