# Reproducing experiments

**Selected-scope acceptance:** the [serial local gate](../experiments/results/validation-20261023-serial/commands.json) passed all ten commands, including 91 core Rust tests, one reference test, 120 Python tests without skips and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-serial/metadata.json) match: `a83d606782f63e9f5c9f8b95a3c80b299f57da30c916de670f61751e8068becc`. All three jobs in [hosted run 39971009249](https://github.com/dumbly-smart/Oblivion/actions/runs/39971009249) for `ade31d2c` passed. The selected roadmap software and empirical deliverables, local gate and hosted source gate are accepted within the documented boundaries. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery; no merge is claimed. Subsequent closing Markdown-only checks are accessible on the PR and do not create a new unfinished source requirement.

The later failed [historical run 39969711451](https://github.com/dumbly-smart/Oblivion/actions/runs/39969711451) remains preserved: Rust failed while analysis/stress passed, and its specific cause remains unproved. [Three-arm scheduling diagnostics](PIPELINE_TEST_SCHEDULING.md) reproduced authenticated timeouts under CPU contention: pinned two-CPU parallel tests had two timeouts, the same serial suite passed, and one CPU with 16 competitors produced an actual 218 ms Timeout with both PIR operations and 128 storage events. Correctness suites explicitly use `--test-threads=1`; production budgets, benchmark concurrency and retry behavior are unchanged.

Updated 2026-10-23. Run from the repository root with a **new output directory**. [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and [REQUIREMENTS_MATRIX.md](REQUIREMENTS_MATRIX.md) distinguish accepted bounded results, current source and optional extensions.

## Environment and provenance

Use Rust 1.96+, a C toolchain and Cargo.lock; historical Linux records used Rust 1.99.1. Scientific Python versions are locked in `research/requirements.lock`.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r research/requirements.lock
cargo build --locked --release --workspace --bins --examples
cargo build --locked --release --manifest-path research/oram_reference/Cargo.toml
PRESENCE_BINARY=target/release/examples/presence EXECUTOR_RESOURCES_BINARY=target/release/examples/resource_measure EXEC_TIMING_BINARY=target/release/examples/timing_measure EPOCH_SYSTEM_BINARY=target/release/oblivion-server .venv/bin/python -m unittest discover -s research/tests
.venv/bin/python scripts/validate.py target/validation-new
```

Scripted runs record configuration/seeds, source SHA-256 including uncommitted implementation, toolchains, host/CPU, repository state, commands and methodology. Current source changes do not alter the meaning of saved launch-time hashes. Runs use a shared host without CPU affinity/resource isolation. Logical workload seeds are separate from OS cryptographic randomness; repeated seeds do not reproduce keys, ciphertexts, leaves or exact latency. The default validator includes the separate GPL reference build/tests; `--with-reference` is retained for compatibility. Modern campaigns freeze an executable/config and write durable provenance before measurement; historical weaker provenance remains explicitly labeled.

## Store correctness, stress and component measurements

```sh
cargo test --locked -p oblivion-store
cargo test --locked --release -p oblivion-store million_operation_oracle -- --ignored --exact
python3 scripts/measure_oram.py experiments/configs/oram-smoke.json target/oram-uniform
python3 scripts/measure_oram.py experiments/configs/oram-same.json target/oram-same
.venv/bin/python research/analysis/oram.py target/oram-uniform target/oram-same target/oram-analysis
```

The separately ignored release test executes one million operations over 256 blocks with periodic full invariants. Ordinary tests cover oracle correctness, fixed fresh ciphertext paths, corruption/replay/substitution, placement/nonce bounds and poison-on-failure. New file/checkpoint tests cover real files, authenticated restore, stale/mixed/truncated images, fresh rekeying and publication/partial-restore failure. [STORAGE_RECOVERY.md](STORAGE_RECOVERY.md) defines the external latest-handle and acknowledgement obligations; these are not durable invocation tests.

The smoke measurement uses 64 blocks of 256 bytes, 100 warm-up accesses and three sessions of 1,000 measured accesses/workload. Saved data are `experiments/results/oram-{uniform,same,analysis}-20261020/`. Private stash/address samples, observer events, quantiles, payload/storage/trusted-state formulas and plots are included. `oram-paper.json` is an independently runnable larger configuration, not proof of an executed larger sweep. Leaf/lag tests have finite power; non-rejection does not prove uniformity/independence. Memory estimates exclude containers/allocator/temporary copies. Bucket bytes are local backend payload, not captured network packets.

## PIR

```sh
cargo test --locked -p oblivion-pir
python3 scripts/demo_pir.py
python3 scripts/measure_pir.py target/pir-measurements
```

The saved `pir-30trials-20261020/` run has 30 independent trials × 16 queries on two 10,000 × 1,024-byte database objects. It measures actual query generation, each complete scan and recovery, excluding warm-up. Database bytes divided by scan duration describes in-process processing throughput, not wire GB/s. Share-marginal tests are narrower than a joint distribution/timing proof.

The original generic loopback worker remains plaintext for individual-server-view component experiments. The reusable `oblivion_pir::secure` protocol supports bounded arbitrary geometry, including 10,000 × 1 KiB, authenticated sequence/epoch/direction/slot and independent encrypted links. New real TCP/process tests cover tamper, replay, timeout, server loss and trickled input. [PIR_TRANSPORT.md](PIR_TRANSPORT.md) specifies framing and bootstrap assumptions. Encrypted transport and query sharing still require PIR server non-collusion.

Use [SIMPLEPIR_REFERENCE.md](SIMPLEPIR_REFERENCE.md) for the genuine upstream comparison and reproduction commands. Saved `simplepir-reference-small-20261020/` contains 30 fresh processes/scheme × 16 measured queries on **10,000 eight-byte records**, real SimplePIR setup/hint, upstream correctness log and all 960 measured full-output oracle checks. Setup/online traffic and timing are separate. This experiment does not replace runtime PIR or the 1 KiB XOR benchmark. The later [100k matched correctness run](../experiments/results/simplepir-100k-20261023/summary.json) uses 30 setups and 3,334 queries/setup per scheme: 100,020 full eight-byte results each for genuine SimplePIR and XOR, all correct. Within-setup outcomes share matrices/hints and are not independent setup trials.

## Current process path and historical demo results

```sh
cargo run --locked -p oblivion-server -- demo target/demo-zero 0 2 mixed
cargo run --locked -p oblivion-server -- demo target/demo-half 50 2 mixed
cargo run --locked -p oblivion-server -- demo target/demo-full 100 2 mixed
```

Arguments enroll one to four participants; `mixed` selects all five functions over eight epochs. Current epochs are 150 ms per enrolled participant and the execution class targets 100 ms, with sequential slots. Each invocation has 164-byte request/response envelopes, encrypted PIR, an independent trusted-client output/counter oracle and eight actual ORAM reads plus eight writes. At N=8/Z=4/64-byte blocks, each invocation has 128 bucket events of 316 bytes. Guest calls operate within trusted namespaces/staging; failed guest mutations are discarded before physical commit. Backend failures and deadline misses remain visible.

The built-in real/dummy/function schedule is deterministic and public from the demo code, percentage and epoch. These commands exercise topology/oracles; they do not hide identity from an adversary who already knows that schedule. Experimental seeds/target truth are separate research-driver inputs excluded from each declared attacker contract, while cadence/classes/geometry remain public.

Historical `demo-{0,50,100}-final-20261020/` instead ran one stateful participant, 20 ms epochs, a 10 ms execution class and two logical ORAM operations per invocation. Their eight invocations had **128 bucket events per entire run**, with final real counters 0/4/8. They are retained historical smoke evidence and must not be relabeled current schedule measurements.

`storage-observer.jsonl` and `envelope-observer.jsonl` model public features. `executor-private.jsonl`, client truth/summary and any decrypted metadata stay inside the trusted boundary in deployments. Local pipes/application frames are not packet captures. A process smoke result does not by itself demonstrate statistical indistinguishability under multi-client faults or all functions.

## Component attacks

```sh
.venv/bin/python scripts/evaluate_leakage.py experiments/configs/leakage-smoke.json target/leakage-smoke
.venv/bin/python scripts/evaluate_leakage.py experiments/configs/leakage-paper.json target/leakage-30trials
```

The paper configuration has 30 trial clusters, eight separately initialized sessions/trial and 128 observations/session. Rust executes real mechanisms; Python fits/evaluates attacks. Recorded runs use release builds, with dev mode explicitly identified when requested.

- **Frequency rank:** a 75%/25% workload, known popularity ordering and persistent observed tags. Plaintext/encrypt-only addresses are positive controls; ORAM leaves are defended features. Target labels are withheld. Compare accuracy with its measured imbalanced majority baseline and balanced accuracy with 0.5.
- **Traffic stump:** balanced echo/Fibonacci, size/local latency features, independent labeled profiling sessions and disjoint target sessions. Leaky baseline returns actual unpadded guest length/time; defended class returns a fixed body at its deadline target. It is a simplified classifier, not a published attack reproduction.

Positive controls must exceed the relevant majority baseline by 0.1 before the analysis accepts a result. Reports include raw session metrics, selected features/thresholds, accuracy/balanced accuracy/AUC, baselines and 5,000-resample percentile intervals over **whole trial means**. Targets sharing one fitted model remain in the same uncertainty cluster. Observer schemas reject truth fields; target labels enter only scoring.

Saved runs are `leakage-smoke-20261020/` and `leakage-30trials-20261020/`. The first smoke session-bootstrap analysis is explicitly superseded; use its corrected `analysis/`. Reanalysis preserves raw data and uses a new directory:

```sh
.venv/bin/python -m research.analysis.leakage experiments/results/leakage-smoke-20261020 target/leakage-reanalysis
.venv/bin/python research/analysis/oram.py experiments/results/oram-uniform-20261020 experiments/results/oram-same-20261020 target/oram-reanalysis
```

These historical component scores do not establish joint runtime privacy or zero information leakage. More trials improve uncertainty estimates for the chosen workload/attacker; stronger auxiliary knowledge/features can change inference.

## SSE and scaling experiments

[SSE_IMPLEMENTATION.md](SSE_IMPLEMENTATION.md) records the ephemeral constrained-GGM component, release oracle, retained-capability challenge and optional real JSONL export. Its sample timings/challenge are narrower evidence than a committed 30-trial attack dataset. Search equality/volume/timing and later authorization remain visible; persistent SSE recovery is unsupported. The [actual count/frequency campaign](SSE_ATTACKS.md), [offline likelihood/iterative/exact comparisons](ADVANCED_ATTACKS.md) and [chosen-update association experiment](UPDATE_LINKABILITY.md) now supply six bounded SSE-facing methods with controls. They are not faithful published Cash/SAP/IHOP/file-injection reproductions. The [common attack API](ATTACK_INTERFACE.md) preserves those original algorithms and their evidence boundaries.

[AUTOSCALER.md](AUTOSCALER.md) documents the five-policy default event simulation, observer knowledge, whole-session splits, trial bootstrap, SLO/drop accounting and plot regeneration. Saved `scaler-paper-30-final/` and `scaler-prewarm2-30-final/` contain 30 trials each, eight sessions/trial, four synthetic workload families and raw compressed public/private records. The optional autoscaler studies, raw reanalysis, centroid/forest attacks, paired epsilon sweep, and sampler assumptions are documented in [AUTOSCALER_DP.md](AUTOSCALER_DP.md). The current 30-trial event-level and bounded-user OS-CSPRNG studies use the bounded discrete-geometric sampler and pass all naive controls; the event-level burst hot-pool forest interval is marginally above chance, while all protected cap-2 forest intervals include chance. Costs use hypothetical instance-second prices; public-seed artifacts have no DP guarantee, and there is no cloud provisioning. Policy tradeoffs and failed SLOs remain reported.

## Actual traces, execution and joint experiments

[TRACE_VALIDATION.md](TRACE_VALIDATION.md) supplies commands/provenance for the actual 100,000-access repeated/uniform workloads and 30 encrypted PIR capture sessions. Their raw compressed records and original pcaps remain intact. Only the two dynamically owned loopback ports are captured. All 30 capture logs report zero drops across the aggregate/component counters; 3,000 verified retrievals form 6,000 complete streams and 61,363 packets. The unvalidated packet inference classifier was removed; current acceptance is structural accounting, not a privacy test.

[EXECUTION_EVALUATION.md](EXECUTION_EVALUATION.md) records the completed 30-trial eight-class experiment over five functions and trap/fuel/memory failures, with the visible-selector control first. Protected accuracy is 11.67% [9.38,13.75] versus 12.5% chance; all protected frames and actual ORAM counts pass their oracle. This earlier binary's timing boundary remains explicitly scoped.

[SYSTEM_EXPERIMENTS.md](SYSTEM_EXPERIMENTS.md) records the final `system-fixed-publication-30-20261022/` A–G/disabled-layer run, raw observer/truth/metrics and all four system plots. Its G balanced accuracy is 33.40% [32.29,34.51] against 33.33% chance. The stopped 18-trial pilot is excluded; the completed earlier corrected campaign's possible arrival signal is retained. Final trusted drivers prepare response encryption/instrumentation before the 100 ms publication wait, clients precompute frames before public emission, and slots have fixed epoch-relative origins. Publication lateness and driver work overrun remain separate diagnostics; shared-host timers are not exact-time guarantees. Library payload accounting is separate from scoped genuine PIR packet capture.

[RUNTIME_BENCHMARKS.md](RUNTIME_BENCHMARKS.md) preserves the earlier 60 offered-load processes and 270 epoch/real-ratio trials and adds 180 extended-load processes / 5,760 offers; [DEMO.md](DEMO.md) records the actual mixed-client SSE/PIR/WASM/ORAM subprocess and generated local MP4/terminalcast. [Recorded validation](../experiments/results/validation-20261022-current/commands.json) has five zero exits, but source changed during that campaign and a final frozen-source rerun remains required. Hosted CI must be observed separately.

## Later selected studies and retained results

Use each linked component document's exact configuration and fresh-directory runner. All result counts below refer to actual saved runs, not merely available configurations.

| Study | Retained output | Execution/scope |
| --- | --- | --- |
| [Licensed corpus/drift](CORPUS_EVALUATION.md) | `corpus-real-frozen-20261023/` | 30 conditional real-text splits, genuine SSE/dummy postings; fixed synthetic queries and private target labels |
| [Presence/intersection](PRESENCE_EVALUATION.md) | Presence raw and independent-tie/Wilson analyses linked there | Real authenticated frames with virtual epochs; semantic-beacon negative outcome, no network timing |
| [Geometry/stash](GEOMETRY_EVALUATION.md) | `geometry-20261022/` | 42 cells × 30, 138,240 ORAM accesses / 2,880 PIR queries; payload/state accounting |
| [Leaf+timing](ORAM_LEAF_TIMING.md) | `oram-leaf-timing-20261023/` | 30 fits/mode with disjoint sessions; possible weak AUC retained |
| [PIR target timing](PIR_TARGET_TIMING.md) | `pir-target-timing-20261023/` | 46,080 full-record checks; own-share/local-time observer; actual control first |
| [Square-root PIR](SQRT_PIR.md) | `sqrt-pir-20261023/` | 5,760 checked actual matrix retrievals; full scans and sometimes larger total payload |
| [Matched Circuit reference](CIRCUIT_ORAM_REFERENCE.md) | `circuit-reference-20261023/` | 61,440 timed accesses / 193,920 full-record checks; genuine separately licensed upstream, matched unencrypted heap |
| [Direct CPU/classes](EXECUTOR_RESOURCES.md) | `executor-cpu-20261023/` | 180 processes / 2,160 calls; engine/compile/first/warm and per-invocation process/thread CPU |
| [Extended offered load](RUNTIME_BENCHMARKS.md) | `runtime-extended-30-20261023/` | Six cells × 30, 5,760 offers; admission/drop/SLO counts and bounded-process quantiles |
| [Repeated faults](FAULT_CAMPAIGN.md) | `fault-campaign-30-20261023-retry/` | 210 assertion-bearing launches; original ENOSPC attempt preserved, no general availability proof |
| [Joint batch load](BATCH_LOAD_EVALUATION.md) | `batch-load-centroid-20261023/` | 720 independent processes, 30 fits/mode, same22 public features; control100%, protected28.33% [22.78,33.89]. Both failed forest controls retained separately |
| [Integrated reader-pipe epochs](EPOCH_SYSTEM_EVALUATION.md) | `epoch-system-pipe-timestamps-20261023/` | 360 process trees / 2,160 verified calls; actual reader completion timestamps and strict separate private rows |
| [Isolated ORAM timing replication](ORAM_TIMING_REPLICATION.md) | `oram-isolated-replication-20261025-v2/` | 30 trials/mode, paired schedules and disjoint profiling/target sessions; positive controls succeed, ORAM timing classifier remains near chance for this setup |
| [Eight-address ORAM timing](ORAM_EIGHT_ADDRESS.md) | `oram-isolated-eight-address-20261024/` | 30 trials/mode over eight addresses; Zipf-like hot/cold labels, positive controls succeed, raw schedules paired and hashes verified |
| [ORAM frequency-only attacker](ORAM_ATTACK_FAMILIES.md) | `oram-eight-address-frequency-20261024/` | Post-hoc independent tag-count attacker; positive controls pass before ORAM, 1,440 input hashes retained, same held-out sessions as temporal RF |
| [Read-heavy ORAM timing](ORAM_READ_HEAVY.md) | `oram-isolated-eight-address-read-heavy-20261024/` | 30 trials/mode at 90% requested reads, 9.84% realized writes; matched address schedules, controls pass, all 1,440 hashes verified |
| [Batcher population sweep](POPULATION_SWEEP.md) | `population-sweep-20261025/` | 120 local trials across 1/8/32/64 participants; fixed-shape authenticated batches, observer/private traces separated |
| [Full-path 64-offer load](RUNTIME_POPULATION.md) | `runtime-population-64-20261024/` | 60 fresh processes / 3,840 real end-to-end offers, each checked through PIR/WASM/ORAM; underload and bounded-queue overload retained |

The integrated epoch campaign's immutable executable/source copy is authoritative. Live checkout fingerprints changed for an unrelated PIR example; later default-wrapper input hardening is separately recorded. The older mixed/private epoch observer files are never attacker input, and the intermediate separated campaign timestamps client consumption rather than pure pipe reads. Neither is relabeled as the current measurement.

## Accepted source gates and further research

Two ten-command local attempts remain preserved and unaccepted as complete gates. `validation-20261023-final/` has nine zero exits and a workspace harness Timeout. `validation-20261023-current-source/` passes workspace tests but its 112-test Python run has one authenticated `demo-sweep` invocation failure; its private cause was not retained and remains unknown. A deterministic Timeout regression does not establish that historical cause.

The fresh [verified local gate](../experiments/results/validation-20261023-verified/commands.json) passed all ten commands: 90 core Rust tests, one reference test, 119 Python tests with all four runtime fixtures and no skips, both workspaces' quality/build checks, and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-verified/metadata.json) match; that historical gate passed for its recorded source.

All three jobs in [hosted run 39971009249](https://github.com/dumbly-smart/Oblivion/actions/runs/39971009249) for `ade31d2c` passed. The selected roadmap software and empirical deliverables, local gate and hosted source gate are accepted within the documented boundaries. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery; no merge is claimed. Subsequent closing Markdown-only checks are accessible on the PR and do not create a new unfinished source requirement.

The research-only `demo-sweep` now retains authenticated masked runtime failures, including their timing, CPU and completed interface work, while successful outputs still require full independent oracles. Legacy `demo`/`demo-sse` stay strict; budgets, reader timestamps and retry behavior are unchanged. Primary CPU/byte cost per real success is a ratio of sums that includes zero-success trials' costs; unknown partial PIR-byte costs, undefined totals and bootstrap draws are explicit, with no unconditional finite interval when a draw is undefined. Historical completed campaigns had zero runtime errors and were not rerun or rewritten. See [the post-measurement policy](EPOCH_SYSTEM_EVALUATION.md#post-measurement-runtime-error-retention).

[The figure reproduction audit](FIGURE_REPRODUCTION.md) now records raw-derived regeneration of all eight required main figures and the supplemental three-axis/SLO plot without ignored measurement executables. Both autoscaler campaigns rebuild from four raw/config files rather than cached reports; audited numerical reports and PNG bytes matched, and accepted inputs stayed unchanged. The serial local and hosted source gates are accepted; subsequent closing Markdown-only checks are accessible on PR #1.

[The completion audit](COMPLETION_AUDIT.md) maps original requirements without adding remote-RSS/provider-calibration/universal-dominance obligations or dropping required square-root/Circuit work. Selected synthetic arrival simulation, explicit hypothetical prices, trusted payload memory and nominal Pareto+CIs/SLO/extreme panels have documented scopes. Longer tails, real query traces, stronger attackers, remote deployment/resource calibration and independent repetition of weak signals are further research. Actual TEE/DP, recursion/native Circuit, DPF/native runtime LWE, persistent/backward SSE and durable invocation acknowledgment remain unselected extensions. No configuration alone is a result, and finite near-chance accuracy is not a security theorem.
