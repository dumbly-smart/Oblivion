# Reproducing experiments

Updated 2026-10-22. Run from the repository root with a **new output directory**. [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and [REQUIREMENTS_MATRIX.md](REQUIREMENTS_MATRIX.md) distinguish executed results, current source and pending evaluation.

## Environment and provenance

Use Rust 1.96+, a C toolchain and Cargo.lock; historical Linux records used Rust 1.99.1. Scientific Python versions are locked in `research/requirements.lock`.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r research/requirements.lock
.venv/bin/python -m unittest discover -s research/tests
```

Scripted runs record configuration/seeds, source SHA-256 including uncommitted implementation, toolchains, host/CPU, repository state, commands and methodology. Current source changes do not alter the meaning of saved launch-time hashes. Runs use a shared host without CPU affinity/resource isolation. Logical workload seeds are separate from OS cryptographic randomness; repeated seeds do not reproduce keys, ciphertexts, leaves or exact latency.

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

Use [SIMPLEPIR_REFERENCE.md](SIMPLEPIR_REFERENCE.md) for the genuine upstream comparison and reproduction commands. Saved `simplepir-reference-small-20261020/` contains 30 fresh processes/scheme × 16 measured queries on **10,000 eight-byte records**, real SimplePIR setup/hint, upstream correctness log and all 960 measured full-output oracle checks. Setup/online traffic and timing are separate. This experiment does not replace runtime PIR or the 1 KiB XOR benchmark.

## Current process path and historical demo results

```sh
cargo run --locked -p oblivion-server -- demo target/demo-zero 0 2 mixed
cargo run --locked -p oblivion-server -- demo target/demo-half 50 2 mixed
cargo run --locked -p oblivion-server -- demo target/demo-full 100 2 mixed
```

Arguments enroll one to four participants; `mixed` selects all five functions over eight epochs. Current epochs are 150 ms per enrolled participant and the execution class targets 100 ms, with sequential slots. Each invocation has 164-byte request/response envelopes, encrypted PIR, an independent trusted-client output/counter oracle and eight actual ORAM reads plus eight writes. At N=8/Z=4/64-byte blocks, each invocation has 128 bucket events of 316 bytes. Guest calls operate within trusted namespaces/staging; failed guest mutations are discarded before physical commit. Backend failures and deadline misses remain visible.

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

[AUTOSCALER.md](AUTOSCALER.md) documents actual five-policy event simulation, observer knowledge, whole-session splits, trial bootstrap, SLO/drop accounting and plot regeneration. Saved `scaler-paper-30-final/` and `scaler-prewarm2-30-final/` contain 30 trials each, eight sessions/trial, four synthetic workload families and raw compressed public/private records. Costs use a hypothetical instance-second price; no cloud provisioning or DP occurs. Policy tradeoffs and failed SLOs remain reported.

## Actual traces, execution and joint experiments

[TRACE_VALIDATION.md](TRACE_VALIDATION.md) supplies commands/provenance for the actual 100,000-access repeated/uniform workloads and 30 encrypted PIR capture sessions. Their raw compressed records and original pcaps remain intact. Only the two dynamically owned loopback ports are captured. All 30 capture logs report zero drops across the aggregate/component counters; 3,000 verified retrievals form 6,000 complete streams and 61,363 packets. The unvalidated packet inference classifier was removed; current acceptance is structural accounting, not a privacy test.

[EXECUTION_EVALUATION.md](EXECUTION_EVALUATION.md) records the completed 30-trial eight-class experiment over five functions and trap/fuel/memory failures, with the visible-selector control first. Protected accuracy is 11.67% [9.38,13.75] versus 12.5% chance; all protected frames and actual ORAM counts pass their oracle. This earlier binary's timing boundary remains explicitly scoped.

[SYSTEM_EXPERIMENTS.md](SYSTEM_EXPERIMENTS.md) records the final `system-fixed-publication-30-20261022/` A–G/disabled-layer run, raw observer/truth/metrics and all four system plots. Its G balanced accuracy is 33.40% [32.29,34.51] against 33.33% chance. The stopped 18-trial pilot is excluded; the completed earlier corrected campaign's possible arrival signal is retained. Final trusted drivers prepare response encryption/instrumentation before the 100 ms publication wait, clients precompute frames before public emission, and slots have fixed epoch-relative origins. Publication lateness and driver work overrun remain separate diagnostics; shared-host timers are not exact-time guarantees. Library payload accounting is separate from scoped genuine PIR packet capture.

[RUNTIME_BENCHMARKS.md](RUNTIME_BENCHMARKS.md) records 60 offered-load processes and 270 epoch/real-ratio trials; [DEMO.md](DEMO.md) records the actual mixed-client SSE/PIR/WASM/ORAM subprocess and generated local MP4/terminalcast. [Recorded validation](../experiments/results/validation-20261022-current/commands.json) has five zero exits, but source changed during that campaign and a final frozen-source rerun remains required. Hosted CI must be observed separately.

## Required remaining evaluation

Broad open-loop/parameter/fault sweeps, well-resolved population tails, detailed cold/warm/high-resolution resource measurements, presence/intersection inference, realistic licensed corpora and auxiliary-knowledge drift remain incomplete. Existing system/component/autoscaler figures satisfy their bounded artifact requirements; they do not imply comprehensive calibrated runtime/cloud or significant Pareto dominance. The full requirement matrix retains these gaps and separates optional native TEE, DP, recursive/Circuit ORAM, PIR variants and persistent/backward-private SSE. No configuration alone is a result.
