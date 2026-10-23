# Oblivion

An experimental privacy-preserving serverless research prototype in Rust. Oblivion combines private registry lookup, oblivious state, bounded WebAssembly execution and scheduled cover traffic, and measures the leakage that remains.

**Status, 2026-10-23:** the selected process pipeline and later component/evaluation artifacts are implemented and mapped in the [completion audit](docs/COMPLETION_AUDIT.md). The selected implementation/evaluation and serial local/hosted source gates are accepted. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is the review artifact. This does not certify optional deployment properties or cryptographic security. This is an unaudited prototype under a **TrustedExecutor** assumption; ordinary processes and Wasmtime provide no hardware TEE protection.

## Implemented

- Encrypted Path ORAM with Z=4, a client position map/stash, fixed bucket sizes, corruption/freshness checks and a million-operation oracle stress test.
- Memory and bounded file backends; authenticated full checkpoints and recovery with fresh bucket keys. Recovery requires an independently protected latest checkpoint handle.
- Two-server XOR PIR over 10,000 × 1 KiB records, independent processes, full scans and a generic authenticated transport. A deliberately plaintext loopback tool remains available for component experiments.
- Five real Wasmtime functions, guest fuel/memory/host-call limits, fixed class I/O and deadlines. Protected execution stages an eight-block working set, makes eight actual ORAM reads and eight writes, and discards guest mutations on failure before physical commit.
- Fixed epochs, bounded queues, real dummy execution, 164-byte authenticated invocation envelopes and enrolled namespaces for one to four clients. The mixed demo exercises all five functions.
- A bounded, ephemeral Diana-inspired GGM SSE component with a 100,000-operation oracle and retained-capability adversary controls.
- A genuine pinned SimplePIR reference comparison with 100,020 full-record checks across 30 fresh setups, a measured square-root XOR variant, and a five-policy autoscaler simulation.
- Frequency/traffic and six bounded SSE-facing methods with leaky controls, a common attack API, separate observer/label data and whole-trial uncertainty.
- Licensed real-text SSE/auxiliary-drift evaluation, measured presence/intersection leakage, ORAM/PIR geometry sweeps and per-invocation CPU/resource measurements.
- Genuine separately licensed matched Path/Circuit reference, individual-server PIR timing, joint batch-load inference and integrated reader-thread pipe-timestamp epoch sweeps, with controls and earlier failed evidence preserved.
- Completed final 30-trial A–G/disabled-layer experiments and figures; eight-class execution/error inference; actual 100k ORAM workload diagnostics and 30-session scoped encrypted PIR packet capture.

Seven Rust crates implement the store, PIR, executor, batcher, server, harness and SSE. [Implementation status](docs/IMPLEMENTATION_STATUS.md) distinguishes current source from historical test/results evidence. The [requirements matrix](docs/REQUIREMENTS_MATRIX.md) tracks the entire supplied roadmap, including remaining validation/delivery gates and unselected extensions.


The final declared-feature joint attacker scores G at **33.40% balanced accuracy [32.29,34.51]**, versus 33.33% chance; an earlier corrected-version function signal is preserved and documented alongside publication/arrival mitigations. The actual packet evidence establishes bounded structural accounting, with an unvalidated packet classifier removed. These results do not cover every host observation.

## Trust and limits

The client and executor are trusted. An administrator of this machine can inspect their memory. Two PIR servers must not collude; encrypting the links prevents a network-only observer from combining plaintext query shares, but separate local processes do not establish independent operators.

The protected storage schedule costs **O(M log N)** bandwidth for public working-set size M. It hides guest-dependent storage counts in successful backend operation, while scheduling jitter, deadline misses, resources, cold starts, participation and active failures remain visible. Fixed shapes do not establish full-transcript indistinguishability.

The process demo uses ephemeral memory state. The separate checkpoint API does not provide durable invocation acknowledgments, exactly-once execution or protection when both snapshot and trusted anchor are rolled back. SSE exposes search equality, result volume and timing and has no persistent recovery or backward privacy. Autoscaling is a simulation, with hypothetical prices and no DP claim. Read the [threat model](docs/THREAT_MODEL.md) and [security assumptions](docs/SECURITY_ASSUMPTIONS.md).

## Build and run

Use Rust **1.96+**, Cargo and a native C toolchain. Linux is the recorded environment. Initial Wasmtime compilation is substantial. Choose a new output directory for every run.

```sh
cargo build --locked --workspace
cargo run --locked -p oblivion-server -- demo target/demo-half 50 2 mixed
cargo run --locked -p oblivion-server -- demo target/demo-zero 0 2 mixed
cargo run --locked -p oblivion-server -- demo target/demo-full 100 2 mixed
```

The demo launches an executor and two PIR workers. Each run has eight epochs, a 100 ms execution class and an epoch period of 150 ms per enrolled participant; slots execute sequentially. A trusted client independently checks function outputs and persistent counters. Observer traces and private instrumentation are separate; private runtime records must stay within the trusted boundary. The built-in demo's real/dummy and function schedule is deterministic and public given its code, configured real percentage and epoch. It is a correctness/topology exercise, not invocation anonymity against an observer who already knows that schedule. Encryption cannot hide an identity already determined by authorized auxiliary knowledge.

## Validation and experiments

**Selected-scope acceptance:** the [serial local gate](experiments/results/validation-20261023-serial/commands.json) passed all ten commands, including 91 core Rust tests, one reference test, 120 Python tests without skips and the million-operation oracle. [Before/after source fingerprints](experiments/results/validation-20261023-serial/metadata.json) match: `a83d606782f63e9f5c9f8b95a3c80b299f57da30c916de670f61751e8068becc`. All three jobs in [hosted run 39971009249](https://github.com/dumbly-smart/Oblivion/actions/runs/39971009249) for `ade31d2c` passed. The selected roadmap software and empirical deliverables, local gate and hosted source gate are accepted within the documented boundaries. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery; no merge is claimed. Subsequent closing Markdown-only checks are accessible on the PR and do not create a new unfinished source requirement.

The later failed [historical run 39969711451](https://github.com/dumbly-smart/Oblivion/actions/runs/39969711451) remains preserved: Rust failed while analysis/stress passed, and its specific cause remains unproved. [Three-arm scheduling diagnostics](docs/PIPELINE_TEST_SCHEDULING.md) reproduced authenticated timeouts under CPU contention: pinned two-CPU parallel tests had two timeouts, the same serial suite passed, and one CPU with 16 competitors produced an actual 218 ms Timeout with both PIR operations and 128 storage events. Correctness suites explicitly use `--test-threads=1`; production budgets, benchmark concurrency and retry behavior are unchanged.

[Correctness test scheduling](docs/PIPELINE_TEST_SCHEDULING.md) records the explicit serial correctness policy and CPU-contention diagnostics. This changes neither production deadlines nor benchmark concurrency and does not silently retry failures.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace -- --test-threads=1
cargo test --locked --release -p oblivion-store million_operation_oracle -- --ignored --exact
python3 -m venv .venv
.venv/bin/python -m pip install -r research/requirements.lock
cargo build --locked --release --workspace --bins --examples
cargo build --locked --release --manifest-path research/oram_reference/Cargo.toml
PRESENCE_BINARY=target/release/examples/presence EXECUTOR_RESOURCES_BINARY=target/release/examples/resource_measure EXEC_TIMING_BINARY=target/release/examples/timing_measure EPOCH_SYSTEM_BINARY=target/release/oblivion-server .venv/bin/python -m unittest discover -s research/tests
```

The release stress test is intentionally ignored by the ordinary suite. [Frozen validation](experiments/results/validation-20261022-frozen/commands.json) records five zero exits with matching before/after source fingerprints, including 53 Python checks (one explicit optional smoke skip) and the million-operation tier. It applies to that saved revision. Hosted Rust, Python analysis and stress jobs have also passed on earlier feature-branch revisions; every later increment still needs current-source gates. A subsequent lock/manifest mismatch was corrected rather than bypassing `--locked`. Work is delivered in small commits and pushes on `codex/oblivion-research-platform`; the branch is not merged into main.

The default full validator builds the separate GPL reference fixture as well as core release fixtures; `--with-reference` remains a compatibility flag:

```sh
.venv/bin/python scripts/validate.py target/validation-new
```

Two ten-command local attempts remain preserved and unaccepted as complete gates. `validation-20261023-final/` has nine zero exits and a workspace harness Timeout. `validation-20261023-current-source/` passes workspace tests but its 112-test Python run has one authenticated `demo-sweep` invocation failure; its private cause was not retained and remains unknown. A deterministic Timeout regression does not establish that historical cause.

The fresh [verified local gate](experiments/results/validation-20261023-verified/commands.json) passed all ten commands: 90 core Rust tests, one reference test, 119 Python tests with all four runtime fixtures and no skips, both workspaces' quality/build checks, and the million-operation oracle. [Before/after source fingerprints](experiments/results/validation-20261023-verified/metadata.json) match; that historical gate passed for its recorded source.

All three jobs in [hosted run 39971009249](https://github.com/dumbly-smart/Oblivion/actions/runs/39971009249) for `ade31d2c` passed. The selected roadmap software and empirical deliverables, local gate and hosted source gate are accepted within the documented boundaries. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery; no merge is claimed. Subsequent closing Markdown-only checks are accessible on the PR and do not create a new unfinished source requirement.

The research sweep now retains authenticated masked errors and charges zero-success trial costs by ratios of sums; legacy demos remain strict, with no deadline increase or silent retry. See [epoch accounting](docs/EPOCH_SYSTEM_EVALUATION.md#post-measurement-runtime-error-retention).

[The figure reproduction audit](docs/FIGURE_REPRODUCTION.md) now records raw-derived reconstruction of the required plots without ignored measurement executables, including raw-only autoscaler report reconstruction. Numerical reports and images matched on the audited environment; the serial local and hosted source gates passed; PR #1 carries delivery and subsequent closing Markdown-only checks.

[EXPERIMENTS.md](docs/EXPERIMENTS.md) documents component experiments and their historical configurations. [SSE_IMPLEMENTATION.md](docs/SSE_IMPLEMENTATION.md), [SIMPLEPIR_REFERENCE.md](docs/SIMPLEPIR_REFERENCE.md) and [AUTOSCALER.md](docs/AUTOSCALER.md) describe additional components and reproducible commands. SimplePIR comparison records are eight bytes; the independent XOR experiment uses 1 KiB records. These geometries must not be conflated.

## Research

The [supplied roadmap](Oblivion_%20Research%20Roadmap%20and%20Build%20Plan%20%281%29.md) remains authoritative. Read [architecture](docs/ARCHITECTURE.md), [protocol](docs/PROTOCOL.md), [storage recovery](docs/STORAGE_RECOVERY.md), [PIR transport](docs/PIR_TRANSPORT.md) and [next steps](docs/NEXT_STEPS.md). The [system report](docs/SYSTEM_EXPERIMENTS.md), [bounded inference study](docs/ADVANCED_ATTACKS.md), [attack interface](docs/ATTACK_INTERFACE.md), [trace validation](docs/TRACE_VALIDATION.md), [execution study](docs/EXECUTION_EVALUATION.md), and [actual local demo video](docs/DEMO.md) now exist. Recent [real-corpus](docs/CORPUS_EVALUATION.md), [presence](docs/PRESENCE_EVALUATION.md), [geometry](docs/GEOMETRY_EVALUATION.md), [invocation CPU](docs/EXECUTOR_RESOURCES.md), [ORAM timing](docs/ORAM_LEAF_TIMING.md), [PIR timing](docs/PIR_TARGET_TIMING.md), [square-root PIR](docs/SQRT_PIR.md), and [fault](docs/FAULT_CAMPAIGN.md) studies retain both favorable and negative outcomes. The [joint batch-load study](docs/BATCH_LOAD_EVALUATION.md), [integrated pipe-timestamp sweep](docs/EPOCH_SYSTEM_EVALUATION.md) and [matched Circuit reference](docs/CIRCUIT_ORAM_REFERENCE.md) now exist. Remaining acceptance work is current-source/hosted validation and reviewed branch delivery, as mapped in the completion audit. Empirical near-chance accuracy for a chosen attacker is not a cryptographic proof.

The core workspace is MIT licensed. The separate [Circuit/Path reference benchmark](research/oram_reference/README.md) is a GPL-3.0 program and is built for the full research test suite; it is not linked into the core. The SimplePIR adapter imports an explicitly pinned MIT reference and preserves its license. OpenSSE is consulted as a construction reference; its AGPL code is not copied into this repository.
