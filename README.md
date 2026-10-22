# Oblivion

An experimental privacy-preserving serverless research prototype in Rust. Oblivion combines private registry lookup, oblivious state, bounded WebAssembly execution and scheduled cover traffic, and measures the leakage that remains.

**Status, 2026-10-22:** the local process pipeline and several later research components are implemented. The complete research roadmap is unfinished. This is an unaudited prototype under a **TrustedExecutor** assumption; ordinary processes and Wasmtime provide no hardware TEE protection.

## Implemented

- Encrypted Path ORAM with Z=4, a client position map/stash, fixed bucket sizes, corruption/freshness checks and a million-operation oracle stress test.
- Memory and bounded file backends; authenticated full checkpoints and recovery with fresh bucket keys. Recovery requires an independently protected latest checkpoint handle.
- Two-server XOR PIR over 10,000 × 1 KiB records, independent processes, full scans and a generic authenticated transport. A deliberately plaintext loopback tool remains available for component experiments.
- Five real Wasmtime functions, guest fuel/memory/host-call limits, fixed class I/O and deadlines. Protected execution stages an eight-block working set, makes eight actual ORAM reads and eight writes, and discards guest mutations on failure before physical commit.
- Fixed epochs, bounded queues, real dummy execution, 164-byte authenticated invocation envelopes and enrolled namespaces for one to four clients. The mixed demo exercises all five functions.
- A bounded, ephemeral Diana-inspired GGM SSE component with a 100,000-operation oracle and retained-capability adversary controls.
- A genuine pinned SimplePIR reference comparison and a five-policy autoscaler simulation, each with saved 30-trial artifacts.
- Frequency/traffic and six bounded SSE-facing methods with leaky controls, a common nine-adapter attack API, separate observer/label data and whole-trial uncertainty.
- Completed final 30-trial A–G/disabled-layer experiments and figures; eight-class execution/error inference; actual 100k ORAM workload diagnostics and 30-session scoped encrypted PIR packet capture.

Seven Rust crates implement the store, PIR, executor, batcher, server, harness and SSE. [Implementation status](docs/IMPLEMENTATION_STATUS.md) distinguishes current source from historical test/results evidence. The [requirements matrix](docs/REQUIREMENTS_MATRIX.md) tracks the entire supplied roadmap, including unfinished requirements.


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

The demo launches an executor and two PIR workers. Each run has eight epochs, a 100 ms execution class and an epoch period of 150 ms per enrolled participant; slots execute sequentially. A trusted client independently checks function outputs and persistent counters. Observer traces and private instrumentation are separate; private runtime records must stay within the trusted boundary.

## Validation and experiments

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --release -p oblivion-store million_operation_oracle -- --ignored --exact
python3 -m venv .venv
.venv/bin/python -m pip install -r research/requirements.lock
.venv/bin/python -m unittest discover -s research/tests
```

The release stress test is intentionally ignored by the ordinary suite. The five commands in [recorded validation](experiments/results/validation-20261022-current/commands.json) exited zero: fmt, Clippy, workspace tests, Python discovery (42 checks, one explicit optional Rust smoke skip) and the million-operation release stress tier (41.44 seconds). Source changed during that campaign, so final frozen-source gates must be rerun. Hosted CI success has not yet been observed. Small component commits and pushes are authorized on `codex/oblivion-research-platform`; the branch is not merged into main.

[EXPERIMENTS.md](docs/EXPERIMENTS.md) documents component experiments and their historical configurations. [SSE_IMPLEMENTATION.md](docs/SSE_IMPLEMENTATION.md), [SIMPLEPIR_REFERENCE.md](docs/SIMPLEPIR_REFERENCE.md) and [AUTOSCALER.md](docs/AUTOSCALER.md) describe additional components and reproducible commands. SimplePIR comparison records are eight bytes; the independent XOR experiment uses 1 KiB records. These geometries must not be conflated.

## Research

The [supplied roadmap](Oblivion_%20Research%20Roadmap%20and%20Build%20Plan%20%281%29.md) remains authoritative. Read [architecture](docs/ARCHITECTURE.md), [protocol](docs/PROTOCOL.md), [storage recovery](docs/STORAGE_RECOVERY.md), [PIR transport](docs/PIR_TRANSPORT.md) and [next steps](docs/NEXT_STEPS.md). The [system report](docs/SYSTEM_EXPERIMENTS.md), [bounded inference study](docs/ADVANCED_ATTACKS.md), [attack interface](docs/ATTACK_INTERFACE.md), [trace validation](docs/TRACE_VALIDATION.md), [execution study](docs/EXECUTION_EVALUATION.md), and [actual local demo video](docs/DEMO.md) now exist. Remaining work includes realistic licensed data/knowledge sensitivity, presence/intersection inference, broad parameter/load/fault campaigns, detailed throughput/resource studies and final frozen-source/hosted acceptance. Empirical near-chance accuracy for a chosen attacker is not a cryptographic proof.

MIT licensed. The SimplePIR adapter imports an explicitly pinned MIT reference and preserves its license. OpenSSE is consulted as a construction reference; its AGPL code is not copied into this repository.
