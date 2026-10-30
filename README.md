# Oblivion

An experimental privacy-preserving serverless research prototype in Rust. Oblivion combines private registry lookup, oblivious state, bounded WebAssembly execution and scheduled cover traffic, and measures the leakage that remains.

**Status, 2026-10-30:** the selected process pipeline and later component/evaluation artifacts are implemented and mapped in the [completion audit](docs/COMPLETION_AUDIT.md). Optional signed invocation receipts and checkpoint recovery integrate with the worker through either a local Unix anchor or a separately administered mTLS witness. Runtime restart/replay and retained ORAM state are exercised through the actual witness. The latest remote witness change adds bounded TLS/frame workers and authenticated per-certificate/slot request rate limits; current validation still has one unresolved timing-sensitive integration failure, recorded in the [progress snapshot](PROGRESS.md) and [implementation status](docs/IMPLEMENTATION_STATUS.md). This does not certify optional deployment properties or cryptographic security. This is an unaudited prototype under a **TrustedExecutor** assumption; ordinary processes and Wasmtime provide no hardware TEE protection.

## Start here

- [Architecture map](ARCHITECTURE.md) shows the runtime components and observer boundaries.
- [Full walkthrough](EXPLANATION.md) follows an invocation through startup, batching, PIR, WASM, ORAM, response publication, and optional durability.
- [Reports and evidence](REPORTS.md) indexes measurements and explains how to interpret controls and uncertainty.
- [Current progress](PROGRESS.md) records the latest verified revision, failures, and next action.
- [Contributor instructions](AGENTS.md) define code discovery, security, experiment, and delivery workflow.

## Implemented

- Encrypted Path ORAM with Z=4, a client position map/stash, fixed bucket sizes, corruption/freshness checks and a million-operation oracle stress test.
- Memory and bounded file backends; authenticated full checkpoints and recovery with fresh bucket keys. Recovery requires an independently protected latest checkpoint handle.
- Anchored checkpoint restore and signed invocation receipts are available as an opt-in worker mode. Local Unix SQLite and remote mTLS invocation backends both atomically bind a fixed-size response to an encrypted full-store checkpoint. The remote witness must remain fresh and trusted; it receives the snapshot decryption handle. Neither backend supplies hardware anti-rollback or a distributed worker lease.
- A separate [`oblivion-registry` library](docs/REGISTRY.md) signs fixed-size function records and full catalog manifests. The worker verifies an externally publisher-signed catalog against a pinned Ed25519 key before PIR startup. It can activate the catalog version and digest through either the local SQLite anchor (`OBLIVION_REGISTRY_ANCHOR_SOCKET`) or the separately administered mTLS witness, configured by the six `OBLIVION_REGISTRY_ANCHOR_MTLS_*` settings documented in [the anchor service guide](docs/ANCHOR_SERVICE.md). The settings are all-or-none and mutually exclusive; activation must succeed before readiness. The [offline publisher example](docs/EXTERNAL_REGISTRY.md) creates the demo catalog. With neither registry file configured, development mode retains its ephemeral signer and cannot use a catalog anchor.
- Two-server XOR PIR over 10,000 × 1 KiB records, independent processes, full scans and a generic authenticated transport. A deliberately plaintext loopback tool remains available for component experiments.
- Five real Wasmtime functions, guest fuel/memory/host-call limits, fixed class I/O and deadlines. Protected execution stages an eight-block working set, makes eight actual ORAM reads and eight writes, and discards guest mutations on failure before physical commit.
- Fixed epochs, bounded queues, real dummy execution, 228-byte v2 authenticated invocation envelopes with signed request identities, and enrolled namespaces for one to four clients. The mixed demo exercises all five functions.
- A bounded, ephemeral Diana-inspired GGM SSE component with a 100,000-operation oracle and retained-capability adversary controls.
- Opt-in persistent SSE client state using an encrypted journal and either the local Unix anchor or a separate mTLS witness. An independently administered witness detects application-host journal rollback while its own database remains fresh; rolling back or compromising that witness defeats the guarantee. This is not backward privacy.
- `oblivion-anchor-remote` runs a mutual-TLS witness with bounded versioned frames and CAS operations for persistent SSE journals, signed registry catalogs, standalone ORAM checkpoint recovery, and atomic runtime invocation receipts. A versioned SHA-256 leaf-certificate-to-slot policy limits each client certificate to explicit slots. Four fixed workers handle TLS/frame I/O, a sixteen-connection queue bounds accepted work, and process-local token buckets default to 100 requests/second with burst 200 per certificate/slot. SQLite operations remain serialized. Invocation traffic uses fixed-capacity responses; the witness sees decrypted request identity, receipt bytes and the 88-byte checkpoint handle. The witness can decrypt snapshots it can access and must be trusted with checkpoint confidentiality. It is not a quorum service and has no durable/shared quota, host-failover storage, or distributed lease.
- A 30-trial size/recovery benchmark for that journal using the actual local anchor service. Application-level journal-byte amplification ranged from 84.04× to 244.75× across the tested sizes; this is not SQLite/WAL or physical storage write amplification. See the [result report](docs/SSE_JOURNAL_BENCHMARK_20261028_RESULT.md) and [raw bundle](experiments/results/sse-persistent-journal-benchmark-20261028/).
- A genuine pinned SimplePIR reference comparison with 100,020 full-record checks across 30 fresh setups, a measured square-root XOR variant, and autoscaler simulations including a scoped event-level Laplace mechanism study.
- An opt-in persistent autoscaler accountant that composes authenticated bounded-user releases across local runs, with atomic SQLite budget checks and keyed pseudonyms. It has no anti-rollback protection and does not make deterministic seeded artifacts differentially private; see [the ledger security and usage notes](docs/PRIVACY_LEDGER.md) and its [local overhead study](docs/PRIVACY_LEDGER_BENCHMARK_20261026.md).
- Frequency/traffic and six bounded SSE-facing methods with leaky controls, a common attack API, separate observer/label data and whole-trial uncertainty.
- Licensed real-text SSE/auxiliary-drift evaluation, measured presence/intersection leakage, ORAM/PIR geometry sweeps and per-invocation CPU/resource measurements.
- Genuine separately licensed matched Path/Circuit reference, individual-server PIR timing, joint batch-load inference and integrated reader-thread pipe-timestamp epoch sweeps, with controls and earlier failed evidence preserved.
- Full-path CPU normalization per successful invocation, paired with offered-load SLO failures and whole-process bootstrap intervals; provider prices are optional explicit scenarios, not inferred from local timings ([method and results](docs/COST_SENSITIVITY.md)).
- Independent Path ORAM leaf/timing replications with successful plaintext/encrypt-only controls, fresh skewed and Markov-locality workloads, isolated bucket-handler timestamps, raw-session hashes and trial intervals. These finite local studies do not rule out weaker signals or establish cryptographic privacy; see the [Markov workload replication](docs/ORAM_SIGNAL_REPLICATION_20261026_B.md), [service-pinned replication](docs/ORAM_PINNED_REPLICATION_20261026.md), and [paired affinity crossover](docs/ORAM_AFFINITY_CROSSOVER_20261026.md).
- A 2026-10-28 preregistered Zipf-16/Markov ORAM replication: both leaky controls achieved AUC 1.0; Path ORAM measured 0.4968 [0.4864, 0.5072] using isolated handler timing. Raw traces, hashes and verification are retained; the result is inconclusive, not a security proof. See the [preregistration](docs/ORAM_ZIPF16_MARKOV_REPLICATION_PREREG_20261028.md) and [report](docs/ORAM_ZIPF16_MARKOV_REPLICATION_20261028.md).
- Completed final 30-trial A–G/disabled-layer experiments and figures; eight-class execution/error inference; actual 100k ORAM workload diagnostics and 30-session scoped encrypted PIR packet capture.

Nine Rust crates implement the store, PIR, executor, batcher, server, harness, SSE, signed registry, and anchor services. Runtime durable invocation state can use either a local Unix anchor or the remote mTLS witness; standalone SSE journals, signed catalogs, and ORAM checkpoint callers also have remote adapters. [Implementation status](docs/IMPLEMENTATION_STATUS.md) distinguishes current source from historical test/results evidence. The [requirements matrix](docs/REQUIREMENTS_MATRIX.md) tracks the entire supplied roadmap, including remaining validation/delivery gates and unselected extensions.


The final declared-feature joint attacker scores G at **33.40% balanced accuracy [32.29,34.51]**, versus 33.33% chance; an earlier corrected-version function signal is preserved and documented alongside publication/arrival mitigations. The actual packet evidence establishes bounded structural accounting, with an unvalidated packet classifier removed. These results do not cover every host observation.

## Trust and limits

The client and executor are trusted. An administrator of this machine can inspect their memory. Two PIR servers must not collude; encrypting the links prevents a network-only observer from combining plaintext query shares, but separate local processes do not establish independent operators.

The protected storage schedule costs **O(M log N)** bandwidth for public working-set size M. It hides guest-dependent storage counts in successful backend operation, while scheduling jitter, deadline misses, resources, cold starts, participation and active failures remain visible. Fixed shapes do not establish full-transcript indistinguishability.

The default process demo uses ephemeral memory state. For durable restart recovery and signed receipt replay, select exactly one anchor: local mode sets `OBLIVION_ANCHOR_SOCKET` with `OBLIVION_ANCHOR_STATE_DIR`; remote mode sets all six `OBLIVION_INVOCATION_ANCHOR_MTLS_*` settings with `OBLIVION_ANCHOR_STATE_DIR` and must not set the local socket. Full configuration and flow details are in [INVOCATION_DURABILITY.md](docs/INVOCATION_DURABILITY.md). The built-in clients still generate per-run signing keys and IDs, so applications must retain the same key, ID and canonical request to retry across sessions. Receipt hits use the reserved dummy function and return the original response. Durable misses write a visible full-store snapshot, then prune obsolete snapshot files after anchor publication and during startup recovery; the anchor operator can distinguish receipt lookup from commit. One cooperating durable worker per local anchor slot is enforced with a process-lifetime advisory lock; direct protocol/database callers and separate hosts can bypass it. Arbitrary external side effects are not atomic. Rolling back either the local SQLite database or the remote witness database defeats the corresponding freshness guarantee, and a host administrator can inspect the process and anchor key. Standalone `PersistentClient` can recover through the local anchor after process restart or use `TlsSseJournalAnchor` with an independently trusted witness to detect application-host journal rollback; restoring the witness database still defeats freshness. SSE exposes search equality, result volume and timing and has no backward privacy. Autoscaling remains a simulation with hypothetical prices. Its optional Laplace study has only a conditional mechanism-design argument; the saved deterministic-public-seed experiment has no formal DP guarantee. A separate OS-CSPRNG mode has a 30-trial public-feature attack study with successful naive controls, but its finite-precision transform has no formal DP analysis. Centroid and forest seed-replay attacks are evaluated against the seeded trace with successful naive positive controls, and a paired four-budget sweep records classifier, cost and SLO results. Read the [autoscaler DP and attack study](docs/AUTOSCALER_DP.md), [threat model](docs/THREAT_MODEL.md) and [security assumptions](docs/SECURITY_ASSUMPTIONS.md).

To authenticate a registry publisher, configure both `OBLIVION_REGISTRY_MANIFEST` and `OBLIVION_REGISTRY_PUBLIC_KEY`; the worker rejects invalid signatures or records that do not match its embedded modules before readiness. Add `OBLIVION_REGISTRY_ANCHOR_SOCKET` to reject lower catalog versions and same-version content changes. This is local SQLite-backed freshness only: restoring an older anchor database rolls back the floor, and host root can replace the database. The key-to-publisher binding must be authenticated independently. See [external registry provisioning](docs/EXTERNAL_REGISTRY.md) for configuration and limits.

## Build and run

Use Rust **1.96+**, Cargo and a native C toolchain. Linux is the recorded environment. Initial Wasmtime compilation is substantial. Choose a new output directory for every run.

```sh
cargo build --locked --workspace
cargo run --locked -p oblivion-server -- demo target/demo-half 50 2 mixed
cargo run --locked -p oblivion-server -- demo target/demo-zero 0 2 mixed
cargo run --locked -p oblivion-server -- demo target/demo-full 100 2 mixed
```

The separate A–G component harness can exercise its invocation boundary across
an independent controller and worker process on loopback TCP:

```sh
cargo run --locked -p oblivion-harness -- system-tcp \
  experiments/configs/system-tcp-smoke.json target/system-tcp-smoke-20261030
```

The command requires a new output directory. Its fixed four-byte length
prefix, per-mode body lengths, inherited-pipe key bootstrap, socket trace and
trust limits are specified in [PROTOCOL.md](docs/PROTOCOL.md). This smoke
configuration checks actual A–G registry/PIR/WASM/storage execution; it is
not a packet capture, a privacy evaluation, or a TEE measurement. The worker's
two PIR servers remain in the same trusted process in this harness, and its
ORAM trace comes from the local memory backend.

The demo launches an executor and two PIR workers. Each run has eight epochs, a 100 ms execution class and an epoch period of 150 ms per enrolled participant; slots execute sequentially. A trusted client independently checks function outputs and persistent counters. Observer traces and private instrumentation are separate; private runtime records must stay within the trusted boundary. The built-in demo's real/dummy and function schedule is deterministic and public given its code, configured real percentage and epoch. It is a correctness/topology exercise, not invocation anonymity against an observer who already knows that schedule. Encryption cannot hide an identity already determined by authorized auxiliary knowledge.

The pipeline worker accepts an optional public `OBLIVION_EXECUTION_DEADLINE_MS` value from 2 through 1000 (default 100). The protected storage phases run at 5% (read) and 65% (commit) of that class deadline. Demo epoch periods must allow one full deadline per sequential participant slot; the default adds 50 ms of per-slot slack. These settings affect latency and are recorded in demo metadata.

### Optional remote mTLS anchor service

The remote witness requires operator-provisioned server/client certificates, a certificate-to-slot authorization policy, and a separate 32-byte witness master-key file. The server key and master-key files must be restricted to the service account. Fingerprint each authorized client certificate as lowercase SHA-256 over its DER leaf certificate; the policy names the exact slots that fingerprint may use. With those files provisioned, start the witness on its separate host:

```sh
cargo run --locked -p oblivion-anchor --bin oblivion-anchor-remote -- \
  serve 0.0.0.0:7443 witness.sqlite witness-master-key.bin \
  witness-cert.pem witness-key.pem client-ca.pem authorization-policy.json
```

Create a client configuration with `oblivion_anchor::mtls_client_config_from_pem`, then pass it to `TlsSseJournalAnchor::new` and a standalone `oblivion_sse::PersistentClient`. For runtime invocation anchoring, set all six `OBLIVION_INVOCATION_ANCHOR_MTLS_*` settings and `OBLIVION_ANCHOR_STATE_DIR`; do not set `OBLIVION_ANCHOR_SOCKET` at the same time. Either runtime mode fails closed before readiness on partial/invalid configuration or missing checkpoint state; remote mode also fails closed on TLS/authentication errors. The worker has no remote-to-local fallback. The policy is loaded once at startup, capped at 1 MiB, and malformed or empty policies fail closed. On Unix it must be a regular, non-symlink, non-group/world-writable file. Updating a client certificate requires updating its fingerprint and restarting the witness. Each authenticated certificate/slot has a process-local token bucket (default 100 requests/second, burst 200); rate, interval, and burst overrides must be set together. Four TLS/frame workers and a sixteen-connection queue keep one stalled peer from blocking every handler, but four slow peers can occupy all workers until their deadlines. Queue saturation closes newly accepted sockets. TCP accepts, handshakes, IP-level filtering, durable quotas, and shared multi-instance rate limits are not implemented. Use a dedicated client CA and restrictive network policy. The full policy format, runtime settings, trust assumptions, failure behavior and limits are in [ANCHOR_SERVICE.md](docs/ANCHOR_SERVICE.md), [INVOCATION_DURABILITY.md](docs/INVOCATION_DURABILITY.md), and [ANCHOR_FRESHNESS_DESIGN.md](docs/ANCHOR_FRESHNESS_DESIGN.md). The main demo does not switch to this witness automatically.

## Validation and experiments

The runtime remote invocation integration was checked on source commit
`7bee2666`. The serial whole-workspace Rust suite passed 187 tests; its
million-operation ORAM stress test remains intentionally ignored by default,
and passed separately with the dedicated release command in 88.76 seconds.
Warning-denied workspace Clippy and formatting passed. The
integration test uses a real mTLS witness and stateful WASM invocation across
witness restart. No performance benchmark or Python test run was performed for
this Rust-only increment; see the [implementation record](docs/IMPLEMENTATION_STATUS.md).

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

The live demo's signed registry/PIR composition and its limits are documented
in [REGISTRY_RUNTIME.md](docs/REGISTRY_RUNTIME.md).
The SQLite-backed checkpoint/version CAS adapters, local socket service and
their rollback limits are documented in [ANCHOR_SERVICE.md](docs/ANCHOR_SERVICE.md).

The [supplied roadmap](Oblivion_%20Research%20Roadmap%20and%20Build%20Plan%20%281%29.md) remains authoritative. Read [architecture](docs/ARCHITECTURE.md), [protocol](docs/PROTOCOL.md), [storage recovery](docs/STORAGE_RECOVERY.md), [PIR transport](docs/PIR_TRANSPORT.md) and [next steps](docs/NEXT_STEPS.md). The [system report](docs/SYSTEM_EXPERIMENTS.md), [bounded inference study](docs/ADVANCED_ATTACKS.md), [attack interface](docs/ATTACK_INTERFACE.md), [trace validation](docs/TRACE_VALIDATION.md), [execution study](docs/EXECUTION_EVALUATION.md), and [actual local demo video](docs/DEMO.md) now exist. Recent [real-corpus](docs/CORPUS_EVALUATION.md), [presence](docs/PRESENCE_EVALUATION.md), [geometry](docs/GEOMETRY_EVALUATION.md), [invocation CPU](docs/EXECUTOR_RESOURCES.md), [ORAM timing](docs/ORAM_LEAF_TIMING.md), [isolated ORAM timing replication](docs/ORAM_TIMING_REPLICATION.md), [eight-address ORAM timing](docs/ORAM_EIGHT_ADDRESS.md), [tag-frequency ORAM attacker](docs/ORAM_ATTACK_FAMILIES.md), [read-heavy ORAM timing](docs/ORAM_READ_HEAVY.md), [PIR timing](docs/PIR_TARGET_TIMING.md), [square-root PIR](docs/SQRT_PIR.md), [fault](docs/FAULT_CAMPAIGN.md), [batcher population](docs/POPULATION_SWEEP.md), and [full-path 64-offer load](docs/RUNTIME_POPULATION.md) studies retain positive controls or measured operating limits. The [joint batch-load study](docs/BATCH_LOAD_EVALUATION.md), [integrated pipe-timestamp sweep](docs/EPOCH_SYSTEM_EVALUATION.md) and [matched Circuit reference](docs/CIRCUIT_ORAM_REFERENCE.md) also retain full experimental scope. See [the experiment index](docs/EXPERIMENTS.md) for recorded outputs and the [completion audit](docs/COMPLETION_AUDIT.md) for remaining research extensions. Empirical near-chance accuracy for a chosen attacker is not a cryptographic proof.

The core workspace is MIT licensed. The separate [Circuit/Path reference benchmark](research/oram_reference/README.md) is a GPL-3.0 program and is built for the full research test suite; it is not linked into the core. The SimplePIR adapter imports an explicitly pinned MIT reference and preserves its license. OpenSSE is consulted as a construction reference; its AGPL code is not copied into this repository.
