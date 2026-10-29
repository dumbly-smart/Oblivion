# Contributor and agent guide

This file is the entry point for people and coding agents working on Oblivion. It describes repository conventions; the research roadmap and the documents linked below remain the technical specifications.

## Read this first

1. Read the complete supplied roadmap, [Oblivion Research Roadmap and Build Plan](Oblivion_%20Research%20Roadmap%20and%20Build%20Plan%20%281%29.md). It is the primary project specification.
2. Read the [README](README.md), [threat model](docs/THREAT_MODEL.md), [security assumptions](docs/SECURITY_ASSUMPTIONS.md), [requirements matrix](docs/REQUIREMENTS_MATRIX.md), [implementation status](docs/IMPLEMENTATION_STATUS.md), and [next steps](docs/NEXT_STEPS.md).
3. For the subsystem being changed, read its linked design, protocol, and experiment report. Use [ARCHITECTURE.md](ARCHITECTURE.md) and [REPORTS.md](REPORTS.md) as maps.
4. Check the working tree and branch before editing. Preserve pre-existing user changes and untracked files. Stage only files belonging to the intended commit.

The root guides are summaries and navigation aids. When they differ from a protocol, threat model, preregistration, or source behavior, investigate and update the summary; do not override the precise source contract by inference.

## Code discovery

This repository is indexed by graft. Before searching or reading source code, use the graft command that fits the question:

- `graft map` for an unfamiliar repository or subsystem.
- `graft ask "question"` to locate and understand a symbol or behavior.
- `graft skeleton path/to/file.rs` for the API of a known source file.
- `graft callers Symbol --depth all` before changing a symbol across call boundaries.
- `graft grep "literal"` for exhaustive literal searches.

Use grep or file listing when searching non-code artifacts such as configs, Markdown, error strings, or workflow files, or when graft coverage is incomplete. Treat graph results as evidence about indexed source, not proof that the whole repository has been indexed. Do not repeat equivalent graft questions when the first answer is adequate.

## Security and research rules

- Keep the adopted model explicit: the executor is trusted; storage, network, and scheduler are untrusted. Processes and Wasmtime simulate boundaries; neither is a TEE.
- Never call WASM constant-time or data-oblivious. Fuel bounds metered guest work, not elapsed time or all host work.
- For two-server XOR PIR, state the non-collusion assumption every time the privacy property is discussed. Separate processes on one host do not establish non-collusion.
- `TlsCheckpointAnchor` sends the 88-byte ORAM checkpoint handle, including the snapshot key, to the mTLS witness. Treat that witness as trusted with snapshot confidentiality; it can decrypt snapshots it can access. Remote requests are restricted by a versioned SHA-256 leaf-certificate-to-slot policy in addition to CA validation. The mTLS service has process-local per-certificate/per-slot token buckets (default 100 requests/second, burst 200); see [the anchor service guide](docs/ANCHOR_SERVICE.md) for configuration and denial-of-service limits.
- The durable runtime can use `TlsInvocationAnchor` for signed invocation receipts and checkpoint commits. Remote mode requires all six `OBLIVION_INVOCATION_ANCHOR_MTLS_*` settings plus `OBLIVION_ANCHOR_STATE_DIR`, and cannot be combined with `OBLIVION_ANCHOR_SOCKET`. The witness sees signed request identity, response bytes, and the checkpoint handle containing the snapshot key; it can distinguish receipt hits from misses. Snapshot files stay local. Remote mode has no distributed lease, multi-host fencing, witness rollback protection, or host failover. See [invocation durability](docs/INVOCATION_DURABILITY.md).
- Distinguish implemented mechanism, trusted assumption, hardware-dependent property, empirical result, and unprotected leakage. Do not infer a proof from a test or near-chance score.
- Use vetted cryptographic libraries and OS cryptographic randomness for runtime secrets. Never replace encryption with plaintext while retaining a secure label. Do not log keys, plaintext, query shares, or private truth.
- Validate untrusted input, bound sizes before allocation, preserve typed errors, and keep public observer traces separate from ground truth and private diagnostics.
- Before a new privacy attack run, freeze its workload, attacker view, split, primary metric, control gate, analysis, and output location. Run and report positive controls first. Split at the independent session/trial unit, use multiple seeds where specified, retain raw inputs and hashes, and report class imbalance and uncertainty.
- A control failure invalidates the corresponding attack result; do not tune the attacker on held-out targets or reverse score direction after seeing results. A failed-to-distinguish experiment is inconclusive within its exact boundary.
- Never invent citations, measurements, provenance, hardware isolation, differential privacy, rollback resistance, or cryptographic review.

## Implementation and verification

Keep changes scoped to one reviewable outcome. Add a focused test for behavior changes, then run relevant quality and correctness checks. The standard Rust gates are:

    cargo fmt --all --check
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo test --locked --workspace -- --test-threads=1

The serial test setting is intentional: these integration fixtures use real deadlines, and local CPU contention can create timeouts. It does not change production deadlines or benchmark concurrency. The million-operation ORAM test is an explicit long-running tier:

    cargo test --locked --release -p oblivion-store million_operation_oracle -- --ignored --exact

For Python research changes, install the pinned dependencies from `research/requirements.lock`, build the required release examples, and run the focused test module(s) before the broader suite. The complete source validator is:

    .venv/bin/python scripts/validate.py target/validation-new

Read the validator and report before interpreting it: some runs include the separate GPL reference workspace and long stress tier. Report the exact commands, exit codes, and whether any tests were skipped. Do not say that a gate passes based only on an older commit, an incomplete job, or a command that was not run.

## Experiment hygiene

- Every run uses a new output directory; collection must refuse to overwrite prior evidence.
- Keep configs, seeds, software/source/binary hashes, environment metadata, raw observations, private labels, predictions, and analysis metadata at their declared boundaries.
- Never pass truth fields to the attacker. Only expose auxiliary knowledge declared in the protocol.
- Keep machine-generated output reproducible from raw data. Do not edit captured records or replace failed results; record supersession and exclusions explicitly.
- For cost, distinguish measured CPU, wall time, queue delay, simulated price, and actual provider bill. Hypothetical pricing is a scenario, not a measured cost.
- For optional noise/DP work, state adjacency, sensitivity, horizon, composition, sampler, randomness source, and observer. Seeded public artifacts do not become private merely because the mechanism is named DP.

## Commits and delivery

- Work on the current task branch unless the user directs otherwise.
- The user requested small commits and pushes: make a focused commit after relevant verification and push it to the existing branch. Keep reports/results separate from unrelated documentation or implementation where practical.
- Never stage unrelated user files. Do not amend or rewrite commits that have already been pushed unless explicitly requested.
- A push is not a merge. Do not merge, publish a release, or change external project state beyond the requested branch push.
- After a push, inspect the matching CI run and report its actual state. Do not wait indefinitely for unrelated provider activity.

## Useful repository map

- Rust workspace and process path: [architecture](ARCHITECTURE.md), [protocol](docs/PROTOCOL.md), `crates/`.
- Research methods and reports: [reports index](REPORTS.md), [experiment instructions](docs/EXPERIMENTS.md), `research/` and `experiments/`.
- Current status and next action: [progress](PROGRESS.md), [implementation status](docs/IMPLEMENTATION_STATUS.md), [next steps](docs/NEXT_STEPS.md).
- Full explanatory walkthrough: [EXPLANATION.md](EXPLANATION.md).
- Every project claim is scoped by [THREAT_MODEL.md](docs/THREAT_MODEL.md) and [SECURITY_ASSUMPTIONS.md](docs/SECURITY_ASSUMPTIONS.md).
