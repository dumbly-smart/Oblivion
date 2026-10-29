# Remote Durable Invocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the mTLS witness and runtime worker so signed invocation receipts and ORAM checkpoint handles commit atomically through one remote transaction.

**Architecture:** Add a version-3 fixed-structure invocation exchange to the existing mTLS anchor protocol and delegate mutations to `AnchorDatabase::commit_invocation`. Configure the runtime to select either its local Unix anchor or a remote `TlsInvocationAnchor`; keep snapshot files local and document that this provides no host failover or distributed lease.

**Tech Stack:** Stable Rust, rustls, serde, SHA-256/ChaCha20-Poly1305 anchor storage, Tokio is not used by the current synchronous witness.

**Spec:** [Remote durable invocation design](../specs/2026-10-29-remote-invocation-anchor-design.md)

## Global Constraints

- `commit_invocation` must atomically persist receipt and checkpoint in one SQLite transaction.
- Two-server PIR non-collusion and TrustedExecutor limits remain unchanged.
- Remote messages stay bounded by the existing 512 KiB frame cap.
- Runtime remote invocation uses fixed 80-byte responses; adapter capacity is public, bounded, and fixed per client instance.
- Partial remote credentials, local/remote conflicts, and uncertain commits fail closed; no local fallback or automatic retry after ambiguity.
- Snapshot files remain under `OBLIVION_ANCHOR_STATE_DIR`; remote witness rollback, host failover, quotas, and external side effects remain outside the guarantee.
- Preserve `.ignore` and unrelated user files; commit implementation, integration, and docs in small coherent increments.

## Review Focus

- A replay could accidentally create an orphan snapshot or advance ORAM generation; verify the identical finish exchange reuses the loaded checkpoint and returns the original generation.
- A hit/miss encoding could alter frame length; test fixed-capacity serialized lengths for both states.
- A truncated, non-hex, padded, or over-capacity response could be accepted; test strict bounds and zero-padding validation.
- A lost reply could be mistaken for a definite failure; test typed indeterminacy and receipt reconciliation.
- Two workers could race at the same generation; test the actual CAS conflict and document that CAS is not a lease.

---

### Task 1: Fixed-shape remote invocation wire contract

**Files:**
- Modify: `crates/oblivion-anchor/src/remote.rs`
- Test: `crates/oblivion-anchor/src/remote.rs`

**Interfaces:**
- Add version-3 `Request::Invocation` with fixed-width token fields, action,
  response capacity/data, expected generation, and optional checkpoint
  record fields.
- Add one fixed-shape invocation response carrying status and optional receipt
  data at the request's declared capacity.

- [x] Write tests for equal load hit/miss lengths, equal finish success/replay
  lengths, and malformed hex/length/capacity rejection.
- [x] Run the focused wire tests and confirm they fail because the v3 message
  types and fixed encoder are absent.
- [x] Implement strict fixed-width encode/decode helpers, request validation,
  and protocol version 3 while retaining the existing 512 KiB limit.
- [x] Run the focused wire tests, then all `oblivion-anchor` tests.
- [x] Commit `feat(anchor): add fixed-width invocation wire protocol`.

### Task 2: Atomic mTLS invocation anchor client and server

**Files:**
- Modify: `crates/oblivion-anchor/src/remote.rs`
- Modify: `crates/oblivion-anchor/src/lib.rs`
- Modify: `crates/oblivion-anchor/tests/remote_mtls.rs`

**Interfaces:**
- Add `TlsInvocationAnchor::new(address, server_name, slot, tls,
  response_capacity)` and `load`, `commit`, and `confirm` methods.
- Implement `oblivion_store::CheckpointAnchor` on `TlsInvocationAnchor` so
  runtime startup can load the current remote checkpoint through the same
  configured client.
- Route new commits to the existing atomic `AnchorDatabase::commit_invocation`;
  route receipt confirmation to an exact response comparison without mutation.

- [x] Add real-certificate tests for miss, receipt recovery, exact duplicate,
  response mismatch, stale generation, invalid signature, denied slot,
  witness outage, and ambiguous commit/reconciliation.
- [x] Run those tests first and observe expected missing-adapter failures.
- [x] Implement the mTLS client/server path and map conflict/indeterminate
  responses to existing typed errors.
- [x] Run anchor tests and verify the checkpoint and receipt remain one atomic
  SQLite update.
- [x] Commit `feat(anchor): support atomic remote invocation receipts`.

### Task 3: Runtime remote configuration and backend selection

**Files:**
- Modify: `crates/oblivion-server/src/pipeline.rs`
- Test: `crates/oblivion-server/tests/pipeline.rs`

**Interfaces:**
- Add an internal local-or-TLS durable anchor enum used by `DurableState`.
- Add the six `OBLIVION_INVOCATION_ANCHOR_MTLS_*` settings listed in the spec;
  require them all with `OBLIVION_ANCHOR_STATE_DIR` and reject conflicts with
  `OBLIVION_ANCHOR_SOCKET`.
- For every invocation, send the same load-then-finish action sequence. On a
  receipt hit, reuse the currently loaded checkpoint and saved response; the
  idempotent finish returns the original receipt without writing a snapshot or
  advancing the generation. Use `confirm` only after an ambiguous finish.

- [ ] Add startup tests for partial credentials, missing state directory, and
  simultaneous local/remote anchors; run and observe their expected failure.
- [ ] Add a process integration test that uses an actual mTLS witness, signed
  request, stateful WASM function, local encrypted snapshot, restart, exact
  receipt replay, and a subsequent state read/write.
- [ ] Implement configuration parsing and backend selection using existing
  PEM permission validation; do not alter the local-mode defaults.
- [ ] Run the focused runtime tests and the existing local restart/single-writer
  tests.
- [ ] Commit `feat(server): use remote durable invocation anchor`.

### Task 4: Security documentation, status, and full verification

**Files:**
- Modify: `README.md`, `ARCHITECTURE.md`, `EXPLANATION.md`, `PROGRESS.md`,
  `docs/ARCHITECTURE.md`, `docs/ANCHOR_SERVICE.md`,
  `docs/INVOCATION_DURABILITY.md`, `docs/SECURITY_ASSUMPTIONS.md`,
  `docs/THREAT_MODEL.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/NEXT_STEPS.md`.

- [ ] Document exact environment variables, policy slot, certificate setup,
  wire sizing, transaction semantics, restart procedure, and residual timing,
  snapshot custody, witness rollback, and host-failover limits.
- [ ] Run `cargo fmt --all --check`, warning-denied workspace Clippy, and
  `cargo test --locked --workspace -- --test-threads=1`.
- [ ] Check changed Markdown links and `git diff --check`; record the million
  operation ORAM stress tier as skipped unless run separately.
- [ ] Commit `docs: describe remote durable invocation path` and push each
  completed commit to the current branch.
