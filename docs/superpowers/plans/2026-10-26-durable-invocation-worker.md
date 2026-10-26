# Durable Invocation Worker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate signed invocation receipts with the local executor so an opt-in worker can restore anchored ORAM state, replay prior responses, and atomically commit each new response with its checkpoint.

**Architecture:** Durability is enabled only when both `OBLIVION_ANCHOR_SOCKET` and `OBLIVION_ANCHOR_STATE_DIR` are configured. The worker restores a verified whole-store checkpoint into a fresh in-memory ORAM backend, checks receipts before execution, uses a fixed cover execution for receipt hits, and commits a new encrypted snapshot handle and fixed-size response before publishing. Default local demo behavior remains ephemeral.

**Tech Stack:** Rust, Path ORAM checkpoint API, `FileBackend`, `UnixCheckpointAnchor`, `UnixInvocationAnchor`, existing Ed25519 payload identity.

**Spec:** `docs/INVOCATION_DURABILITY.md`, `docs/PROTOCOL.md`, and `docs/THREAT_MODEL.md`.

## Global Constraints

- Never describe the local worker or Wasmtime as a TEE.
- The anchor database and master key require a separately trusted freshness source; SQLite backup rollback remains possible.
- Do not return an uncommitted successful result after an indeterminate anchor commit.
- Preserve fixed-size request and response envelopes.
- Duplicate invocation IDs with different request digests fail closed.
- Do not claim same-ID concurrency fencing or atomicity for arbitrary external side effects.
- Keep the existing ephemeral demo behavior when durability is not configured.

## Review Focus

- Missing or malformed anchor configuration must fail before readiness.
- A stale, corrupted, or path-traversing snapshot reference must not be restored.
- A matching receipt must return the original response and must not rerun the real invocation.
- A different digest under the same signed ID must fail closed.
- Anchor loss after local state mutation must not publish the uncommitted result.

---

### Task 1: Durable worker state bootstrap

**Files:**
- Modify: `crates/oblivion-server/src/pipeline.rs`
- Test: `crates/oblivion-server/tests/pipeline.rs`

**Interfaces:**
- Consume `UnixCheckpointAnchor::load`, `CheckpointAnchorRecord`, `TrustedCheckpoint::from_secret_bytes`, and `PathOram::restore`.
- Add a worker-owned durable state object that supplies a `PathOram<MemoryBackend>`, snapshot directory, current generation, and invocation anchor.

- [x] Write a test that configures only one required anchor environment variable and verifies worker startup fails before readiness.
- [x] Run the test and confirm it fails because worker anchor configuration is not implemented.
- [x] Implement paired environment-variable validation and fail-before-ready behavior.
- [x] Restore only from the anchored snapshot ID after validating the ID as a bounded safe filename component; otherwise initialize only when no previous backend session exists.
- [x] Run the test and relevant store/anchor tests.
- [x] Commit the independently working bootstrap slice (`1061df0a`).

### Task 2: Receipt lookup and atomic response commit

**Files:**
- Modify: `crates/oblivion-server/src/pipeline.rs`
- Test: `crates/oblivion-server/tests/pipeline.rs`

**Interfaces:**
- Use the already verified `SignedInvocationId` from `verify_request`.
- Store exactly `PAYLOAD_BYTES` response bytes in the receipt.
- Before execution, load the receipt; on a hit use the reserved cover function and return the saved body.
- After a cache miss, write the instrumented in-memory ORAM state to a uniquely named encrypted full-store checkpoint, and call `UnixInvocationAnchor::commit` with the expected generation.

- [x] Add an end-to-end test that commits an invocation, restarts with the same anchor and state directory, retries the same signed request and then makes a new request; assert the retry response is byte-identical and the new request advances state only once. Add a same-ID/different-digest conflict assertion.
- [x] Implement lookup, cover replay, checkpoint publication, and atomic anchor commit before response publication.
- [x] Treat `CommitIndeterminate` by looking up the same signed receipt; fail closed if no exact receipt is available.
- [x] Run signed identity, replay, conflict, and storage-recovery tests.
- [x] Commit the receipt-integrated worker slice.

### Task 3: Operator documentation and complete local verification

**Files:**
- Modify: `docs/INVOCATION_DURABILITY.md`
- Modify: `docs/PROTOCOL.md`
- Modify: `docs/SECURITY_ASSUMPTIONS.md`
- Modify: `docs/IMPLEMENTATION_STATUS.md`
- Modify: `docs/NEXT_STEPS.md`

- [x] Document exact environment variables, restart/replay procedure, and anchor master-key handling.
- [x] State duplicate timing/storage leakage, single-writer assumptions, rollback limits, and external-side-effect limits.
- [ ] Run format, warning-denied Clippy, relevant Rust tests, and the full local gate where host timing permits.
- [ ] Commit the documentation/verification record and push all small commits.
