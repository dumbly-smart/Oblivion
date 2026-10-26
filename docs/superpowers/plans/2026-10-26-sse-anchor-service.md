# Persistent SSE Anchor Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `PersistentClient` a concrete durable compare-and-swap adapter to the local `oblivion-anchor` service.

**Architecture:** Add a dedicated encrypted SSE journal state row and slot API to `oblivion-anchor`, expose it through additive protocol-v3 Unix operations, and implement the existing `SseJournalAnchor` trait for the resulting Unix client type. Test the actual SSE client against an anchor service process that is stopped and restarted.

**Tech Stack:** Stable Rust, existing SQLite/Rusqlite, HKDF, ChaCha20-Poly1305, OS randomness, Serde, Unix domain sockets, and integration tests.

**Spec:** `docs/superpowers/specs/2026-10-26-sse-anchor-service-design.md`

## Global Constraints

- Preserve existing protocol-v2 operations and schema-v3 data through an explicit migration to schema v4.
- Initial SSE checkpoint generation is 0; all later CAS updates advance exactly one generation and retain the same index ID.
- The application supplies one stable opaque 1–128 character ASCII slot per SSE index and reuses it after restart; the slot is not derived from the index ID.
- Derive the per-slot AEAD key from the anchor service master key with a dedicated HKDF domain; changing that master key fails closed until a rekey procedure exists.
- Encrypt index ID and digest at rest with ChaCha20-Poly1305 and a fresh OS-random nonce.
- Treat anchor conflicts as definite failures and uncertain database outcomes as commit-unknown; never reset state silently.
- Keep anchor keys outside the SSE journal directory. A privileged rollback of the anchor database remains out of scope.
- Keep the user-visible SSE core generic and preserve its legacy ephemeral client API.
- Commit and push each independently testable increment.

## Review Focus

- A schema-v3 database must migrate without losing current anchor rows; test migration and reopen.
- A generation-0 initial checkpoint must be accepted exactly once, then only consecutive generations; test valid and invalid transitions.
- A stale writer and an index-ID substitution must not replace current state; test both CAS conflicts.
- Wrong-key or corrupted encrypted metadata must fail closed without returning an empty anchor; test both.
- A service restart between journal operations must preserve the selected anchor and allow exact SSE recovery; test process stop/restart and retry bytes.
- Reopening with a different service master key must not silently initialize or discard an existing slot; test that it fails closed.

---

### Task 1: Encrypted SQLite SSE Journal Slot

**Files:**
- Modify: `crates/oblivion-anchor/src/lib.rs`
- Test: `crates/oblivion-anchor/src/lib.rs`

**Interfaces:**
- `SseJournalState::new(index_id: [u8; 16], generation: u64, digest: [u8; 32]) -> Result<SseJournalState, Error>`; generation 0 is valid.
- `AnchorDatabase::sse_journal_anchor(slot: &str) -> Result<SseJournalSlot<'_>, Error>`
- `SseJournalSlot::load() -> Result<Option<SseJournalState>, Error>`
- `SseJournalSlot::compare_and_swap(expected_generation: Option<u64>, next: SseJournalState) -> Result<(), Error>`

- [ ] **Step 1: Write failing SQLite tests** for generation-0 initialization, consecutive updates, stale-writer conflict, index binding, schema-v3 migration/reopen, slot isolation, wrong-key rejection, and ciphertext tampering.
- [ ] **Step 2: Run the focused tests** and confirm missing slot/API behavior.
- [ ] **Step 3: Implement schema-v4 migration and encrypted slot persistence** with transactionally enforced generation/index invariants, domain-separated key/AAD, and unique random nonces.
- [ ] **Step 4: Run `cargo test --locked -p oblivion-anchor` and fix failures.**
- [ ] **Step 5: Commit and push the database increment.**

### Task 2: Versioned Unix Service Operations

**Files:**
- Modify: `crates/oblivion-anchor/src/local.rs`
- Modify: `crates/oblivion-anchor/src/lib.rs`
- Test: `crates/oblivion-anchor/src/local.rs` and/or `crates/oblivion-anchor/tests/local_service.rs`

**Interfaces:**
- `UnixAnchorClient::sse_journal(socket_path, slot) -> Result<UnixSseJournalAnchor, Error>`
- `UnixSseJournalAnchor::load() -> Result<Option<SseJournalState>, Error>`
- `UnixSseJournalAnchor::compare_and_swap(expected_generation, next) -> Result<(), Error>`

- [ ] **Step 1: Write failing service tests** for protocol-v3 load/CAS round-trip, generation conflict, invalid slot/version, and v2 operation compatibility.
- [ ] **Step 2: Run the focused service tests** and confirm the expected unsupported-operation failures.
- [ ] **Step 3: Add typed protocol-v3 journal load/CAS messages** while leaving all existing operations at protocol v2; map conflict and indeterminate commit responses distinctly.
- [ ] **Step 4: Run `cargo test --locked -p oblivion-anchor` and verify v2 plus v3 clients.**
- [ ] **Step 5: Commit and push the Unix protocol increment.**

### Task 3: SSE Trait Adapter and Process-Restart Integration

**Files:**
- Create: `crates/oblivion-sse/src/anchor.rs`
- Modify: `crates/oblivion-sse/src/lib.rs`
- Modify: `crates/oblivion-sse/Cargo.toml`
- Create: `crates/oblivion-sse/tests/journal_anchor_service.rs`
- Modify: `docs/REQUIREMENTS_MATRIX.md`, `docs/SECURITY_ASSUMPTIONS.md`, `docs/SSE_DESIGN.md`, `docs/IMPLEMENTATION_STATUS.md`, and `docs/NEXT_STEPS.md`

**Interfaces:**
- Implement `SseJournalAnchor` for `oblivion_anchor::UnixSseJournalAnchor`.
- Map anchor conflict to `SseJournalAnchorError::Conflict`, indeterminate commit to `CommitUnknown`, and other service failures to `Unavailable`.
- Convert between `SseJournalAnchorRecord` and `oblivion_anchor::SseJournalState` without changing the SSE wire/request API.

- [ ] **Step 1: Write a failing integration test** that starts the anchor service as a child test process, creates an SSE index, persists a pending request, stops and restarts the service, reopens the SSE client, verifies byte-identical retry, finishes the actual server update, and searches the recovered state.
- [ ] **Step 2: Run the test** and confirm the missing adapter/type failure.
- [ ] **Step 3: Implement the trait adapter** and add the anchor crate dependency.
- [ ] **Step 4: Run the focused integration test, full SSE and anchor tests, formatting, and warning-denied Clippy.**
- [ ] **Step 5: Document service visibility and rollback limits**; update S11 status only to the bounded level demonstrated by the tests.
- [ ] **Step 6: Commit and push the integrated adapter.**
