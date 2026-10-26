# Persistent SSE Client State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add encrypted, restartable SSE client state with rollback checks through a caller-supplied durable compare-and-swap anchor.

**Architecture:** Keep `Client` ephemeral and introduce `PersistentClient<A>` in `journal.rs`. Persist encrypted event records and periodic full-state checkpoints as immutable files; the external anchor selects one digest and generation. Any uncertain persistence outcome poisons the instance until it is reopened.

**Tech Stack:** Stable Rust, existing RustCrypto HKDF/ChaCha20-Poly1305/SHA-256, OS randomness, Serde, filesystem fsync, and Rust unit tests.

**Spec:** `docs/superpowers/specs/2026-10-26-sse-persistent-state-design.md`

## Global Constraints

- Preserve the current `Client` behavior and ephemeral constructor.
- Never persist plaintext keywords, keys, or pending request state.
- Use a separate trusted anchor; an adjacent ordinary file is not rollback-resistant.
- Never return an update request until its exact pending state is durable and anchored.
- Do not claim TEE confidentiality, backward privacy, or a Diana security theorem.
- Keep each completed change in a small commit and push it.

## Review Focus

- An interrupted update must resume with the exact same request bytes: test close/reopen and compare the entire request.
- A restored old or corrupted journal must not be accepted: test digest mismatch and AEAD failure.
- Two writers from one generation must not both publish: test one CAS winner and require the loser to reopen.
- Malformed decrypted state or an oversized chain must not allocate without bound: test record and replay limits.
- A successful acknowledgment must remain searchable after restart: test a real server round trip before and after reopening.

---

### Task 1: Encrypted SSE Journal and CAS-gated Client

**Files:**
- Create: `crates/oblivion-sse/src/journal.rs`
- Modify: `crates/oblivion-sse/src/lib.rs`
- Modify: `crates/oblivion-sse/Cargo.toml`
- Modify: `docs/REQUIREMENTS_MATRIX.md`, `docs/SECURITY_ASSUMPTIONS.md`, `docs/IMPLEMENTATION_STATUS.md`, and `docs/NEXT_STEPS.md`

**Interfaces:**
- `SseJournalAnchor::load() -> Result<Option<SseJournalAnchorRecord>, SseJournalAnchorError>`
- `SseJournalAnchor::compare_and_swap(expected_generation, next_record) -> Result<(), SseJournalAnchorError>`
- `PersistentClient::create(directory, key, limits, anchor)` and `PersistentClient::open(directory, key, anchor)`
- Durable wrappers for `prepare_add`, `retry_pending`, `finish_add`, `rotate_keyword`, `prepare_search`, and `finish_search`.

- [x] **Step 1: Write failing tests** for initial persistence, exact pending retry after reopen, post-ack search after reopen, wrong-key/corruption/rollback rejection, and one-winner concurrent compare-and-swap.
- [x] **Step 2: Run the focused tests** and confirm the expected missing-type or missing-behavior failures.
- [x] **Step 3: Implement the journal format and persistence wrapper** with bounded encrypted records, periodic encrypted checkpoints, fsync-before-CAS ordering, and fail-closed poisoned state after uncertain commits.
- [x] **Step 4: Run the focused SSE tests, crate tests, formatter, and clippy**; fix actual failures before proceeding.
- [x] **Step 5: Update security/status documentation** to mark the interface as partial until a concrete independent anchor-service adapter exists.
- [x] **Step 6: Commit and push** the verified increment (`7a31efa2`).
