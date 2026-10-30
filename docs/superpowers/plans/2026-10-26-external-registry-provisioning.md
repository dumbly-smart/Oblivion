# External Registry Provisioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the worker verify a publisher-signed fixed catalog against an independently provisioned Ed25519 public key and the embedded modules before PIR startup.

**Architecture:** Add a bounded file loader for the binary manifest and raw public key, then verify with the existing `oblivion-registry` APIs. Validate every signed record against its dispatch ID, module digest, location digest, and supported resource class. Keep the current ephemeral signer only as an explicit compatibility path when neither external setting is provided.

**Tech Stack:** Stable Rust, `ed25519-dalek`, existing `oblivion-registry`, standard filesystem APIs, Cargo tests.

**Spec:** [Registry and publisher identity requirements](../../RESEARCH_NOTES.md), [external registry design](../../EXTERNAL_REGISTRY.md), and the primary roadmap requirement for signed registry records.

## Global Constraints

- Verify the catalog before announcing worker readiness or starting PIR workers.
- Bound all untrusted allocations and reject malformed encodings.
- Do not load publisher private keys in runtime external-catalog mode.
- Preserve a clear distinction between pinned-key signature authentication and monotonic rollback protection.
- Do not claim publisher identity unless the public-key-to-publisher binding was provisioned independently.

## Review Focus

- Partial environment configuration must fail before readiness.
- Wrong publisher key or malformed signature must fail closed.
- Validly signed but mismatched module records must fail closed.
- Empty, oversized, short, and non-regular key/manifest inputs must be bounded and rejected.
- Development fallback must remain explicitly identified as ephemeral and unauthenticated publisher identity.

---

### Task 1: Verify externally supplied catalogs

**Files:**
- Modify: `crates/oblivion-server/src/pipeline.rs`
- Test: `crates/oblivion-server/src/pipeline.rs` unit tests

**Interfaces:**
- `Deployment::from_catalog(encoded: &[u8], publisher: &VerifyingKey) -> Result<Self>`
- `Deployment::from_environment() -> Result<Self>`

- [x] Add tests for valid signed catalog acceptance, wrong-key rejection, and module-digest mismatch.
- [x] Run the targeted test and confirm the new API/test fails because it is missing.
- [x] Implement bounded manifest/key input, signature verification, exact five-record dispatch validation, and existing fallback behavior.
- [x] Run the focused server test and warning-denied Clippy.
- [x] Commit and push the independently tested core change (`f1c673f9`).

### Task 2: Exercise worker startup and document operations

**Files:**
- Modify: `crates/oblivion-server/tests/pipeline.rs`
- Create: `crates/oblivion-server/examples/publish-registry.rs`
- Modify: `README.md`
- Create: `docs/EXTERNAL_REGISTRY.md`
- Modify: `docs/IMPLEMENTATION_STATUS.md`
- Modify: `docs/NEXT_STEPS.md`
- Test: `crates/oblivion-server/tests/pipeline.rs`

- [x] Add a subprocess test that supplies a valid signed manifest and pinned key and reaches worker readiness.
- [x] Add subprocess checks for wrong key, partial configuration, invalid key size, and oversized manifest; each fails before readiness.
- [x] Add an offline example that signs the five embedded demo records using a separately provisioned seed.
- [x] Document signing, provisioning, and independent public-key authentication.
- [x] Record that restart recovery is anchored separately and catalog-version anti-rollback is not added here.
- [x] Run the focused pipeline tests, formatter, warning-denied Clippy, and serialized full workspace suite.
- [ ] Commit and push the documentation and offline publisher slice.
