# Registry Rollback Anchor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Anchor the signed runtime catalog's version and content digest so exact restarts are accepted while rollback and same-version equivocation fail closed.

**Architecture:** Add a digest-aware catalog-anchor interface beside the existing version-only API. Persist the interface through a schema-v3 SQLite table and versioned Unix protocol. The executor activates the verified catalog through this interface before PIR startup when `OBLIVION_REGISTRY_ANCHOR_SOCKET` is configured.

**Tech Stack:** Rust, SQLite/rusqlite, Serde JSON over the existing Unix socket, Ed25519 catalog verification, Cargo tests.

**Spec:** [Registry activation design](../../REGISTRY_ACTIVATION.md), [external registry provisioning](../../EXTERNAL_REGISTRY.md), and the project requirement for signed registries, rollback handling, and a trusted local anchor.

## Global Constraints

- Preserve the current version-only API for existing consumers.
- Persist catalog version and digest atomically.
- Exact version/digest restart is idempotent; lower version and same-version/different-digest are rejected.
- Legacy version-only state is not retroactively claimed to authenticate a digest.
- Anchor unavailability, conflicts, and indeterminate commits fail closed before worker readiness.
- Do not claim rollback resistance against host-root restoration of the SQLite database.

## Review Focus

- A v1/v2 database migrates without losing its old version lower bound.
- A migrated null-digest row rejects same-version activation and permits a strictly newer catalog.
- A successful CAS followed by lost reply is reconciled by reloading exact version and digest.
- Concurrent activators cannot both advance from one expected state.
- Protocol clients reject malformed digest lengths and wrong protocol versions.

---

### Task 1: Digest-aware registry activation API

**Files:**
- Modify: `crates/oblivion-registry/src/lib.rs`
- Test: `crates/oblivion-registry/tests/registry.rs`

- [x] Write tests for exact restart, rollback, same-version equivocation, version advance, and legacy null-digest upgrade.
- [x] Run tests and confirm the new API is missing.
- [x] Implement `RegistryCatalogState`, `RegistryCatalogAnchor`, manifest digest retention, and `VerifiedRegistry::activate_catalog`.
- [x] Run all 7 registry integration tests and warning-denied registry Clippy.
- [ ] Commit this API slice.

### Task 2: Persistent local anchor and Unix protocol

**Files:**
- Modify: `crates/oblivion-anchor/src/lib.rs`
- Modify: `crates/oblivion-anchor/src/local.rs`
- Test: anchor unit, migration, socket, and process tests

- [ ] Write tests for digest CAS, restart, old-schema migration, conflicts, and malformed protocol requests.
- [ ] Run tests and confirm the catalog-anchor operations are missing.
- [ ] Add schema-v3 migration and transactional catalog state CAS.
- [ ] Add protocol load/CAS requests and the client adapter.
- [ ] Run anchor tests and warning-denied Clippy, then commit.

### Task 3: Activate catalogs before worker readiness

**Files:**
- Modify: `crates/oblivion-server/src/pipeline.rs`
- Modify: `crates/oblivion-server/tests/pipeline.rs`
- Modify: `README.md`, `docs/EXTERNAL_REGISTRY.md`, `docs/SECURITY_ASSUMPTIONS.md`, `docs/THREAT_MODEL.md`, and `docs/IMPLEMENTATION_STATUS.md`

- [ ] Write subprocess tests for first activation, same-catalog restart, and stale-catalog rejection before readiness.
- [ ] Run the new tests and confirm the worker does not yet use the anchor.
- [ ] Implement optional `OBLIVION_REGISTRY_ANCHOR_SOCKET` activation before PIR startup.
- [ ] Document the legacy upgrade rule, rollback boundary, and commands.
- [ ] Run formatting, warning-denied workspace Clippy, and serialized workspace tests; record timing-sensitive failures without changing budgets.
- [ ] Commit and push each independently tested slice.
