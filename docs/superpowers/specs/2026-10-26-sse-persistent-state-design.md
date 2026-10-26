# Persistent SSE Client State Design

## Intent

Add an opt-in way to restart an SSE client without losing keyword counters or
the exact bytes of an update whose acknowledgment may have been lost. This
supports applications that need durable update retries while preserving the
existing ephemeral `Client` API.

## Goals

- Persist client keys, keyword counters, limits, and pending update state only
  in authenticated encrypted journal records.
- Recover by replaying a bounded tail after a complete encrypted checkpoint.
- Select each new generation with an independent, atomic compare-and-swap
  anchor. A stale generation, altered record, wrong key, or lost anchor must
  fail closed.
- Allow multiple processes to open the same state, while ensuring only one
  writer can publish a mutation for a given anchor generation.
- Keep the anchor interface small enough for a separate trusted anchor service
  to implement.

## Non-goals

- This increment will not claim a Unix anchor-service adapter or hardware
  rollback resistance. The caller must provide a durable, rollback-resistant
  anchor whose administrative trust boundary is independent of journal files.
- It will not protect state while the trusted client process is running, hide
  SSE leakage, implement backward privacy, or make the Diana-inspired design a
  theorem-backed Diana implementation.
- Multiwriter execution is optimistic generation compare-and-swap, not a lease
  or distributed transaction spanning the remote SSE server.

## Approaches

1. Serialize plaintext client state: small implementation, but exposes keys and
   keywords in backups and temporary files. Rejected.
2. Encrypt one full snapshot for every mutation: simple recovery, but write
   amplification grows with the index size. Rejected as the primary format.
3. Use an encrypted append-only event journal with periodic encrypted state
   checkpoints, plus an external digest-and-generation CAS anchor. Chosen
   because it keeps ordinary mutations small, bounds recovery replay, and
   detects rollback when the external anchor remains trusted.

## Design decisions

- Add `PersistentClient<A: SseJournalAnchor>` in a focused `journal.rs` module.
- A journal starts with an encrypted full-state checkpoint. Each subsequent
  mutation writes an immutable encrypted event record containing its sequence
  number and previous-record digest. Every 256 mutations, write a full-state
  checkpoint instead of an event.
- Use ChaCha20-Poly1305 with an OS-random 96-bit nonce, HKDF domain separation
  by index ID, and a versioned associated-data prefix.
- Fsync each new record and its containing directory before asking the anchor
  to advance. The anchor record binds the index ID, generation, and SHA-256
  digest of the selected record.
- On anchor conflict or indeterminate commit, poison the local client and
  require reopening. Do not return a prepared request unless its pending state
  is anchored.
- Use a private directory, content-addressed immutable files, bounded record
  sizes, and bounded replay. Older files are garbage-collectable only after a
  new checkpoint is committed.

## Acceptance checks

- Reopening after a prepared update returns byte-identical retry material.
- Reopening after an acknowledged update preserves search results.
- Restoring an older file, corrupting a record, using the wrong key, exceeding
  replay bounds, or racing two writers fails closed.
- Existing ephemeral SSE tests and the crate's test/lint gates remain green.

## Residual boundary

The journal's confidentiality and rollback detection depend on the caller's
key custody and external anchor. A file-based anchor stored beside the journal
does not satisfy the rollback assumption. A concrete adapter for the existing
separate anchor service remains a subsequent integration task.
