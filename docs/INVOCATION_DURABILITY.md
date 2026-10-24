# Durable invocation receipt design

## Intent

Add a local anchor operation that lets a client retry an invocation after a
lost response without silently applying a second state transition. The
operation binds a client-signed stable invocation ID and request digest to a
checkpoint generation and the exact fixed-shape response bytes.

## Contract

- The client identity is an Ed25519 public key. The client signs a
  domain-separated tuple of protocol version, 16-byte invocation ID, and
  32-byte request digest. This proves control of that key for the identifier
  and request; it does not authorize the key to invoke a function.
- The anchor derives an opaque keyed lookup token from the client key and
  invocation ID. It stores the request digest, checkpoint snapshot/generation,
  and response bytes in an AEAD-protected receipt.
- A first commit uses one SQLite `IMMEDIATE` transaction to compare-and-swap
  the checkpoint and insert the receipt. Both become visible together or
  neither does.
- A retry with the same signed ID and request digest returns the stored
  response receipt. Reusing an ID with a different request digest is a
  conflict. A commit with a stale checkpoint generation is also a conflict.
- An indeterminate transaction result is resolved by loading the receipt by
  the signed ID. Clients must not infer commit or non-commit from a transport
  error.
- The local Unix socket remains protected by filesystem permissions. The
  anchor verifies signatures, but does not enforce a function-level
  authorization policy.

## Scope limits

This makes checkpointed ORAM state and the receipt atomic at the SQLite anchor;
it does not provide exactly-once behavior for arbitrary external side effects.
The runtime must persist/fsync a snapshot before asking the anchor to commit
its pointer and receipt. A loser in a concurrent execution can receive a CAS
conflict, but the design does not prevent both executions from running before
that conflict; callers must serialize a given invocation and state slot.

The SQLite database can still be rolled back from an old backup, and host root
can inspect or replace it. The local service is not a TEE and does not protect
against host-root compromise. Request signatures authenticate stable
idempotency identity, not function input confidentiality or runtime
attestation. Receipt responses are bounded to a documented maximum.

## Acceptance

Tests must show signature rejection, correct first commit, exact response
recovery after reopening the database, idempotent replay, request-digest
conflict, checkpoint-generation conflict, and atomicity when either write
fails. The Unix service tests must exercise the same behavior across the
versioned local protocol. Documentation must retain the single-writer,
rollback, host-root, and external-side-effect limitations.
