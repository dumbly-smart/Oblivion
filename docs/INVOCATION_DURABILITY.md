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

The anchor API provides this contract as `SignedInvocationId`,
`AnchorDatabase::{load_invocation_receipt, commit_invocation}`, and the local
`UnixInvocationAnchor` adapter. Its SQLite schema migrates from version 1 to
version 2, and response bytes are bounded to 64 KiB. The worker now supports
opt-in startup restore when both `OBLIVION_ANCHOR_SOCKET` and
`OBLIVION_ANCHOR_STATE_DIR` are set; it validates the anchored snapshot ID,
handle generation, and snapshot file before restoring. Request receipt lookup
and commit after invocation remain to be integrated. Before committing, the
trusted executor must recompute the signed request digest from its canonical
authenticated request and serialize the associated state slot.

The worker reconstructs Path ORAM into its instrumented in-memory bucket
backend from the encrypted whole-store snapshot. This retains the existing
storage trace instrumentation and gives process-restart recovery, but does not
provide a continuously persistent bucket-file service. Snapshot writes and
full-tree recovery are visible in size and timing.

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
attestation. The signer identity is not authorized by an application policy.
Receipt responses are bounded to 64 KiB; callers must supply the already
fixed-shape executor response.

## Acceptance

Tests must show signature rejection, correct first commit, exact response
recovery after reopening the database, idempotent replay, request-digest
conflict, checkpoint-generation conflict, atomic rollback when either SQL
insert fails, response confidentiality at rest, and the version-1 to version-2
schema migration. The Unix service tests must exercise signed lookup, commit,
and invalid signature behavior across the versioned local protocol.
Documentation must retain the single-writer, rollback, host-root, unverified
request-digest, and external-side-effect limitations.
