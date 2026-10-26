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
handle generation, and snapshot file before restoring. After authenticating a
request, the worker looks up its receipt before running the selected function.
A hit runs the reserved dummy function and returns the exact stored fixed-size
response. A miss runs the request, writes a fresh encrypted whole-store
checkpoint, and atomically commits its secret handle and response at the
anchor before publishing the response. An indeterminate commit is resolved by
looking up the receipt; if that fails, the worker exits without publishing an
uncommitted success. A same-ID/different-digest conflict is rejected through
the cover path.

The worker reconstructs Path ORAM into its instrumented in-memory bucket
backend from the encrypted whole-store snapshot. This retains the existing
storage trace instrumentation and gives process-restart recovery, but does not
provide a continuously persistent bucket-file service. Snapshot writes and
full-tree recovery are visible in size and timing. In durable mode, new
invocations add a full-tree snapshot read to the ORAM trace; receipt hits run
the cover path without another checkpoint. The anchor operator can distinguish
receipt lookup from receipt commit, and the protocol does not claim to hide
retry status from that operator. After publishing a checkpoint/receipt, the
worker keeps only the snapshot named by the current checkpoint anchor and
fsyncs the snapshot directory after deleting obsolete `*.snapshot` files.
Startup recovery also prunes old snapshots before readiness, which cleans up
files left by a crash after anchor commit. Older receipt rows retain their
response bytes and do not require their historical snapshots. A cleanup error
after commit prevents response publication; the client can retry from the
durable receipt after storage is repaired. There is a crash window between
anchor commit and cleanup in which stale encrypted snapshots can remain until
the next startup.

The worker obtains the cooperative `UnixAnchorClient::invocation` lock for
`server-state-v1` before loading the current checkpoint or announcing
readiness. Only one cooperating worker process can own this local slot at a
time; another fails startup before readiness. The kernel releases the lock on
process exit, so crash recovery can start a new worker without stale-lock
cleanup. The persistent mode-0600 lock file is adjacent to the anchor socket;
its parent directory must be writable by the executor account and protected
from untrusted replacement. This is a same-host advisory lock, not a service
protocol fence: direct protocol or `AnchorDatabase` callers and separate hosts
can bypass it. It does not make arbitrary side effects transactional.

The built-in demo generates ephemeral signing keys and random IDs per run.
Applications that need retries across process/session restarts must retain the
same client signing key and invocation ID and resubmit the same canonical
request. The Unix anchor socket must be readable only by the trusted executor
account, while the anchor master key stays in a separate 32-byte file with
mode 0600. Environment variables select the socket and state directory; they
do not provision or authenticate the anchor master key.

## Local operation

Create a separate executor snapshot directory and anchor database/key paths.
Keep the master-key file outside the database directory and restrict it to the
anchor service account:

```sh
oblivion-anchor serve /run/oblivion/anchor.sock /var/lib/oblivion-anchor/state.sqlite /etc/oblivion-anchor/master.key 0600
OBLIVION_ANCHOR_SOCKET=/run/oblivion/anchor.sock \
OBLIVION_ANCHOR_STATE_DIR=/var/lib/oblivion/executor-state \
oblivion-server demo /var/lib/oblivion/runs/run-001 100 1
```

The socket parent must exist before the anchor starts. The executor creates
and restricts its state directory to mode 0700. The example uses one local OS
account; a split-account deployment needs an explicitly group-readable socket
and compatible directory ownership. The current demo creates a new signing
key and invocation IDs per run, so rerunning that exact command demonstrates
checkpoint recovery but does not retry an earlier ID. A retry-capable client
must persist its Ed25519 key and invocation ID and recreate the same canonical
request bytes.

## Scope limits

This makes checkpointed ORAM state and the receipt atomic at the SQLite anchor;
it does not provide exactly-once behavior for arbitrary external side effects.
The runtime must persist/fsync a snapshot before asking the anchor to commit
its pointer and receipt. The local worker API serializes cooperating worker
processes for a state slot before execution. Raw protocol clients, direct
database users, or separate hosts are outside this lock's scope and must
serialize writers themselves; checkpoint CAS remains the final stale-writer
check.

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
