# Durable invocation receipt design

## Intent

Add an anchor operation that lets a client retry an invocation after a
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
  error. The runtime's remote adapter confirms an ambiguous finish by exact
  response; local adapter callers can load the receipt.
- The local Unix socket remains protected by filesystem permissions. The
  anchor verifies signatures, but does not enforce a function-level
  authorization policy.

The anchor API provides this contract as `SignedInvocationId`,
`AnchorDatabase::{load_invocation_receipt, commit_invocation}`, and the local
`UnixInvocationAnchor` adapter. The remote `TlsInvocationAnchor` uses the mTLS
witness protocol and the same atomic SQLite receipt/checkpoint transaction.
The anchor API bounds response bytes to 64 KiB; the runtime fixes response
capacity at 80 bytes. Its SQLite schema migrates from version 1 to version 2.
The worker supports opt-in startup restore with either local or remote anchor
configuration; it validates the anchored snapshot ID, handle generation, and
snapshot file before restoring. After authenticating a request, the worker
loads its receipt before running the selected function. It then follows the
same `finish` exchange on a receipt hit or miss. A hit runs the reserved dummy
function, reuses the currently loaded checkpoint and secret handle, creates no
snapshot, and returns the exact stored fixed-size response. A miss runs the
request, writes a fresh encrypted whole-store checkpoint, and atomically
commits its secret handle and response at the anchor before publishing the
response. An indeterminate finish is resolved by exact-response confirmation;
if that fails, the worker exits without publishing an unconfirmed success. A
same-ID/different-digest conflict is rejected through the cover path.

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

In local mode, the worker obtains the cooperative
`UnixAnchorClient::invocation` lock for `server-state-v1` before loading the
current checkpoint or announcing readiness. Only one cooperating worker
process can own this local slot at a time; another fails startup before
readiness. The kernel releases the lock on process exit, so crash recovery can
start a new worker without stale-lock cleanup. The persistent mode-0600 lock
file is adjacent to the anchor socket; its parent directory must be writable
by the executor account and protected from untrusted replacement. This is a
same-host advisory lock, not a service protocol fence: direct protocol or
`AnchorDatabase` callers and separate hosts can bypass it. Remote mode has no
distributed lease. Checkpoint compare-and-swap rejects a stale publication,
but does not fence execution or provide multi-host recovery. Neither mode
makes arbitrary side effects transactional.

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

## Remote mTLS operation

Remote mode requires all six invocation mTLS settings below and
`OBLIVION_ANCHOR_STATE_DIR`. The settings are all-or-none, and the remote
configuration cannot be combined with `OBLIVION_ANCHOR_SOCKET`. Partial
configuration fails before worker readiness. There is no local fallback.

| Environment setting | Purpose |
| --- | --- |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_ADDRESS` | Numeric witness `SocketAddr`, including a nonzero port. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_SERVER_NAME` | TLS server name used to verify the witness certificate. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_SLOT` | Exact witness slot requested by this worker. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_CA_PEM` | PEM trust roots for the witness certificate. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_CLIENT_CERT_PEM` | Client certificate presented for mutual TLS. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_CLIENT_KEY_PEM` | Matching client private key; existing PEM permission checks apply. |
| `OBLIVION_ANCHOR_STATE_DIR` | Local directory for encrypted executor snapshots and state files. |

The witness must be started with a certificate-to-slot policy granting the
worker's leaf-certificate fingerprint access to the configured slot. The
witness validates the client certificate chain and then enforces that exact
slot grant. Policy changes require a witness restart. Every checkpoint handle
contains the snapshot encryption key, and the witness receives that handle in
the TLS payload. The witness is therefore trusted with snapshot confidentiality
and can decrypt snapshots it can access.

The runtime uses the v3 fixed-width invocation exchange with an 80-byte
response capacity. For each authenticated request it performs `load` followed
by the same `finish` action whether a receipt exists or not. On a miss, finish
atomically commits the checkpoint pointer and exact response. On a hit, the
worker reuses the current checkpoint (which may be newer than the replayed
receipt), creates no snapshot, and idempotent finish returns the stored
response. An ambiguous finish uses the explicit exact-response `confirm`
action. The client does not automatically retry a mutation or use another
anchor after a failure.

The witness sees the mTLS client identity, slot, signed invocation identifier
and request digest, response bytes, checkpoint handle, and timing. The finish
request contents let it distinguish receipt hits from misses. TLS hides those
fields from a passive network observer, who still sees endpoints, connection
timing, fixed-capacity frame sizes, cadence, and failures. Snapshot files
remain on the executor host; the witness stores only receipts and checkpoint
records. It is a single SQLite operator: database rollback, compromise, loss,
or unavailability defeats freshness or availability. The runtime does not get
a distributed writer lease, multi-host fencing, snapshot replication, or host
failover.

Example worker configuration (certificate and policy provisioning are
deployment-specific):

```sh
OBLIVION_INVOCATION_ANCHOR_MTLS_ADDRESS=127.0.0.1:9443 \
OBLIVION_INVOCATION_ANCHOR_MTLS_SERVER_NAME=anchor.example.test \
OBLIVION_INVOCATION_ANCHOR_MTLS_SLOT=server-state-v1 \
OBLIVION_INVOCATION_ANCHOR_MTLS_CA_PEM=/etc/oblivion/client-ca.pem \
OBLIVION_INVOCATION_ANCHOR_MTLS_CLIENT_CERT_PEM=/etc/oblivion/worker-client.pem \
OBLIVION_INVOCATION_ANCHOR_MTLS_CLIENT_KEY_PEM=/etc/oblivion/worker-client-key.pem \
OBLIVION_ANCHOR_STATE_DIR=/var/lib/oblivion/executor-state \
oblivion-server demo /var/lib/oblivion/runs/run-001 100 1
```

## Scope limits

This makes checkpointed ORAM state and the receipt atomic at the SQLite anchor;
it does not provide exactly-once behavior for arbitrary external side effects.
The runtime must persist/fsync a snapshot before asking the anchor to commit
its pointer and receipt. The local worker API serializes cooperating worker
processes for a state slot before execution. Remote mode has no corresponding
distributed lock. Raw protocol clients, direct database users, or separate
hosts are outside the local lock's scope and must serialize writers
themselves; checkpoint CAS remains the final stale-writer check.

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
and invalid signature behavior across the versioned local protocol. Remote
mTLS tests cover exact certificate-slot authorization, replay and witness
restart. The current lost-finish transport test disconnects after the peer
reads the request; it does not simulate a committed SQLite transaction whose
reply is then dropped. A commit-then-drop integration fault test remains open.
Documentation must retain the single-writer, rollback, host-root, unverified
request-digest, and external-side-effect limitations.
