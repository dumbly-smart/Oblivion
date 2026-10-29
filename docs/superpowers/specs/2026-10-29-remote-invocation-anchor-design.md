# Remote durable invocation design

## Intent

Allow the Unix runtime worker to keep its existing crash-recovery and
idempotent-retry behavior while storing the authoritative checkpoint handle
and signed invocation receipt in the independent mTLS witness. The current
worker commits those two records atomically through SQLite. Sending a
checkpoint through `TlsCheckpointAnchor` and a receipt through a second API
would split that transaction and is not an acceptable design.

## Goals

- Keep checkpoint advancement and receipt creation in one
  `AnchorDatabase::commit_invocation` transaction.
- Let the runtime use either its existing local Unix anchor or one remote mTLS
  witness, with fail-closed startup and no silent local fallback.
- Preserve exact replay responses after restart and reconcile an ambiguous
  commit by loading the receipt.
- Give the mTLS network observer equal request and response lengths for
  receipt hits and misses at a configured public response capacity.
- Keep the executor's snapshot directory and ORAM data handling unchanged.
- Test the actual witness, worker, client, durable snapshot, restart, and
  replay path.

## Non-goals

- Replicating the witness or protecting it from rollback, compromise, root, or
  operator inspection.
- Moving snapshots to a remote object store, enabling host failover, or
  claiming a cross-host lease. Snapshot files remain in the configured local
  state directory.
- Making arbitrary external effects exactly once. WASM guests still have no
  external side-effect API; this transaction covers only the saved ORAM
  snapshot handle and response receipt.
- Hiding request timing, the connection schedule, success versus error
  behavior, or anchor-operation metadata from the witness or every network
  observer.
- Adding automatic client certificate revocation, quotas, or rate limits.

## Approaches considered

1. **Use `TlsCheckpointAnchor` from the runtime and keep receipts local.**
   This makes checkpoint and receipt publication non-atomic. A crash can leave
   one updated without the other, breaking replay semantics. Rejected.
2. **Add a remote invocation transaction to the existing witness.** The client
   sends a signed invocation, expected generation, fixed response, and optional
   next checkpoint record. The witness uses the existing atomic database
   method. This preserves local semantics and reuses mTLS, authorization, and
   freshness assumptions. **Chosen.**
3. **Add a distributed lock service or replicated quorum register first.**
   That would require a separate protocol and failure model, and still would
   not move snapshot files. It is outside this integration's scope.

## Architecture and interface

The remote anchor protocol advances to version 3. It adds a fixed-structure
invocation exchange with three actions: load a receipt, commit a new
checkpoint/receipt pair, and confirm an already-loaded receipt on replay.
The commit action delegates to `AnchorDatabase::commit_invocation`, which
authenticates the signed identity, enforces the expected generation, and
atomically stores the encrypted checkpoint handle and response receipt. The
confirm action reads the receipt and requires the exact response bytes to
match; it does not advance the checkpoint.

Invocation wire fields use fixed-width lowercase hex for keys, IDs, digests,
signatures, checkpoint handles, snapshot IDs, and response bytes. Decimal
lengths and generations use fixed-width strings. The client declares a
response capacity from 1 byte through `MAX_INVOCATION_RESPONSE_BYTES`; the
request and response carry that many response bytes, padded with zeroes, plus
the actual length. Thus receipt presence does not change frame size for one
configured capacity. The runtime uses its fixed 80-byte response capacity.
The witness returns one fixed-shape invocation result for hit, miss, and
protocol-level operation statuses. Timing, connection visibility, and failure
behavior remain observable.

The public `TlsInvocationAnchor` provides `load`, `commit`, and `confirm` and
also supplies the checkpoint load operation needed during runtime restore.
The server's authorization policy grants the runtime certificate the
configured exact state slot in addition to mTLS CA validation. The existing
local Unix configuration remains supported. Runtime durable mode requires
`OBLIVION_ANCHOR_STATE_DIR` plus exactly one anchor selection:

- Local: `OBLIVION_ANCHOR_SOCKET`.
- Remote: `OBLIVION_INVOCATION_ANCHOR_MTLS_ADDRESS`,
  `..._SERVER_NAME`, `..._SLOT`, `..._CA_PEM`,
  `..._CLIENT_CERT_PEM`, and `..._CLIENT_KEY_PEM`.

Partial remote configuration and simultaneous local/remote durable anchors
fail before worker readiness. Remote credentials use the existing PEM
validation and permissions checks. No fallback is allowed.

For every valid durable invocation the worker loads the receipt, performs the
same executor/PIR/storage schedule, then sends exactly one finish exchange:
new invocations commit a new checkpoint and response; receipt hits confirm
the saved response without creating another snapshot. A commit whose reply is
lost is reconciled by loading the receipt and comparing the exact response.
The remote witness is trusted with the checkpoint secret handle and can decrypt
available snapshots. The state directory still needs trusted custody and
backup. A separate host cannot restore unless it has the referenced snapshot;
remote CAS rejects a stale generation but is not a distributed lock or
failover mechanism.

## Security and leakage limits

- The witness sees client identity, slot, invocation identifiers, signed
  request digest, response bytes, checkpoint generation, snapshot ID, and
  secret handle. It is trusted with snapshot confidentiality and receipt
  processing.
- An external network observer sees peers, timing, number of exchanges,
  configured capacity, frame lengths, retries, and failures. Fixed lengths do
  not imply constant-time service or hide operation timing.
- A lost or malformed reply after sending is indeterminate. The worker must
  reconcile through receipt load or stop; it must not fall back locally.
- A witness rollback defeats remote freshness. The local snapshot directory
  does not become rollback resistant merely because the handle is remote.
- Remote CAS provides one winning generation transition, not an execution
  lease. No guarantee is made for deployments that share snapshot storage with
  uncoordinated writers or expose external side effects.

## Acceptance evidence

- Load miss and hit have equal serialized response lengths at equal capacity.
- New commit, exact duplicate commit, response mismatch, stale generation,
  invalid signature, malformed fixed-width fields, too-small capacity, and
  oversized frames have explicit outcomes.
- A runtime test creates a real signed request, persists an actual ORAM state
  change and response through the remote witness, restarts both worker and
  witness while retaining witness state, replays the request byte-for-byte,
  then performs a new invocation and verifies recovered user state.
- Partial and conflicting environment configurations fail before readiness;
  witness outage and ambiguous commit fail closed.
- Existing local durable tests continue to pass.
