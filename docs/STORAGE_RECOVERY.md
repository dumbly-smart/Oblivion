# ORAM checkpoints and recovery

`FileBackend` provides real bounded bucket storage, and `PathOram::checkpoint`
provides a durable authenticated snapshot containing both encrypted buckets and
the trusted controller state needed to recover them. A bucket file alone cannot
be reopened as a valid controller. Freshness requires the latest checkpoint
handle from independently protected trusted storage.

## APIs

- `FileBackend::create(path, &config)` creates a new fixed-size ciphertext file
  and rejects existing paths. `open(path, &config)` validates its exact size.
  Bucket reads and writes validate the index and fixed length before allocation
  or I/O. `sync_all()` explicitly flushes the working bucket file.
- `PathOram::checkpoint(path)` scans and authenticates every bucket, verifies
  placement/uniqueness and controller bounds, encrypts the complete image, and
  atomically publishes it. It returns `TrustedCheckpoint` after the snapshot
  file and its containing directory have both been synchronized.
- `PathOram::checkpoint_anchored(path, anchor)` reads the current secret anchor,
  rejects a handle whose generation differs from this controller, publishes a
  checkpoint, then asks the adapter to atomically compare-and-swap to the new
  handle. Use a new immutable snapshot path for each generation. A failed
  definite CAS leaves an unanchored snapshot that can be discarded; the live
  controller generation remains retryable. The `CheckpointAnchor` trait is an
  integration contract, not an anchor implementation. Its backend must provide
  durable rollback-resistant secret storage, per-store identity binding, and
  unambiguous atomic CAS results. If a remote operation has an ambiguous result,
  reload and reconcile the anchor before any retry or acknowledgment.
- `PathOram::restore(path, &trusted_checkpoint, backend)` requires an external
  trusted handle, checks exact length/digest/version/generation, authenticates
  the snapshot, validates its geometry and controller state, authenticates all
  buckets and verifies placement, uniqueness and nonce bounds. Only then does
  it populate the supplied backend and return a controller. Backend write
  failure returns an error and no controller; discard that partial backend and
  retry from the same authenticated snapshot into a fresh backend.
- `TrustedCheckpoint::generation()` and `snapshot_digest()` expose public
  identifiers. `to_secret_bytes()` exports an 88 byte **secret** handle into a
  zeroizing buffer; `from_secret_bytes(bytes)` imports it with fixed length and
  size bounds. Handle Debug is redacted. Do not log exported bytes.

Normal `PathOram::new`, `read`, `write`, `config` and backend access interfaces
remain compatible. A normal successful write updates the live store; it does
**not** promise persistence across a controller crash. Only an externally
published checkpoint establishes a recoverable point. Existing poisoned
controllers cannot checkpoint; recover from an earlier trusted checkpoint.

## Cryptography and nonce lifetime

Each checkpoint attempt generates a fresh OS random 256 bit key and uses
RustCrypto ChaCha20Poly1305 once with the all-zero 96 bit nonce. No public API
accepts a reusable snapshot encryption key. A failed attempt discards its key;
retrying generates a different key. The trusted handle holds this key, an exact
snapshot length, SHA-256 digest and generation. The snapshot header is 32 bytes:
`OBLSNAP1`, little endian u64 generation, u64 plaintext length, eight reserved
zero bytes. The whole header is authenticated as associated data; the encrypted
body ends with its 16 byte authentication tag.

The encrypted body contains configuration, bucket AEAD key, next nonce,
per-bucket versions, position map, stash contents and maximum stash size,
followed by all encrypted buckets. Bucket nonces must have their prescribed
zero prefix, be unique within the tree, and be below the saved next nonce.
Versions and bucket addresses remain bound by each bucket's AEAD.

Recovery always generates a **new bucket key** and re-encrypts the complete tree
before returning a controller. It preserves versions, position map, stash and
logical contents. The new key starts a new nonce domain with sequential nonces;
the original key is used only for decryption during recovery. This is necessary
because the pre-crash controller may have written under the old key after its
last checkpoint. Simply restoring an old next-nonce counter would reuse nonces.
Repeated recovery from a valid handle also gets fresh keys. OS entropy and
single-owner controller execution are required; restoring live controller RAM
snapshots while retaining keys/counters is outside this model.

## Publication and crash ordering

Checkpoint publication writes a randomly named temporary file in the target
directory, calls file `fsync`, renames it onto the requested path, then calls
containing-directory `fsync`. Temporary files are removed on errors before
rename. On Unix they are created with mode 0600. Filesystem support for durable
rename and file/directory synchronization is required. This is a local file
protocol, not a transaction across an external trusted anchor service.

An application that needs to acknowledge durable operations must implement this
ordering (the anchored helper covers only snapshot/handle publication):

1. Finish the writes and checkpoint into a **new, unique snapshot path**. Retain
   the prior snapshot and its trusted handle until the transition commits.
2. Durably and atomically publish the new handle and snapshot identifier to an
   external trusted storage/anchor service, using serialization or compare and
   swap to enforce one owner and the latest generation.
3. Acknowledge those operations only after that trusted publication succeeds.
   Older snapshots may then be retired according to the application's policy.

A crash before step 2 leaves the previous trusted checkpoint authoritative;
unacknowledged writes can be lost. A crash after step 2 recovers the new image.
An uncertain anchor publication requires querying that trusted service before
further acknowledgement or recovery. The library intentionally supplies no
anchor service or acknowledge-after-checkpoint wrapper. A local counter or file
next to the snapshots remains rollbackable and cannot serve as the external
trust anchor.

If rename succeeds but directory synchronization fails, checkpoint returns an
error and no new handle. The target image may have changed despite that error.
If an application overwrites its only snapshot before publishing its new handle,
a crash or anchor failure can leave an image/handle mismatch that **fails
closed** and cannot recover that image. New immutable snapshot names and
retaining the prior checkpoint avoid losing the last committed recovery point.
The caller must never silently choose an older handle when the latest anchor
and snapshot disagree.

Supplying the latest trusted handle rejects older, mixed, partial, modified or
truncated snapshots, including otherwise valid older ciphertext. **Rolling back
both the trusted handle and snapshot is not solved.** Preventing that requires
hardware monotonic state or an external service that resists rollback. AEAD
alone establishes authenticity, not freshness. Storing the secret handle next
to the snapshot in the same untrusted filesystem provides no rollback resistance.
The generation is checked against the trusted handle; it is not itself a
monotonic hardware counter.

## Bounds, overhead and leakage

The complete encrypted checkpoint is limited to 256 MiB, including header,
controller metadata and bucket ciphertext. Configurations near the separate
256 MiB bucket-storage cap may therefore be unable to checkpoint. A size failure
occurs before allocating the complete image. Working bucket files also obey
validated Config bounds; snapshots with a mismatched or excessive file length
are rejected before their payload allocation. Restore decodes only authenticated
and bounded dimensions and validates the entire state before backend mutation.

Checkpoint performs a full-tree read, snapshot encryption and full-image file
write. Recovery reads/authenticates the complete image and original tree, then
re-encrypts and writes the complete tree. Both are intentionally observable
maintenance phases and must be excluded from normal invocation trace claims.
They are linear in tree size and are synchronous; no latency bound is claimed.
Full-image buffers, validation maps, stashes and an optional memory backend can
consume several times the checkpoint size in RAM. This prototype favors clear
atomic recovery boundaries over incremental checkpoint efficiency.

Untrusted storage can still deny availability. These APIs do not provide remote
attestation, process isolation, multi-writer coordination, transactional external
side effects, exactly-once invocation acknowledgements, or a hardware TEE.
