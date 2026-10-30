# Runtime signed registry over PIR

## Flow

The local executor worker creates a fresh OS-random Ed25519 key at startup,
signs the five fixed deployment records and manifest, then verifies the
complete encoded catalog with the corresponding public key. It exports the
verified records as fixed 160-byte rows to two independently spawned
`secure-pir-worker` processes. The inherited stdin bootstrap uses the versioned
`OBLPIR01` header and checks dimensions before allocating the record array.

For each invocation, the executor creates the two XOR-PIR shares, queries each
worker over its authenticated TCP session and recovers one row. It accepts a
result only if the full row is byte-for-byte equal to the corresponding
record from the already verified local catalog. Per-record signatures are
verified once during catalog validation at startup; per-query exact comparison
uses that verified pin. This avoids repeating public-key verification on every
invocation while preserving rejection of changed or misindexed responses.
Only then does the executor select the preloaded module.

The private executor trace records returned row width and separate PIR and
local pin-check durations. These fields are internal instrumentation; they
are not part of the modeled network observer.

## Scope and limits

- The two PIR workers run on one host. Process separation does not establish
  non-collusion; if they collude, they recover the selected record.
- The executor generates the signing key itself. This checks the registry
  implementation and composes signed records with PIR, but it does not prove
  who published a deployment or provide production signing-key custody.
- The demo uses registry version 1 without a persistent monotonic version
  anchor, so rollback across restarts is not prevented.
- Module-location digests are synthetic descriptors for embedded modules.
  Encrypted module-location storage and retrieval are not implemented.
- The generic legacy `pir-worker` command keeps its 128-byte synthetic rows;
  the end-to-end runtime uses `secure-pir-worker` with signed 160-byte rows.
- A normal process is not a TEE. A host administrator can inspect executor
  memory, its ephemeral signing key, and inherited pipes.

## Verification

Run the focused tests with:

```sh
cargo test -p oblivion-server --bin oblivion-server -- --test-threads=1
cargo test -p oblivion-server --test pipeline sse_metadata_discovery_precedes_real_mixed_invocation -- --test-threads=1
```

The integration test exercises the actual executor and two child PIR workers,
checks all five signed record identities and rejects tampered/misindexed rows.
