# Durable anchor services

`oblivion-anchor` provides SQLite-backed implementations of the store's
`CheckpointAnchor`, registry's version-only `RegistryVersionAnchor`, and
digest-bound `RegistryCatalogAnchor` contracts, plus a separate local service
process over a versioned Unix-domain socket. The service
can hold the database and master key under its own OS account while the
executor uses socket client adapters. Each anchor has a validated opaque slot
name. Updates use SQLite `IMMEDIATE` transactions, compare the caller's
expected generation/version, and commit with `synchronous=FULL`. Concurrent
compare-and-swap callers cannot both publish the same generation.

The database schema is versioned with SQLite `user_version`. New databases use
schema 3. Migrations from schemas 1 and 2 copy existing version-only registry
rows into the digest-backed catalog table with a null digest; those rows remain
rollback floors and require a strictly newer catalog to initialize a trusted
content digest. Unknown versions are rejected without changing the database.
The Unix socket protocol is version 2 and adds catalog state load/CAS requests.

If SQLite reports an error while committing an anchor update, the adapter
returns an explicit indeterminate-commit error because it cannot safely infer
whether the transaction became durable. Path ORAM poisons that controller and
requires restore from the latest anchor; registry callers must reload the
current state before another activation attempt. Pre-commit validation and
conflict errors remain definite non-commits.

Checkpoint secret handles are encrypted with ChaCha20-Poly1305. HKDF-SHA-256
derives separate keys for checkpoint slots; associated data binds each handle
to its slot, snapshot identifier, and generation. Fresh nonces come from the
operating-system CSPRNG and are reserved in a unique database table before
encryption, so failed CAS attempts burn their nonce. Catalog versions and
content digests are integrity metadata, not secret payloads.

The caller supplies a zeroizing 32-byte master key when opening the database.
It must come from a separate trusted secret source, such as a service secret
manager, and must not be stored with the database. The CLI opens the raw key
file without following symlinks or blocking on special files, validates the
opened descriptor is a regular file with no group/world permissions, and
accepts exactly 32 bytes; the service zeroizes its in-memory key. The local
service rejects database symlinks and special files, then restricts the SQLite
database file to mode `0600` before binding its socket. The database parent
directory must be trusted to prevent path replacement during startup.
Deployments must also restrict database backup access.

## Local service protocol

The `oblivion-anchor` binary accepts:

```sh
oblivion-anchor serve SOCKET DATABASE MASTER_KEY_FILE [0600|0660]
```

Socket mode `0600` restricts access to the service account. Mode `0660` also
allows members of the socket's preconfigured group. The socket's parent
directory and group configuration must be controlled by the service operator.
Existing socket paths are not removed automatically; verify the prior service
has stopped before cleaning a stale path.

Each connection carries one length-prefixed JSON request, limited to 512 KiB.
Requests and responses use protocol version 2, strict operation/status tags,
validated slots, and a five-second read/write timeout. The client exposes
checkpoint, version-only registry, digest-backed catalog, and invocation
adapters. CAS methods classify a lost or malformed response after sending as
an indeterminate commit and require caller reconciliation.

The cooperating `UnixAnchorClient::invocation` adapter takes a nonblocking OS
file lock for its slot and holds it until the adapter is dropped or its process
exits. The persistent empty lock file is named by appending
`.<slot>.writer-lock` to the socket path, uses mode `0600`, and is opened with
no-follow and close-on-exec flags. This allows one durable worker per slot
through the local client API. The socket parent directory must be writable by
the executor account and controlled by trusted operators; do not remove or
replace a live lock file. Raw protocol clients and direct `AnchorDatabase`
callers can bypass this cooperative lock, so they remain trusted components.
The lock does not coordinate separate hosts or remote anchor services.

## Independent mTLS witness for persistent SSE

The `oblivion-anchor-remote` binary exposes the SSE journal-head CAS through
an authenticated TLS listener. It is intended to run under a separate witness
operator, with that operator's database and master key stored outside the
application host's administrative domain. The service accepts only the SSE
load and compare-and-swap contract; registry activation, ORAM checkpoints,
and invocation receipts still use the local service/API.

Start the witness with:

```sh
oblivion-anchor-remote serve \
  0.0.0.0:7443 witness.sqlite witness-master-key.bin \
  witness-cert.pem witness-key.pem client-ca.pem
```

The master key is exactly 32 raw bytes in a regular file with mode `0600` on
Unix. The witness private TLS key must also be a regular non-symlink file with
no group/world permissions. The server certificate must chain to a CA trusted
by the client, and the client certificate must chain to a CA trusted by the
witness. Provision certificates and private keys through an authenticated
operator channel; this prototype does not issue or rotate them.

The Rust client setup is explicit:

```rust,ignore
let tls = oblivion_anchor::mtls_client_config_from_pem(
    "witness-ca.pem",
    "oblivion-client-cert.pem",
    "oblivion-client-key.pem",
)?;
let anchor = oblivion_anchor::TlsSseJournalAnchor::new(
    "witness.example:7443".parse()?,
    "witness.example",
    "stable-sse-index-slot",
    tls,
)?;
```

`oblivion-sse` implements its `SseJournalAnchor` trait for this client, so a
standalone `PersistentClient` can use the remote witness without changing its
encrypted local journal format. The application must preserve the same slot,
client journal key, and client journal directory identity across restart. The
network path is synchronous, uses one bounded 512 KiB version-1 JSON frame per
connection, a five-second TCP connect timeout, and an absolute five-second
TLS/frame I/O deadline shared by reads and writes after connect/accept. The
deadline includes the TLS handshake, so byte trickling cannot reset it. The
single-process listener handles connections serially. It fails closed on authentication,
protocol, or availability errors and does not automatically retry an uncertain
CAS result.

To anchor a restored application's freshness, keep the witness current while
restoring only the application-side journal. The regression test
`restored_application_journal_is_rejected_when_remote_witness_kept_newer_head`
exercises this case against the actual SQLite-backed service. The test does
not roll back the witness database.

## Trust limits

The Unix socket remains a trusted local service, not a remotely authenticated
network anchor. The mTLS witness is a separate trust domain, not a distributed
or rollback-proof service. The SSE remote adapter detects rollback of the
application host's database only while the witness operator preserves the
latest committed row, protects its master key and database, and remains
reachable. A witness administrator who restores an old SQLite image can roll
back the witness itself. The client and server CAs, certificate issuance,
private-key storage, witness host and service code are trusted. TLS protects
payloads in transit from a network observer but does not hide connection
endpoints, sizes, timing, or witness access patterns. Host root can still
inspect the local executor and client keys. The service has no quorum, no
hardware monotonic counter, and no Byzantine or crash-tolerant replication.
Any client certificate chaining to the configured client CA can access any
valid slot: there is no per-certificate slot authorization, quota, or rate
limit. The configured CA and network policy therefore define the complete
client authorization boundary. Production key provisioning, certificate rotation, remote availability,
backup/restore controls and a replicated register remain open.

The optional durable worker mode uses this service for anchored checkpoint
recovery and signed invocation receipts. This does not prove the identity of a
registry publisher: the runtime registry signer is ephemeral, and publisher
key custody remains a separate concern.

Run its adapter tests with:

```sh
cargo test -p oblivion-anchor -- --test-threads=1
```

The tests cover persistence across reopen, encrypted handle storage, wrong-key
and ciphertext rejection, namespaced registry versions and catalog digests,
stale CAS rejection, schema migration, competing checkpoint writers, real Path
ORAM checkpoint/restore and stale writer rejection, and signed registry
activation through persistent version adapters. A database-copy rollback
control demonstrates the residual rollback. Local RPC tests exercise version,
digest-backed catalog, and checkpoint requests and fail-closed transport
errors. CLI integration tests run the service as a separate process, check
socket and database permissions, exercise persistent registry version and
catalog CAS, and reject invalid key-file permissions/lengths, symlink key and
database paths.
Another process-level test checkpoints real Path ORAM state through the service,
restarts the service, and restores the snapshot through the durable checkpoint
adapter. The tests do not test power-loss
behavior of every filesystem or establish rollback resistance.
