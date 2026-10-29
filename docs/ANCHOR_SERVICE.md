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

## Independent mTLS witness for SSE, runtime catalog activation, and ORAM checkpoint anchoring

The `oblivion-anchor-remote` binary exposes SSE journal-head CAS,
digest-bound registry catalog activation CAS, and ORAM checkpoint load/CAS
through an authenticated TLS listener. It is intended to run under a separate
witness operator, with that operator's database and master key stored outside
the application host's administrative domain. Runtime workers can opt into
remote registry activation with the six environment settings described below.
The worker's durable ORAM checkpoint and invocation-receipt path still uses the
local service/API; remote checkpoint anchoring is currently an explicit
standalone adapter for callers of `PathOram::checkpoint_anchored`.

Start the witness with:

```sh
oblivion-anchor-remote serve \
  0.0.0.0:7443 witness.sqlite witness-master-key.bin \
  witness-cert.pem witness-key.pem client-ca.pem authorization-policy.json
```

The witness requires a version-1 certificate-to-slot authorization policy.
Fingerprint the complete DER leaf certificate with
`openssl x509 -in client-cert.pem -outform DER | sha256sum`, then place its
64-character lowercase SHA-256 digest and the exact allowed slot names in the
policy file:

```json
{
  "version": 1,
  "clients": [
    {
      "certificate_sha256": "<replace with the client's lowercase DER SHA-256>",
      "slots": ["sse-main-index", "function-registry", "oram-main"]
    }
  ]
}
```

Replace the fingerprint placeholder with exactly 64 lowercase hexadecimal
characters. Slot names contain 1–128 ASCII letters, digits, dots, underscores,
or hyphens. Each request is checked against both the mTLS-authenticated leaf
certificate and its exact requested slot before any anchor operation is
dispatched. An unlisted certificate or slot is denied by closing the connection;
the caller sees a transport failure. There are no wildcard grants. The JSON
schema rejects unknown fields, duplicate certificates, duplicate slots,
unsupported versions, empty policies, and malformed fingerprints. The policy is
loaded once at startup and capped at 1 MiB, so changes require a witness restart.
On Unix it must be a regular, non-symlink file that is not group- or
world-writable. Certificate rotation requires updating the fingerprint and
restarting the witness. The client CA still controls which certificates can
complete mTLS; the policy narrows those accepted certificates to slots.

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
client journal key, and client journal directory identity across restart.
`oblivion_anchor::TlsRegistryCatalogAnchor` implements
`oblivion_registry::RegistryCatalogAnchor`; pass it to
`VerifiedRegistry::activate_catalog` to anchor a signed catalog version and
digest. Reusing a version with a different digest is rejected by registry
activation, and the CAS rejects stale state. The runtime worker can construct
this adapter through the following settings:

| Setting | Meaning |
| --- | --- |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_ADDRESS` | Numeric `IP:PORT` for the witness, such as `127.0.0.1:7443` |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_SERVER_NAME` | TLS server name checked against the witness certificate |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_SLOT` | Validated catalog slot, commonly `runtime-functions` |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_CA_PEM` | PEM trust roots for authenticating the witness |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_CLIENT_CERT_PEM` | Worker client certificate chain |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_CLIENT_KEY_PEM` | Worker client private key |

All six settings are required together and cannot be combined with
`OBLIVION_REGISTRY_ANCHOR_SOCKET`. The worker also requires the external
`OBLIVION_REGISTRY_MANIFEST` and 32-byte pinned
`OBLIVION_REGISTRY_PUBLIC_KEY` files. Invalid or partial settings,
TLS/authentication failures,
witness unavailability, catalog rollback/equivocation, and indeterminate CAS
results prevent worker readiness; there is no local fallback or automatic
retry. The worker verifies the publisher signature and embedded module
bindings, then activates the catalog before announcing readiness. The network path is synchronous,
uses one bounded 512 KiB version-2 JSON frame per
connection, a five-second TCP connect timeout, and an absolute five-second
TLS/frame I/O deadline shared by reads and writes after connect/accept. The
deadline includes the TLS handshake, so byte trickling cannot reset it. The
single-process listener handles connections serially. It fails closed on authentication,
protocol, or availability errors and does not automatically retry an uncertain
CAS result.

Standalone registry activation uses the same mutual-TLS setup:

```rust,ignore
let tls = oblivion_anchor::mtls_client_config_from_pem(
    "witness-ca.pem",
    "oblivion-client-cert.pem",
    "oblivion-client-key.pem",
)?;
let mut catalog_anchor = oblivion_anchor::TlsRegistryCatalogAnchor::new(
    "witness.example:7443".parse()?,
    "witness.example",
    "function-catalog-slot",
    tls,
)?;
verified_catalog.activate_catalog(&mut catalog_anchor)?;
```

### Remote ORAM checkpoint anchor

`oblivion_anchor::TlsCheckpointAnchor` implements the store's
`CheckpointAnchor` trait. It can be passed directly to
`PathOram::checkpoint_anchored`; loading returns the current opaque snapshot
identifier and secret handle, and publishing uses the store's generation
compare-and-swap. For example:

```rust,ignore
let tls = oblivion_anchor::mtls_client_config_from_pem(
    "witness-ca.pem",
    "oblivion-client-cert.pem",
    "oblivion-client-key.pem",
)?;
let mut checkpoint_anchor = oblivion_anchor::TlsCheckpointAnchor::new(
    "witness.example:7443".parse()?,
    "witness.example",
    "oram-state-slot",
    tls,
)?;
oram.checkpoint_anchored(
    "snapshot-0001.bin",
    "snapshot-0001",
    &mut checkpoint_anchor,
)?;
```

The checkpoint request contains the snapshot identifier and the
`TrustedCheckpoint` secret handle encoded as exactly 176 lowercase ASCII hex
characters. The decoded handle is 88 bytes and includes the snapshot
decryption key, digest, size and generation. This fixed-width encoding keeps
the request length independent of the handle's byte values. TLS protects it from a network-only observer,
but the witness process receives the plaintext handle and can decrypt a
snapshot it can also access. The SQLite database encrypts the handle at rest
under the witness master key; this does not hide it from the witness operator
or a privileged witness host administrator. Use this adapter only when the
witness is trusted with ORAM snapshot confidentiality. The server and client
zeroize their application-owned handle fields and serialized frames on drop;
this is best-effort memory cleanup and does not establish erasure of copies
inside the TLS library, allocator, kernel or crash dumps.

The remote checkpoint CAS preserves the store contract: a definite stale
generation returns `AnchorConflict`; a reported uncertain database commit or
a lost/malformed response after request transmission returns
`AnchorCommitUnknown`, requiring restore/reconciliation before the controller
continues. A connection failure before sending returns a backend error. The
remote adapter has no local fallback. The checkpoint operation and fixed-width
hex handle encoding use protocol version 2; version-1 peers are rejected, so
both ends must run compatible version-2 binaries. The mTLS integration test checkpoints real ORAM data,
restarts the witness process, restores and reads the actual snapshot, advances
the checkpoint, and rejects a stale controller.

To anchor a restored application's freshness, keep the witness current while
restoring only the application-side journal. The regression test
`restored_application_journal_is_rejected_when_remote_witness_kept_newer_head`
exercises this case against the actual SQLite-backed service. The mTLS
integration test also activates a real signed catalog, rejects a stale CAS,
and checks the version/digest after witness-process restart. These tests do not
roll back the witness database.

## Trust limits

The Unix socket remains a trusted local service, not a remotely authenticated
network anchor. The mTLS witness is a separate trust domain, not a distributed
or rollback-proof service. The remote SSE and catalog adapters detect rollback
of the corresponding application-side journal or catalog state, and the
checkpoint adapter rejects stale snapshot handles, only while the
witness operator preserves the latest committed row, protects its master key
and database, and remains reachable. A witness administrator who restores an old SQLite image can roll
back the witness itself. The client and server CAs, certificate issuance,
private-key storage, witness host and service code are trusted. TLS protects
payloads in transit from a network observer but does not hide connection
endpoints, sizes, timing, or witness access patterns. Host root can still
inspect the local executor and client keys. The service has no quorum, no
hardware monotonic counter, and no Byzantine or crash-tolerant replication.
The configured client CA validates certificate issuance, while the loaded
fingerprint policy limits each accepted leaf certificate to named slots. The
policy is immutable for the life of the process. The service still has no
request quota or rate limit. Certificate issuance/rotation, remote availability,
backup/restore controls and a replicated register remain operator/research
responsibilities.

Checkpoint anchoring expands what must be trusted: the witness sees each
checkpoint slot, snapshot identifier, generation and 88-byte secret handle
inside the TLS endpoint. Since that handle contains the snapshot key, the
witness can decrypt an available snapshot. The certificate-to-slot policy is
checked before dispatch for SSE, registry and checkpoint operations. A
certificate holder can still read or mutate every slot granted to its
fingerprint; there is no quota, rate limit, automated revocation or hot policy
reload.

The optional durable worker mode uses the local Unix service for anchored
checkpoint recovery and signed invocation receipts. This does not prove the identity of a
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
Another process-level test checkpoints real Path ORAM state through the local
service, restarts it, and restores the snapshot. The remote mTLS test also
performs real ORAM checkpoint/restore and stale-writer rejection across witness
restart. The tests do not test power-loss
behavior of every filesystem or establish rollback resistance.
