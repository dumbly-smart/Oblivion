# Local durable anchor service

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

## Trust limits

This is a trusted local service, not a remotely authenticated network anchor.
The Unix socket limits clients through OS filesystem permissions, while a
host administrator can still inspect the service process, key and socket
traffic. The SQLite database operator and master-key source must be trusted
separately from the ORAM snapshot and registry publication path. SQLite
transactions provide atomic updates and process-crash durability; they do not
provide a hardware monotonic counter. An operator or attacker able to restore
an older database image can roll back both version state and checkpoint
handles. A remote authenticated protocol, production key provisioning,
backup/restore policy, and an anti-rollback source remain open under the
project's untrusted-storage threat model.

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
