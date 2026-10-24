# Durable anchor adapter

`oblivion-anchor` provides SQLite-backed implementations of the store's
`CheckpointAnchor` and the registry's `RegistryVersionAnchor` contracts. Each
anchor has a validated opaque slot name. Updates use SQLite `IMMEDIATE`
transactions, compare the caller's expected generation/version, and commit
with `synchronous=FULL`. Concurrent compare-and-swap callers cannot both
publish the same generation.

The database schema is versioned with SQLite `user_version`. A new database
is initialized transactionally as schema 1; unknown versions are rejected
without changing the database. Future schema changes need an explicit
migration.

If SQLite reports an error while committing an anchor update, the adapter
returns an explicit indeterminate-commit error because it cannot safely infer
whether the transaction became durable. Path ORAM poisons that controller and
requires restore from the latest anchor; registry callers must reload the
current version before another activation attempt. Pre-commit validation and
conflict errors remain definite non-commits.

Checkpoint secret handles are encrypted with ChaCha20-Poly1305. HKDF-SHA-256
derives separate keys for checkpoint slots; associated data binds each handle
to its slot, snapshot identifier, and generation. Fresh nonces come from the
operating-system CSPRNG and are reserved in a unique database table before
encryption, so failed CAS attempts burn their nonce. Registry versions contain
no secret payload.

The caller supplies a zeroizing 32-byte master key when opening the database. It must
come from a separate trusted secret source, such as a service secret manager,
and must not be stored with the database. The adapter zeroizes its in-memory
key. Deployments must also restrict database file and backup access.

## Trust limits

This is a durable local adapter, not a remotely authenticated anchor service.
The SQLite database operator and master-key source must be trusted separately
from the ORAM snapshot and registry publication path. SQLite transactions
provide atomic updates and process-crash durability; they do not provide a
hardware monotonic counter. An operator or attacker able to restore an older
database image can roll back both version state and checkpoint handles. A
separate service process, authenticated remote protocol, key provisioning,
backup/restore policy, and an anti-rollback source remain to be implemented
before deployment under the project's untrusted-storage threat model.

The adapter does not prove the identity of a registry publisher. Registry
signature verification and publisher-key custody remain separate concerns.
The demo does not yet use this adapter: its runtime registry signer is
ephemeral, and its ORAM is not restored from persistent checkpoints.

Run its adapter tests with:

```sh
cargo test -p oblivion-anchor -- --test-threads=1
```

The tests cover persistence across reopen, encrypted handle storage, wrong-key
and ciphertext rejection, namespaced registry versions, stale CAS rejection,
competing checkpoint writers, real Path ORAM checkpoint/restore and stale
writer rejection, and signed registry activation through the persistent
version adapter. A database-copy rollback control demonstrates the residual
rollback. The tests do not test power-loss behavior of every filesystem or
establish rollback resistance.
