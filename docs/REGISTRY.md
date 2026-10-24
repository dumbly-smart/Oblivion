# Signed registry records

`oblivion-registry` provides a fixed-format Ed25519 registry representation.
`Record::sign` authenticates a function ID, registry version, module digest,
encrypted-location digest, and resource class. `SignedRegistry::sign` validates
all records, requires unique increasing IDs and one version, hashes the ordered
records, and signs a catalog manifest. `VerifiedRegistry::verify` checks the
manifest signature, exact encoded length, record count bound, catalog digest,
record signatures, record order, and version consistency before exposing a
lookup API.

The wire format is a 124-byte manifest header followed by 160-byte records.
Records are suitable as fixed-size PIR values. Callers must compare the recovered
record ID with their requested function ID and check the module digest against
the module they load. The location digest is an authenticated identifier; this
crate does not fetch or encrypt modules.

To accept a new signed catalog, first call `VerifiedRegistry::verify` with a
verifying key provisioned through an authenticated trusted channel. Then call
`activate` with a `RegistryVersionAnchor` adapter that atomically advances a
durable, rollback-resistant version. A signature authenticates old catalogs as
well as new ones; the external anchor is what rejects rollback. An anchor error
must distinguish definite non-commit from an ambiguous result, and the caller
must reconcile ambiguous results before retrying.

This crate does not manage signing-key custody, key rotation, threshold
approval, remote publication, module fetching, or a monotonic anchor service.
The current `oblivion-server` demo still uses immutable compile-time deployment
pins; it does not yet route runtime PIR responses through this registry crate.
It also does not provide a Merkle inclusion-proof protocol for clients that
receive only one record instead of verifying the complete catalog.

Ed25519 operations use RustCrypto's `ed25519-dalek`; verification calls its
strict verification method. See the [crate API documentation](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/).
