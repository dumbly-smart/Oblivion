# Durable registry catalog activation

## Goal

Protect external publisher-signed runtime catalogs from rollback while allowing
the exact same catalog to be loaded after a normal worker restart. The local
anchor must bind a monotonically increasing catalog version to the manifest
content digest in one compare-and-swap operation.

## Approaches

1. **Version only, with immutable-version publisher policy.** Idempotent
   same-version startup is simple but the anchor cannot detect two different
   catalogs signed under the same version. This is insufficient for the
   project's explicit rollback and integrity goals.
2. **Version plus content digest in the anchor.** The anchor accepts an exact
   same-version/same-digest restart, rejects same-version equivocation and
   older versions, and atomically advances to a newer signed catalog. This is
   selected. It requires an anchor schema migration and a new local protocol
   request pair.
3. **Require a remote registry transparency service.** This can add
   independently operated witnesses and publication proofs, but no such
   service or remote authenticated transport exists in this prototype.

## State and migration

Keep the existing version-only API for compatibility with its tests and
callers. Add a catalog activation API whose state is `(version, optional
digest)`. Schema v3 creates a digest-backed table and copies old version-only
rows with a null digest. A migrated null-digest row remains a lower bound: the
same version cannot start in digest-backed mode, but a strictly newer signed
catalog can atomically establish its digest. This avoids treating a legacy
version-only state as if it authenticated content.

For digest-backed rows, activation is idempotent only when both version and
digest match. Lower versions fail as rollback; the same version with a
different digest fails as equivocation; higher versions use a CAS against the
full previously loaded state. Unknown commit outcomes are reported for caller
reconciliation and never treated as success without a reload.

## Runtime policy

`OBLIVION_REGISTRY_ANCHOR_SOCKET` optionally enables activation for an external
signed catalog through the local Unix service. Alternatively, configure all six
`OBLIVION_REGISTRY_ANCHOR_MTLS_*` settings documented in
[ANCHOR_SERVICE.md](ANCHOR_SERVICE.md) to use the independent witness. The local
and remote modes are mutually exclusive, and either mode requires the manifest
and pinned public key. Activation completes before PIR workers start or
readiness is published. With neither anchor configured, the worker still
verifies signatures and embedded-module digests but provides no catalog-version
rollback protection. Local SQLite can be inspected or rolled back by a host
administrator; a remote witness protects freshness only while its independent
operator preserves its current database. Neither mode provides hardware
monotonicity.
