# Persistent SSE Anchor Service Design

## Intent

Connect the encrypted SSE client journal to the existing local `oblivion-anchor` service. This gives `PersistentClient` a concrete durable compare-and-swap anchor across application and service restarts, while preserving the generic `SseJournalAnchor` interface for other deployments.

## Goals and non-goals

- Provide a typed journal record containing a stable index ID, monotonically increasing generation, and record digest.
- Use one caller-supplied stable opaque slot per SSE index. The slot follows the anchor service's existing 1–128 character ASCII validation and is retained by the application across restarts; it is not derived from the index ID.
- Persist it with atomic compare-and-swap in the SQLite anchor service and expose it over the existing Unix socket boundary.
- Encrypt the index ID and digest at rest with a per-slot key HKDF-derived from the existing anchor database master key under a dedicated domain, AEAD, and a fresh OS-random nonce. Keep the generation visible for bounded, transactional CAS.
- Adapt the Unix client to `oblivion_sse::SseJournalAnchor` and verify a real persistent SSE operation through service restart.
- Preserve existing protocol-v2 clients and schema-v3 databases through additive protocol operations and an explicit schema migration.
- Do not promise protection against an operator or host root restoring an old anchor database, anchor-process compromise, or hardware rollback.

## Approaches considered

1. **Reuse the ORAM checkpoint anchor.** Rejected because it parses its handle as an ORAM checkpoint key and has incompatible record semantics.
2. **Reuse the registry catalog anchor.** Rejected because SSE state is not a registry catalog, it exposes a digest in the existing row, and it would conflate independent rollback domains.
3. **Add a dedicated journal-anchor record, SQLite slot, and Unix operations.** Selected because it keeps the persistence boundary typed, supports independent slots and explicit migration, and avoids changing existing checkpoint or registry behavior.

## Architecture

`oblivion-anchor` owns a `SseJournalState` value and a slot API. The application supplies and persists one validated opaque slot per index, with the same slot used after restart. The SQLite database stores one row per slot; generation is clear for CAS while index ID and digest are protected under a slot-specific AEAD key derived from the service master key. The initial journal checkpoint is generation 0 and is inserted only when the expected generation is `None`; every later transition must advance by exactly one and preserve the index ID. A transaction validates these conditions and atomically replaces the row. Indeterminate transaction results are reported distinctly from definite conflicts.

The Unix protocol adds journal load/CAS operations at protocol version 3 while retaining version 2 for existing operations. The service checks slot and record bounds, maps stale generations to conflict, and maps uncertain commits to commit-unknown. The public Unix client returns the typed state without exposing the database key.

`oblivion-sse` adds an adapter that maps service conflicts and commit-unknown results into `SseJournalAnchorError`. A real integration test runs the anchor service as a child process, performs journal-backed SSE operations, restarts the service, reopens the client, and verifies recovery and stale-writer rejection.

## Security boundaries and residual leakage

The anchor process receives index IDs, generations, and digests in its local protocol and can observe per-index persistence frequency. SQLite protects the ID and digest at rest, not while the trusted anchor process handles them. The per-slot key uses the service's existing master key, which must be preserved across restarts; changing it makes existing records unauthentic until a separately designed rekey procedure is implemented. Unix socket filesystem permissions authenticate local clients. This service is a separate process and database, not a TEE or hardware monotonic counter. Privileged rollback of the anchor database can roll back SSE state too; the service host and database backup policy remain trusted. The adapter does not make the SSE scheme backward-private or hide its normal search/update leakage.

## Validation

Tests cover schema-v3 migration, restart persistence, AEAD corruption and wrong-key rejection, slot isolation, invalid transitions, concurrent/stale CAS, protocol framing and error mapping, and an actual `PersistentClient` restart against a restarted anchor service. Existing anchor, SSE, and workspace checks are rerun as practical; workspace deadline flakes remain reported separately.
