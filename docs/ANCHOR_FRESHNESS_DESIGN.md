# Independent anchor witness design

## Purpose

Persistent Oblivion state is encrypted and authenticated, but a valid old
SQLite snapshot can still be restored by an administrator with access to the
host that stores it. This design adds an independently administered witness
for the freshness head. The application can then detect rollback of its own
local database, provided the witness keeps its committed state and remains
reachable.

The current service supports standalone remote adapters for the persistent SSE
journal head, digest-bound signed-registry catalog activation, and Path ORAM
checkpoint freshness. The runtime worker can use the remote catalog adapter
through explicit mutually exclusive configuration alongside the local Unix
adapter. Its durable checkpoint and invocation-receipt path still uses the
local service. Remote invocation receipts are not included.

## Approaches considered

1. **Another local file, counter, or SQLite table.** Simple, but the same
   privileged host can roll it back with the application database. Rejected as
   a mitigation for host-administrator rollback.
2. **A distributed rollback-resistant register.** This can avoid a single
   witness trust root, but needs a precise replica fault model, quorum protocol,
   recovery algorithm, key provisioning, and adversarial schedule testing.
   TEE-Rex is recent work on a correct rollback-resistant register under
   explicit dynamic failure models; this prototype will not claim to implement
   that algorithm. [TEE-Rex / DISC 2025](https://drops.dagstuhl.de/storage/00lipics/lipics-vol356-disc2025/html/LIPIcs.DISC.2025.39/LIPIcs.DISC.2025.39.html)
3. **An independent authenticated witness service.** A separate operator owns
   the witness process, its database, and its backup/restore policy. This is
   the selected engineering step: it has a narrow contract and can be
   exercised against the existing SQLite compare-and-swap implementation.
   It adds an explicit trust assumption rather than pretending ordinary
   software can make its own local state rollback-proof.

ROTE also realizes rollback protection using cooperating SGX enclaves, while
Nimble uses a TEE-backed append-only ledger with crash-fault-tolerant storage.
Neither construction is reproduced here. [ROTE / USENIX Security 2017](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/matetic), [Nimble / OSDI 2023](https://www.usenix.org/conference/osdi23/presentation/angel)

## Trust and failure model

The application host, its local storage, and the network are adversarial. The
application process may be restarted and its local database restored from an
older snapshot. The witness is in a separate administrative domain and is
trusted to authenticate clients, perform the documented atomic CAS, preserve
accepted state across restart, and not restore an older database. The client
trusts a configured certificate authority for the witness and the witness
trusts a configured CA for Oblivion clients. The service has no per-client
identity mapping or per-slot ACL: every certificate chaining to that CA can
load or update any syntactically valid slot. The configured client CA is the
entire authorization boundary in this prototype.

The witness operator, its host administrator, its signing keys, its durable
storage, certificate issuance, and client credential provisioning are inside
the trusted boundary. For checkpoint requests, this specifically includes
confidentiality of ORAM snapshot contents: the witness receives the plaintext
88-byte secret handle containing the snapshot key and can decrypt a snapshot
it can access. The versioned JSON wire encodes that handle as a fixed-width
176-character hex string, so the serialized frame length does not depend on
secret byte values. Its SQLite copy encrypts the handle at rest under the witness
master key, but this does not hide the key from the witness process/operator.
Application-owned wire state and JSON frame buffers are zeroized on drop as
best-effort cleanup; TLS-library, allocator, kernel and crash-dump copies are
outside that claim. The network may observe packet lengths and timing,
delay or drop connections, and inject, replay, or alter bytes. TLS protects
application payload confidentiality and integrity and authenticates both
peers. Connection failure is an availability failure: the client must stop
the protected update rather than continue without an anchor decision.

This design does not protect against a malicious or rolled-back witness,
compromise of either endpoint, certificate/key theft, witness unavailability,
or rollback of unanchored state. It is not a TEE, a replicated service, a
formal proof, or a production audit.

## Protocol and state transition

Each TLS connection carries one bounded, versioned JSON request and one
bounded response. Each operation is bound to a stable configured slot. SSE
requests load the current index identifier, generation, and journal digest,
or atomically advance an empty slot to generation `0` or generation `g` to
`g + 1` while preserving the index identifier. Registry requests load the
current version and optional catalog digest, or compare-and-swap from the
expected state to a strictly newer version and its signed-catalog digest.
Checkpoint requests load a snapshot identifier and secret handle, or atomically
compare-and-swap to a consecutive checkpoint generation. The decoded handle is
88 bytes and includes the generation, snapshot size, digest and snapshot
decryption key; the JSON field carries a fixed-width 176-character hex string.
All operations delegate to the corresponding SQLite CAS.

The client authenticates the witness certificate against configured roots and
presents a client certificate accepted by the witness. There is no plaintext
fallback and no custom transport cryptography. A TLS or protocol failure maps
to a fail-closed error at the adapter. A CAS conflict remains a conflict. An
uncertain database commit remains an indeterminate commit, which requires
caller reconciliation; it is never silently retried as though it were known
not to have committed.

Each remote adapter implements its existing component trait; no search/update,
registry-signing or local Unix behavior changes. A checkpoint connection
failure before request transmission is a definite backend failure. A failed
write after transmission begins or a missing/malformed response is treated as
`AnchorCommitUnknown`, because the commit may already have occurred. The client
does not retry automatically: repeating a mutation after a transport failure
could obscure whether the witness committed it. Both peer binaries must
understand protocol version 2 to use checkpoint anchoring and its fixed-width
hex handle encoding; version-1 peers are rejected rather than silently
downgraded.

## Observable behavior

The network observer learns when anchor operations happen, peer network
addresses, connection timing, record counts, and approximate TLS record
sizes. The observer cannot read the slot, index identifier, digest, generation,
snapshot identifier, secret handle, or operation kind from the protected
application payload under the TLS assumption. This does not conceal which
client connects or when, nor does it hide witness-side access timing from the
witness operator. The witness itself sees the slot, snapshot identifier,
generation and secret handle for checkpoint operations and can derive the
snapshot key from that handle.

## Acceptance tests

- An mTLS client reads an empty slot, commits its first head, reloads it, and
  rejects a stale compare-and-swap.
- A client that does not chain to the configured client CA is rejected.
- A client that does not trust the witness CA is rejected.
- A slow-drip client cannot extend the absolute connection I/O deadline by
  sending a frame in small pieces.
- A TLS peer cannot substitute or corrupt a framed request and receive a valid
  anchor response.
- The remote adapter's `SseJournalAnchor` operations round-trip through the
  actual SQLite database, including ordinary witness-process restart.
- A signed registry activates through `TlsRegistryCatalogAnchor`; digest and
  version survive witness restart and stale CAS writers are rejected.
- `PathOram::checkpoint_anchored` uses `TlsCheckpointAnchor` to publish a real
  encrypted snapshot, restores its real blocks after witness restart, advances
  the checkpoint, and rejects a stale restored controller.
- A catalog CAS with an unavailable witness returns an indeterminate result so
  the caller reloads and reconciles instead of retrying blindly.
- A demonstration restoring the application-side journal while retaining the
  witness head fails closed. Restoring the witness database is documented as
  outside the guarantee.

## Implementation limits

The service is synchronous and serial at the witness listener, suitable
for local research and low-rate anchoring. It has a five-second TCP connect
timeout and an absolute five-second TLS/frame I/O deadline shared by reads
and writes after connect/accept, plus bounded frames. Byte trickling cannot
reset the absolute I/O budget. It does not provide load balancing, quorum
replication, per-client or per-slot authorization, request quotas, rate
limiting, automated certificate issuance/rotation, remote deployment
automation, or a benchmarked multi-host service. Production certificate and
key provisioning remain operator responsibilities; do not reuse a broad
client CA for unrelated workloads.
