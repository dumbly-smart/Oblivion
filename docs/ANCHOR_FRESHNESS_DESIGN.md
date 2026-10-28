# Independent anchor witness design

## Purpose

Persistent Oblivion state is encrypted and authenticated, but a valid old
SQLite snapshot can still be restored by an administrator with access to the
host that stores it. This design adds an independently administered witness
for the freshness head. The application can then detect rollback of its own
local database, provided the witness keeps its committed state and remains
reachable.

The first target is the persistent SSE journal head. The same transport may
later carry catalog, ORAM checkpoint, and invocation-receipt anchors, but those
interfaces are not included in this first version.

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
the trusted boundary. The network may observe packet lengths and timing,
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
bounded response. The client opens a stable configured slot and requests
either the current state or an atomic transition from an empty slot to genesis
generation `0`, or from expected generation `g` to `g + 1`. The request includes the SSE index identifier and the digest
of the authenticated journal head. The service binds the slot to the index
identifier and delegates the transition to the existing SQLite CAS.

The client authenticates the witness certificate against configured roots and
presents a client certificate accepted by the witness. There is no plaintext
fallback and no custom transport cryptography. A TLS or protocol failure maps
to anchor unavailability. A CAS conflict remains a conflict. An uncertain
database commit remains an indeterminate commit, which requires caller
reconciliation; it is never silently retried as though it were known not to
have committed.

The adapter implements only the existing SSE anchor trait. Search/update
behavior, encrypted journal contents, and local Unix service behavior do not
change. It does not add retry logic: repeating a mutation after a transport
failure could obscure whether the witness committed it.

## Observable behavior

The network observer learns when anchor operations happen, peer network
addresses, connection timing, record counts, and approximate TLS record
sizes. The observer cannot read the slot, index identifier, digest, generation,
or operation kind from the protected application payload under the TLS
assumption. This does not conceal which client connects or when, nor does it
hide witness-side access timing from the witness operator.

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
- A demonstration restoring the application-side journal while retaining the
  witness head fails closed. Restoring the witness database is documented as
  outside the guarantee.

## Implementation limits

The first version is synchronous and serial at the witness listener, suitable
for local research and low-rate anchoring. It has a five-second TCP connect
timeout and an absolute five-second TLS/frame I/O deadline shared by reads
and writes after connect/accept, plus bounded frames. Byte trickling cannot
reset the absolute I/O budget. It does not provide load balancing, quorum
replication, per-client or per-slot authorization, request quotas, rate
limiting, automated certificate issuance/rotation, remote deployment
automation, or a benchmarked multi-host service. Production certificate and
key provisioning remain operator responsibilities; do not reuse a broad
client CA for unrelated workloads.
