# Oblivion, explained

This is the detailed orientation and walkthrough for the repository. It explains the intent, request flow, components, messages, trust assumptions, experiments, and limits using the implementation that exists in this checkout. It is a guide, not a replacement for the precise [threat model](docs/THREAT_MODEL.md), [protocol specification](docs/PROTOCOL.md), [security assumptions](docs/SECURITY_ASSUMPTIONS.md), component designs, or source code. Follow those links whenever a security or wire-level detail matters.

## 1. The problem the project studies

Serverless function execution is often described as a function receiving input and returning output. The infrastructure around that computation can expose much more: which function was selected, when it ran, how often it ran, which state locations it accessed, how large requests and responses were, whether an instance was cold, how much work the host performed, and how traffic changes over time.

Encryption protects message contents in transit or stored bytes against parties without the key. By itself it does not hide packet length, arrival time, repetition, storage locations, queue behavior, or machine activity. Oblivion combines mechanisms that target different observable channels, then tests whether an attacker can still infer workload properties and measures the overhead that those mechanisms add.

The project is explicitly empirical and experimental. A cryptographic construction can support a precise claim under its formal assumptions. An attack study can report what a specified classifier inferred from a specified set of observations. An engineering mechanism such as padding or fixed-rate batching can make some messages more regular under operational assumptions. Those are different kinds of evidence and are not interchangeable.

## 2. Primary specification and current scope

The complete roadmap in [Oblivion Research Roadmap and Build Plan](Oblivion_%20Research%20Roadmap%20and%20Build%20Plan%20%281%29.md) is the primary specification. The [requirements matrix](docs/REQUIREMENTS_MATRIX.md) maps its items to implementation/evidence and marks remaining work. The prototype has a working local process path and many retained measurements, but the entire research program and production deployment are not complete.

The original layered design is:

1. **Forward-private searchable encryption (SSE):** hide stored index contents while supporting updates/search, subject to stated leakage.
2. **Oblivious storage (Path ORAM):** make the server access tree paths rather than the application's logical address.
3. **Private function discovery (PIR):** let a client recover one registry record without exposing its index to either single PIR server.
4. **Bounded WASM execution:** validate and execute functions with fixed interface shapes and fuel/resource bounds.
5. **Epoch batching and dummy traffic:** regularize request schedules and include cover work.
6. **Privacy-aware scaling:** study how resource-count decisions reveal demand; the existing implementation is a simulator.
7. **Leakage measurement:** build controls, attacks, and analysis over server-visible traces.

These layers are complementary but do not automatically compose into whole-system indistinguishability. For example, ORAM affects storage traces but does not hide cold starts; PIR masks a selected row from one server but the trusted executor sees the row; padding standardizes a response representation but not every internal runtime cost.

## 3. Threat model and trust boundaries

### 3.1 Adopted model

The implementation follows **Threat Model A: TrustedExecutor; untrusted storage, network, and scheduler**. The client and executor are treated as trusted. Storage, communications and scheduling are observable or controlled by an adversary. The prototype simulates the boundary with operating-system process isolation and a Wasmtime sandbox.

This is an assumption, not hardware protection. A privileged host operator can inspect either process's memory, keys, plaintext, selected registry row, labels if mounted there, and internal timing. There is no TEE, remote attestation, secure boot, enclave runtime, or hardware anti-rollback proof in this repository. Wasmtime limits guest capabilities; it does not keep the host from reading its own memory and does not make guest code constant-time.

### 3.2 Adversary knowledge and observation

The adversary is assumed to know the implementation, cryptographic algorithms, public parameters, message formats, and defense configuration. Depending on the experiment, observations include some subset of:

- request/response size and time;
- epoch and public slot cadence;
- storage physical bucket, ORAM leaf, operation direction, or byte count;
- individual PIR server query share, local scan timing, and frame metadata;
- visible batch arrivals, output timing, and queue effects;
- instance count and scaling/cold-start events in a simulator;
- failures, availability, deadlines, and partial storage traces.

Experiments define an exact attacker view. They must not quietly provide the target label or private runtime fields to a classifier. Public parameters such as cadence and ORAM geometry may be supplied when the study declares them as attacker knowledge.

### 3.3 PIR non-collusion

The XOR PIR implementation uses two servers. The client sends a uniformly random bit-selection vector to server 1 and that same vector XOR the target one-hot vector to server 2. Each individual share is distributed independently of the requested index. If the servers combine their shares, they recover the target vector and the privacy property fails. Two local worker processes on one machine are a test topology, not evidence of organizational non-collusion.

### 3.4 Assets and residual exposure

Important assets include client secrets, invocation plaintext, function catalog and selection, WASM inputs/outputs, persistent state, ORAM controller map/stash/keys, PIR session keys, SSE client state and keys, anchor secrets, user identities, and experiment labels. Different components protect different assets. The executor must see invocation data and function code to execute them; ORAM does not hide data from that trusted executor.

Residual leakage includes public schedules, timing and scheduling noise, host resource behavior, request participation, module work variation, error/deadline events, authenticated metadata, ORAM controller computation and stash behavior inside the trusted domain, failure traces, the existence of checkpoint maintenance, SSE equality/result volumes, and any observation not represented by a tested defense. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for formal leakage-function notation and documented attacks/non-goals.

## 4. End-to-end invocation, one step at a time

The relevant source responsibilities are in `crates/oblivion-server`, `crates/oblivion-batcher`, `crates/oblivion-pir`, `crates/oblivion-registry`, `crates/oblivion-exec`, and `crates/oblivion-store`. The diagram is in [ARCHITECTURE.md](ARCHITECTURE.md); the exact versioned protocol fields are in [docs/PROTOCOL.md](docs/PROTOCOL.md).

### Step 1: Startup and function catalog

The server loads and validates bundled WASM modules before accepting work. Each function has a registry row describing an ID/version, module digest, location digest, and resource class. The runtime can use an external publisher-signed catalog plus a separately provisioned pinned Ed25519 public key. It verifies the signature and checks that the records match the actual embedded modules before worker readiness.

Each registry row is exactly 160 bytes, including its signature. The offline signed-catalog format has a 124-byte manifest header followed by fixed-size records. The external catalog key must arrive through an independently authenticated deployment channel; a valid signature alone does not prove who owns the key. The example's module-location digest is synthetic; module retrieval from a remote encrypted object store is not implemented. With no external catalog settings, a development-only ephemeral signer is available. See [registry runtime](docs/REGISTRY_RUNTIME.md) and [external provisioning](docs/EXTERNAL_REGISTRY.md).

### Step 2: Client request envelope

The current invocation protocol documents a 228-byte authenticated envelope: a 20-byte public header, 192 bytes of ciphertext, and a 16-byte authentication tag. The header carries a magic/version, direction, epoch, and participant slot. It is authenticated as AEAD associated data. The nonce is derived from slot and epoch; it is not sent as a separate field. HKDF-SHA256 separates request and response keys from a fresh operating-system-random session root. Epochs must increase, and a channel's keys/state must not be cloned or restored to reuse a nonce.

Inside the request ciphertext, the payload contains the real/dummy indicator, registry index, fixed 64-byte input, invocation ID, Ed25519 public key and signature, plus reserved zero bytes. The request signature binds a domain-separated digest of the canonical request fields to the participant slot. The server first authenticates the envelope, then verifies the signature and canonical fields. An invalid request is routed through the fixed-shape cover path. The real/dummy field is encrypted from a network observer, but the trusted executor necessarily learns what work it will perform.

Some older experiment reports refer to 164-byte envelopes or earlier execution schedules. These are historical formats for those captured binaries, not the current protocol. Never combine their measurements with v2 without an explicit compatibility analysis.

### Step 3: Epoch queue and batching

The batcher collects fixed-shape participant envelopes for an epoch. It has bounded queues and backpressure behavior. Dummy requests are designed to take a downstream cover path with equivalent observable processing shape; they are not simply discarded at the edge and then counted as end-to-end privacy. The local demo uses fixed periods, a bounded number of clients, and sequential slot execution.

The demo's real/dummy/function schedule is deterministic and public from the source, configured percentage, and epoch. That makes the demo a correctness and topology exercise, not an anonymity experiment against an attacker that knows the schedule. Research workloads may keep the seed and truth labels private relative to a declared attacker, but must make that boundary explicit.

The demo runs eight epochs, with a 150 ms period per enrolled participant, and a 100 ms execution-class target. A public slot order and resource class are visible. These configured deadlines do not force a process to run at an exact time: scheduler jitter, overloaded cores, synchronous work, and host wake-up delay can cause lateness.

### Step 4: Private registry lookup

After epoch release, the executor (on behalf of the trusted side of the protocol) performs two-server XOR PIR. For a database with `n` records and requested index `i`, it samples random vector `S` of length `n`; server 1 receives `S`, and server 2 receives `S XOR e_i`. Each server scans the database and XORs all records selected by its share. XORing the two answers cancels `S` and yields record `i`.

The database records have equal width. Query and response shapes are determined by public database geometry, not by `i`. The basic server computation is linear in the database size; this implementation does not claim sublinear computation. The authenticated generic transport binds geometry, slot, sequence, and epoch and encrypts each link with independently derived directional keys. It does not make a malicious PIR server return a correct answer. The executor checks the recovered record byte-for-byte against its locally pinned signed catalog before dispatch. A party that sees both query shares can recover `i`.

The separate generic transport supports bounded larger geometries, including the studied 10,000 records × 1 KiB. The runtime demo uses five 160-byte function records and a small padded query. Do not confuse the generic PIR benchmark's 1 KiB records with the separate genuine SimplePIR reference comparison, which uses 8-byte records. Full protocol details and failure bounds are in [docs/PIR_TRANSPORT.md](docs/PIR_TRANSPORT.md) and [docs/PROTOCOL.md](docs/PROTOCOL.md).

### Step 5: WASM execution

The executor validates each module and runs it with Wasmtime. The guest ABI exports linear memory and an `invoke(input_ptr, input_len, output_ptr, capacity)` function returning the number of output bytes. WASI is not provided. A function's public execution class defines its input/output limits, fuel budget, memory/table/instance bounds, host-call budget, and deadline.

The repository includes five actual example functions with different computational behavior. The protected path uses fixed-size buffers and returns a fixed-size class response, with uniform external error framing for invalid input, guest traps, fuel exhaustion, and related failures. Internal status remains private to the trusted side and to separately stored private instrumentation.

Fuel is a count of metered WASM work. It is not wall-clock time. It does not automatically count all runtime, operating-system, or host-function work, and a timer cannot make scheduling, caches, or machine execution constant-time. The executor sets a public response target and records missed deadlines. These mechanisms bound and regularize specific behaviors; they do not guarantee exact-time execution.

### Step 6: Bounded state access through Path ORAM

The host gives a WASM guest a restricted key-value-like state interface. In the protected schedule, guest operations use a staged snapshot rather than directly causing an arbitrary number of backend operations. The current public working-set size is eight blocks. At a public read phase the executor reads all eight blocks into trusted staging memory. At a later public commit phase it writes all eight blocks back. Successful guest work commits the staged state. On a guest trap, invalid input, or fuel failure, guest modifications are discarded and the original snapshot is written back. On a successful backend path, stateful and non-stateful functions perform the same scheduled read/write counts.

Path ORAM maps each logical block to a leaf in a binary tree. The client-side trusted controller keeps a position map, encryption keys, nonce counters, and a stash of blocks temporarily outside buckets. A logical read/write obtains the current leaf, reads every encrypted bucket on the path, removes the target block into trusted state, assigns the block a new random leaf, and evicts blocks back into buckets subject to path-placement invariants. A write changes the block contents before the same remap/eviction process. Empty slots are fixed-size dummy entries. The storage backend sees complete encrypted buckets rather than a logical address.

The default bucket capacity is `Z=4`. Bucket payloads have fixed size for a configuration. AEAD binds the physical bucket index and trusted version, so relocation/substitution and corruption are authenticated. A live trusted per-bucket version vector detects stale bucket replay in the current controller. AEAD by itself would only prove that old ciphertext was authentic; it would not prove that it was fresh. The controller serializes accesses and can be poisoned after uncertain failures; separate controllers cannot safely share one live tree.

For a tree with `N` logical blocks, the number of leaves is the next power of two at least `N`; total binary buckets are `2*leaves - 1`. A root-to-leaf path contains `log2(leaves)+1` buckets. One logical access reads and then writes the whole path. For an 8-block tree, capacity 4, and 64-byte values, each bucket holds four slots, each slot being an 8-byte logical ID plus 64 data bytes. The encrypted representation adds a 12-byte nonce and 16-byte tag, yielding `12 + 4*(8+64) + 16 = 316` bytes. Each logical access therefore emits eight bucket backend events (four reads and four writes). Sixteen logical operations yield 128 events. These are backend payload/event counts, not a measured remote RPC/network protocol.

ORAM hides the logical address in its access pattern under the construction's assumptions, but the Rust position map/stash code is not constant-time. The experiment may additionally observe random leaf values and backend-handler timing. Failure paths can produce shorter traces; they are not silently declared indistinguishable. See [storage details](docs/ARCHITECTURE.md) and [storage recovery](docs/STORAGE_RECOVERY.md).

### Step 7: Fixed response and publication

The runtime returns the fixed payload through the authenticated response direction. The result's class width and external envelope size are fixed. Internal success/failure details are encrypted. The client checks the matching epoch and independently verifies expected function outputs/state counters in the demo.

The process prepares response encryption and instrumentation, then waits for its public publication target. It records private lateness and work diagnostics, but no timer can force the kernel or a shared machine to publish at an exact instant. Network delivery, queue arrival, load, CPU/cache behavior, backend errors, and later client processing may still differ.

## 5. Storage durability and the anchor service

### 5.1 Checkpoint model

The `FileBackend` stores fixed-size bucket ciphertexts in a bounded file. A full checkpoint authenticates encrypted buckets and the trusted controller state (maps, stash, versions, counters, and geometry). It is published using synchronized file/directory operations and returns a secret `TrustedCheckpoint` handle. Restore requires the trusted latest handle, verifies the full snapshot and every bucket/placement invariant, then rekeys and reencrypts all buckets before returning a controller. Re-encryption prevents reuse of an old bucket nonce domain after recovery.

A bucket file or encrypted checkpoint by itself cannot say it is the newest checkpoint. The caller must keep the latest secret handle somewhere the storage adversary cannot roll back, atomically publish the new snapshot identifier and handle, and only then acknowledge durability. Failure or ambiguous compare-and-swap outcomes require reconciliation. See [docs/STORAGE_RECOVERY.md](docs/STORAGE_RECOVERY.md) for APIs, layout, crash ordering, and failure cases.

### 5.2 Local anchor service

`oblivion-anchor` exposes a local Unix socket backed by SQLite. It can atomically compare-and-swap catalog version/digest, checkpoint handle, SSE journal generation, and signed invocation receipt information. File permissions and a stable master key are part of the local assumption. This is useful for process restart on one host; it is not a remote consensus service or hardware monotonic counter.

A root operator who restores an older SQLite database can roll back the catalog version floor, receipt history, and SSE freshness state. Host root can also inspect the process and keys. The anchor does not make arbitrary third-party side effects atomic. These limits are detailed in [docs/ANCHOR_SERVICE.md](docs/ANCHOR_SERVICE.md) and [docs/INVOCATION_DURABILITY.md](docs/INVOCATION_DURABILITY.md).

### 5.3 Independent mTLS witness for SSE, runtime catalog activation, and ORAM checkpoints

`oblivion-anchor-remote` is a separate synchronous TCP service backed by SQLite. It exposes persistent SSE journal-head load/CAS, digest-bound signed-registry catalog activation, standalone Path ORAM checkpoint load/CAS, and atomic runtime invocation receipt/checkpoint commits. It requires mutual TLS: the client authenticates the witness through its configured CA roots, and the witness verifies the client's certificate against its own configured client CA. Every remote request and response envelope uses protocol version 4; older peers fail closed. The local Unix anchor protocol has its own version and is unchanged. Frames remain capped at 512 KiB, with a five-second TCP connect timeout and an absolute five-second TLS/frame I/O deadline shared by reads and writes after connect/accept. Byte trickling cannot reset that I/O budget. Rustls performs the TLS cryptography; there is no custom handshake or plaintext fallback. Four fixed workers process TLS and frames concurrently, with a bounded queue for sixteen accepted connections; queue time counts toward the absolute I/O deadline. SQLite requests remain serialized through one database connection. Full queues close accepted sockets, and four slow peers can occupy all workers until their deadlines. The server uses atomic SQLite transactions. If a mutation reply is lost or malformed after sending, the result is indeterminate because the update may have committed; the invocation adapter follows that with exact-response confirmation. Pre-send connection failure is a definite backend error. No operation silently falls back to the local anchor.

The witness must be administered independently from the application host. Under that assumption, the mTLS SSE adapter can reject an old local encrypted-journal snapshot because its head generation/digest differs from the witness's newest head. The runtime worker can construct `TlsRegistryCatalogAnchor` from explicit environment settings and activate its verified catalog version/digest through CAS before readiness. Local Unix and remote mTLS catalog settings are mutually exclusive; all six remote settings must be present, and manifest plus pinned publisher key are still required. The witness operator sees the configured slot and catalog version/digest, along with operation times. A network observer sees peer endpoints, connection timing, and approximate TLS sizes, but not those fields inside the encrypted TLS payload. A client that cannot reach the witness fails closed; there is no local fallback or automatic mutation retry.

Before a request reaches SQLite, the witness checks the authenticated
certificate's configured slot grant and consumes one token from that
certificate/slot bucket. The default is 100 requests per second with burst 200;
the binary accepts rate, interval, and burst overrides only when all three
settings are present. Each process starts with full buckets and maintains its
own counters, so restart or a second witness instance does not share quota
state. Rejected requests receive a typed rate-limit response before database
dispatch. This limit covers authenticated request volume; it does not filter
TCP accepts, TLS handshakes, or IP traffic. Four connection workers and a
sixteen-connection queue provide bounded handler concurrency, while four slow
clients can still hold every worker until the absolute I/O deadlines expire.

After TLS authentication, request decoding, and the certificate/slot grant check,
the server consumes one token for that exact leaf-certificate fingerprint and
slot. The configured grant list determines the bucket keys at startup, so
incoming names cannot grow the bucket map. Each bucket begins with its burst
capacity. Refill uses monotonic elapsed nanoseconds and carries the integer
remainder of the token-rate division; repeated short checks therefore do not
discard fractional refill. The bucket never grows beyond burst. The default is
100 tokens per second with burst 200. The remote binary can override rate,
interval in milliseconds, and burst only when all three
`OBLIVION_ANCHOR_RATE_*` variables are set. A rejected request receives a
version-4 `rate_limited` response before any database handler runs. SSE and
catalog clients surface a typed anchor error; the checkpoint adapter reports
a definite backend rejection because that request was not dispatched.

These counters live only in the running process. Restarting resets each bucket
to full, and running multiple witness instances gives each an independent
budget. This is an authenticated-request volume control, not a durable user
quota or a distributed fairness mechanism. TLS handshakes happen before the
certificate/slot bucket is consulted. Four workers can handle TLS and frame
I/O at once, with sixteen accepted sockets queued; four slow clients can fill
the worker pool until their deadlines expire. A full queue closes the newly
accepted socket. The kernel accept backlog, IP-level limits, durable identity
quotas, and shared multi-replica accounting are not controlled here.

The remote worker settings are:

| Environment variable | Purpose |
| --- | --- |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_ADDRESS` | Numeric witness IP address and TCP port |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_SERVER_NAME` | DNS name used to verify the witness certificate |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_SLOT` | Opaque catalog-state slot stored by the witness |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_CA_PEM` | PEM CA roots trusted by the worker |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_CLIENT_CERT_PEM` | Worker certificate chain presented to the witness |
| `OBLIVION_REGISTRY_ANCHOR_MTLS_CLIENT_KEY_PEM` | Private key matching the worker certificate |

All six must be set together. They cannot be combined with
`OBLIVION_REGISTRY_ANCHOR_SOCKET`, which selects the local Unix anchor instead.
Both anchored modes require `OBLIVION_REGISTRY_MANIFEST` and
`OBLIVION_REGISTRY_PUBLIC_KEY`: the publisher signature and each record's
embedded-module binding are checked before the catalog is sent to the witness.
The witness performs the version/digest compare-and-swap before the worker
announces readiness. If the response is lost after the witness committed, the
worker cannot know whether activation occurred; it exits without readiness,
and the operator must reconcile witness state before retrying. No fallback
silently turns the same startup into a local or unanchored activation.

This is a single trusted witness, not a quorum protocol, hardware monotonic counter, or replicated register. A witness administrator who rolls back its own SQLite database can roll back the freshness head. The client and witness certificates, private keys, CA provisioning, witness code, operator, and durable witness database are trusted. The checkpoint adapter expands this trust: its 88-byte handle contains the snapshot decryption key, so the witness can decrypt any snapshot it can access. Runtime invocation requests also disclose their signed identities, exact saved response, current checkpoint handle, and slot to the witness. The witness sees plaintext during load, finish, and confirmation. After validating the certificate chain, the witness checks a versioned policy mapping the SHA-256 fingerprint of the DER leaf certificate to explicit slots. Policy files are loaded once at startup; changes and revocation require a restart. A certificate can issue requests up to its per-process certificate/slot token bucket; the default is 100 requests per second with burst 200, and bucket state resets on restart. The worker pool limits simultaneous TLS/frame handlers to four with sixteen queued connections, but does not limit TCP accepts, handshakes, or distributed quotas. Runtime invocation anchoring is opt-in, and uses the same witness trust model. Full protocol and failure details are in [docs/ANCHOR_SERVICE.md](docs/ANCHOR_SERVICE.md) and [the design record](docs/ANCHOR_FRESHNESS_DESIGN.md).

At the wire level, checkpoint load is a request containing the configured slot and returns either no record or a snapshot ID plus handle. Compare-and-swap sends the slot, the caller's expected current generation (or `null` for an empty slot), a snapshot ID, and the 88-byte logical handle encoded as exactly 176 lowercase ASCII hex characters. This makes wire length independent of the key/digest byte values. The remote server decodes and validates the handle, rebuilds a `CheckpointAnchorRecord`, which derives its generation from the trusted handle, then delegates atomicity and consecutive-generation checks to the existing SQLite-backed `CheckpointSlot`. A success returns `updated`; a stale generation returns `conflict`. A server-side uncertain commit returns `commit_indeterminate`. If the client connected and began transmitting but cannot validate the reply, it reports `AnchorCommitUnknown` so Path ORAM requires recovery/reconciliation; if TCP connection fails before sending, it reports a definite backend failure. The client does not retry or fall back. Four fixed workers handle TLS/frame work concurrently with a bounded queue of sixteen accepted sockets; database operations remain serialized. This improves behavior against one stalled connection, but is not a capacity or multi-host availability result. The 512 KiB cap, five-second connect timeout, absolute five-second TLS/frame deadline, strict JSON fields, and mutual TLS apply to this operation as they do to the other remote anchor operations. Application-owned JSON frames and secret-handle hex strings are zeroized on drop, but this does not erase copies that rustls, allocators, the kernel, or crash reporting may keep.

### 5.4 Optional durable invocation receipts

When durable anchor settings are used, a valid stable client identity and invocation ID are checked for an earlier receipt. A repeated canonical request can receive its original fixed response through the reserved cover path; a new request can atomically associate a fixed-size response with a new full-store checkpoint. Local mode uses the Unix SQLite service. Remote mode uses the mTLS witness and keeps snapshot files in the executor's local `OBLIVION_ANCHOR_STATE_DIR`. Both can recover state and receipt behavior after an ordinary worker process restart.

The built-in demo generates per-run client IDs and signing keys. An application that wants retries across process restarts must persist and safely provision the same identity/key and canonical request. Same-ID concurrent requests are not a distributed lease: atomic checkpoint CAS allows only a writer based on the current generation to publish, and stale writers fail closed. Execution is not exactly-once for future external side effects. A local SQLite rollback breaks local freshness; restoring the remote witness database breaks remote freshness. Full checkpoints are visible maintenance work. These details are not a claim that the default in-memory demo is durable.

### 5.5 Remote runtime invocation settings

The executor chooses exactly one durable backend. The existing local mode uses
`OBLIVION_ANCHOR_SOCKET` together with `OBLIVION_ANCHOR_STATE_DIR`. Remote
mode uses `OBLIVION_ANCHOR_STATE_DIR` and every setting in the following
table. Partial blocks, a missing state directory, or a local socket combined
with any remote setting are rejected before the worker announces readiness.
There is no automatic local fallback.

| Setting | Smallest detail that matters |
| --- | --- |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_ADDRESS` | Numeric IP address and nonzero TCP port, for example `127.0.0.1:7443`; hostnames are not accepted in this field. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_SERVER_NAME` | Nonempty TLS server name checked against the server certificate. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_SLOT` | Nonempty witness slot. The witness certificate-to-slot policy must grant this exact string to the client's DER certificate fingerprint. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_CA_PEM` | PEM trust root(s) used by the worker to validate the witness certificate. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_CLIENT_CERT_PEM` | Worker certificate chain presented during mutual TLS. |
| `OBLIVION_INVOCATION_ANCHOR_MTLS_CLIENT_KEY_PEM` | Private key matching the worker certificate; existing PEM permission checks apply. |
| `OBLIVION_ANCHOR_STATE_DIR` | Local directory containing `snapshots/`; it is created with mode 0700 and is not copied to the witness. |

The witness operator must configure its server certificate, client CA, SQLite
database and master key, plus a policy granting the client certificate the
requested slot. Certificate rotation requires policy updates and a witness
restart. The remote witness is single-instance state; its database must be
kept in a separate administrative domain. The worker and witness can restart
independently as long as the witness database and master key persist and the
executor's anchored snapshot file is retained.

### 5.6 Invocation request flow, hit and miss behavior

For every valid signed request, the worker performs the same logical exchange:

1. Verify the authenticated envelope and Ed25519 identity signature. The
   signature binds the endpoint slot, canonical request digest and invocation
   ID. It proves key possession, not application authorization.
2. Send a receipt `load` using the signed identity. The result is either no
   receipt or the original snapshot ID, generation and fixed response.
3. Run the normal function for a miss, or execute the reserved dummy cover
   path for a hit. A hit replaces the dummy result with the saved response.
4. Send a `finish` action in both cases. On a miss, the worker creates a
   randomized snapshot ID, checkpoints the complete ORAM state, and sends the
   new checkpoint record plus response. On a hit, it sends the currently
   loaded checkpoint record and the saved response without creating a file.
5. The witness atomically commits a new checkpoint and encrypted receipt on a
   miss. On a duplicate ID/digest, it returns the original receipt without
   advancing its checkpoint. The worker checks that the result is exactly the
   receipt it loaded before using the response.
6. Publish the fixed-size application response only after the finish result
   has been accepted. If the finish reply may have been lost, the worker sends
   `confirm` with the exact response. It fails closed if the witness cannot
   confirm it.

The `finish` action is the same code on a hit and a miss. The fixed v3 request
and response structures use a public capacity of 80 bytes for this runtime
path; hit/miss action order and serialized shape do not change. The witness is
trusted and decrypts these fields, so the equal shape is for an external
network observer. That observer can still see the TLS peer, timing, connection
count, request cadence, failures and restarts. The witness itself can infer a
hit from the loaded receipt, old receipt generation, response and checkpoint
record values.

A replay does not write a snapshot, and it does not advance the checkpoint.
This remains true for an old receipt after newer invocations: `finish` receives
the current checkpoint, but idempotence returns the older loaded receipt. The
worker checks that exact receipt and leaves the current checkpoint unchanged.
The process-level integration test covers witness restart, stateful WASM
read/write, exact replay, a later state generation, and replay of the older
receipt without rollback.

A separate fault test uses a real mTLS client and the production v3 request
decoder, certificate-to-slot check, and SQLite request handler. The handler
commits a new receipt and checkpoint, then the test server closes the TLS
connection before sending the response. The client must report an indeterminate
commit; a new `confirm` connection must return the exact response and receipt,
and the stored checkpoint must still be at generation 1. This verifies the
commit-then-lost-reply reconciliation contract at the handler boundary. The
fault harness intentionally skips the response write rather than killing the
production witness process, so socket/process crash timing is still broader
fault-injection work.

Local mode obtains a cooperative same-host per-slot advisory lock through the
Unix invocation client before restore/readiness. Remote mode has no distributed
lease. The witness's generation compare-and-swap rejects a stale writer, but
workers can compute from the same prior state and only one may publish. Snapshot
files remain local, so losing a host or its state directory is not repaired by
the witness. A worker that loses a CAS race fails; it does not merge state or
retry automatically. External side effects are not covered by the receipt and
checkpoint transaction.

## 6. SSE: encrypted search and its limits

`oblivion-sse` is a separate bounded dynamic encrypted-search component. Its implementation is inspired by constrained GGM/forward-private designs and is accompanied by an explicit security target, oracle tests, retained-capability controls, and leakage attacks. It must not be called a faithful implementation of Diana, Sophos, or another named scheme unless the relevant construction is actually present.

The server holds encrypted postings/tokens; the client maintains secret state needed to create/update search capabilities. An update changes client state so that a later search capability does not trivially expose new updates to an observer retaining earlier capabilities, within the exact construction and corruption/capability model. That property is narrower than hiding all query relations. Search equality, result volume, timing, update sizes, and some historical posting linkage can be visible. No backward-privacy claim is made.

The legacy client is ephemeral. An opt-in persistent client journals encrypted client state and can anchor journal generations through the local Unix service for ordinary process restart, or through the independent mTLS witness to detect application-host rollback while the witness keeps its state. Restoring the local SQLite database defeats local freshness; restoring the witness database defeats remote freshness. A caller must preserve the stable slot, client journal key, client certificate, and witness trust configuration. Distributed transactions, witness rollback protection, and a complete end-to-end search-invocation composition remain open. Details: [docs/SSE_DESIGN.md](docs/SSE_DESIGN.md), [docs/SSE_IMPLEMENTATION.md](docs/SSE_IMPLEMENTATION.md), [docs/SSE_ATTACKS.md](docs/SSE_ATTACKS.md).

For a persistent update, `prepare_add` first changes the client's in-memory
state and creates the encrypted journal record containing that exact pending
request. It writes the record, then compare-and-swaps the `(index, generation,
digest)` head at the configured anchor before returning the request to the
caller. Only after that reservation succeeds should the caller submit the
request to the SSE server. A second client opened from the old generation may
construct a competing record, but its anchor CAS fails; that client is
poisoned and cannot return or retry its competing request. Reopening from the
current anchored head recovers the winning pending request byte-for-byte.
After the server acknowledges it, `finish_add` journals the acknowledgement
and publishes the next generation. If the server committed but the client
lost the acknowledgment, recovery resends the same request, and the server
must treat that request idempotently. The new remote-witness test checks this
stale-generation sequence through real mTLS and SQLite, including that only
the winning keyword is searchable. A second test releases two clients from a
barrier after both opened the same generation, checks one CAS winner and one
conflict, then reopens and verifies the losing keyword is absent. That test
passed 10 repeated executions on one host. Neither test measures simultaneous
scheduling on separate hosts or creates an atomic transaction spanning the
anchor and SSE server.

The persistent client journal also has a dedicated size/recovery benchmark. It records encrypted journal frame bytes when each immutable record is created, even if checkpoint compaction later deletes that record, and times `PersistentClient::open` in newly launched child processes. The 2026-10-28 study ran 30 indexes at each of 64, 257, 1,024, and 4,093 postings, then performed five reopens per index. It used the real local Unix anchor service. Mean application-level journal-byte amplification was 84.037×, 99.225×, 130.489×, and 244.754× respectively; mean build time rose from 3.316 seconds to 242.889 seconds. The full 95% intervals, p50/p95/p99 values, raw samples, and reproduction commands are in [the result report](docs/SSE_JOURNAL_BENCHMARK_20261028_RESULT.md).

“Application-level journal bytes” is the sum of encrypted frame-file lengths written by the client divided by logical keyword-plus-document-ID bytes. It includes records later pruned and the initial checkpoint. It excludes SQLite pages, the WAL, filesystem amplification, block-device writes, and storage-controller behavior. Fresh processes reused the host's potentially warm page cache; this is not cold-cache recovery. The run remained on one host and did not test rollback resistance. The [independent verifier](research/analysis/verify_sse_journal_benchmark.py) checks raw trial coverage, generation/byte relations, distinct recovery-process IDs, and descriptive summaries. It validates bootstrap metadata but does not replay the exact Rust RNG stream.

## 7. Leakage harness: how privacy claims are tested

The Rust harness runs real component mechanisms and produces structured observer events. The Python analysis layer separates three types of data:

1. **Attacker-visible features:** the columns actually supplied to an attack, such as event timing, length, visible storage tag, or declared public configuration.
2. **Ground-truth labels:** what the experiment wants the attack to infer, held in a separate file until scoring.
3. **Private internal instrumentation:** useful for correctness, process timing, status, or debugging, but outside the attacker view unless a threat model explicitly includes it.

File names do not enforce this separation; deployment permissions and analysis code must. An observer schema should reject truth/private-only columns. The attack interface returns predictions, confidence only where implemented/calibrated, and metrics; registered adapters are not automatically validated attacks. See [trace/protocol schemas](docs/PROTOCOL.md), [attack API](docs/ATTACK_INTERFACE.md), and [trace validation](docs/TRACE_VALIDATION.md).

### Positive controls

Every attack is first tested against a configuration designed to leak the target (for example plaintext addresses or clear request sizes). A successful positive control demonstrates that this attacker and feature set can recognize the signal in that setting. If the control fails, a near-chance defended score may mean the attack is broken or underpowered, so the defense comparison is invalid.

Training and target sessions are split at the independent unit, such as whole sessions or whole trials; observations from a single session must not leak across the split. Report class counts, majority baseline for raw accuracy, balanced accuracy, ROC AUC where appropriate, confidence intervals clustered over the independent trial/session, and exactly which features were tested. Do not tune on the held-out target or call chance-level performance proof of cryptographic security.

### Attack families in the repository

The repository includes frequency and traffic classifiers, SSE count/volume and inference methods, chosen-update association, corpus/auxiliary drift, presence/intersection inference, ORAM leaf/timing and transition attacks, PIR server timing, integrated epoch/batch inference, and autoscaler demand/popularity attacks. Some are simplified bounded attacks, not faithful reproductions of published attack papers. Each report states the method, auxiliary knowledge, control, split, uncertainty, and limits. Browse [REPORTS.md](REPORTS.md) by category.

## 8. Autoscaling simulator and privacy mechanism studies

The autoscaler is a discrete-event simulator. It supports synthetic uniform/Zipf/diurnal/burst loads and imported data, and compares policies such as reactive, smoothed, quantized/hysteretic, fixed schedule, and noise-affected signals. It computes simulated instances, queueing/cold starts, latency/SLO/cost proxies, and attacks on visible instance counts/scaling events. It does not provision Kubernetes, cloud functions, or real provider resources.

Some studies analyze a bounded event-level or user-level mechanism under a declared fixed horizon, sensitivity, contribution cap, sampler, and observer. Any `(epsilon, delta)` statement is conditional on those assumptions and composition. Public seeded traces are reproducible experiment artifacts, not differentially private releases. The optional local accountant's persistent SQLite state itself has key custody and rollback limitations. See [docs/AUTOSCALER.md](docs/AUTOSCALER.md), [docs/AUTOSCALER_DP.md](docs/AUTOSCALER_DP.md), and [docs/PRIVACY_LEDGER.md](docs/PRIVACY_LEDGER.md).

## 9. What the latest ORAM replication says

The frozen study used 30 independent trials, eight sessions/trial, four profiling and four disjoint target sessions, 256 measured operations/session, and 16 warmups. Its address workload was a 16-address rank^-1.10 Zipf distribution with a Markov retention component. The declared classifier and sole primary metric were frozen before collection. Plaintext and encrypt-only controls both achieved mean ROC AUC 1.000. Path ORAM scored 0.4968 with a 95% percentile-bootstrap interval [0.4864, 0.5072].

The observer's timer covered the isolated in-memory bucket service only, excluding ORAM path calculation, pipe waiting/encoding, and trace output. The service was pinned to CPU 0 and the driver to CPU 2 on a shared 24-logical-CPU machine; the CPUs were not reserved and load increased during the run. Thus this is evidence that the frozen classifier did not reproduce the earlier possible weak signal under this specific local workload, machine, and timing boundary. The interval contains 0.5. It is not evidence that all ORAM timing is independent, that no better attack exists, or that the system is secure.

The complete preregistration, output, hashes, predictions, host metadata, independent verifier record, figure and exact reproduction command are linked from [REPORTS.md](REPORTS.md) and [the result report](docs/ORAM_ZIPF16_MARKOV_REPLICATION_20261028.md).

## 10. Build, run, test, and reproduce

### Toolchain

The root workspace uses stable Rust, edition 2024, and requires Rust 1.96 or newer. Wasmtime compilation is large. Research analysis uses the pinned versions in `research/requirements.lock`; the recorded latest study used the repository's `.venv` Python environment. The independent Circuit ORAM reference has its own separately licensed workspace; read its README before building or redistributing it.

### Build and run local pipeline

From the repository root:

    cargo build --locked --workspace
    cargo run --locked -p oblivion-server -- demo target/demo-half 50 2 mixed

Use a fresh output path for each demo. To test all-dummy/all-real configurations, use 0 or 100 instead of 50. The demo starts local child processes, performs eight epochs, runs the embedded modules and checks outputs with a trusted client oracle. It makes no network call to an external cloud. For the richer recorded terminal visualization, see [docs/DEMO.md](docs/DEMO.md).

### Quality and tests

    cargo fmt --all --check
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo test --locked --workspace -- --test-threads=1
    cargo test --locked --release -p oblivion-store million_operation_oracle -- --ignored --exact

The million-operation command is deliberately separate from the normal suite. Do not report it as run unless it completed. The serial Rust test setting reduces deadline failures caused by test-thread CPU contention; it does not alter runtime SLOs.

### Python analysis tests and full validation

    python3 -m venv .venv
    .venv/bin/python -m pip install -r research/requirements.lock
    cargo build --locked --release --workspace --bins --examples
    .venv/bin/python -m unittest discover -s research/tests
    .venv/bin/python scripts/validate.py target/validation-new

The full validator may build and test the separate reference and run long stress tiers. Always use a new validation output directory and read the resulting command manifest, source fingerprints, skips, and exit statuses. Historical successful gates in `experiments/results/` validate their recorded source hashes; they do not automatically certify later commits.

### Reproduce the newest ORAM experiment

The preregistration must be read before any re-run. The original output directory is immutable. Use the exact command and a new output path shown in [REPORTS.md](REPORTS.md); compare its config and attacker implementation hashes with the new report. The collector runs plaintext and encrypt-only positive controls before Path ORAM. If a positive-control gate fails, do not interpret the protected result.

## 11. Repository map

| Path | What belongs there |
| --- | --- |
| `Cargo.toml`, `Cargo.lock` | Workspace membership, pinned dependency resolution, compiler/lint settings. |
| `crates/oblivion-store` | ORAM controller, encrypted storage backend, recovery, tests, measurement examples. |
| `crates/oblivion-pir` | PIR algorithms, generic authenticated transport, workers, geometry tests. |
| `crates/oblivion-exec` | Wasmtime ABI, classes, host interfaces, staged schedules and tests. |
| `crates/oblivion-batcher` | Epoch envelope, endpoints, queue and batch tests/examples. |
| `crates/oblivion-server` | Integration process, client/demo, invocation verification and registry/PIR orchestration. |
| `crates/oblivion-registry` | Fixed signed catalog types and version activation interface. |
| `crates/oblivion-anchor` | Local persistent anchor database/service, standalone SSE, registry and ORAM-checkpoint mTLS witness adapters, and crash/restart/rollback tests. |
| `crates/oblivion-sse` | Dynamic encrypted search, client state/journal, attacks and tests. |
| `crates/oblivion-harness` | Actual-mechanism experimental traces and attack inputs. |
| `examples/wasm-functions` | Guest modules executed by the runtime. |
| `research/analysis`, `research/attacks` | Parsers, statistics, classifiers, figures and evaluations. |
| `research/simulation` | Workload and autoscaling simulation. |
| `research/oram_reference`, `research/pir_reference` | Separately built/pinned comparison programs with their own licensing. |
| `experiments/configs` | Machine-readable configurations and frozen seeds/settings. |
| `experiments/results` | Retained generated evidence, plots, logs and provenance. Do not edit results by hand. |
| `docs/` | Detailed designs, protocol, security, result reports, preregistrations and status. |
| `scripts/`, `.github/workflows/` | Reproduction/validation utilities and CI gates. |

## 12. Glossary

- **AEAD:** authenticated encryption that protects ciphertext confidentiality and detects modification, but does not on its own prove freshness.
- **AUC:** area under a receiver-operating-characteristic curve; 0.5 is chance-level ranking for a binary distinction, not a proof of no leakage.
- **Balanced accuracy:** average recall over classes; unlike raw accuracy, it accounts for class imbalance.
- **Dummy request:** cover operation that follows a fixed-shape scheduled path; its exact equivalence is limited to tested external features.
- **Ground truth:** experiment label used to score an attack, held outside attacker features.
- **ORAM:** oblivious RAM; here, Path ORAM remaps logical blocks to random tree leaves and moves encrypted buckets.
- **PIR:** private information retrieval; here, two-server XOR PIR hides the selected row from either server alone under non-collusion.
- **Positive control:** deliberately leaky setting in which the evaluated attack should recover the target above the declared baseline.
- **Preregistration:** frozen workload, attacker, split, metric, controls and analysis written before collection.
- **SSE:** searchable symmetric encryption; the server sees ciphertext/index activity and some declared leakage while the client keeps search keys/state.
- **Trusted anchor:** independently trusted state used to select the newest durable checkpoint/version. The local SQLite service is not resistant to privileged rollback. The standalone mTLS witness supports SSE journal, registry catalog, and ORAM checkpoint state only while its separate operator preserves its SQLite state; checkpoint handles include snapshot keys, so the witness is trusted with checkpoint confidentiality. It is not replicated or hardware-backed.
- **Trusted executor:** a role and assumption in this project threat model, not a claim that the current Rust process is hardware protected.

## 13. How the repository fits together

Use the root documents as a map and the detailed documents as contracts:

| Question | Start here | Normative detail |
| --- | --- | --- |
| What runs in the request path? | [ARCHITECTURE.md](ARCHITECTURE.md) | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/RUNTIME_INTEGRATION.md](docs/RUNTIME_INTEGRATION.md) |
| What bytes cross a boundary? | [docs/PROTOCOL.md](docs/PROTOCOL.md) | [docs/PIR_TRANSPORT.md](docs/PIR_TRANSPORT.md), [docs/ANCHOR_SERVICE.md](docs/ANCHOR_SERVICE.md) |
| What is trusted and what leaks? | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | [docs/SECURITY_ASSUMPTIONS.md](docs/SECURITY_ASSUMPTIONS.md) and subsystem security targets |
| Which requirement is implemented? | [docs/REQUIREMENTS_MATRIX.md](docs/REQUIREMENTS_MATRIX.md) | The linked source, test, or result for that row |
| Which evidence is current? | [PROGRESS.md](PROGRESS.md) | [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) plus source hashes in each result bundle |
| How do I reproduce a result? | [REPORTS.md](REPORTS.md) | [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md), that study's preregistration, and its verifier |

The Rust workspace owns runtime mechanisms and their local integration tests.
The `research/` tree owns attack implementations, simulators, statistical
analysis, and independent reference adapters. `experiments/configs/` stores
machine-readable run parameters; `experiments/results/` stores generated
evidence and must be treated as immutable. A report is only reproducible when
its source/binary identity, configuration, seed, workload, attacker view,
independent trial split, and analysis are retained together.

When a request fails, distinguish the guest result from the service result.
The executor maps invalid input, guest traps, fuel exhaustion, and timeout to
private internal statuses; the protected external response keeps the fixed
class shape. The driver and test harness retain private diagnostics for
correctness. A real backend failure may stop an access partway through the
tree and can poison the controller when its final state is uncertain. A
response deadline miss is measured, not repaired by silently retrying or
extending the budget. The test suite uses serial test threads because several
fixtures intentionally exercise short real deadlines; that setting does not
change runtime scheduling or benchmark concurrency.
