# Ephemeral bounded GGM SSE implementation

Implemented 2026-10-20 in [`crates/oblivion-sse`](../crates/oblivion-sse). The [construction and primary sources](SSE_DESIGN.md) define the mechanism and leakage assumptions. This is a Diana-inspired research component with actual constrained GGM capabilities. It is not an exact Diana port, a production security claim, or an implementation of the original adaptive-security theorem.

## Implemented boundary

`Client::new` samples a fresh master secret and public index identity from `OsRng`, derives separate tree, value and search-tag keys, and holds all keyword/counter state in memory. Client objects cannot be cloned or serialized, and there is no key import or state restore API. Secret keys use zeroizing wrappers; that does not establish that every compiler/library intermediate is erased. Plaintext keywords stay on the client. `Server` receives fixed-sized encrypted updates and explicit search covers; it has no client keys or keyword API.

The tree has depth 32, traverses bits most significant first, and expands nodes with HMAC-SHA-256 under separate child labels. Search releases the canonical disjoint cover of exactly the committed prefix. Every search can be retained indefinitely by the server. Search neither resets a counter nor rotates a key. An explicit keyword rotation freezes the prior count and selects a fresh PRF-derived root; later searches include all epochs. Defaults cap an index at 100,000 postings, 10,000 keywords, 4096 bytes per keyword and 16 epochs per keyword. Invalid requests are checked before seed expansion. Smaller limits are supported; larger limits are rejected.

Every immutable posting encrypts an eight-byte document ID with ChaCha20-Poly1305. An HKDF-derived client-only key is unique to its 32-byte posting address; its twelve-byte zero nonce is used for that one plaintext only. Identical retries resend saved ciphertext bytes. The value key is independent of released GGM seeds. Payload ciphertexts are 24 bytes; address plus ciphertext is 56 bytes, before map/container/protocol overhead. Version and index identity make an update 73 logical binary bytes. The example uses JSON, whose sizes are substantially larger and vary with numeric byte encodings.

There is one pending add globally. Preparing an add reserves its counter before handing out the request. More adds, new search requests and rotation remain blocked until acknowledgment; a prior search snapshot may still be verified locally. A lost acknowledgment is handled by `retry_pending`; the server accepts an identical retry even at its posting limit and rejects conflicting ciphertexts. Snapshot verification checks exact epoch/index/address order, missing/extra/duplicate entries and all payload tags. Repeated IDs remain repeated postings; results preserve posting order rather than silently deduplicating.

## Reproduce the checks

```sh
cargo test --release -p oblivion-sse
cargo clippy -p oblivion-sse --all-targets -- -D warnings
cargo run --release -p oblivion-sse --example measure
cargo run --release -p oblivion-sse --example measure -- /tmp/sse-transcript.jsonl
```

The release test suite passed **8 tests**, including a seeded **100,000-operation** add/search plaintext oracle, in 3.52 seconds in this workspace. Debug cryptographic loops run much more slowly. Clippy passed with warnings denied. Tests exercise:

- Every prefix and every leaf of depth-4 and depth-8 trees, plus empty/full trees, canonical coverage, explicit bit-order example and invalid ranges.
- All previously released constraint nodes, including requests whose responses were never consumed; fresh posting addresses remain outside their scopes, and the next search authorizes their lookup.
- Positive controls that disclose a full root too early or attach a stable search tag to updates, both of which permit linking.
- Pending requests, exact retry bytes, acknowledgment errors, limits, full-tree retirement and explicit epoch rotation.
- Duplicate IDs, separate per-address keys, payload modifications, ciphertext swaps, response duplication/omission, cross-index snapshots and malformed covers.
- An internal stale-counter negative fixture that demonstrates reused addresses and recognizability under an old cover. This is deliberately private-state corruption, not a supported restore operation.

## Measured example

One release run in this workspace, with workload seed `20261020` and fresh cryptographic keys, produced the following. Timings describe this single process and hardware load; they are not general performance guarantees. Updates measure prepare/insert/acknowledge. Search measures prepare/server lookup/client verification and response cloning; JSON trace serialization occurs after each timed operation.

| Measurement | Observed |
| --- | --- |
| Median update, first 10,000 postings | 14.35 microseconds |
| p99 update | 17.86 microseconds |
| Search median, 1 posting | 26.20 microseconds |
| Search median, 10 postings | 86.30 microseconds |
| Search median, 100 postings | 523.07 microseconds |
| Search median, 1000 postings | 4.83 milliseconds |
| Cover nodes for 1 / 10 / 100 / 1000 postings | 1 / 2 / 3 / 6 |

The balanced two-keyword challenge had **400 trials**, with equal posting counts before each challenge. Its explicitly narrow attacker retains **all 1200 search requests and 4995 constraint nodes**, tries their capabilities on the fresh counter, and guesses a class when no capability matches. It derived **0/400** fresh addresses before authorization; after each next search it derived **400/400**. Independent guessing was **202/400 = 50.5%**, with a Wilson 95% interval of **45.62%–55.37%** around a 50% chance baseline. A separate deliberately leaky stable-tag control recovered **400/400** classes by comparing the attached tag with previously observed search tags. The unit tests separately demonstrate full-root leakage predicting the next address.

This experiment checks one attacker and known implementation mistakes. A method programmed to guess after a capability miss should guess near chance; that observation is not a proof, nor evidence against every leakage-abuse attack. The argument that released nodes cannot derive outside their scopes depends on the constrained GGM/PRF assumptions and correct client state. Randomized byte comparisons do not establish computational indistinguishability.

The optional JSONL export was run and parsed successfully: **13,161 events**, comprising **11,911 adds and 1250 searches**, approximately **70.5 MB**. Each line records a monotonic sequence, elapsed time, full server request and server response. Search requests include every released constraint seed; responses include looked-up addresses and encrypted payloads. No plaintext keyword or document-ID field is exported. Timings and operation order remain visible, and workload knowledge may identify data despite encrypted fields. These large raw transcripts are generated on demand rather than committed. No fixed-size search traffic or timing-hiding claim is made.

## Limits and unfinished integration

This crate is append-only and ephemeral. It has no persistent transaction journal, state recovery, antirollback anchor, multiwriter protocol, deletion/backward privacy, padding, network endpoint or integration into the function runtime. Restarting starts a fresh independent index; losing the client means losing access to this index. A malicious server can lie about acknowledgment, withhold data, delay requests or deny service. AEAD and snapshot checks detect particular modifications when results arrive; no complete active-security theorem is claimed.

`serde` is provided for explicit wire/transcript objects. The server bounds typed request metadata before expansion, but deriving `Deserialize` does not itself prevent allocating a huge attacker-supplied JSON vector. A future network adapter must bound message bytes and collection parsing before constructing these types. The example writes local JSONL and does not expose a deserialization service.

Search equality (including empty searches), result/posting volume, timing, storage growth, and historical update-to-query linkage at the next search all remain exposed. Client-only ID encryption does not hide posting addresses. Runtime integration must analyze any later visible use of a decrypted function/document ID, and composition with the other layers needs its own transcript analysis. The full persistent-crash acceptance criteria in the design remain deferred because this implementation intentionally offers no persistence API.
