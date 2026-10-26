# Bounded forward-private keyword index

Status: the bounded ephemeral construction is implemented in `crates/oblivion-sse`; see [implementation and measured checks](SSE_IMPLEMENTATION.md). No security proof is claimed. Sources checked 2026-10-20. Integration follows the general function runtime stage. The intended application is encrypted keyword metadata mapping to opaque function/document identifiers.

## Source basis and precise scope

Bost, Minaud, and Ohrimenko, *Forward and Backward Private Searchable Encryption from Constrained Cryptographic Primitives*, ACM CCS **2017**, pp. 1465–1482, DOI [10.1145/3133956.3133980](https://doi.org/10.1145/3133956.3133980), introduces FS-RCPRF in Algorithm 3 and Diana in §§5.1–5.2. Diana instantiates a range-constrained PRF with a GGM tree and a best range cover. A search releases keys covering the counters already used; later counters remain outside that cover. The adaptive-security theorem in that paper uses the random-oracle model. [Conference PDF](https://acmccs.github.io/papers/p1465-bostA.pdf); [author institution publication record](https://pure.royalholloway.ac.uk/en/publications/forward-and-backward-private-searchable-encryption-from-constrain/).

This proposal retains that constrained-tree mechanism, with different payload encryption and explicit resource/state limits. Call it **OBLIVION bounded GGM SSE**, or “Diana-inspired,” rather than an exact port or an implementation of the paper's theorem. In particular, document identifiers remain encrypted to the client, whereas Algorithm 3 unmasks them at the server. The construction below has an engineering security argument; a complete adaptive simulation proof for these modifications remains work to do.

The original [OpenSSE implementation](https://github.com/OpenSSE/opensse-schemes) and [Diana explanation](https://opensse.github.io/docs/diana/) were inspected. Reference revision: `084e80bb1223560d30024b7d20b165e3dfc64426` (2021-06-11). Its [client header](https://github.com/OpenSSE/opensse-schemes/blob/084e80bb1223560d30024b7d20b165e3dfc64426/lib/include/sse/schemes/diana/diana_client.hpp) constructs constrained ranges and increments counters; its [server header](https://github.com/OpenSSE/opensse-schemes/blob/084e80bb1223560d30024b7d20b165e3dfc64426/lib/include/sse/schemes/diana/diana_server.hpp) evaluates the cover. OpenSSE is AGPLv3. Use its architecture as a reference; do not copy or translate its code into this MIT repository. The pseudocode here specifies a separate construction.

## Model and bounds

One trusted client owns all secret keys and serializes operations. An honest-but-curious server keeps the entire encrypted map and every message, including **every constraint node from every past search**. No erasure, cache forgetting, or transport encryption is needed for the cryptographic forward-privacy argument. TLS is still appropriate in deployment. Client compromise, rollback, multiwriter coordination, and malicious-server availability are outside that argument.

Operations are append-only `add(keyword, doc_id)` and single-keyword `search(keyword)`. Each add creates one immutable posting. Adding the same pair twice creates two postings; the client may return a sorted unique set of identifiers, but the server still sees both postings. There is no deletion, overwrite, backward privacy, conjunctive search, or keyword normalization. Keywords are exact byte strings, limited to 4096 bytes; document IDs are fixed eight-byte unsigned integers. No document ID appears in an update header or trace.

Use 32-byte keys and a depth `D = 32` binary tree, with leaves numbered `0 .. 2^32-1`. Store counts in `u64` to represent a completely full tree. A keyword has an ordered list of at most 16 epochs; only the last is writable. Operational limits should initially be 100,000 total postings and 10,000 keywords, with a total-result limit no larger than the posting limit. Check limits before allocating or mutating. The cryptographic leaf capacity is not a promise that billions of records fit in memory. Internal tests can use depth 4 or 8 to exercise full trees without large allocations; wire version 1 always uses depth 32.

## Key schedule and encoding

Use the library implementations of HMAC-SHA-256, HKDF-SHA-256, and ChaCha20-Poly1305. Add the `hmac` crate to make the PRF explicit; reuse `sha2`, `hkdf`, `chacha20poly1305`, `rand`, `zeroize`, `serde`, and `thiserror`. A bare hash of `secret || input` is not the PRF interface.

Draw a fresh uniformly random 32-byte master secret for each new index and a fresh public 16-byte `index_id`. Define `HKDF(ikm, salt, info, len)` as the RFC 5869 extract-and-expand API. Derive three independent 32-byte secrets with salt `index_id` and distinct info strings `oblivion/sse/v1/tree`, `.../value`, and `.../search-tag`: `K_tree`, `K_value`, `K_tag`. [RFC 5869, May 2010](https://www.rfc-editor.org/rfc/rfc5869).

All labels below are literal ASCII bytes. Integers use unsigned big-endian fixed-width encodings; `len(keyword)` uses `u32`, epochs use `u64`, counts/leaf indices use `u64`. Concatenation has no implicit string formatting. Reject oversized inputs before converting lengths.

```text
kw_encoding(w) = u32be(len(w)) || w
root(w,e) = HMAC(K_tree, "oblivion/sse/v1/root" || kw_encoding(w) || u64be(e))
tag(w)    = HMAC(K_tag,  "oblivion/sse/v1/tag"  || kw_encoding(w))
child(s,b)= HMAC(s, "oblivion/sse/v1/child" || byte(b))       # b in {0,1}
address(s)= SHA256("oblivion/sse/v1/address" || s)            # s is a leaf
record_key(a) = HKDF(K_value, salt=a,
                    info="oblivion/sse/v1/record", len=32)
AD(a) = "oblivion/sse/v1/posting" || index_id || a
```

The assumption for `child(s,0) || child(s,1)` is pseudorandom expansion of an unknown random seed under the HMAC PRF assumption. Disclosing a node seed allows all its descendants to be computed. It must not allow its parent, siblings, or other branches to be recovered. Domain separation prevents a leaf/address operation from being confused with tree expansion. The stable `tag` is sent only in searches and deliberately reveals repeat searches, including empty searches; never attach it to updates.

Encrypt `u64be(doc_id)` under `record_key(address(leaf))` with ChaCha20-Poly1305, nonce **twelve zero bytes**, and `AD(address)`. The ciphertext including tag is 24 bytes. This fixed nonce is valid only because each posting has its own derived key and that key encrypts exactly one immutable plaintext. Retries resend identical saved ciphertext bytes; they do not re-encrypt changed content at the same address. Distinct address/key collisions are a negligible-probability cryptographic failure, not an absolute uniqueness theorem. Abort on a conflicting address at the server; never silently overwrite. Nonce uniqueness is required **per key**, as specified by [RFC 8439 §2.8 and §4, June 2018](https://www.rfc-editor.org/rfc/rfc8439).

`K_value` is never sent to the server and is not derivable from released tree seeds. Thus past-search exposure does not itself disclose plaintext IDs. All mutable secrets and serialized client state must be kept out of debug output; use zeroizing wrappers where supported. Wire constraint seeds are intentionally server-visible secrets with restricted scope.

## Tree and cover algorithms

A node is `(depth, prefix, seed)`. `prefix` is an unshifted unsigned integer containing exactly `depth` significant path bits; the root is `(0,0,root_seed)`. Its interval is `[prefix * 2^(D-depth), (prefix+1) * 2^(D-depth))`. Arithmetic uses `u64` with checked operations. Traverse index bits **most significant first**.

```text
Leaf(root_seed, i):
    require 0 <= i < 2^D
    s = root_seed
    for bit_position in D-1 down to 0:
        s = child(s, (i >> bit_position) & 1)
    return s

CoverPrefix(root_seed, n):
    require 0 <= n <= 2^D
    out = []
    Visit(depth=0, prefix=0, seed=root_seed)
    return out
    where Visit(depth, prefix, seed):
        lo = prefix * 2^(D-depth)
        hi = (prefix+1) * 2^(D-depth)
        if lo >= n: return
        if hi <= n:
            out.push((depth,prefix,seed)); return
        # Partial overlap implies depth < D.
        Visit(depth+1, 2*prefix,   child(seed,0))
        Visit(depth+1, 2*prefix+1, child(seed,1))

ConstrainedEval(cover, i):
    find the unique node whose interval contains i
    if none: return OutsideConstraint
    expand its seed along remaining MSB-first path bits of i
    return resulting leaf
```

The cover is a disjoint exact partition of `[0,n)`; it never covers the next leaf `n`. At most `D` nodes are needed for a proper prefix; a full tree uses its root. For depth 4 and `n=5`, the nodes are prefix `00` at depth 2 (leaves 0–3) and prefix `0100` at depth 4 (leaf 4). Leaf 5 is not covered. For `n=0`, release nothing. For `n=16`, release the root and **permanently retire this tree for updates**.

The server enumerates a node's descendants once using depth-first expansion; it should not evaluate the entire root path independently for every leaf. Both the server and client validate a received result count before allocating. The server validates canonical cover metadata, disjointness, exact range coverage, prefix width, number of epochs/nodes, and version/bounds before evaluation. It cannot authenticate a client's seeds, but malformed requests must not cause unbounded work.

## State machines and exact operations

Client state comprises the keys, `index_id`, the per-keyword ordered `(epoch, count)` list, and at most one globally pending add for the simplest initial implementation. New keywords begin at epoch 0, count 0. Counts only increase. A pending add stores the keyword, epoch, index, address, **exact ciphertext**, and the complete post-reservation state. Block other operations until it is acknowledged; this avoids searches authorizing a posting not yet delivered. A timeout leaves it pending and retryable.

```text
PrepareAdd(w, doc_id):
    require no pending operation; validate bounds and capacity
    obtain writable epoch e and count n for w (initially 0,0)
    require n < 2^D                         # otherwise rotate or fail closed
    a = address(Leaf(root(w,e), n))
    c = AEAD_Encrypt(record_key(a), nonce=0^96, u64be(doc_id), AD(a))
    atomically persist count(e)=n+1 AND Pending(w,e,n,a,c)
    # In memory, make the same atomic logical transition under one owner.
    return Update(version=1, index_id, address=a, ciphertext=c)

ServerInsert(update):
    validate version, index_id, fixed lengths
    if address absent:
        require total capacity permits one more posting
        store (address,ciphertext); acknowledge
    else if ciphertext identical: acknowledge exact retry
    else: return ConflictingAddress          # no mutation

FinishAdd(ack):
    require ack corresponds to pending.address
    atomically clear pending; never decrement count
    # Lost acknowledgment => resend exact pending bytes; no new reservation.

PrepareSearch(w):
    require no pending operation
    for each epoch e and committed count n for w:
        include (e,n,CoverPrefix(root(w,e),n))
    return Search(version=1,index_id,tag(w),epoch_covers)
    # Empty/new w has no cover. Counters and roots do not change.

ServerSearch(request):
    validate request bounds and canonical cover structure
    enumerate (e,i,leaf) for every covered leaf
    a = address(leaf)
    return exactly one (e,i,a,ciphertext-or-Missing) per leaf
    # Never delete postings, even after a successful search.

FinishSearch(w, locally_saved_request, response):
    require response contains exactly the expected (e,i) range, once each
    reject duplicates, missing, extra, malformed, or out-of-snapshot entries
    for each entry:
        derive expected a from own root(w,e) and i; require supplied a == expected a
        decrypt using record_key(a), zero nonce, and AD(a); reject invalid tags
    decode IDs; return posting list (or client-side sorted unique IDs)
```

Use the locally saved search snapshot when validating; do not trust a server-provided replacement request. `FinishSearch` needs the original keyword locally; the server only receives the tag. Client verification can enumerate its own covers in linear tree-expansion time as the server does. Validating only the number of returned ciphertexts is insufficient: duplicates could replace missing postings.

Search does **not** reset counters, mutate the encrypted map, replace roots, or require epoch rotation. Its security effect is irreversible disclosure of the prefix constraint: a server can keep those seeds forever even if the response is dropped. A local `exposed_count` audit watermark may be recorded before sending, but safety must not rely on that watermark or on acknowledging a search.

`RotateKeyword(w)` requires no pending operation, freezes the old epoch and its count forever, and atomically appends `(e+1,0)`. Derive the new root with the new epoch; never reuse or wrap epoch identifiers. Rotation is needed before leaf capacity exhaustion, and may be requested early to bound a tree's growth. A full exposed tree cannot accept another posting. Enforce the 16-epoch limit by returning an error before any mutation. Searches continue to include all frozen epochs and the current prefix, so earlier results remain available. New epoch roots remain pseudorandom despite all seeds released for old epochs. Rotation does not erase the server's knowledge, hide search equality, or provide backward privacy. No public epoch identifier is carried by an update; grouping epochs occurs when a later search discloses their covers.

## Why retained search capabilities do not authorize a fresh update

Fix keyword `w` and current epoch `e`. If its largest previously searched prefix was `[0,m)`, every seed ever disclosed for that epoch has descendants entirely inside `[0,m)`. Older covers can overlap newer covers but their union cannot extend beyond the largest released prefix. If a new posting uses counter `n >= m`, its leaf lies outside **every** retained node. Combining two sibling seeds does not yield their parent. Under the constrained GGM/PRF assumption, the server cannot compute the fresh leaf or its address from that accumulated exposure. For a rotated epoch it additionally lacks any disclosed seed under the new root.

This is a computational inability to derive or recognize the fresh address using old capabilities. It is not literal impossibility: random guessing, collisions, side information, timing, or learning the client state can defeat a particular guessing experiment. The fixed-length payload is encrypted with an independent client secret, so it provides no deterministic document-ID equality tag to bypass the address protection. No secret root or stable keyword tag is attached to the add request.

On the **next search for `w`**, the server receives an expanded prefix and can map each newly authorized address to the exact earlier update event it stored. Forward privacy intentionally delays this association until that search. It does not stop an injected document from influencing future observed query volumes or other application outputs. A stable per-keyword update tag, disclosure of the full root before exhaustion, or a root mistakenly included as a cover for a partial prefix would immediately invalidate this argument.

## Server transcript and leakage contract

Record server-visible bytes or a faithful canonical representation, timestamps, sizes, operation order, and server lookup addresses. Do not log client keywords, plaintext IDs, master keys, or trusted-client derived value keys. A retained search request includes its constraint seeds; a public research export may redact seed bytes while preserving a separate full adversary fixture for capability tests.

| Operation | Deliberately visible |
| --- | --- |
| Setup | Index identity, version, configured public limits; empty initial map |
| Add | Client/connection identity, timing/order, operation type, random-looking 32-byte address, fixed 24-byte ciphertext, map growth; exact retries repeat the same bytes |
| Search request | Stable opaque keyword tag, repeat-query equality, epoch IDs and exact posting counts, cover shape and seeds, timing, request size |
| Search execution/response | All accessed posting addresses, the historical update events now matching this query, posting order within each epoch, exact posting/result volume and errors |
| Later application actions | Any separately visible ID use, function invocation, output, ORAM/PIR interaction or timing; must be analyzed by the integration layer |

This is a proposed leakage budget, not an established simulation theorem. Search pattern, volume, timing, client activity, total storage, and update-to-query linkage after authorization remain exposed. Encrypting IDs does not hide the posting access pattern or the intersection of repeated posting sets. Operations adding several keywords to the same document may be linked by their batching/timing; the first interface adds one posting at a time. Payload encryption alone does not conceal that workload correlation. Multiple independent users need separately keyed indices or an explicitly designed shared-client protocol.

The honest-but-curious argument permits all historical transcripts and auxiliary workload information. For an active server, AEAD and expected-address/range checks detect changed ciphertexts, swaps, duplicate substitution, and missing known postings when a response is received. They do not force delivery or establish a distributed commit. A malicious server may lie about insertion acknowledgments, omit data, delay operations, or use selective failure behavior. Do not automatically send a replacement plaintext-dependent request after an authentication error. Treat the error as failure, not an empty result. Confidentiality against arbitrary active interaction and an authenticated persistent storage protocol require separate analysis. No availability, trusted-server erasure, or full malicious security claim is made.

## Crash, rollback, and concurrency requirements

The legacy `Client` and minimal in-memory demo remain explicitly **ephemeral**, with a fresh master/index identity for every new run. The opt-in `PersistentClient` now provides encrypted event/checkpoint recovery when the application supplies a durable independent anchor; it does not change the legacy API or make the process a TEE.

For a persistent implementation, commit the advanced count and exact pending request in one durable trusted-client transaction **before any network send**. A crash before commit sends nothing. A crash after commit resumes the exact pending request; an insertion followed by a lost acknowledgment is an idempotent retry. Clear the pending record only after acknowledgment. Search remains blocked until the pending write is resolved. Never “cancel” a possibly sent posting by decrementing its counter. Recovery must replay the original ciphertext, including after a crash between insertion and client acknowledgment.

Atomic local persistence solves torn writes, not rollback. Restoring an older client state can reuse an already exposed leaf, immediately linking the new update to a past query. Reusing that address with a different document also reuses an AEAD key/nonce, breaking the payload-encryption precondition. Encryption and MACs authenticate old snapshots too; they do not establish freshness. The implemented journal verifies the selected record against a digest/generation supplied by `SseJournalAnchor`; the caller must keep that anchor durable and outside the journal directory's rollback domain. The interface has no production adapter to the separate anchor service yet. A server's claimed highest counter is not a trusted repair mechanism. Multiple writers opened at one generation use compare-and-swap, so at most one can publish that generation; the loser is poisoned and must reopen. This is optimistic state reservation, not a lease or a distributed transaction with the server. A rollback-resistant anchor and fresh-key complete rebuild after anchor loss remain necessary.

Journal state is encrypted with ChaCha20-Poly1305 under an HKDF-separated key and a fresh OS-random nonce. Record payload serialization is capped at 8 MiB and complete encrypted records at 64 MiB; exceeding either limit fails closed. Checkpoints are written at most 256 state mutations apart, bounding recovery replay. Fsync and anchor CAS precede returning an update request. An anchor commit error poisons the live object because its outcome may be uncertain; reopening is required to reconcile. The test anchor is in-memory only and proves API behavior, not a deployable trust boundary.

Rotation does not repair an unknown rolled-back epoch sequence under the same key. Fresh master/index identity plus a complete rebuild is the straightforward recovery policy when a trusted freshness anchor is unavailable. Old transcripts remain exposed under their old keys, and rebuild timing/volume is additional leakage.

## Minimal Rust boundary after the runtime work

Keep client secrets and keyword state in a distinct type/module from server storage. The server API must accept wire objects, never a keyword or client object. Public capability structs have no secret-bearing `Debug` implementation. The current typed API checks request structure before expansion, but its derived serde implementations do not bound allocations while parsing arbitrary input. A future network adapter must impose body and collection limits during deserialization before accepting hostile wire bytes; no such adapter is supplied here.

```rust
pub type DocumentId = u64;
pub struct Client { /* secret keys, per-keyword epochs, pending operation */ }
pub struct Server { /* index identity, address -> ciphertext */ }
pub struct UpdateRequest { /* version, index_id, address, [u8; 24] */ }
pub struct SearchRequest { /* version, index_id, search tag, epoch covers */ }
pub struct SearchSnapshot { /* local keyword/snapshot binding; not sent */ }
pub struct SearchResponse { /* bounded entries and explicit missing/error */ }

impl Client {
    pub fn prepare_add(&mut self, keyword: &[u8], id: DocumentId)
        -> Result<UpdateRequest, Error>;
    pub fn retry_pending(&self) -> Result<UpdateRequest, Error>;
    pub fn finish_add(&mut self, acknowledged_address: [u8; 32])
        -> Result<(), Error>;
    pub fn prepare_search(&self, keyword: &[u8])
        -> Result<(SearchSnapshot, SearchRequest), Error>;
    pub fn finish_search(&self, snapshot: &SearchSnapshot, response: SearchResponse)
        -> Result<Vec<DocumentId>, Error>;
    pub fn rotate_keyword(&mut self, keyword: &[u8]) -> Result<(), Error>;
}
impl Server {
    pub fn insert(&mut self, request: UpdateRequest) -> Result<[u8; 32], Error>;
    pub fn search(&self, request: &SearchRequest) -> Result<SearchResponse, Error>;
}
```

The acknowledgment identifies the pending posting; it is not a proof of durable storage. Keep resource-limit, malformed-cover, conflicting-address, pending-operation, exhausted-epoch, missing-posting, authentication, and state-recovery errors distinct. Document duplicate posting semantics at the application boundary. Integration can map decrypted document IDs to function IDs on the trusted client; do not expose IDs merely to connect SSE to the runtime.

## Required checks before making implementation claims

These are acceptance criteria; their implemented checks and limitations are recorded separately in [SSE_IMPLEMENTATION.md](SSE_IMPLEMENTATION.md). The roadmap's “identically distributed transcript” wording must be weakened to computational indistinguishability under stated assumptions; comparing byte histograms cannot establish that property.

1. **Exact constrained capability:** at depth 4/8, exhaustively enumerate every `n` from zero through full capacity and every leaf. Constrained evaluation equals full-root evaluation exactly for `i < n`, and rejects every `i >= n`. Check canonical exact disjoint coverage, node count, MSB ordering, powers of two, full-root retirement, zero, and overflow boundaries.
2. **All retained past constraints:** make multiple searches with growing prefixes for several keywords/epochs. Give the adversary every original request, seed, record, and update log. Maintain and expand the union of all retained nodes. Confirm that every previously authorized address is derivable, and that the next fresh address is outside all their descendant intervals. Test after a failed/lost search response too: its seeds were still exposed. Rotate and repeat with frozen partial and full old trees.
3. **Positive controls for the adversary:** deliberately release a root for a partial prefix, then show the adversary derives the next address and links the next update. Also show that a stable keyword tag on updates permits direct linking. A missing positive control makes a failed attack uninformative.
4. **Bounded challenge experiment:** randomly choose one of two previously searched keywords with equal disclosed counts/epoch shapes, add a fixed-size opaque posting, and give only server-visible information to an adversary that retains all earlier constraints. Report classification accuracy, binomial confidence interval, seeds/trial count, and visible features. A capability-enumeration adversary should have no cryptographic match until the relevant next search, when linking should succeed. Counter and timing side information must be balanced or reported. Chance-like accuracy is an engineering regression check, never a proof of forward privacy.
5. **Correctness oracle:** at least 100,000 seeded mixed add/search operations against a plaintext keyword multimap, covering empty searches, duplicate IDs, repeated keywords, overlapping keyword sets, exact retries, rotation, limits, and post-error state. Verify the posting list first; any deduplicating application API must also match a set oracle.
6. **Payload separation and integrity:** identical IDs at different leaves/keywords/epochs have different keys/addresses except negligible collision; the same pending retry is byte-identical. A released leaf does not give the client-only value key. Bit flips, cross-address swaps, extra entries, duplicate `(e,i)`, wrong indices, wrong index identity, and dropped entries fail closed. A valid old ciphertext cannot replace a distinct expected leaf. Enforce exact eight-byte plaintext decoding.
7. **State failure injection:** crash at reservation/commit/send/insert/ack/clear boundaries in a durable implementation. Verify exact replay and no reused index for a different posting. Deliberately restore a stale snapshot in a negative fixture and demonstrate address reuse/old-cover recognizability; the supported restore interface must reject stale state or require rebuild. An ephemeral implementation should expose no persistence/recovery claim.
8. **Leakage and cost:** capture actual request/response shapes and lookup addresses; show update size is fixed while search size/count/timing and stable search tags remain visible. Report index bytes per posting (56 bytes of cryptographic address/payload before container/protocol overhead), client memory by keyword/epoch, update time, search time vs posting count, and seed/node counts. Report failures and workload limits.

Update work costs one root derivation, `D` child evaluations, and one short AEAD encryption. A search sends at most `D` node seeds per nonfull epoch, enumerates the matching leaves in linear tree-expansion work, and returns one encrypted posting per match. Client verification can use the same linear expansion. Repeated searches resend and reread all matching postings; there is no compaction or incremental cache requirement. These are algorithmic bounds, not measured throughput claims.
