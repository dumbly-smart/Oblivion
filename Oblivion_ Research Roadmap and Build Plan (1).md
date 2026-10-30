# Oblivion: Research Roadmap and Build Plan

Last researched: 20 Sep 2026. Legend: ✅ = page or repo surfaced in my searches this session (link should be live); ⚠ = I know of it from background knowledge but did **not** verify it this session (search for it before trusting the venue/year/link). I found **no** verified public attack-code repo for IKK/IHOP-style attacks and **no** canonical paper on privacy-aware serverless autoscaling. Both are flagged where they come up. Section names and theorem numbers below are described, not quoted, because I did not read every PDF end to end; check against the PDF.

---

## 0. Read this first: four design tensions

1. **Who executes the function?** Layers 1–3 protect data at rest and on the wire. Layer 4 has an untrusted operator *running* your WASM. An operator who runs code sees that code, its instruction trace, and its memory unless the executor is a TEE, split across non-colluding parties, or the client runs it. The Berkeley serverless paper lists oblivious serverless computing as an open problem and notes that oblivious algorithms carry high overhead ✅ [arXiv 1902.03383](https://arxiv.org/pdf/1902.03383). **Pick a threat model now:**
   - **A (recommended): trusted executor, untrusted storage/network/scheduler.** Executor is a TEE (or simulated as one). This is the model ZeroTrace and facebook/oram assume ✅. If you keep attestation gating from your Blindfold design, it carries over directly.
   - **B: split trust.** Storage servers and executors are non-colluding operators.
   - **C: network + storage observer only.** Weakest, easiest to build honestly.
2. **Layers don't compose for free.** SSE hides keywords, ORAM hides which block, PIR hides which record, batching hides load. Each leaves a residue (volume, timing, existence). Your job is to make every externally visible message the same shape.
3. **Timing and billing are leakage channels.** Fuel used, cold starts, instance counts, and the bill itself reveal behavior.
4. **Novelty is in the integration and the harness.** Pieces exist: Snoopy (oblivious storage with epoch-style batching), Pancake (frequency smoothing), Vuvuzela (noise and batching for metadata) ✅. A system that combines them for serverless and *measures its leakage against real attacks* is a defensible contribution. A claim of "hides everything" is not.

---

## 1. Prerequisite map (dependency order)

| # | Topic | Minimum you need | Unlocks |
| --- | --- | --- | --- |
| P1 | Probability | union bound, Chernoff/Hoeffding, birthday bound, expectation vs high probability | ORAM stash analysis, DP, attack evaluation |
| P2 | Security games | PRF/PRG, IND-CPA, hybrid argument, simulation-based definitions, "leakage function" idea | L1, L2 |
| P3 | Symmetric crypto engineering | AEAD (ChaCha20-Poly1305/AES-GCM), HKDF domain separation, nonce rules, constant-time compare | every layer |
| P4 | Constrained PRFs / GGM tree | how a tree PRF lets you hand out a prefix of keys | L1 (Diana) |
| P5 | Trapdoor permutation (RSA) | why RSA "forward" chain works, and why textbook RSA is unsafe | L1 (Sophos) |
| P6 | Information-theoretic secret sharing | XOR sharing, why one share is uniform | L3 (2-server PIR) |
| P7 | LWE basics | matrix-vector form, noise vs modulus, correctness bound | L3 (SimplePIR) |
| P8 | Differential privacy | Laplace/geometric noise, composition, ε–δ | L5, L6 |
| P9 | Distributed systems | RPC (gRPC), queues, batching, tail latency, Little's law, control loops | L5, L6 |
| P10 | WASM | modules, linear memory, imports/exports, WASI, embedding Wasmtime | L4 |
| P11 | Side channels | cache/timing basics, constant-time programming, why WASM doesn't give you that | L4, L7 |
| P12 | Stats/ML for evaluation | train/test split, confidence intervals, KS test, classifiers, linear assignment | L7 |

Good resources: Stanford CS 355 (Topics in Cryptography, Spring 2026 offering; covers PRGs/PRFs, MPC, ZK, privacy, but not ORAM/PIR specifically; lecture notes were still "coming soon" when I looked) ✅ [cs355.stanford.edu](https://cs355.stanford.edu). Textbooks I'd use: Boneh–Shoup *A Graduate Course in Applied Cryptography* ⚠ (find the free PDF via the authors), Katz–Lindell ⚠, Dwork–Roth *Algorithmic Foundations of Differential Privacy* ⚠, Peikert's LWE survey ⚠.

**Minimum before each layer:** L1 → P2, P3, P4, P5. L2 → P1, P3. L3 → P6 (then P7 for SimplePIR). L4 → P10, P11. L5 → P8, P9. L6 → P8, P9. L7 → P12 plus whatever the attack targets.

---

## 2. Layer 1: SSE with forward/backward privacy

**Foundational papers (reading order)**

| # | Paper | Contribution | Skip on first pass |
| --- | --- | --- | --- |
| 1 | Curtmola–Garay–Kamara–Ostrovsky, *Searchable symmetric encryption: improved definitions and efficient constructions*, CCS 2006 ✅ (cited in several papers I fetched; PDF not fetched) | Defines SSE security via leakage functions and adaptive security. The vocabulary everyone uses. | Full construction proofs; read the definitions |
| 2 | Cash–Grubbs–Perry–Ristenpart, *Leakage-abuse attacks against searchable encryption*, CCS 2015 ✅ (cited) | Shows what "small leakage" actually gives an attacker. Motivates everything after. | Dataset-specific tuning |
| 3 | Bost, *Σoφoς: Forward secure searchable encryption*, CCS 2016 ✅ [eprint 2016/728](https://eprint.iacr.org/2016/728) | First forward-private scheme from trapdoor permutations, no ORAM. Optimal asymptotics but RSA makes it slow in practice. | Optimality/lower-bound discussion; adaptive-security proof appendices (read the leakage definitions) |
| 4 | Bost–Minaud–Ohrimenko, *Forward and backward private SSE from constrained cryptographic primitives*, CCS 2017 ✅ (cited; repo README describes Diana and Janus) | Diana: forward privacy with symmetric crypto only, fast. Janus: first practical backward-private scheme via puncturable encryption. Defines backward-privacy "types". | Puncturable-encryption construction details on a first pass |
| 5 | Chamani–Papadopoulos–Papamanthou–Jalili, *New constructions for forward and backward private SSE*, CCS 2018 ✅ (cited) | Alternative constructions with better trade-offs for deletions. | Anything comparing performance to schemes you aren't implementing |

Recent attack-side reading to see what still breaks FP/BP schemes: *Leakage-Abuse Attacks Against Forward and Backward Private SSE* ✅ [arXiv 2309.04697](https://arxiv.org/pdf/2309.04697) (venue not confirmed) and *Peekaboo: Passive Attacks Against DSSE via Intermittent Observations* ✅ [arXiv 2509.03806](https://arxiv.org/pdf/2509.03806). Also Oya–Kerschbaum below (search-pattern leakage).

**Explanatory resources**

- Bost & Minaud slides "Sophos and Diane: SSE with (very) low overhead" ✅ [PDF](https://www.di.ens.fr/~bminaud/slides/ISG-2016.pdf). Read before the papers.
- Bost's CSAIL talk page (abstract only; no video verified) ✅ [csail.mit.edu](https://www.csail.mit.edu/event/sophos-forward-secure-searchable-encryption).

**Repos**

| Repo | Read first |
| --- | --- |
| ✅ [OpenSSE/opensse-schemes](https://github.com/OpenSSE/opensse-schemes) (C++; Sophos, Diana, Janus, Tethys, Pluto; AGPLv3; last push about 2021, so treat as reference not maintained dependency) | `lib/include/sse/schemes/{sophos,diana,janus}/` headers, then the `*_client`/`*_server` sources; the README table comparing schemes |
| ✅ OpenSSE crypto-tk (submodule of the above; the README says it is a toolkit built for SSE) | Its constrained PRF and puncturable-PRF code, if present in your checkout |

I could not verify a third maintained SSE repo. Do not pad with a random GitHub project.

**Mini project (5 days): "Diana-lite," forward-private dynamic SSE in Rust or Go**

- GGM-tree constrained PRF for per-keyword tokens; server stores `token → AEAD(doc id)`.
- **Acceptance:** (a) after 10^5 random add/search operations, results equal a plaintext oracle; (b) a written **forward-privacy adversary** that, holding every token the server ever received in past searches, fails to link a *new* update to those keywords (test passes if link rate ≈ chance); (c) server-side log of exactly what is revealed per update/search (your empirical leakage profile); (d) update latency and storage blowup reported.
- Stretch: deletions via a simple backward-private design from paper 5. Cut Janus's puncturable encryption entirely.

**"Prove it works"**

- Correctness: property-based testing (proptest/Hypothesis) against a plaintext index.
- Forward privacy: the adversary above, plus a transcript-equivalence check (the server-visible bytes of "update w" are identically distributed for any w).
- Overhead: search time vs result count; index size vs plaintext.
- Leakage that remains **by design**: search pattern (repeat queries), result volume, timing. Say so in your write-up.

**Pitfalls**

- Forward privacy is not backward privacy; deletions need separate treatment.
- Client counter state is security-critical: loss, rollback, or concurrent updates break correctness or privacy.
- Reusing one key for tokens, values and MACs; use HKDF labels.
- Textbook RSA in Sophos; use a vetted implementation and check the paper's hash/encoding requirements.
- Unpadded result volumes enable volume attacks (see L7).
- Assuming FP/BP schemes are "attack proof". The 2023 and 2025 papers above show otherwise.

**Interview questions**

- Define forward and backward privacy. Why does the file-injection attack motivate forward privacy?
- Why is Sophos slow and Diana fast, and what does Diana give up?
- What does an FP+BP scheme still leak?
- How would you compose SSE with ORAM to hide the search pattern, and what does it cost?
- What breaks if the client loses its counter?

**Cut/simplify:** implement Diana-lite only; treat Janus and backward privacy as a read-and-explain item plus a one-page design sketch.

---

## 3. Layer 2: Oblivious storage (Path ORAM → Circuit ORAM)

**Foundational papers**

| # | Paper | Contribution | Skip on first pass |
| --- | --- | --- | --- |
| 1 | Goldreich–Ostrovsky, *Software protection and simulation on oblivious RAMs*, J.ACM 1996 ✅ (cited by Path ORAM) | Origin of ORAM and the Ω(log N) lower bound idea. | Skim only; read Path ORAM's related-work summary instead |
| 2 | Stefanov et al., *Path ORAM*, CCS 2013 / J.ACM 2018 ✅ [eprint 2013/280](https://eprint.iacr.org/2013/280), [arXiv 1202.5150](https://arxiv.org/abs/1202.5150) | Tree ORAM with a stash; O(log N) bandwidth for large enough blocks (B = Ω(log² N)). The one to implement. | Full stash-bound proof on pass one; keep the intuition (invariant + eviction) |
| 3 | Wang–Chan–Shi, *Circuit ORAM*, CCS 2015 ✅ [eprint 2014/672](https://eprint.iacr.org/2014/672) | Eviction redesigned for tiny circuit size; tight against the GO lower-bound interpretations; the choice for MPC/oblivious-compute settings. | Circuit-complexity comparisons unless you work on TEEs/MPC |
| 4 | Larsen–Nielsen, *Yes, there is an ORAM lower bound!*, CRYPTO 2018 ✅ (cited) | Proves the Ω(log N) bound for general ORAM. | Proof details |
| 5 | Dauterman et al., *Snoopy: Surpassing the scalability bottleneck of oblivious storage*, SOSP 2021 ✅ [eprint 2021/1280](https://eprint.iacr.org/2021/1280) | Scales an oblivious store by adding machines: 13.7× Obladi's throughput in the paper's setup. Directly relevant to your batching and scaling layers. | Their subORAM microbenchmarks; look at architecture first |

Newer follow-ups worth a skim: **SONIC** (Aug 2026 eprint), a parallel tree ORAM for TEEs ✅ [eprint 2026/1577](https://eprint.iacr.org/2026/1577). Also mentioned there: Oblix (S&P'18), EnigMap (USENIX'23), GraphOS (PVLDB'23) ✅. Read these only for your related-work section.

**Explanatory resources**

- Maiyya's ORAM lecture slides (Waterloo CS 848) ✅ [PDF](https://cs.uwaterloo.ca/~smaiyya/cs848/slides/ORAM.pdf); includes step-by-step Path ORAM figures.
- Elaine Shi's talk abstracts on tree-based ORAM (Stanford, Purdue CERIAS) ✅ (abstracts only, I did not confirm a public video).

**Repos**

| Repo | Read first |
| --- | --- |
| ✅ [facebook/oram](https://github.com/facebook/oram) (Rust; unaudited; assumes an enclave with memory encryption) | `src/lib.rs` (the `Oram` trait), `src/path_oram.rs` |
| ✅ [obliviouslabs/oram](https://github.com/obliviouslabs/oram) (C++; Circuit ORAM as the non-recursive tree, recursive position map, oblivious map) | `odsl/circuit_oram.hpp`, `odsl/recursive_oram.hpp`, `odsl/omap.hpp` |
| ✅ [sshsshy/ZeroTrace](https://github.com/sshsshy/ZeroTrace) (SGX; Path ORAM and Circuit ORAM backends; oblivious controller via CMOV; GPLv3) | `CONFIG.h` for parameters, then the ORAM controller sources; note how stash/position-map operations use linear scans and conditional moves |

**Mini project (5 days): `oblivion-store`, a Path ORAM block store**

- Rust. Z = 4 buckets, fixed-size AEAD-encrypted blocks, fresh nonce per bucket write, `Backend` trait (memory / file), client-held position map first, recursion second.
- **Acceptance:** (a) 10^6 random reads/writes match a `HashMap` oracle; (b) stash-size histogram logged, max stays small for your N; (c) chi-square/KS test shows the accessed **leaf sequence is uniform and independent of logical addresses** (test workloads: same block 10^5 times vs uniform random blocks; distributions must be indistinguishable); (d) measured bandwidth ≈ 2·Z·(log N + 1) blocks/access; (e) every server-visible message has fixed size.
- Stretch: read Circuit ORAM eviction in obliviouslabs/oram and write a design note on what would change. Skip a full Circuit ORAM implementation unless you're ahead of schedule.

**"Prove it works"**

- Obliviousness test as in (c), and a stronger one: train a classifier on server-visible traces (leaf ids, timing) to predict the logical address or operation type; accuracy must stay at chance.
- Overhead: bytes moved per access, latency p50/p99, client memory (stash + position map).

**Pitfalls**

- Not re-randomizing the leaf on **reads** as well as writes.
- Dummy blocks distinguishable from real ones (must be re-encrypted with fresh randomness).
- Data-dependent branching on stash contents (timing/cache leaks). ZeroTrace uses linear scans and CMOV for this reason ✅.
- Position map recursion leaking, or client storage exploding.
- **No integrity or freshness**: an operator can replay old buckets. Add a Merkle tree or version counters.
- Sequential design: Path ORAM does not parallelize; concurrent clients need a proxy (Snoopy's problem).
- ORAM hides *which* block, not *that* you accessed, nor timing or sizes.

**Interview questions**

- Walk through a Path ORAM access. Why must the leaf be re-assigned on every access?
- Why does the stash stay small? What happens on overflow?
- Bandwidth of Path ORAM vs Circuit ORAM; why Circuit ORAM for MPC?
- What does the Ω(log N) lower bound say, and what does it not say?
- Why can't a single-proxy ORAM scale, and how does Snoopy address that?

**Cut/simplify:** Path ORAM only, non-recursive position map for the MVP. Use the existing Circuit ORAM implementation as a benchmark reference rather than reimplementing it.

---

## 4. Layer 3: Private function invocation via PIR

**Foundational papers**

| # | Paper | Contribution | Skip on first pass |
| --- | --- | --- | --- |
| 1 | Chor–Goldreich–Kushilevitz–Sudan, *Private information retrieval* (1995) ✅ (cited as \[CGKS95\] in the YPIR slides) | Defines PIR; the multi-server information-theoretic constructions, including XOR-based ones. | Lower bounds and generalizations |
| 2 | Henzinger–Hong–Corrigan-Gibbs–Meiklejohn–Vaikuntanathan, *One server for the price of two* (SimplePIR/DoublePIR), USENIX Sec 2023 ✅ [USENIX](https://www.usenix.org/conference/usenixsecurity23/presentation/henzinger) | Single-server PIR from LWE with per-core throughput near memory bandwidth (about 10 GB/s). Cost: an offline "hint" the client downloads (121 MB for a 1 GB DB in SimplePIR, 16 MB for DoublePIR) plus about 242–345 KB per query. | Certificate-transparency application section |
| 3 | Menon–Wu, *YPIR*, USENIX Sec 2024 ✅ [eprint 2024/270](https://eprint.iacr.org/2024/270) | Removes the offline hint at small overhead; about 12 GB/s/core and 2.5 MB total communication on a 32 GB database (per the abstract). | Silent-preprocessing details on a first pass |
| 4 | Related, pick one: Spiral (S&P 2022), OnionPIR (CCS 2021), or Hintless PIR ✅ (all cited by ZipPIR paper) | Contrast points: response size, client state. | Optional |

Also for a two-server upgrade: **distributed point functions** (the standard tool for compact 2-server queries) ⚠ paper not verified this session.

**Explanatory resources**

- USENIX'24 YPIR slides (clear SimplePIR vs Hintless vs YPIR comparison) ✅ [PDF](https://usenix.org/system/files/usenixsecurity24_slides-menon.pdf).
- The SimplePIR paper's introduction is unusually readable; the artifact appendix says the whole implementation is about 1,400 lines of Go plus 200 lines of C ✅.

**Repos**

| Repo | Read first |
| --- | --- |
| ✅ [ahenzinger/simplepir](https://github.com/ahenzinger/simplepir) (Go, MIT; research prototype) | `pir/pir.go` (interface: Setup/Query/Answer/Recover), `pir/simple_pir.go`, `pir/double_pir.go`; the C matmul in the same folder |
| ✅ [menonsamir/ypir](https://github.com/menonsamir/ypir) (Rust; needs AVX-512 CPU per the README) | The README's build/run steps, then the benchmark binary |
| Snoopy (subORAM linear scans are the PIR-adjacent workload): ✅ mirror listing at github.fr/ucbrise/snoopy; canonical path is probably [github.com/ucbrise/snoopy](https://github.com/ucbrise/snoopy) ⚠ confirm | Artifact-evaluation README |

**Mini project (4–5 days): two-server XOR PIR "function registry"**

- DB = padded records (function metadata + encrypted blob pointer). Client builds a random index set S, sends S to server 1 and S⊕{i} to server 2; each returns the XOR of selected records; client XORs the answers. Then the √n communication variant.
- **Acceptance:** (a) correct retrieval on 10^4 × 1 KB records; (b) statistical test that each server's query is uniform regardless of target index i; (c) throughput reported in GB/s; (d) query/answer sizes are fixed.
- Stretch (week 10 in the plan): toy SimplePIR for a small DB; validate against the Go reference on the same DB.

**"Prove it works"**

- Privacy: run the query-distribution test for many i values; also test that timing does not depend on i.
- Correctness of the LWE version: failure rate over 10^5 queries at your parameters must be ≈ 0.
- Overhead: server ms/query vs DB size, communication vs DB size, and the hint size for SimplePIR-style schemes.

**Pitfalls**

- Two-server PIR is private only if the servers **do not collude**. Say this in your threat model.
- LWE parameter mistakes (noise budget vs modulus) cause silent wrong answers.
- Records must be the same size; the server still learns DB size, query timing, and answer size.
- PIR is for **read-mostly** data. Updating the DB invalidates hints and pre-processing; writes belong in ORAM.
- Malicious servers can return wrong answers; PIR alone gives no verifiability.
- Server work is linear in DB size per query in these schemes; do not promise sublinear.
- Query path must not early-exit or cache in an index-dependent way.

**Interview questions**

- Why is 2-server XOR PIR information-theoretically private? What breaks under collusion?
- SimplePIR: what is the hint, why is it reusable, and what does DoublePIR/YPIR trade to shrink it?
- PIR vs ORAM: which for read-only, which for read-write, and why?
- Why does PIR server work scale linearly with database size?
- What does hiding *which function is invoked* via PIR actually achieve if the executor then runs the code? (Ties to tension 1.)

**Cut/simplify:** two-server XOR PIR for the MVP, SimplePIR toy only in weeks 10+. Use YPIR/SimplePIR reference code as a benchmark baseline instead of reimplementing them.

---

## 5. Layer 4: Oblivious execution (fuel-metered WASM, padded runtime, fixed I/O)

Direct literature on "oblivious serverless execution" is thin. This layer is engineering guided by side-channel papers. That is normal; say so.

**Reading list (reading order)**

| # | Item | Contribution | Skip |
| --- | --- | --- | --- |
| 1 | Wasmtime docs, *Interrupting Wasm execution* ✅ [docs.wasmtime.dev](https://docs.wasmtime.dev/examples-interrupting-wasm.html) | Fuel is deterministic (same fuel → same interruption point) but slower; epochs are about 10% overhead but non-deterministic (wall-clock based). | Nothing; short |
| 2 | Wasmtime `Config::consume_fuel` / `Store::set_fuel` API docs ✅ (docs.rs) | Starts with zero fuel; most instructions cost 1; embedder can manually consume fuel to account for host-call costs. | Async yield details |
| 3 | Berkeley View on Serverless, section on oblivious serverless ✅ [arXiv 1902.03383](https://arxiv.org/pdf/1902.03383) | Problem statement: function communication patterns leak even when payloads are encrypted. | Rest of the paper |
| 4 | Trapeze: secure serverless via dynamic information flow control ✅ [arXiv 1802.08984](https://arxiv.org/pdf/1802.08984) | An IFC model for serverless; contrast with your obliviousness approach. | Formal TSNI proof |
| 5 | Side-channel context: *LeakLess* (NDSS'25) and *Everywhere all at once: Colocation attacks on public cloud FaaS* (ASPLOS'24) ✅ (cited in the CCS'25 FaaSGuard poster) | Why co-tenant timing/cache leakage is real in FaaS. | Attack engineering details |

Also see the CCS 2025 poster **FaaSGuard** (obfuscating function activity states in network side channels) ✅ [ACM](https://dl.acm.org/doi/10.1145/3719027.3760729). Swivel (Spectre hardening for WASM) ⚠ and CT-Wasm (constant-time WASM) ⚠ exist as far as I know; verify before citing.

**Explanatory resources:** the Wasmtime book and its `examples/fuel.rs` and `examples/epochs.rs` (referenced from the doc page above) ✅.

**Repos:** I verified only Wasmtime's docs pages, not a repo listing. Use the [Wasmtime repo](https://github.com/bytecodealliance/wasmtime) ⚠ (canonical URL, not fetched) and its `examples/` directory. I could not verify a second WASM-sandbox repo worth recommending; ZeroTrace is your reference for oblivious-primitive style (CMOV/linear-scan) ✅.

**Mini project (4–5 days): `oblivion-exec`, a fixed-shape WASM executor**

- Embed Wasmtime; enable fuel; cap linear memory; fixed-size input/output buffers (length inside the encrypted payload); per-function-class fuel budgets.
- **Padding:** fuel gives a deterministic *instruction* bound; wall-clock is what an observer sees, so also pad completion to a fixed deadline per class using an epoch/timer. Success, out-of-fuel trap, and guest panic must produce identical-shaped responses.
- **Acceptance:** (a) five functions with very different runtimes return same-size responses at the same wall-clock deadline; (b) trap paths indistinguishable in size and timing; (c) a timing+size classifier cannot beat chance by more than your CI; (d) overhead = padded budget / actual cost reported.

**"Prove it works"**

- Use the L7 traffic classifier: features = response latency, size, inter-arrival; label = function id. Accuracy ≈ 1/k passes.
- Also measure cache-warm vs cold (first call after deploy) explicitly.
- Overhead: padding waste (%), throughput per core.

**Pitfalls**

- Fuel is not time. Host functions (I/O, crypto, ORAM calls) cost wall-clock time fuel doesn't see unless you charge it manually ✅.
- Epoch interruption is non-deterministic by design ✅, so don't use it as your correctness bound.
- Module compilation/instantiation time reveals which module you loaded; precompile and use uniform instantiation.
- `memory.grow` and zeroing time depend on size; pre-size memory.
- WASM does not give constant-time execution; secret-dependent branches can leak through cache/timing on shared hosts.
- WASI clocks/randomness/env expose information; strip or virtualize.
- Error messages, logs, metrics, and **billing** (fuel used) are covert channels.

**Interview questions**

- Fuel vs epoch interruption: determinism, overhead, use cases.
- What does "padded runtime" hide, and against which observer?
- Where does the threat model break if the operator sees the WASM bytes?
- How do you make a trap look like a success?
- What is data-oblivious execution and why isn't sandboxing the same thing?

**Cut/simplify:** one runtime (Wasmtime), 3–5 function classes with fixed budgets. Cut cache-side-channel mitigations to a documented limitation.

---

## 6. Layer 5: Epoch-based batching with dummy requests

**Foundational papers**

| # | Paper | Contribution | Skip |
| --- | --- | --- | --- |
| 1 | van den Hooff–Lazar et al., *Vuvuzela*, SOSP 2015 ✅ [PDF](https://davidlazar.org/papers/vuvuzela.pdf), [repo](https://github.com/vuvuzela/vuvuzela) | Rounds with cover traffic from servers; noise gives differential-privacy guarantees for metadata; needs one honest server in the chain. | Dialing protocol details |
| 2 | Grubbs et al., *Pancake: Frequency smoothing for encrypted data stores*, USENIX Sec 2020 ✅ [USENIX](https://www.usenix.org/conference/usenixsecurity20/presentation/grubbs), [eprint](https://eprint.iacr.org/2020/1501) | Makes encrypted accesses uniform via fake queries; claims 229× better throughput than non-recursive Path ORAM in its setting; passive persistent adversary. | Integration with specific KV stores |
| 3 | Snoopy (SOSP 2021) ✅ (see L2) | Epoch-style batching across sharded oblivious stores. | subORAM internals |
| 4 | Oya–Kerschbaum, IHOP (USENIX Sec 2022) ✅, which shows frequency-only leakage can still be exploited when queries are correlated, even against Pancake | Reminds you defenses must be attacked (L7). | Optimization details |

Mix-net side: Loopix (USENIX Sec 2017) ⚠, Stadium/Karaoke ⚠, Pung (PIR-based messaging) ⚠, not verified this session.

**Explanatory resources:** Adrian Colyer's Vuvuzela summary ✅ [blog.acolyer.org](https://blog.acolyer.org/2015/10/23/vuvuzela-scalable-private-messaging-resistant-to-traffic-analysis/); Pancake's USENIX slides ✅.

**Repos:** ✅ [vuvuzela/vuvuzela](https://github.com/vuvuzela/vuvuzela) (Go; read the top-level package for message sizes and dead-drop structure, then the noise generation code); ✅ Snoopy artifact repo (see L3 note). I could not verify a public Pancake implementation. Do not assume one exists.

**Mini project (4 days): `oblivion-batcher`**

- Fixed epoch length E; clients send exactly one fixed-size request per epoch (real or dummy); batcher emits fixed-size padded batches to downstream layers on a fixed schedule.
- Variant B: server-side dummies with noise drawn from a DP distribution (Vuvuzela style) instead of fixed-rate.
- **Acceptance:** (a) observer view (arrival times, batch sizes, destinations) has the same distribution for 0%, 50% and 100% real load (test with a classifier or two-sample test); (b) dummies indistinguishable from real requests (same size, same encryption); (c) latency ≈ E/2 + processing; (d) dummy overhead and stated (ε, δ) for variant B including composition over T epochs.

**"Prove it works"**

- Two-sample test / classifier on traces from different workloads.
- Intersection-style test: simulate users going online/offline across epochs and show what an attacker can infer.
- Overhead: goodput vs dummy ratio; latency vs epoch length.

**Pitfalls**

- Clients that skip epochs leak presence; constant-rate sending is the fix and costs bandwidth.
- Real and dummy requests distinguishable via size, timing, nonce structure, or downstream ORAM/PIR behavior.
- DP budgets degrade under composition across many epochs.
- Batching shape leaks if batch size depends on true load; pad or noise it.
- Active attacks: an operator dropping or delaying specific messages to test hypotheses.
- Epoch boundaries are visible; choose them independent of load.

**Interview questions**

- Fixed-rate vs noise-based dummies: privacy, cost, composition.
- What does Vuvuzela's noise guarantee, and against whom?
- Why does Snoopy batch, and what does batching buy for obliviousness?
- What can an adversary learn from *which epochs* a user participates in?
- How do you evaluate "indistinguishable" empirically?

**Cut/simplify:** fixed-rate + fixed-size batches only (no DP variant) for the MVP.

---

## 7. Layer 6: Privacy-aware autoscaling and cold starts

**Honest status:** I found no canonical paper on privacy-preserving serverless autoscaling. Treat this as the part of Oblivion closest to original research, and scope it as a simulation plus one real mechanism.

**Adjacent reading (reading order)**

1. Berkeley View on Serverless (oblivious serverless open problem) ✅.
2. Vuvuzela: how server-side noise trades cost for privacy ✅.
3. Snoopy: machine provisioning is part of its artifact evaluation, so capacity planning is treated as a measurable cost ✅.
4. FaaSGuard poster (network side-channel obfuscation for function activity) ✅; LeakLess (NDSS'25) ✅ cited.
5. Public serverless workload traces (Azure Functions dataset, ATC'20) ⚠ verify availability before building on it.

**Repos:** none verified for this layer. OpenFaaS/Knative are plausible integration targets but I did not verify their current state, so I am not recommending them. Simulation-first avoids the dependency.

**Mini project (5 days): privacy-aware autoscaler simulator**

- Discrete-event simulator; inputs: workload trace (real if verified, else synthetic Zipf + diurnal); policies: (1) naive reactive, (2) EWMA-smoothed, (3) quantized scale steps + hysteresis, (4) fixed schedule with pre-warmed pool, (5) noise-added scaling signal.
- Adversary observes instance count and cold-start events over time and tries to infer per-epoch load or the hot function class.
- **Acceptance:** for each policy, produce (cost in instance-seconds, p99 latency, attacker accuracy or estimated leakage); at least one policy dominates naive on the leakage/cost plane; outputs feed the L8 Pareto plot.

**"Prove it works"** Attack success vs cost curves; sensitivity to trace burstiness; show that cold-start rate under the private policy is bounded and does not correlate with function identity.

**Pitfalls**

- Scaling on raw queue length or function-specific metrics leaks load.
- Cold starts are a per-function timing signal; uniform pre-warming costs money.
- Billing meters reveal usage; consider fixed-bucket billing.
- Smoothing lag hurts SLOs during bursts; measure tail latency, not just mean.
- Evaluating with a weak adversary (one that doesn't know your policy).

**Interview questions**

- What does an observer learn from instance-count time series?
- How do you trade cost for privacy in scaling, and how would you quantify it?
- Why are cold starts a side channel?
- Compare fixed-schedule scaling with DP-noised scaling.

**Cut/simplify:** simulation only; add one real "pre-warmed pool of constant size" knob to `oblivion-exec` if time allows. Do not build Kubernetes integration.

---

## 8. Layer 7: Leakage-quantification harness

**Papers (reading order)**

| # | Paper | Why |
| --- | --- | --- |
| 1 | Islam–Kuzu–Kantarcioglu (IKK), NDSS 2012 ⚠ | Classic query-recovery from access pattern with known co-occurrence; cited across the field but not fetched this session |
| 2 | Cash et al., CCS 2015 ✅ | Count-style leakage-abuse attacks; a baseline you can reproduce |
| 3 | Zhang–Katz–Papamanthou, file-injection attacks, USENIX Sec 2016 ⚠ | Why forward privacy exists; implement against a non-forward-private baseline |
| 4 | Kellaris–Kollios–Nissim–O'Neill, *Generic attacks on secure outsourced databases*, CCS 2016 ✅ (cited) | Volume/response-length attacks |
| 5 | Oya–Kerschbaum, *Hiding the access pattern is not enough*, USENIX Sec 2021 ✅ [USENIX](https://www.usenix.org/conference/usenixsecurity21/presentation/oya) | MLE attack using search-pattern + access-pattern leakage; breaks two of three access-obfuscation defenses tested in the paper |
| 6 | Oya–Kerschbaum, IHOP, USENIX Sec 2022 ✅ [USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/oya) | Statistical query recovery as quadratic optimization via repeated linear assignment; evaluated even against a frequency-hiding defense (Pancake) |
| 7 | Also cited and relevant: Pouliot–Wright *Shadow Nemesis* (CCS'16), Ning et al. LEAP (CCS'21), Grubbs et al. *Learning to Reconstruct* (S&P'19), Poddar et al. volume attacks (EuroS&P'20) ✅ (all cited in papers I fetched) | Breadth for your related-work section |

**Explanatory resources:** each paper's intro plus its evaluation section (what auxiliary knowledge the attacker gets); the Pancake slides for how defenders frame "attacker knowledge" ✅.

**Repos:** **I could not verify any public attack-code repository** for IKK, IHOP, or the file-injection attack. Check each paper's artifact link and the authors' GitHub pages yourself. Plan to write the attacks. IHOP's optimization step maps to `scipy.optimize.linear_sum_assignment` (the paper describes iterating linear assignment problems ✅), so a from-scratch reimplementation is realistic. The Pancake USENIX page lists no artifact link in what I saw.

**Mini project (5 days): `oblivion-harness`**

- Trace format (JSON/Parquet): timestamp, actor, op type, sizes, server-visible addresses (ORAM leaf ids, shard ids, batch ids).
- Plug-in interface: `Attack.run(trace, aux_knowledge) → predictions`; metrics: accuracy, top-k accuracy, ROC for binary distinctions, CI via bootstrap.
- Ship these attacks: (1) frequency analysis on access patterns, (2) Cash-style count attack, (3) Oya–Kerschbaum-style MLE using search pattern, (4) IHOP-lite, (5) file-injection vs a non-forward-private baseline, (6) traffic-analysis classifier (packet sizes/timing → function id).
- **Acceptance:** every attack has a **positive control**: it succeeds well above chance on a deliberately leaky baseline (plaintext-index SSE, unpadded ORAM traces, unbatched invocations). Only then run it against Oblivion configs. Seeds fixed; results reproducible with one command.

**"Prove it works"**

- Positive control first, then defended system, then vary knobs (epoch length, padding, dummy rate).
- Report leakage as **attack success at a stated attacker-knowledge level**. If you also report bits, use a classifier-based or nonparametric mutual-information *estimate* and label it a lower bound under the chosen feature set.

**Pitfalls**

- Reporting "attack fails" without a positive control. It may just be buggy.
- Attacker too weak (unaware of your batching schedule or padding budget). Assume Kerckhoffs.
- Train/test leakage in ML-based attacks (same session in both splits).
- Using easy synthetic data only; add a realistic corpus (Enron email is the traditional SSE-attack dataset ⚠ check current availability and licence).
- Claiming "0 bits leaked".

**Interview questions**

- Distinguish access pattern, search pattern, volume, and timing leakage.
- Why do known-document attacks need auxiliary information, and what does that imply about your threat model?
- How do you validate a negative result?
- Why does Oya–Kerschbaum say hiding the access pattern isn't enough?
- How would you estimate leakage in bits, and what are the caveats?

**Cut/simplify:** MVP harness has frequency analysis, a traffic classifier, and one SSE attack. Add the rest in weeks 11–12.

---

## 9. 14-week milestone plan

| Wk | Focus | Deliverable |
| --- | --- | --- |
| 1 | Prereqs P1–P3, P10; threat model v0 (pick A/B/C); repo skeleton; trace format | Design doc stub, CI running |
| 2–3 | **L2** Path ORAM | `oblivion-store` passes obliviousness tests |
| 4 | **L3** two-server XOR PIR | `oblivion-pir` + registry lookup |
| 5 | **L4** fixed-shape WASM executor | `oblivion-exec` with padding tests |
| 6 | **L5** epoch batcher (fixed-rate) | `oblivion-batcher` |
| 7 | Integration + **L7 v0** (frequency analysis + traffic classifier, positive controls) | End-to-end request path |
| **8** | **★ Smallest impressive version.** Client → batcher → PIR function lookup → padded WASM execution → ORAM state; leakage harness shows before/after on two attacks; threat model v1 with honest limits; benchmark plots v1 | Demo, README, 2–3 page design doc |
| 9 | **L1** Diana-lite | `oblivion-sse` integrated as encrypted keyword index over function metadata |
| 10 | **L3+** SimplePIR toy; compare to reference | Single-server option |
| 11 | **L7** full attack set (Cash, Oya–Kerschbaum, IHOP-lite, file-injection) | Attack results table with positive controls |
| 12 | **L6** autoscaler simulator; optional pre-warm knob | Policy comparison data |
| 13 | Benchmark sweep, Pareto analysis, ablations | Final figures |
| 14 | Writeup, threat model v2, talk/demo video, cleanup, related work | Public repo + report |

**If you run out of time:** weeks 1–8 are a coherent project. Layers 1, 6 and the fuller attack set are the cuttable ones.

---

## 10. Benchmark design

**What to measure**

| Axis | Metrics | How |
| --- | --- | --- |
| Latency | p50/p95/p99 end-to-end; per-layer breakdown | Open-loop load generator; warm-up excluded; 30+ runs |
| Bandwidth | bytes per real request (client↔server, server↔server), blowup vs plaintext | Count at the wire |
| Compute | CPU-seconds per real request, padding waste | Per-layer counters |
| Cost | $/million invocations from instance-seconds × price, plus egress | Use a stated price sheet; report the assumption |
| Privacy | attack success at stated attacker knowledge (accuracy vs chance), classifier-based MI estimate, DP ε where applicable | L7 harness |
| Robustness | behavior under bursts, epoch skips, dropped messages | Fault injection |

**Baselines:** (1) plaintext serverless, (2) encrypt-only (data encrypted, patterns visible), (3) each layer alone, (4) full Oblivion. Ablation = turn layers off one at a time.

**Sweep knobs:** epoch length, batch size, dummy rate, fuel/deadline budgets, ORAM Z and block size, PIR scheme, autoscaler policy.

**Pareto presentation**

- Plot **latency (x) vs cost (y)**, with point color or size = attack success (lower is better). Draw the non-dominated frontier per attack model.
- Add a second panel: **attack success vs cost** at fixed latency SLO.
- Always include the two extremes (plaintext, max-padding) so the reader sees the range.
- Report CIs; state attacker knowledge next to every privacy number.

---

## 11. Threat model and design-doc template

1. **Goal and scope.** One paragraph: what Oblivion protects, for whom.
2. **System model.** Components, trust boundaries, data flow diagram; which layer runs where.
3. **Assets.** Function code, inputs/outputs, keywords/metadata, which function is invoked, invocation timing and volume.
4. **Adversary.** Capabilities: controls network, storage, scheduler, billing; passive vs active; collusion bound (e.g., 2-server PIR non-collusion); can it read executor memory (choose A/B/C from §0)? Can it drop/delay/replay? Persistent (many epochs) or snapshot?
5. **Security goals.** Stated as leakage functions, e.g., L_setup, L_update, L_query, L_exec, L_scale: exactly what the server may learn.
6. **Assumptions.** Crypto (LWE, PRF, AEAD), non-collusion, TEE integrity, client state honesty, clock assumptions.
7. **Mechanisms per layer.** One paragraph each plus its residual leakage.
8. **Attacks evaluated.** List with attacker-knowledge level; link to harness results.
9. **Evaluation summary.** Pareto figure; positive-control table.
10. **Non-goals.** Availability against a malicious operator, hardware side channels beyond what you test, etc.
11. **Open issues.**

**What a malicious operator can still learn (honest limits)**

| Channel | Still visible unless mitigated |
| --- | --- |
| Existence and rate of use | That a client is active, connection metadata, epoch participation |
| Volume | Total data size, upper bounds on record counts, batch sizes if not padded, epoch-level load (or only DP-noised) |
| Timing | Epoch cadence, latency distribution, cold starts, billing meter |
| Search pattern | Repeated identical queries in SSE unless obfuscated (Oya–Kerschbaum) |
| Compute | Under models B/C, the code and its execution; under A, TEE side channels |
| Collusion | Two colluding PIR servers reveal the queried index |
| Active attacks | Selective dropping/delaying, rollback/replay of storage state, denial of service |
| Long-term | Intersection and composition across many epochs |

---

## 12. Groups, courses, and open-source to follow

**Research groups (authors of the papers above; find current pages yourself)**

- UC Berkeley: Raluca Ada Popa (co-founder/co-director of RISELab and SkyLab per her bio), Natacha Crooks, Emma Dauterman (Snoopy) ✅
- MIT: Henry Corrigan-Gibbs, Vinod Vaikuntanathan, Alexandra Henzinger (SimplePIR) ✅
- Cornell / Cornell Tech: Thomas Ristenpart, Paul Grubbs (Pancake; Paul's later affiliation ⚠), Rachit Agarwal ✅ (Cornell page)
- University of Waterloo: Florian Kerschbaum and Simon Oya (SSE attacks); Sujaya Maiyya (ORAM/oblivious datastores) ✅
- UT Austin: David Wu; Blyss (Samir Menon, YPIR) ✅
- Inria/ENS: Brice Minaud; Raphael Bost (Sophos, Diana, Janus, OpenSSE) ✅

**Courses**

- Stanford CS 355 (Topics in Cryptography), Spring 2026 ✅ [cs355.stanford.edu](https://cs355.stanford.edu). Prereq CS 255 or equivalent.
- MIT, Berkeley (CS 276 / CS 261 and special-topics crypto or systems-security courses) ⚠ I did not verify current offerings; check the departments' course listings.

**Open-source to read or contribute to:** OpenSSE ✅, facebook/oram (Rust; unaudited, so there's room for tests/docs/issues) ✅, obliviouslabs/oram ✅, ZeroTrace ✅, SimplePIR ✅, YPIR ✅, Snoopy ✅, Vuvuzela ✅. Contribution ideas that fit an internship narrative: a leakage-test suite for facebook/oram, an obliviousness statistical test harness, or a Rust port/benchmark of Diana.

---

## 13. Venues to follow

| Venue | Notes (dates verified where marked ✅) |
| --- | --- |
| USENIX Security | 2026 was Aug 12–14, Baltimore ✅ [usenix.org](https://www.usenix.org/conferences/usenixsecurity26). 2027: Aug 11–13, Denver ✅. Home of SimplePIR, YPIR, Pancake, Oya–Kerschbaum ✅ |
| ACM CCS | 2026: The Hague, Nov 15–19 (per Dec 2025 IEEE Cipher listing) ✅. Home of Sophos, Diana/Janus, Path/Circuit ORAM, IKK-style follow-ups ✅ |
| NDSS | 2027: Seoul, Mar 22–26 (aggregator listing) ✅. SSE attacks/defenses appear here |
| IEEE S&P | Spiral, Oblix, Learning to Reconstruct ✅ (cited); I did not verify the 2027 dates ⚠ |
| Systems venues | SOSP (Snoopy) ✅, OSDI (Obladi ✅; OSDI '27 Jul 7–9, Baltimore ✅), NSDI '27 May 11–13 ✅ |
| Privacy/crypto | PETS 2027 (Delft, Jul 19–24 ✅ per aggregator), PEPR '27 Jun 7–8 ✅, IACR ePrint (Cryptographic protocols category) for preprints such as SONIC ✅ |

How to follow: set arXiv/ePrint keyword alerts for "oblivious RAM," "private information retrieval," "searchable encryption," "leakage-abuse"; skim USENIX/CCS/NDSS accepted-paper lists each cycle; read artifact appendices (USENIX publishes them) for reproducible code.

---

## 14. Verification appendix

**Unverified this session (⚠), search before citing:** IKK (NDSS 2012); file-injection paper (USENIX Sec 2016); Janus++/other SSE follow-ups; distributed point function paper; Loopix, Stadium, Karaoke, Pung; Swivel; CT-Wasm; Azure Functions trace; Boneh–Shoup/Dwork–Roth/Peikert links; MIT/Berkeley course pages; S&P 2027 dates; Snoopy canonical GitHub path; Wasmtime repo URL (docs verified, repo not fetched); Enron dataset availability.

**Searched for and not found:** public attack-code repos for IKK/IHOP/file-injection; a public Pancake implementation; a canonical paper on privacy-preserving autoscaling.