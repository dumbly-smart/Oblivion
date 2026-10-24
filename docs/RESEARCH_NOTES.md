# Research notes and decisions

Updated 2026-10-24. Current status and acceptance evidence are maintained in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and [REQUIREMENTS_MATRIX.md](REQUIREMENTS_MATRIX.md). Historical results retain their launch-time source hashes.

## Specification reconciliation

The supplied roadmap was initially missing, then supplied during this session and read in full before subsystem implementation. Its Week 8 scope was prioritized. Research motivations, seven layers, prerequisites, experimental controls, later extensions, and limitations remain requirements rather than being replaced by a different project. The complete user instructions refine the roadmap where scientific acceptance criteria would otherwise require a positive result.

| Roadmap area | Current treatment |
| --- | --- |
| Prerequisites/security games/leakage functions | Assumptions and observation scopes documented; no new proof is claimed |
| L2 Path ORAM | Actual non-recursive encrypted store; memory/file backends, position map/stash, live-session freshness, externally anchored full checkpoints and fresh-key restore |
| L3 PIR | Actual XOR and generic authenticated geometry-bound transport; large TCP/process tests. Genuine pinned SimplePIR reference comparison exists separately from runtime |
| L4 execution | Five real WASM functions, resource classes, public staged storage schedule and namespaces; no TEE/constant-time claim |
| L5 epochs | Fixed rate/shape queues and cover/dummy processing; DP variant deferred as specified |
| Week 8 integration/L7 | Actual local path; component attacks with positive controls; full-transcript and larger integration evaluation pending |
| L1 SSE | Actual bounded ephemeral constrained-GGM component and 100,000-operation oracle; Diana-inspired label, no exact theorem-port or backward-privacy claim |
| L6 scaling | Five-policy default plus optional event-level Laplace analysis, known-seed attacks, four-budget sweep and a separate OS-CSPRNG public-feature study; no runtime scaling or formal DP claim for either implemented sampler |
| Weeks 10–14 research | Genuine reference PIR and scaling simulations recorded; metadata integration, full attack suite, system sweeps/ablations and final writeup still require acceptance evidence |

The roadmap's autoscaler acceptance asks for a policy that dominates naive scaling. Whether such a policy exists depends on workload, attacker and cost model. A future implementation must report negative results rather than force that outcome. Likewise, statistical non-rejection in the ORAM/execution acceptance criteria is interpreted as finite empirical evidence, never a proof.

## Primary sources checked

- Stefanov et al., [Path ORAM, arXiv:1202.5150v3](https://arxiv.org/html/1202.5150v3), especially initialization, access protocol, and invariant. Construction details were checked against this primary source.
- [facebook/oram](https://github.com/facebook/oram), including its [trait](https://raw.githubusercontent.com/facebook/oram/main/src/lib.rs) and [Path ORAM implementation](https://raw.githubusercontent.com/facebook/oram/main/src/path_oram.rs). Its enclave-memory-encryption assumption is material: it does not itself encrypt bucket writes. Oblivion instead explicitly AEAD-encrypts the bucket interface. Its oblivious client structures and recursion are not reproduced here. No source code was copied.
- Official [Wasmtime interruption documentation](https://docs.wasmtime.dev/examples-interrupting-wasm.html), [Config](https://docs.rs/wasmtime/49.0.4/wasmtime/struct.Config.html), and resource-limit APIs. Local Wasmtime 49.0.4 sources were checked for owned/static host state and current resource-limiter signatures. This dependency requires Rust 1.96; the workspace declares that minimum.
- RustCrypto [ChaCha20-Poly1305 documentation](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/). The implementation uses the established library, not a homemade primitive.
- Ghosh, Roughgarden and Sundararajan, [Universally Utility-Maximizing Privacy Mechanisms](https://timroughgarden.org/papers/priv.pdf), especially the two-sided geometric count mechanism and its neighboring-count probability-ratio argument. This supports the ideal discrete mechanism derivation for sensitivity-one counts, not the finite-precision Python sampler in this repository.
- OpenDP's [discrete additive-noise guide](https://docs.opendp.org/en/stable/api/user-guide/measurements/additive-noise-mechanisms.html) and [`make_laplace` API](https://docs.opendp.org/en/stable/api/python/opendp.measurements.html) describe integer-domain discrete Laplace sampling and a proof interface. The current Python API marks the constructor as `contrib`; it was not added as a runtime dependency. OpenDP remains a candidate for a separately reviewed exact-discrete backend.
- [Verified Foundations for Differential Privacy](https://doi.org/10.1145/3729294) provides machine-checked sampler proofs, including discrete Laplace. This supports the feasibility of verified samplers; it does not verify Oblivion's sampler or establish a guarantee for its generated traces.

The roadmap's complete literature list has **not** been independently verified. SSE construction/source verification is now recorded in SSE_DESIGN.md and the genuine reference pin/license in SIMPLEPIR_REFERENCE.md. Attack algorithms/artifacts, recent ORAM follow-ups, external datasets/licensing and the broader literature still require targeted verification before use. No published IKK, IHOP, Cash or Diana reproduction is claimed. No external dataset was used.

## Engineering decisions

- Whole-bucket AEAD makes dummy/real slots indistinguishable in representation and fixes each bucket's length. Nonces are unique counters, not random nonce samples. Fresh per-controller keys and one-way nonce state are required.
- Trusted per-bucket version counters provide a simple explicit active-session freshness mechanism. This costs O(N) trusted memory in addition to the position map. AEAD alone would not detect replay. Durable trusted-state rollback remains unsupported.
- Authentication validates a full old path before remapping, permitting placement checks under the previous position map. Eviction choices are computed deepest first; physical writes use root-to-leaf order. This preserves fixed path shape while keeping failure semantics explicit.
- After uncertain failure the controller is invalidated. The current full-image checkpoint API validates against an external trusted handle and rekeys on restore. It does not implement the external freshness-anchor publication or durable invocation acknowledgement protocol; silently retrying uncertain live state remains unsafe.
- A shared owned ORAM handle satisfies Wasmtime's host-state lifetime requirements and serializes guest calls without unsafe code.
- Discovery occurs after batch release inside the trusted executor, which already knows executed code under Model A. This avoids unscheduled discovery traffic. Queries to both PIR workers use distinct AEAD channel keys; the generic plaintext CLI remains explicitly isolated from that guarantee.
- Trusted namespaces separate enrolled real/dummy state. In one-client mode real addresses 0..6 and dummy block 7 are separate; multi-client mode assigns one real and one dummy block per slot. Unknown selections return protected errors with sanitized actual-component dummy work.
- Queue cover for missing participants is random ciphertext, not a forged authenticated request. Equivalent downstream handling belongs to the trusted pipeline. The source now enrolls one to four participants and tests mixed all-five-function state isolation; full active-fault and joint inference campaigns remain separate requirements.

## Review findings and corrections

A read-only independent review found that unknown authenticated function IDs could fall through to stateful code, and that real inputs could address the dummy block. Regression tests now verify rejection and non-mutation of user state. Review also identified that classifier targets sharing a fitted profile must remain clustered in uncertainty estimation. Analysis now bootstraps equal-weight trial means. The initial session-bootstrap smoke analysis is preserved in an explicitly superseded subdirectory; raw traces were reanalyzed.

## Scientific limits

The frequency attack uses only persistent visible tags plus known popularity order. The traffic attack is a supervised decision stump over application response size and local component latency with independent profiling sessions. These are deliberately simple positive-control attacks. They do not assess all timing features, joint interfaces, adversarial faults, cold starts, caches, billing, or scaling.

Statistical confidence intervals estimate variation under the tested synthetic workload/attacker. Perfect positive-control accuracy with a degenerate bootstrap interval does not prove perfect generalization. Three-trial smoke runs provide weak uncertainty estimates. The 30-trial configuration supplies more independent retrained attacks; it still cannot imply cryptographic security.

Measurements are from a shared host without CPU pinning. Private state byte fields are payload/metadata formulas, not full RSS or allocator measurements. Local bucket and application payload sizes are not TCP packet captures. Actual seeds, configs, source fingerprints, toolchain and hardware data accompany the scripted runs. Secure runtime randomness prevents exact ciphertext/leaf replay; seeded logical workloads remain reproducible.

## Current composition decisions

Protected execution stages a public working set and performs M actual ORAM reads and M writes at public read/commit phases. Guest traps discard staged mutations; physical commit failure is still uncertain and poisons the ORAM controller. This improves guest-dependent storage shape at O(M log N) bandwidth and bounded trusted staging memory. It does not remove scheduler/resource/cache/failure leakage. Current demo class and epoch values are 100 ms and 150 ms per participant; historical D20 measurements used smaller budgets and two direct ORAM accesses per invocation.

The reference PIR adapter executes the unmodified pinned upstream with real hint generation and matched eight-byte records. Offline setup, online operations and payload sizes are accounted separately. The autoscaler simulator uses actual queue/readiness/completion events but synthetic durations and arrivals. Fixed-capacity inference/cost improvements have SLO tradeoffs; no universal policy superiority is claimed.
