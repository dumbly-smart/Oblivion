# Unimplemented extension design notes

21 October 2026. These sketches preserve optional roadmap work and clarify where the current construction would need to change. They are not implemented features, security proofs or accepted benchmark comparisons.

## Backward privacy and a Janus-inspired direction

The CCS 2017 [Bost–Minaud–Ohrimenko paper](https://acmccs.github.io/papers/p1465-bostA.pdf) distinguishes backward-privacy strengths and develops Janus using puncturable encryption. Its objective concerns what later searches expose after deletion, separately from forward privacy of new updates. It does not erase information already learned by an observer.

The present append-only index has neither deletions nor this property. Filtering deleted IDs at the client would still expose their old server addresses and response volume. Merely rotating future GGM roots would not revoke all previously released capabilities. Calling either operation backward privacy would be incorrect.

A future design would first select a precise deletion leakage function and threat model, then use a reviewed revocation/puncturing construction rather than inventing a modified AEAD. The client would require authoritative durable deletion/version state, exact retries, atomic mutation ordering and rollback protection. Tests would retain every historical request/ciphertext, delete/reinsert overlapping IDs and distinguish newly authorized results from old exposed information. Volume, deletion timing, rebuilds and update-to-search correlations must be recorded. This is a proposed engineering evaluation plan; it is not a claim that puncturing alone solves malicious-server security, client compromise or persistence.

The simpler permitted roadmap deliverable is this explanatory sketch. Implementing a backward-private scheme would require independent construction review and benchmarks; no Janus code is copied from OpenSSE.

## Circuit ORAM eviction comparison

[Circuit ORAM, ePrint 2014/672](https://eprint.iacr.org/2014/672), targets efficient oblivious circuits. The current store uses Path ORAM's full-path fetch/remap and deepest-first placement in ordinary trusted Rust structures. Replacing that placement with a different algorithm would require rechecking correctness, stash behavior and observable controller behavior; changing a function name would not reproduce Circuit ORAM.

A bounded future comparison would retain identical block/database/workload geometry, measure actual communication and stash distributions, and separately count circuit gates or oblivious-memory work where the deployment needs them. Ciphertext integrity/freshness, nonce management and failure poisoning must survive the new eviction path. Conditional moves/linear scans would need concrete controller implementation and compiler/side-channel analysis before claiming an oblivious controller. The existing 30-trial Path ORAM size study provides baseline data, not evidence for Circuit ORAM performance.

## Recursive position map and durability boundary

Today the position map and bucket versions occupy O(N) trusted state. Recursion would store map entries in smaller ORAMs until a bounded top map fits in trusted memory. Every logical access then induces map accesses at multiple levels, so bandwidth/latency accounting must include the whole recursion chain. This is a proposed extension and not a claim about current asymptotics.

A prototype must specify packed map-entry format, per-level geometry/keys/nonces, top-map memory, namespace translation, initialization and invariant checks. It also needs one authenticated checkpoint generation across all levels. A partial update or mismatched restore across levels must fail closed; independently restoring each level can corrupt address knowledge. An external latest-handle anchor still controls freshness. Recursion does not solve whole-anchor replay, multiple writers or durable invocation acknowledgments.

Priority remains completing the accepted current-system evaluation. These extensions should be compared on measured deployment goals rather than treated as automatic improvements.
