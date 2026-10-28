# Persistent SSE journal size and recovery benchmark — preregistration

**Status:** design and configuration frozen before collection. No benchmark result is claimed in this document.

## Question

How do encrypted client-journal bytes and restart-recovery latency change as the persistent SSE client tracks more distinct keyword/document postings when every update uses the real local Unix anchor service?

This is an engineering performance characterization of the existing persistent journal. It does not measure a remote storage provider, cold disk cache, physical flash writes, or privacy against a search-pattern attacker.

## Frozen configuration

The machine-readable configuration is [sse-persistent-journal-benchmark-20261028.json](../experiments/configs/sse-persistent-journal-benchmark-20261028.json):

- Index sizes: 64, 257, 1,024, and 4,093 postings.
- 30 independent index-build trials per size.
- Five recovery repetitions per completed index; each recovery uses a new OS process.
- A fixed seed of 20,261,028 shuffles the size order within each trial. Workload values themselves use deterministic enumeration.
- Runtime storage keys, index IDs, journal AEAD nonces, and the per-run anchor namespace use the OS CSPRNG. These are not derived from the schedule seed.
- Each posting uses a distinct deterministic ASCII keyword and a distinct zero-based 64-bit document ID. The same actual `oblivion-sse::Server` receives and stores the prepared update.
- The index uses default bounded SSE limits. All selected sizes are below both the 100,000-posting and 10,000-keyword limits.
- The journal checkpoints every 256 persistent mutation events. Each posting has a prepare and finish mutation; initial generation zero is also a full checkpoint.

## Measurement boundary and metrics

The primary write metric is the sum of immutable encrypted journal record file lengths at the moment they are created. It includes the initial checkpoint, delta records, and full checkpoints even when an old record is later pruned. The reported application-level byte amplification divides those bytes by the logical input definition: UTF-8 keyword bytes plus the eight-byte document identifier for each posting.

This is **not** physical disk write amplification. It excludes filesystem allocation/metadata, directory-sync implementation costs, the anchor SQLite database/WAL bytes, block-device behavior, and any storage-controller amplification. The runner records retained journal file count/bytes separately after checkpoint pruning.

The runner times `prepare_add`, the actual `Server::insert`, and `finish_add` separately. The persistent-client API timings include client-side serialization/encryption, the durable journal file write and sync, and the Unix anchor call where applicable. They are not pure cryptographic CPU timings.

For recovery, the parent launches a fresh copy of the benchmark executable for each repetition and sends the client storage key over that child's stdin pipe; the key is not put in arguments or output. The child times creation of the Unix anchor client and `PersistentClient::open`, including anchor lookup, frame read, authentication, state validation, checkpoint load, and bounded replay. The parent separately records total process-launch-to-exit duration. The OS page cache is not flushed, so this is a fresh-process recovery measurement with potentially warm file cache, not cold-storage recovery.

The independent statistical unit is an index-build trial. Five process opens nested within one completed index are repeated measurements, not five independent datasets. The report includes raw per-trial observations, descriptive p50/p95/p99 summaries, and a deterministic 5,000-resample percentile bootstrap interval for the mean of trial-level summaries. Pooled per-operation quantiles are descriptive and are not treated as independent observations.

## Integrity and failure policy

- Use the real `oblivion-anchor serve` binary and the actual `UnixAnchorClient::sse_journal` adapter; do not replace it with an in-memory test anchor.
- Use a new output directory. The runner refuses an existing path.
- Every successful persistent mutation must create exactly one immutable record. The collector counts only a new final `.journal` record path; failure to observe exactly one is a failed sample, not a zero-byte result.
- Any anchor error, journal error, child exit, generation mismatch, or malformed output fails the run. Do not omit failed samples from the summary.
- Keep the anchor master key and all test client keys out of results. The client key is transferred to the recovery child through a private process pipe and the temporary private work directory is removed after collection.
- The report records config, source revision when available, tracked-tree status, toolchain, platform and CPU model. Raw benchmark records remain in `report.json`.

## Reproduction

Build the benchmark and anchor service:

    cargo build --locked --release -p oblivion-anchor --bin oblivion-anchor
    cargo build --locked --release -p oblivion-sse --bin sse-journal-benchmark

In one terminal, provision a temporary owner-only anchor key and start the real local service:

    umask 077
    openssl rand 32 > target/sse-anchor-master.key
    target/release/oblivion-anchor serve target/sse-anchor.sock target/sse-anchor.sqlite target/sse-anchor-master.key

In another terminal, run the frozen configuration into a new output directory:

    target/release/sse-journal-benchmark run target/sse-anchor.sock experiments/configs/sse-persistent-journal-benchmark-20261028.json experiments/results/sse-persistent-journal-benchmark-20261028

The command is for first collection; the actual result path may never be overwritten. Stop the service after collection and securely manage or delete the temporary key/database according to the local research environment's policy.

## Limits

This experiment covers one synthetic update pattern, one host, the local SQLite-backed anchor, and the current implementation/configuration. It does not establish production capacity, remote filesystem latency, cold boot recovery, distributed concurrency, rollback resistance, a backward-privacy property, or general storage amplification. The local anchor's SQLite database can still be rolled back by a privileged host operator.
