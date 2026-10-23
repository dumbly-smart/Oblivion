# Historical client-consumer timing — not pure pipe-read timestamps

This campaign correctly separates client readiness/queue/arrival fields into
`client-private-latency.jsonl.gz`, but its public `latency_ns` was timestamped
by the main client after receiving a frame from an internal channel. A delayed
consumer can therefore include previous-slot private decryption, oracle or
logging work. Do not use these timing fields as pure batch-pipe/network
observer timing, or as acceptance for the current reader-thread boundary.

The performance measurements remain valid for their declared client-consumer
receipt boundary. All original raw files, source/binary snapshots, manifests
and recorded hashes are preserved. The final implementation carries an Instant
captured in the response reader immediately after read_exact and before channel
send; its independent campaign is ../epoch-system-pipe-timestamps-20261023/.

This explanatory sidecar was added after the original artifact manifest. No
original manifest entry or measured byte was rewritten.
