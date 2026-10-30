# Historical mixed instrumentation — exclude from attacker input

This preserved campaign predates the client timing separation fix. Its files
named `envelope-observer.jsonl.gz` contain trusted client readiness and derived
queue/arrival timing. Those fields were not observable at the untrusted batch
pipe before client emission. Do not use these files as attacker input, or as
acceptance evidence for the corrected strict observer/private schema.

The scoped performance measurements, original raw data, executable, source
snapshots and original artifact hashes remain preserved. The recovery audit
predates the correction. The intermediate `../epoch-system-separated-20261023/` campaign separates
fields but timestamps client-consumer receipt. Current reader-thread pipe
timestamps are measured independently under
`../epoch-system-pipe-timestamps-20261023/`.

This explanatory sidecar was added after the original artifact manifest; no
original manifest entry or recorded raw byte was changed.
