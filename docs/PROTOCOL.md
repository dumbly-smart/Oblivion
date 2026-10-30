# Protocols and trace schemas

## Authenticated envelope v2

All integers are big endian. Exactly 228 bytes:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII OBLV |
| 4 | 2 | Version 2 |
| 6 | 1 | Direction 1 request / 2 response |
| 7 | 1 | Reserved zero |
| 8 | 8 | Epoch |
| 16 | 4 | Participant/channel slot |
| 20 | 192 | AEAD ciphertext |
| 212 | 16 | Authentication tag |

The header is AEAD associated data. Nonce = slot u32 || epoch u64, derived rather than transmitted. HKDF-SHA256 separates request/response keys from a fresh OS-random 32-byte session root. Sending epochs increase strictly; receiving authenticated epochs increase strictly. Failed authentication does not advance receive state. No endpoint cloning or persisted restore is provided. Bootstrap APIs assume a fresh trusted inherited pipe; recording/replaying bootstrap secrets is unsupported.

The demo uses distinct fresh roots for the client/executor channel and each PIR link. Its protected PIR query payload pads the one-byte vector for five records to 128 bytes; its answer is one 160-byte signed registry record. This transport is deliberately limited to the demo registry. Generic large-database PIR remains a separate interface.

Invocation payload v2: real flag at 0, registry index u32 at 1..5, input[64] at 5..69, invocation ID[16] at 69..85, Ed25519 public key[32] at 85..117, signature[64] at 117..181, and 11 reserved zero bytes at 181..192. The signature authenticates a domain-separated SHA-256 digest over payload bytes 0..69 and the endpoint slot. The worker validates it after channel AEAD authentication; invalid signatures, noncanonical reserved bytes, or a mismatched slot make the request invalid and force the fixed-shape cover path. When the optional local anchor is configured, a valid identity is used to look up a receipt before execution and atomically commit a new encrypted whole-store checkpoint with the fixed 192-byte response payload. A receipt hit runs the reserved cover function and returns the stored response. New invocations require a stable client key and ID to retry across process restarts; the built-in demo currently generates ephemeral identities per run. Same-ID concurrency is not fenced, non-ORAM side effects are not transactional, and SQLite rollback remains possible. The worker discovers the registry index through PIR after epoch release and compares the full recovered record with its locally pinned, startup-verified catalog. A registry record is 160 bytes: id u32, version u64, module digest[32], location digest[32], resource class u8, 19 reserved zero bytes, and an Ed25519 signature[64]. The demo's module-location digest is a synthetic embedded-module descriptor. All five modules are preloaded from trusted bundled sources; external publication and signer identity are not implemented.

## Secure PIR worker database bootstrap v1

Before endpoint-key bootstrap, the executor writes `OBLPIR01`, record count u32 BE, record width u32 BE, and the fixed-width record array to each worker's inherited stdin. The worker checks count, width and total-byte bounds before allocating, reads exactly the declared database, then accepts the authenticated endpoint bootstrap. The integrated demo sends five 160-byte signed rows. This is local process provisioning, not an independently authenticated remote registry service.

Response payload: internal success/failure flag at 0, class output[64] at 1..65, zero padding. The flag is encrypted and never placed in observer traces. Valid dummy responses clear the output but execute the actual stateful function on reserved block 7.

## A–G loopback invocation harness v1

`oblivion-harness system-tcp CONFIG NEW_OUTPUT_DIRECTORY` runs the A–G
component experiment with one controller process and a fresh worker child for
each mode/session. This is a separate research harness path; it is not the
signed-registry demo protocol described above. The worker binds only to
`127.0.0.1` on an ephemeral port and accepts one client connection. It prints
`READY <loopback-address>` before reading the channel bootstrap. The controller
passes the fresh 32-byte channel root through the child's inherited stdin pipe;
the root is never sent on TCP. If startup or an invocation fails, the
controller closes the socket and kills/reaps the child.

Each TCP application frame is `u32_be(body length) || body`. The four-byte
prefix is checked against the exact mode-specific body length before allocating
or reading the body. The controller applies the same check to the expected
response shape. An empty frame, partial prefix/body, or wrong fixed mode length
is rejected. Each prefix-plus-body read has one absolute 30-second deadline;
trickling bytes cannot renew it. Mode A sends the legacy harness's 192-byte
plaintext request body; its deliberately leaky response is 65 bytes for the
echo function and 5 bytes for the stateful function or a dummy. Modes B–G send
and receive the 228-byte authenticated envelope body. The socket wire lengths
add four bytes for the prefix. Modes E and G send one envelope for every
scheduled opportunity, including dummies; unbatched modes send no request for
a dummy opportunity.

The child performs the harness's actual registry lookup, two-share XOR PIR
operations when enabled, Wasmtime execution, direct or Path ORAM state access,
response masking and fixed-deadline wait. The two PIR server objects remain
inside the trusted worker process for this harness, so this run does not create
independent non-colluding PIR operators. The ORAM backend is the harness's
memory backend with a local storage trace, not a remote storage RPC. Only the
invocation boundary uses TCP.

`socket-observer.jsonl` is the worker-side application socket trace: version,
observer, direction, public sequence, framed byte count, local monotonic
elapsed time, and raw frame body. It has no ground-truth label or step field.
Mode A's raw body intentionally exposes the dummy bit and requested function
to demonstrate its positive-control leakage. Modes B–G contain authenticated
ciphertext. `observer.jsonl` and `storage-observer.jsonl` contain the harness's
visible registry/storage observations; `private.jsonl` holds worker timing and
private store statistics; `ground-truth.jsonl` is written by the controller.
The files share an output directory and filenames do not enforce access
control, so the directory is an experimental bundle, not a deployed trust
boundary.

The system harness submits only valid generated invocations. A malformed frame,
authentication failure, invalid function identity, or failed execution closes
the worker session without an application response; this loopback path does
not implement uniform external error responses for adversarial requests.

These are application socket observations from two local processes. They are
not packet captures, remote-network arrival times, host/cache telemetry,
independent operator separation, TEE measurements, or an attack result. No
privacy conclusion follows from the transport implementation or its
correctness test alone. A new attack using these traces requires a separate
preregistration and successful positive controls.

## Standalone generic PIR wire v1

`oblivion-pir::wire` uses a 16-byte OBLP header: magic[4], version u16, kind u8, reserved zero, record count u32, record width u32. Query body is ceil(count/8) bytes; answer body is exactly record width. Exact configured headers are checked before allocation. One query per connection, bounded timeouts. Unused query bits remain random and are ignored by the server.

This standalone transport is plaintext and loopback-restricted by its CLI. It simulates each individual server's view; a joint network observer can recover selection. The integrated demo uses the AEAD transport above instead. Neither standalone PIR nor XOR recovery authenticates registry contents; the integrated executor verifies the signed catalog before startup and checks each recovered row against that verified local pin.

## ORAM bucket interface

A successful logical access reads then writes height+1 buckets, in root-to-leaf physical order. Each bucket contains Z slots, each encoded as logical id u64 LE + fixed block bytes. Dummy id is u64::MAX. The whole bucket is encrypted: nonce[12] || ciphertext[Z*(8+B)] || tag[16]. Associated data binds protocol domain, physical bucket number, and trusted bucket version. Nonce is a per-key monotonic counter; the controller does not persist or reopen. Slot metadata is invisible at the backend interface.

For N logical blocks, leaves = next_power_of_two(N), buckets = 2*leaves-1, bytes/access = 2*(log2(leaves)+1)*(Z*(B+8)+28). This counts bucket payloads, not a real storage RPC transport. Failure traces can be shorter.

## Traces

Storage observer v1 (`StorageEvent`): version, elapsed_ns since backend creation, direction (physical read/write), bucket, bytes. Initialization and invariant scans must be excluded explicitly from invocation experiments.

Harness observer v1: version, step, tag, bytes, latency_ns. For the storage attack, tag is a physical baseline location or an ORAM leaf. For traffic, tag is a constant and bytes is application response length; latency is measured component duration. These are not packet captures.

Harness ground truth: step, label, in a separate file. Private runtime instrumentation includes epoch, real, function, status, work/prepare durations, deadline status, registry row width, PIR duration and local registry-pin check duration. It is written separately from observer traces. File access permissions in a real deployment must enforce the distinction; filenames alone are not isolation. Synthetic experiment labels may be released for reproducibility, but target inference code receives only observable rows and declared auxiliary knowledge.

Client-side responses must match the latest sent request epoch; this endpoint protocol supports one current request per channel. Delayed unseen older responses are rejected without advancing receive state.
