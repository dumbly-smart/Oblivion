# Protocols and trace schemas

## Authenticated envelope v1

All integers are big endian. Exactly 164 bytes:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII OBLV |
| 4 | 2 | Version 1 |
| 6 | 1 | Direction 1 request / 2 response |
| 7 | 1 | Reserved zero |
| 8 | 8 | Epoch |
| 16 | 4 | Participant/channel slot |
| 20 | 128 | AEAD ciphertext |
| 148 | 16 | Authentication tag |

The header is AEAD associated data. Nonce = slot u32 || epoch u64, derived rather than transmitted. HKDF-SHA256 separates request/response keys from a fresh OS-random 32-byte session root. Sending epochs increase strictly; receiving authenticated epochs increase strictly. Failed authentication does not advance receive state. No endpoint cloning or persisted restore is provided. Bootstrap APIs assume a fresh trusted inherited pipe; recording/replaying bootstrap secrets is unsupported.

The demo uses distinct fresh roots for the client/executor channel and each PIR link. Its protected PIR query payload pads the one-byte vector for five records to 128 bytes; its answer is one 160-byte signed registry record. This transport is deliberately limited to the demo registry. Generic large-database PIR remains a separate interface.

Invocation payload: real flag at 0, registry index u32 at 1..5, input[64] at 5..69, remaining bytes reserved. The worker discovers that index through PIR after epoch release and compares the full recovered record with its locally pinned, startup-verified catalog. A registry record is 160 bytes: id u32, version u64, module digest[32], location digest[32], resource class u8, 19 reserved zero bytes, and an Ed25519 signature[64]. The demo's module-location digest is a synthetic embedded-module descriptor. All five modules are preloaded from trusted bundled sources; external publication and signer identity are not implemented.

## Secure PIR worker database bootstrap v1

Before endpoint-key bootstrap, the executor writes `OBLPIR01`, record count u32 BE, record width u32 BE, and the fixed-width record array to each worker's inherited stdin. The worker checks count, width and total-byte bounds before allocating, reads exactly the declared database, then accepts the authenticated endpoint bootstrap. The integrated demo sends five 160-byte signed rows. This is local process provisioning, not an independently authenticated remote registry service.

Response payload: internal success/failure flag at 0, class output[64] at 1..65, zero padding. The flag is encrypted and never placed in observer traces. Valid dummy responses clear the output but execute the actual stateful function on reserved block 7.

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
