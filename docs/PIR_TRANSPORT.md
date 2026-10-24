# Authenticated PIR transport

`oblivion_pir::secure` is a reusable, bounded session protocol for arbitrary
validated database geometry. `Geometry::new(count, width)` enforces the database
limits: 1–1,000,000 records, 1–1,048,576 bytes per record and at most 64 MiB in
record contents. A 10,000 × 1,024 database is supported and covered by real TCP
and separate process tests. Queries contain `ceil(count / 8)` bytes; answers
contain `width` bytes. Each frame adds 52 bytes. Sizes are fixed within a
geometry and independent of the target. Every answer scans all records and all
bytes, taking linear work in the total database size.

## API and process integration

Use `Endpoint::provision(slot, geometry)` for a pair of local endpoints, or
`Endpoint::provision_over_pipe(slot, geometry, private_pipe)` and
`Endpoint::accept_bootstrap(slot, private_pipe)` across an inherited private
pipe. Pass the client endpoint to `Client::new(address, endpoint, timeout)`;
`request(epoch, query_share)` opens a TCP connection and returns an authenticated
answer. `serve_connection(stream, database, server_endpoint, timeout)` accepts
one request. Endpoint frame methods also support other transports. Neither the
endpoint nor keys implement Debug or serialization. Do not log query shares or
send both shares to a single observer.

`oblivion-server` retains `Session::spawn(slot)`, `request(epoch, share)` and
`serve(slot)`. Its adapter derives geometry from the registry rather than
assuming five records or 128 bytes. Worker startup and bootstrap reads have a
two second bound; address output is bounded to 128 bytes. Failed startup and
Session drop kill and reap the child. TCP deadlines bound the complete exchange,
including clients that trickle input. The deadline cannot preempt a synchronous
database scan, but the geometry bounds its work and the deadline is checked
before writing the response. Failed exchanges return errors and consume their
sequence numbers; callers must handle unavailable servers.

The `secure-pir-server DATABASE SLOT` executable exposes a generic local worker.
Only the public database path and slot appear in its arguments. The private
inherited stdin supplies geometry and keys. File length must match validated
geometry before allocation. Public listen address goes to stdout. It binds
loopback and serves one connection at a time, with a two second exchange bound.
The lower level bootstrap methods read a fixed 52 bytes but do not implement a
deadline on arbitrary `Read` implementations; adapters must bound these reads.

## Version 1 wire format

All integers are unsigned big endian. The authenticated header is:

| Byte offset | Field |
| --- | --- |
| 0 | Magic `OPIR` (4 bytes) |
| 4 | Version 1 (u16) |
| 6 | Kind: query 1, answer 2 (u8) |
| 7 | Reserved, must be zero (u8) |
| 8 | Slot (u32) |
| 12 | Record count (u32) |
| 16 | Record width (u32) |
| 20 | Request sequence (u64) |
| 28 | Application epoch (u64) |
| 36 | Ciphertext followed by 16 byte Poly1305 tag |

RustCrypto ChaCha20Poly1305 authenticates the complete header as associated data.
HKDF-SHA256 derives separate query and answer keys from a fresh OS generated
256 bit root for each session, using the `oblivion-pir-secure-v1` salt and
`client-to-server query` / `server-to-client answer` labels. The 96 bit nonce is
four zero bytes followed by the 64 bit request sequence. Each direction uses a
separate key. Sequences never wrap; restoring old sequence state with the same
keys is forbidden. Start a fresh session after a process restart or snapshot
restore. The private bootstrap format is `OPBS`, u16 version, two zero reserved
bytes, u32 slot/count/width and 32 root key bytes (52 bytes total).

Network headers never determine allocations. Endpoints allocate frames only
from their validated, trusted geometry. Authentication and replay validation
precede the database scan. The server accepts strictly increasing sequences,
allowing gaps after client transport failures. Each client permits one pending
request and accepts only its exact sequence and epoch. Abandoning a timed out
request retires its nonce; a delayed authenticated answer cannot satisfy the
next request. Dropped or replayed connections receive no answer. Frames from a
previous independently provisioned session fail authentication.

## Security boundary

The legacy `wire` module remains an explicitly unauthenticated experimental
protocol for compatibility. New code should use `secure`.

Transport authentication protects a channel from an active network observer;
it does not prove that a malicious server answered the PIR query correctly.
The invocation pipeline must continue checking recovered registry records
against trusted pinned data. Two-server XOR PIR still requires non-collusion;
any party with both shares can recover the selected index. OS private pipes
simulate local provisioning and do not provide hardware TEE isolation or
remote attestation. Process owners, shared hosts, server timing, geometry,
participation and availability remain outside a stronger privacy guarantee.
