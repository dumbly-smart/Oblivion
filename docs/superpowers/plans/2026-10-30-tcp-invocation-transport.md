# TCP Invocation Transport Implementation Plan

> **For agentic workers:** use this plan task by task; each task ends with a focused test and a small commit.

**Goal:** Add a loopback TCP-backed A–G invocation harness path with separate client and server processes, bounded framing, actual Oblivion execution, and socket-boundary traces.

**Architecture:** Keep the existing in-process `system` command unchanged. Add `system-tcp`, whose controller generates the existing deterministic schedule and starts one `system-tcp-worker` process for each mode/session. The controller provisions the channel key through the child's inherited stdin pipe; invocation request and response frames then cross a loopback TCP socket with a four-byte big-endian length prefix. The worker performs the real registry/PIR/WASM/storage path and records socket read/write observations without function labels or hidden step IDs.

**Tech Stack:** Stable Rust, existing Oblivion crates, `std::net`, inherited process pipes; no new dependency.

**Spec:** `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md`, `docs/NEXT_STEPS.md`, and the current A–G harness contract in `crates/oblivion-harness/src/system.rs`.

## Global Constraints

- Bind the experimental worker to `127.0.0.1` only.
- Keep channel bootstrap secrets on the inherited local process pipe; never send them on TCP.
- Prefix each body with a four-byte big-endian length and reject lengths above `ENVELOPE_BYTES` before allocation.
- Accept only the mode-specific fixed request lengths: `PAYLOAD_BYTES` or `ENVELOPE_BYTES`.
- Keep ground-truth labels and private step IDs out of socket frames and server-visible observer records.
- Preserve the old `system` command and its existing result format.
- Run actual registry/PIR/WASM/storage code in the server worker; do not use a mock invocation handler.
- Call the result a loopback TCP/socket-observer simulation, not packet capture, remote-network timing, or TEE evaluation.
- Use fresh output directories and deterministic experiment configuration; never overwrite captured output.
- Do not collect attack targets in this transport implementation plan; preregister the attack and control gate separately first.

## Review Focus

- A truncated length prefix or body must fail the worker session without parsing a partial request.
- An oversized or mode-incompatible length must be rejected before allocating based on peer input.
- A client disconnect must terminate and reap the worker rather than leave a child blocked indefinitely.
- A duplicate, tampered, or malformed authenticated envelope must fail through the existing endpoint checks and must not produce a successful invocation result.
- Unbatched dummy opportunities must create no socket request; batched dummy envelopes must take the real fixed-shape execution path.

---

### Task 1: Bounded TCP framing primitives

**Files:**
- Create: `crates/oblivion-harness/src/system_tcp.rs`
- Modify: `crates/oblivion-harness/src/main.rs` only to declare the module after it exists.
- Test: unit tests in `crates/oblivion-harness/src/system_tcp.rs`.

**Interfaces:**
- `read_frame(reader: &mut impl Read, maximum: usize) -> io::Result<Option<Vec<u8>>>`; `None` means clean EOF before a new length prefix.
- `write_frame(writer: &mut impl Write, body: &[u8], maximum: usize) -> io::Result<usize>`; return the complete on-wire byte count including the prefix.
- Wire encoding: `u32::to_be_bytes(body.len()) || body`.

- [ ] **Step 1: Write failing codec tests** for round-trip/prefix byte count, clean EOF between messages, truncated prefix, truncated body, zero length, oversized length, and a short-read/short-write stream.
- [ ] **Step 2: Run the focused test** with `cargo test --locked -p oblivion-harness --bin oblivion-harness system_tcp::tests` and confirm it fails because the codec API is absent.
- [ ] **Step 3: Implement only bounded framing** in `system_tcp.rs`; reject invalid lengths before allocating and use `read_exact`/`write_all` semantics.
- [ ] **Step 4: Run the focused test and formatting check**; require all codec cases to pass.
- [ ] **Step 5: Commit** as `feat: add bounded TCP frame codec`.

### Task 2: Independent worker process and secret bootstrap

**Files:**
- Modify: `crates/oblivion-harness/src/main.rs` to add `system-tcp` and `system-tcp-worker` dispatch.
- Modify: `crates/oblivion-harness/src/system.rs` to expose the immutable mode/config data needed by the TCP controller.
- Modify: `crates/oblivion-harness/src/system_tcp.rs` to start a loopback listener and accept one worker session.
- Test: create `crates/oblivion-harness/tests/system_tcp.rs`.

**Interfaces:**
- `system_tcp::run(config_path: &Path, out: &Path) -> Result<()>` drives the fresh output collection.
- `system_tcp::worker(output: &Path, mode_name: &str, maximum_frame: usize) -> Result<()>` serves one session and writes a `READY <socket-address>` line to stdout before waiting for channel bootstrap on stdin.
- The controller calls `Endpoint::provision_over_pipe`; the worker calls `Endpoint::accept_bootstrap`. The generated root never crosses TCP.

- [ ] **Step 1: Write failing process tests** proving the worker binds only loopback, emits a parseable ready address, accepts bootstrap over stdin, and exits on client EOF.
- [ ] **Step 2: Run the focused tests** and confirm failure because the CLI commands are absent.
- [ ] **Step 3: Add the worker startup path** with bounded socket read/write timeouts, child cleanup on every error path, and no concurrent/unbounded connection queue.
- [ ] **Step 4: Run the process tests** and verify child exit status and no orphan worker remain.
- [ ] **Step 5: Commit** as `feat: add isolated TCP invocation worker`.

### Task 3: Real A–G execution over the socket

**Files:**
- Modify: `crates/oblivion-harness/src/system_tcp.rs` for controller and worker request handling.
- Modify: `crates/oblivion-harness/src/system.rs` only for shared mode/config/storage visibility required by the new sibling module.
- Test: `crates/oblivion-harness/tests/system_tcp.rs`.

**Interfaces:**
- The controller reuses the same seed derivation, per-session label balance, mode order randomization, epoch period, and A–G mode flags as `system::run`.
- The server handles one bounded request body at a time, performs the current authentication/registry/PIR/WASM/storage behavior, then returns the current response format through `write_frame`.
- The socket observer records `observer`, direction, monotonic timestamp, framed byte count, and complete on-wire frame bytes. It does not record labels or private steps. A public sequence number may identify ordering only.
- The controller keeps the ground-truth schedule in its separate file and validates actual response behavior using the same expected function outputs as the current harness.

- [ ] **Step 1: Write failing end-to-end tests** with a small valid configuration; assert that A–G complete real invocations, request/response frames cross TCP, response shapes match each mode, and the raw observer file contains no `label`, `real`, `function`, or `step` fields.
- [ ] **Step 2: Run the focused integration test** and confirm it fails at the missing worker execution path.
- [ ] **Step 3: Move the server-side invocation work into the TCP worker** without mocking PIR, WASM, ORAM/direct storage, authentication, or response masking.
- [ ] **Step 4: Run focused tests** and compare successful client outputs and fixed sizes against the existing in-process system path.
- [ ] **Step 5: Run the complete serial Rust workspace suite** with `cargo test --locked --workspace -- --test-threads=1`; report exact exit status and skips.
- [ ] **Step 6: Commit** as `feat: run A-G invocations over loopback TCP`.

### Task 4: Protocol, architecture, and acceptance record

**Files:**
- Modify: `docs/PROTOCOL.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/NEXT_STEPS.md`
- Modify: `PROGRESS.md`

- [ ] **Step 1: Document the socket frame and trust boundary**: fixed application frame sizes, four-byte prefix, private inherited-pipe bootstrap, loopback-only binding, server-visible fields, and the limitations that distinguish socket timing from TCP packet capture or remote timing.
- [ ] **Step 2: Document one-command smoke/reproduction commands** and the test result; state clearly that no attack comparison or privacy claim is made by this infrastructure change.
- [ ] **Step 3: Check local Markdown links and `git diff --check`**.
- [ ] **Step 4: Commit** documentation separately as `docs: specify loopback invocation transport`.

## Acceptance

The transport path is accepted when the existing in-process system remains unchanged, the new command runs actual A–G components across independent client/worker processes, every socket frame is bounded and validated, observer traces contain no truth or private step, the integration and serial workspace suites pass, and documentation explicitly limits the result to a local loopback socket observer. Any subsequent attack collection requires its own preregistration and successful plaintext/encrypt-only positive controls before protected modes are scored.
