# Isolated ORAM bucket-service timing

This experiment adds a measurement backend for Path ORAM that places the
bucket service in a separate child process. The client still performs real
Path ORAM reads and writes; the service stores the encrypted bucket byte
strings in its own address space. Each request and response has the same
fixed length for a configuration. Every logical access still emits the
existing root-to-leaf bucket reads followed by root-to-leaf writes.

The service_ns field is measured inside the bucket-service process after a
complete fixed-length request has been decoded and before the fixed-length
reply is encoded. It includes the in-memory bucket handler, but excludes
controller path computation, process-pipe waiting, request decoding, reply
serialization, and trace file output. It is a local process-isolated service
measurement, not a remote network latency or a hardware-independent timing
guarantee. The child process and its OS are not a TEE.

Observer rows contain the step number, direction, physical bucket identifier,
byte count, and isolated service time. They do not contain the logical address,
the client-side read/write label, plaintext data, or ground-truth workload
labels. The private-*.jsonl file is experiment-driver output and is not an
attacker input. Treat it as sensitive and keep it separate from observer
traces.

Run the smoke measurement into a fresh output directory:

```sh
cargo run --locked --release -p oblivion-store --example oram-measure -- \
  experiments/configs/oram-isolated-timing-smoke.json \
  experiments/results/oram-isolated-timing-local
```

The runner refuses to overwrite an existing output directory. The output
contains per-trial observer and private traces, the configuration, a summary,
and isolated-service.json with process IDs, fixed message sizes, and the
declared timing scope. This small configuration checks integration only; its
timings are not a benchmark result.

Focused checks:

```sh
cargo test -p oblivion-store --example oram-measure
cargo build --locked --release -p oblivion-store --example oram-measure
ORAM_MEASURE_BINARY=$PWD/target/release/examples/oram-measure \
  .venv/bin/python -m unittest research.tests.test_oram_isolated_timing
```

The full fresh-workload study now has plaintext and encrypt-only positive
controls, a predeclared AUC primary metric, whole-session splits, 30 trials,
and a nonlinear temporal attacker. See the
[replication report](ORAM_TIMING_REPLICATION.md). It currently covers two
addresses and a local process boundary; broader address/operation universes
and real network timing remain open.
