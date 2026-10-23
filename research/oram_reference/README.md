# Isolated Circuit/Path ORAM reference adapter

This directory is its own Cargo workspace and GPL-3.0 program. It depends on the genuine unmodified `mc-oblivious-ram = 2.3.0` and `mc-oblivious-traits = 2.3.0` crates, whose sources are Copyright (c) 2018–2023 The MobileCoin Foundation. The exact registry dependencies and checksums are pinned in this directory's Cargo.lock. The GPL license text is retained in LICENSE. No GPL dependency is linked into the Oblivion workspace or its MIT-licensed core.

Both reference algorithms use the vendor HeapORAMStorage and U1024 logical values with 4096-byte Z=4 storage buckets. HeapORAMStorage is unencrypted trusted heap memory and provides no storage encryption. This is an algorithm reference benchmark; it does not represent untrusted-storage security or an enclave deployment. The default upstream assembly implementation is used; `no_asm_insecure` is not enabled.

```sh
cargo build --locked --release --manifest-path research/oram_reference/Cargo.toml
cargo test --locked --manifest-path research/oram_reference/Cargo.toml
.venv/bin/python -m unittest research.tests.test_oram_reference
.venv/bin/python scripts/evaluate_oram_reference.py --output experiments/results/circuit-reference-new
```

The benchmark alone can be called as `oblivion-oram-reference path|circuit BLOCKS OPERATIONS WARMUP WORKLOAD_SEED NEW_OUTPUT.jsonl`. Bounds and power-of-two sizes are checked before ORAM creation or output file allocation. Cryptographic controller RNG makers use fresh OS entropy via `ChaCha20Rng::from_entropy`; only the logical workload is seeded. Every initialization return, warm-up read, measured read/write old value and final full-dataset audit is checked against a HashMap of complete 1024-byte values. Upstream panics or oracle errors fail the process; the runner retains failure logs and any partial raw output.

Sources: https://crates.io/crates/mc-oblivious-ram/2.3.0 and https://github.com/mobilecoinfoundation/mc-oblivious . The crate's own package metadata lists its historical repository URL; checksums/version, rather than a moving branch, identify the measured dependency.
