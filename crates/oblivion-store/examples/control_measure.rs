//! Fresh plaintext and encrypt-only direct-address controls for ORAM timing studies.
#[path = "support/isolated.rs"]
mod isolated;

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use isolated::{IsolatedBackend, ServiceEvent};
use oblivion_store::Backend;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Experiment {
    version: u16,
    blocks: usize,
    bucket_capacity: usize,
    block_bytes: usize,
    operations: usize,
    warmup: usize,
    trials: usize,
    seed: u64,
    workload: String,
    #[serde(default)]
    address_distribution: BTreeMap<usize, f64>,
    #[serde(default)]
    hot_addresses: Vec<usize>,
}

struct DirectStore {
    backend: IsolatedBackend,
    cipher: Option<ChaCha20Poly1305>,
    nonce_prefix: [u8; 4],
    nonce_counter: u64,
    block_bytes: usize,
    bucket_bytes: usize,
}

impl DirectStore {
    fn new(
        executable: &Path,
        blocks: usize,
        bucket_bytes: usize,
        block_bytes: usize,
        encrypt: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let backend = IsolatedBackend::spawn(executable, blocks, bucket_bytes)?;
        let cipher = if encrypt {
            let mut key = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            Some(ChaCha20Poly1305::new_from_slice(&key)?)
        } else {
            None
        };
        let mut nonce_prefix = [0; 4];
        rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);
        Ok(Self {
            backend,
            cipher,
            nonce_prefix,
            nonce_counter: 0,
            block_bytes,
            bucket_bytes,
        })
    }

    fn next_nonce(&mut self) -> Result<[u8; 12], Box<dyn Error>> {
        let counter = self.nonce_counter;
        self.nonce_counter = self
            .nonce_counter
            .checked_add(1)
            .ok_or("control AEAD nonce exhausted")?;
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        Ok(nonce)
    }

    fn read(&mut self, address: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        let stored = self.backend.read_bucket(address)?;
        let Some(cipher) = &self.cipher else {
            if stored[self.block_bytes..].iter().any(|byte| *byte != 0) {
                return Err("plaintext control padding corruption".into());
            }
            return Ok(stored[..self.block_bytes].to_vec());
        };
        let encrypted_len = self.block_bytes + 16;
        let used = 12 + encrypted_len;
        if used > stored.len() || stored[used..].iter().any(|byte| *byte != 0) {
            return Err("encrypted control padding corruption".into());
        }
        let nonce = Nonce::from_slice(&stored[..12]);
        let aad = (address as u64).to_le_bytes();
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &stored[12..used],
                    aad: &aad,
                },
            )
            .map_err(|_| std::io::Error::other("control record authentication failed").into())
    }

    fn write(&mut self, address: usize, block: &[u8]) -> Result<(), Box<dyn Error>> {
        if block.len() != self.block_bytes {
            return Err("control block length mismatch".into());
        }
        let mut stored = vec![0; self.bucket_bytes];
        let nonce = if self.cipher.is_some() {
            Some(self.next_nonce()?)
        } else {
            None
        };
        if let Some(cipher) = &self.cipher {
            let nonce = nonce.expect("cipher has a fresh nonce");
            let aad = (address as u64).to_le_bytes();
            let encrypted = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: block,
                        aad: &aad,
                    },
                )
                .map_err(|_| std::io::Error::other("control record encryption failed"))?;
            let used = 12 + encrypted.len();
            if used > stored.len() {
                return Err("encrypted control does not fit the fixed slot".into());
            }
            stored[..12].copy_from_slice(&nonce);
            stored[12..used].copy_from_slice(&encrypted);
        } else {
            if block.len() > stored.len() {
                return Err("plaintext control does not fit the fixed slot".into());
            }
            stored[..block.len()].copy_from_slice(block);
        }
        self.backend.write_bucket(address, &stored)?;
        Ok(())
    }

    /// Perform one read and one write for both logical operation types.
    fn access(
        &mut self,
        address: usize,
        is_write: bool,
        value: &[u8],
    ) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let previous = self.read(address)?;
        if is_write {
            self.write(address, value)?;
            Ok(None)
        } else {
            self.write(address, &previous)?;
            Ok(Some(previous))
        }
    }
}

#[derive(Serialize)]
struct Event {
    step: usize,
    direction: oblivion_store::StorageDirection,
    bucket: usize,
    bytes: usize,
    service_ns: u64,
}

impl From<(usize, ServiceEvent)> for Event {
    fn from((step, event): (usize, ServiceEvent)) -> Self {
        Self {
            step,
            direction: event.direction,
            bucket: event.bucket,
            bytes: event.bytes,
            service_ns: event.service_ns,
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "--bucket-server") {
        if args.len() != 4 {
            return Err("usage: oram-control --bucket-server BUCKET_COUNT BUCKET_BYTES".into());
        }
        isolated::serve(
            std::io::stdin().lock(),
            std::io::stdout().lock(),
            args[2].parse()?,
            args[3].parse()?,
        )?;
        return Ok(());
    }
    if args.len() != 4 || !["plaintext", "encrypt_only"].contains(&args[1].as_str()) {
        return Err(
            "usage: oram-control plaintext|encrypt_only CONFIG.json NEW_OUTPUT_DIRECTORY".into(),
        );
    }
    let mode = args[1].as_str();
    let config: Experiment = serde_json::from_slice(&fs::read(&args[2])?)?;
    if config.version != 1
        || config.blocks < 2
        || !config.blocks.is_power_of_two()
        || config.operations < 10
        || config.operations > 1_000_000
        || config.warmup > 100_000
        || config.trials == 0
        || config.trials > 1000
        || !["two_record_skewed", "configured_distribution"].contains(&config.workload.as_str())
    {
        return Err("invalid direct-control configuration".into());
    }
    if config.workload == "configured_distribution" {
        isolated::validate_distribution(
            &config.address_distribution,
            config.blocks,
            &config.hot_addresses,
        )?;
    }
    let geometry = oblivion_store::Config::with_parameters(
        config.blocks,
        config.block_bytes,
        config.bucket_capacity,
        128,
    )?;
    let output = Path::new(&args[3]);
    fs::create_dir(output)?;
    fs::write(
        output.join("config.json"),
        serde_json::to_vec_pretty(&config)?,
    )?;
    let mut summary = BufWriter::new(File::create(output.join("summary.jsonl"))?);
    for trial in 0..config.trials {
        let mut rng = ChaCha20Rng::seed_from_u64(
            config
                .seed
                .checked_add(trial as u64)
                .ok_or("seed overflow")?,
        );
        let mut store = DirectStore::new(
            &std::env::current_exe()?,
            config.blocks,
            geometry.bucket_bytes(),
            config.block_bytes,
            mode == "encrypt_only",
        )?;
        store.backend.set_recording(false);
        let mut oracle = vec![vec![0; config.block_bytes]; config.blocks];
        for (address, block) in oracle.iter().enumerate() {
            store.write(address, block)?;
        }
        let seed = config
            .seed
            .checked_add(trial as u64)
            .ok_or("seed overflow")?;
        let mut warmup_rng = ChaCha20Rng::seed_from_u64(seed ^ 0x4f52_414d_5741_524d);
        for _ in 0..config.warmup {
            let address = if config.workload == "configured_distribution" {
                isolated::sample_address(&mut warmup_rng, &config.address_distribution)
            } else if warmup_rng.gen_bool(0.75) {
                0
            } else {
                1
            };
            store.read(address)?;
        }
        store.backend.set_recording(true);
        let metadata = serde_json::json!({
            "backend": mode,
            "worker_pid": store.backend.worker_pid(),
            "controller_pid": std::process::id(),
            "request_bytes": store.backend.request_bytes(),
            "response_bytes": store.backend.response_bytes(),
            "bucket_bytes": geometry.bucket_bytes(),
            "events_per_access": 2,
            "timing_scope": "bucket-handler-only; excludes pipe wait, client crypto, request decoding, response encoding, and file output"
        });
        fs::write(
            output.join("isolated-service.json"),
            serde_json::to_vec_pretty(&metadata)?,
        )?;
        let mut observer = BufWriter::new(File::create(
            output.join(format!("isolated-observer-{trial}.jsonl")),
        )?);
        let mut private =
            BufWriter::new(File::create(output.join(format!("private-{trial}.jsonl")))?);
        let mut latencies = Vec::new();
        for step in 0..config.operations {
            let address = if config.workload == "configured_distribution" {
                isolated::sample_address(&mut rng, &config.address_distribution)
            } else if rng.gen_bool(0.75) {
                0
            } else {
                1
            };
            let is_write = rng.gen_bool(0.5);
            let mut value = vec![0; config.block_bytes];
            rng.fill(value.as_mut_slice());
            let started = Instant::now();
            let recovered = store.access(address, is_write, &value)?;
            let elapsed_ns = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let oracle_verified = if is_write {
                oracle[address].copy_from_slice(&value);
                false
            } else {
                if recovered.as_ref() != Some(&oracle[address]) {
                    return Err("direct control oracle mismatch".into());
                }
                true
            };
            latencies.push(elapsed_ns);
            serde_json::to_writer(
                &mut private,
                &serde_json::json!({
                    "step": step, "logical_address": address, "write": is_write,
                    "oracle_verified": oracle_verified, "latency_ns": elapsed_ns
                }),
            )?;
            writeln!(private)?;
            let events = store.backend.take_events();
            if events.len() != 2 {
                return Err("direct control access shape changed".into());
            }
            for event in events {
                serde_json::to_writer(&mut observer, &Event::from((step, event)))?;
                writeln!(observer)?;
            }
        }
        latencies.sort_unstable();
        let quantile = |percent: usize| latencies[(latencies.len() - 1) * percent / 100];
        serde_json::to_writer(
            &mut summary,
            &serde_json::json!({
                "trial": trial, "seed": config.seed + trial as u64,
                "p50_ns": quantile(50), "p95_ns": quantile(95), "p99_ns": quantile(99),
                "oracle_verified_reads": true
            }),
        )?;
        writeln!(summary)?;
    }
    Ok(())
}
