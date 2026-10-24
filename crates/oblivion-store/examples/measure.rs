//! Reproducible workload generator; cryptographic randomness remains OS sourced.
#[path = "support/isolated.rs"]
mod isolated;

use isolated::{IsolatedBackend, ServiceEvent};
use oblivion_store::{
    Config, MemoryBackend, PathOram, PrivateStats, StorageDirection, StorageEvent,
};
use rand::{Rng, SeedableRng};
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
    #[serde(default = "default_bucket_capacity")]
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
    #[serde(default = "default_backend")]
    backend: String,
}

fn default_backend() -> String {
    "memory".to_owned()
}

enum Store {
    Memory(PathOram<MemoryBackend>),
    Isolated {
        store: PathOram<IsolatedBackend>,
        worker_pid: u32,
        request_bytes: usize,
        response_bytes: usize,
    },
}

impl Store {
    fn read(&mut self, address: usize) -> Result<Vec<u8>, oblivion_store::Error> {
        match self {
            Self::Memory(store) => store.read(address),
            Self::Isolated { store, .. } => store.read(address),
        }
    }
    fn write(&mut self, address: usize, value: &[u8]) -> Result<(), oblivion_store::Error> {
        match self {
            Self::Memory(store) => store.write(address, value),
            Self::Isolated { store, .. } => store.write(address, value),
        }
    }
    fn private_stats(&self) -> PrivateStats {
        match self {
            Self::Memory(store) => store.private_stats(),
            Self::Isolated { store, .. } => store.private_stats(),
        }
    }
    fn set_tracing(&mut self, enabled: bool) {
        match self {
            Self::Memory(store) => store.backend_mut().set_tracing(enabled),
            Self::Isolated { store, .. } => store.backend_mut().set_recording(enabled),
        }
    }
    fn take_events(&mut self) -> Vec<VisibleEvent> {
        match self {
            Self::Memory(store) => store
                .backend_mut()
                .take_trace()
                .into_iter()
                .map(VisibleEvent::from)
                .collect(),
            Self::Isolated { store, .. } => store
                .backend_mut()
                .take_events()
                .into_iter()
                .map(VisibleEvent::from)
                .collect(),
        }
    }
    fn isolated_metadata(&self) -> Option<(u32, usize, usize)> {
        match self {
            Self::Memory(_) => None,
            Self::Isolated {
                worker_pid,
                request_bytes,
                response_bytes,
                ..
            } => Some((*worker_pid, *request_bytes, *response_bytes)),
        }
    }
}

#[derive(Serialize)]
struct VisibleEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<usize>,
    direction: StorageDirection,
    bucket: usize,
    bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_ns: Option<u64>,
}
impl From<StorageEvent> for VisibleEvent {
    fn from(event: StorageEvent) -> Self {
        Self {
            step: None,
            direction: event.direction,
            bucket: event.bucket,
            bytes: event.bytes,
            service_ns: None,
        }
    }
}
impl From<ServiceEvent> for VisibleEvent {
    fn from(event: ServiceEvent) -> Self {
        Self {
            step: None,
            direction: event.direction,
            bucket: event.bucket,
            bytes: event.bytes,
            service_ns: Some(event.service_ns),
        }
    }
}

fn default_bucket_capacity() -> usize {
    4
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "--bucket-server") {
        if args.len() != 4 {
            return Err("usage: oram-measure --bucket-server BUCKET_COUNT BUCKET_BYTES".into());
        }
        return isolated::serve(
            std::io::stdin().lock(),
            std::io::stdout().lock(),
            args[2].parse()?,
            args[3].parse()?,
        )
        .map_err(Into::into);
    }
    if args.len() != 3 {
        return Err("usage: measure CONFIG.json NEW_OUTPUT_DIRECTORY".into());
    }
    let config: Experiment = serde_json::from_slice(&fs::read(&args[1])?)?;
    if config.version != 1
        || config.operations < 10
        || config.operations > 1_000_000
        || config.warmup > 100_000
        || config.trials == 0
        || config.trials > 1000
        || ![
            "same",
            "uniform",
            "two_record_skewed",
            "configured_distribution",
        ]
        .contains(&config.workload.as_str())
        || !["memory", "isolated_process"].contains(&config.backend.as_str())
    {
        return Err("invalid experiment configuration".into());
    }
    if config.workload == "configured_distribution" {
        isolated::validate_distribution(
            &config.address_distribution,
            config.blocks,
            &config.hot_addresses,
        )?;
    }
    let geometry = Config::with_parameters(
        config.blocks,
        config.block_bytes,
        config.bucket_capacity,
        128,
    )?;
    let out = Path::new(&args[2]);
    fs::create_dir(out)?; // Never overwrite raw results.
    fs::write(out.join("config.json"), serde_json::to_vec_pretty(&config)?)?;
    let mut summary = BufWriter::new(File::create(out.join("summary.jsonl"))?);
    for trial in 0..config.trials {
        let seed = config
            .seed
            .checked_add(trial as u64)
            .ok_or("seed overflow")?;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut store = match config.backend.as_str() {
            "memory" => Store::Memory(PathOram::new(geometry.clone(), MemoryBackend::default())?),
            "isolated_process" => {
                let backend = IsolatedBackend::spawn(
                    &std::env::current_exe()?,
                    geometry.bucket_count(),
                    geometry.bucket_bytes(),
                )?;
                let worker_pid = backend.worker_pid();
                let request_bytes = backend.request_bytes();
                let response_bytes = backend.response_bytes();
                Store::Isolated {
                    store: PathOram::new(geometry.clone(), backend)?,
                    worker_pid,
                    request_bytes,
                    response_bytes,
                }
            }
            _ => unreachable!("validated backend"),
        };
        store.set_tracing(false);
        // Materialize the entire logical dataset before warm-up/measurement.
        for id in 0..config.blocks {
            store.write(id, &vec![0; config.block_bytes])?;
        }
        let mut warmup_rng = ChaCha20Rng::seed_from_u64(seed ^ 0x4f52_414d_5741_524d);
        for _ in 0..config.warmup {
            let address = if config.workload == "configured_distribution" {
                isolated::sample_address(&mut warmup_rng, &config.address_distribution)
            } else if config.workload == "two_record_skewed" {
                if warmup_rng.gen_bool(0.75) { 0 } else { 1 }
            } else {
                warmup_rng.gen_range(0..config.blocks)
            };
            store.read(address)?;
        }
        store.set_tracing(true);
        if let Some((worker_pid, request_bytes, response_bytes)) = store.isolated_metadata() {
            fs::write(
                out.join("isolated-service.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "worker_pid": worker_pid, "controller_pid": std::process::id(),
                    "request_bytes": request_bytes, "response_bytes": response_bytes,
                    "bucket_bytes": geometry.bucket_bytes(), "path_buckets": geometry.path_buckets(),
                    "timing_scope": "bucket-handler-only; excludes pipe wait, path computation, request decoding, response encoding, and file output"
                }))?,
            )?;
        }
        let observer_name = if config.backend == "isolated_process" {
            format!("isolated-observer-{trial}.jsonl")
        } else {
            format!("observer-{trial}.jsonl")
        };
        let mut observer = BufWriter::new(File::create(out.join(observer_name))?);
        let mut private = BufWriter::new(File::create(out.join(format!("private-{trial}.jsonl")))?);
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        let mut max_stash = 0;
        let mut stash_histogram = std::collections::BTreeMap::<usize, usize>::new();
        let mut oracle = vec![vec![0; config.block_bytes]; config.blocks];
        for step in 0..config.operations {
            let address = match config.workload.as_str() {
                "same" => 0,
                "uniform" => rng.gen_range(0..config.blocks),
                "two_record_skewed" => {
                    if rng.gen_bool(0.75) {
                        0
                    } else {
                        1
                    }
                }
                "configured_distribution" => {
                    isolated::sample_address(&mut rng, &config.address_distribution)
                }
                _ => unreachable!("validated workload"),
            };
            let is_write = rng.gen_bool(0.5);
            let mut value = vec![0; config.block_bytes];
            rng.fill(value.as_mut_slice());
            let mut recovered = None;
            let mut oracle_verified = false;
            let start = Instant::now();
            if is_write {
                store.write(address, &value)?;
            } else {
                recovered = Some(store.read(address)?);
            }
            let ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            if is_write {
                oracle[address].copy_from_slice(&value);
                writes.push(ns);
            } else {
                if recovered.as_ref().unwrap() != &oracle[address] {
                    return Err("ORAM full-record oracle mismatch".into());
                }
                oracle_verified = true;
                reads.push(ns);
            }
            let stats = store.private_stats();
            max_stash = max_stash.max(stats.stash_blocks);
            *stash_histogram.entry(stats.stash_blocks).or_default() += 1;
            serde_json::to_writer(
                &mut private,
                &serde_json::json!({"step":step, "logical_address":address,"write":is_write,"latency_ns":ns,"stash":stats.stash_blocks,"oracle_verified":oracle_verified}),
            )?;
            writeln!(private)?;
            let mut events = store.take_events();
            assert_eq!(events.len(), 2 * geometry.path_buckets());
            for event in &mut events {
                if config.backend == "isolated_process" {
                    event.step = Some(step);
                }
                serde_json::to_writer(&mut observer, &event)?;
                writeln!(observer)?;
            }
        }
        reads.sort_unstable();
        writes.sort_unstable();
        let quantiles = |values: &[u64]| -> serde_json::Value {
            if values.is_empty() {
                return serde_json::Value::Null;
            }
            serde_json::json!({"count":values.len(), "p50_ns":values[(values.len()-1)*50/100], "p95_ns":values[(values.len()-1)*95/100], "p99_ns":values[(values.len()-1)*99/100]})
        };
        serde_json::to_writer(
            &mut summary,
            &serde_json::json!({"trial":trial,"seed":seed,"read":quantiles(&reads),"write":quantiles(&writes),"bytes_per_access":geometry.access_bytes(),"encrypted_storage_bytes":geometry.storage_bytes(),"logical_storage_bytes":config.blocks*config.block_bytes,"max_measured_stash":max_stash,"stash_histogram":stash_histogram,"private_state":store.private_stats()}),
        )?;
        writeln!(summary)?;
    }
    Ok(())
}
