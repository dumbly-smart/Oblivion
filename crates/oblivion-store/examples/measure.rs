//! Reproducible workload generator; cryptographic randomness remains OS sourced.
use oblivion_store::{Config, MemoryBackend, PathOram};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::{
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
    block_bytes: usize,
    operations: usize,
    warmup: usize,
    trials: usize,
    seed: u64,
    workload: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
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
        || !["same", "uniform"].contains(&config.workload.as_str())
    {
        return Err("invalid experiment configuration".into());
    }
    let geometry = Config::new(config.blocks, config.block_bytes)?;
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
        let mut store = PathOram::new(geometry.clone(), MemoryBackend::default())?;
        store.backend_mut().set_tracing(false);
        // Materialize the entire logical dataset before warm-up/measurement.
        for id in 0..config.blocks {
            store.write(id, &vec![0; config.block_bytes])?;
        }
        for _ in 0..config.warmup {
            store.read(rng.gen_range(0..config.blocks))?;
        }
        store.backend_mut().set_tracing(true);
        let mut observer =
            BufWriter::new(File::create(out.join(format!("observer-{trial}.jsonl")))?);
        let mut private = BufWriter::new(File::create(out.join(format!("private-{trial}.jsonl")))?);
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        let mut max_stash = 0;
        for step in 0..config.operations {
            let address = if config.workload == "same" {
                0
            } else {
                rng.gen_range(0..config.blocks)
            };
            let is_write = rng.gen_bool(0.5);
            let mut value = vec![0; config.block_bytes];
            rng.fill(value.as_mut_slice());
            let start = Instant::now();
            if is_write {
                store.write(address, &value)?;
            } else {
                store.read(address)?;
            }
            let ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            if is_write {
                writes.push(ns);
            } else {
                reads.push(ns);
            }
            let stats = store.private_stats();
            max_stash = max_stash.max(stats.stash_blocks);
            serde_json::to_writer(
                &mut private,
                &serde_json::json!({"step":step, "logical_address":address,"write":is_write,"latency_ns":ns,"stash":stats.stash_blocks}),
            )?;
            writeln!(private)?;
            let events = store.backend_mut().take_trace();
            assert_eq!(events.len(), 2 * geometry.path_buckets());
            for event in events {
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
            &serde_json::json!({"trial":trial,"seed":seed,"read":quantiles(&reads),"write":quantiles(&writes),"bytes_per_access":geometry.access_bytes(),"encrypted_storage_bytes":geometry.storage_bytes(),"logical_storage_bytes":config.blocks*config.block_bytes,"max_measured_stash":max_stash,"private_state":store.private_stats()}),
        )?;
        writeln!(summary)?;
    }
    Ok(())
}
