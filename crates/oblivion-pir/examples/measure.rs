//! In-process two-server PIR microbenchmark; not a network throughput result.
use oblivion_pir::{Database, QueryPair, recover};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

struct Experiment {
    version: u16,
    count: usize,
    record_bytes: usize,
    trials: usize,
    queries_per_trial: usize,
    seed: u64,
}
impl Experiment {
    fn parse(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let v: serde_json::Value = serde_json::from_slice(bytes)?;
        let o = v.as_object().ok_or("configuration must be object")?;
        let keys = [
            "version",
            "count",
            "record_bytes",
            "trials",
            "queries_per_trial",
            "seed",
        ];
        if o.len() != keys.len() || o.keys().any(|k| !keys.contains(&k.as_str())) {
            return Err("unexpected or missing configuration field".into());
        }
        let n = |key: &str| -> Result<u64, Box<dyn std::error::Error>> {
            Ok(v[key]
                .as_u64()
                .ok_or("configuration fields must be nonnegative integers")?)
        };
        Ok(Self {
            version: u16::try_from(n("version")?)?,
            count: usize::try_from(n("count")?)?,
            record_bytes: usize::try_from(n("record_bytes")?)?,
            trials: usize::try_from(n("trials")?)?,
            queries_per_trial: usize::try_from(n("queries_per_trial")?)?,
            seed: n("seed")?,
        })
    }
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"version":self.version,"count":self.count,"record_bytes":self.record_bytes,"trials":self.trials,"queries_per_trial":self.queries_per_trial,"seed":self.seed})
    }
}
impl Default for Experiment {
    fn default() -> Self {
        Self {
            version: 1,
            count: 10000,
            record_bytes: 1024,
            trials: 30,
            queries_per_trial: 16,
            seed: 9001,
        }
    }
}
fn record(index: usize, width: usize) -> Vec<u8> {
    // Nontrivial full-record oracle, including bytes beyond the encoded index.
    (0..width)
        .map(|offset| {
            ((index.wrapping_mul(131) ^ offset.wrapping_mul(17) ^ (index >> (offset % 8))) & 255)
                as u8
        })
        .collect()
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let (config, output) = match args.len() {
        2 => (Experiment::default(), Path::new(&args[1])),
        3 => (
            Experiment::parse(&fs::read(&args[1])?)?,
            Path::new(&args[2]),
        ),
        _ => return Err("usage: measure [CONFIG.json] NEW_OUTPUT_DIRECTORY".into()),
    };
    let count = config.count;
    let width = config.record_bytes;
    if config.version != 1
        || count == 0
        || count > 100_000
        || width == 0
        || width > 16384
        || count
            .checked_mul(width)
            .is_none_or(|n| n > 64 * 1024 * 1024)
        || config.trials < 1
        || config.trials > 1000
        || config.queries_per_trial < 1
        || config.queries_per_trial > 1000
        || config.seed.checked_add(config.trials as u64).is_none()
    {
        return Err("invalid bounded PIR experiment configuration".into());
    }
    fs::create_dir(output)?;
    fs::write(
        output.join("config.json"),
        serde_json::to_vec_pretty(&config.json())?,
    )?;
    let mut raw = BufWriter::new(File::create(output.join("private-samples.jsonl"))?);
    for trial in 0..config.trials {
        // Fresh separately owned states each trial, with initialization excluded.
        let a = Database::new((0..count).map(|i| record(i, width)).collect())?;
        let b = Database::new((0..count).map(|i| record(i, width)).collect())?;
        let mut rng = ChaCha20Rng::seed_from_u64(config.seed + trial as u64);
        let warm = QueryPair::generate(count, 0)?;
        a.answer(&warm.first)?;
        b.answer(&warm.second)?;
        for query in 0..config.queries_per_trial {
            let index = rng.gen_range(0..count);
            let start = Instant::now();
            let pair = QueryPair::generate(count, index)?;
            let generation = start.elapsed().as_nanos() as u64;
            let start = Instant::now();
            let first = a.answer(&pair.first)?;
            let server1 = start.elapsed().as_nanos() as u64;
            let start = Instant::now();
            let second = b.answer(&pair.second)?;
            let server2 = start.elapsed().as_nanos() as u64;
            let start = Instant::now();
            let result = recover(&first, &second)?;
            let recovery = start.elapsed().as_nanos() as u64;
            if result != record(index, width) {
                return Err("PIR full-record recovery mismatch".into());
            }
            serde_json::to_writer(
                &mut raw,
                &serde_json::json!({"trial":trial,"query":query,"generation_ns":generation,"server1_ns":server1,"server2_ns":server2,"recovery_ns":recovery,"query_payload_bytes":2*count.div_ceil(8),"response_payload_bytes":2*width,"database_payload_bytes_per_server":count*width}),
            )?;
            writeln!(raw)?;
        }
    }
    Ok(())
}
