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
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: measure NEW_OUTPUT_DIRECTORY".into());
    }
    let output = Path::new(&args[1]);
    fs::create_dir(output)?;
    let count = 10000usize;
    let width = 1024usize;
    let trials = 30;
    let queries = 16;
    let records: Vec<Vec<u8>> = (0..count)
        .map(|index| {
            let mut record = vec![0; width];
            record[..8].copy_from_slice(&(index as u64).to_le_bytes());
            record
        })
        .collect();
    let a = Database::new(records.clone())?;
    let b = Database::new(records)?;
    let mut raw = BufWriter::new(File::create(output.join("private-samples.jsonl"))?);
    fs::write(
        output.join("config.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"version":1,"count":count,"record_bytes":width,"trials":trials,"queries_per_trial":queries,"seed":9001,"methodology":"In-process independent server states; full scan; warm-up excluded. OS-random shares, seeded index workload. Times are wall-clock ns. Payload memory excludes allocator/object overhead. No wire throughput or network latency claim."}),
        )?,
    )?;
    for trial in 0..trials {
        let mut rng = ChaCha20Rng::seed_from_u64(9001 + trial);
        let warm = QueryPair::generate(count, 0)?;
        a.answer(&warm.first)?;
        b.answer(&warm.second)?;
        for query in 0..queries {
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
            if u64::from_le_bytes(result[..8].try_into()?) != index as u64 {
                return Err("PIR recovery mismatch".into());
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
