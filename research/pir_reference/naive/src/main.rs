//! Matched-geometry adapter using the project's actual naive XOR PIR API.
use oblivion_pir::{Database, QueryPair, recover};
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    time::Instant,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: naive OUTPUT COUNT TRIALS QUERIES SEED".into());
    }
    let count: usize = args[2].parse()?;
    let trials: usize = args[3].parse()?;
    let queries: usize = args[4].parse()?;
    let seed: u64 = args[5].parse()?;
    if count == 0
        || count > 1_000_000
        || trials == 0
        || trials > 1000
        || queries == 0
        || queries > 10000
    {
        return Err("excessive benchmark dimensions".into());
    }
    let mut output = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[1])?,
    );
    let values: Vec<_> = (0..count)
        .map(|i| {
            (i as u64)
                .wrapping_mul(0x9e3779b97f4a7c15)
                .wrapping_add(17)
                .to_le_bytes()
                .to_vec()
        })
        .collect();
    for trial in 0..trials {
        let start = Instant::now();
        let first = Database::new(values.clone())?;
        let second = Database::new(values.clone())?;
        writeln!(
            output,
            "{}",
            serde_json::json!({"kind":"setup","trial":trial,"database_build_ns":start.elapsed().as_nanos() as u64,"shared_init_ns":0,"preprocessing_ns":0,"offline_upload_bytes":0,"offline_download_bytes":0,"database_replication_bytes_excluded":2*count*8,"logical_database_bytes":count*8,"server_matrix_bytes":count*8})
        )?;
        let warm = QueryPair::generate(count, 0)?;
        first.answer(&warm.first)?;
        second.answer(&warm.second)?;
        for query in 0..queries {
            let index = (((trial * queries + query) as u64 * 7919 + seed) % count as u64) as usize;
            let start = Instant::now();
            let pair = QueryPair::generate(count, index)?;
            let generation = start.elapsed().as_nanos() as u64;
            let start = Instant::now();
            let a = first.answer(&pair.first)?;
            let server1 = start.elapsed().as_nanos() as u64;
            let start = Instant::now();
            let b = second.answer(&pair.second)?;
            let server2 = start.elapsed().as_nanos() as u64;
            let start = Instant::now();
            let result = recover(&a, &b)?;
            let recovery = start.elapsed().as_nanos() as u64;
            if result != values[index] {
                return Err("naive PIR oracle mismatch".into());
            }
            writeln!(
                output,
                "{}",
                serde_json::json!({"kind":"query","trial":trial,"query":query,"generation_ns":generation,"server1_ns":server1,"server2_ns":server2,"recovery_ns":recovery,"query_payload_bytes":2*count.div_ceil(8),"response_payload_bytes":16,"database_payload_bytes_per_server":count*8,"server_matrix_bytes_scanned":2*count*8,"correct":true})
            )?;
        }
    }
    output.flush()?;
    Ok(())
}
