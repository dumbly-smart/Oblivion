//! Single-server observer export; never serialize the second PIR query share.
use oblivion_pir::{Database, QueryPair, recover};
use rand::{SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;
use std::{
    error::Error,
    fs::{self, File},
    hint::black_box,
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};
fn record(index: usize, width: usize) -> Vec<u8> {
    (0..width)
        .map(|j| ((index.wrapping_mul(131) ^ j.wrapping_mul(17) ^ (index >> (j % 8))) & 255) as u8)
        .collect()
}
fn emit(file: &mut BufWriter<File>, row: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *file, row)?;
    writeln!(file)?;
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 8 {
        return Err(
            "usage: target_timing control|pir COUNT WIDTH QUERIES SEED SESSION NEW_OUTPUT".into(),
        );
    }
    let mode = &args[1];
    let count: usize = args[2].parse()?;
    let width: usize = args[3].parse()?;
    let queries: usize = args[4].parse()?;
    let seed: u64 = args[5].parse()?;
    let session = &args[6];
    if !["control", "pir"].contains(&mode.as_str())
        || !(4..=32768).contains(&count)
        || width == 0
        || width > 4096
        || queries < 6
        || queries > 3000
        || !queries.is_multiple_of(3)
        || session.is_empty()
        || session.len() > 128
    {
        return Err("invalid bounded experiment dimensions".into());
    }
    let indices = [0, count / 2, count - 1];
    let records: Vec<Vec<u8>> = (0..count).map(|i| record(i, width)).collect();
    let first = Database::new(records.clone())?;
    let second = Database::new(records.clone())?;
    let output = Path::new(&args[7]);
    fs::create_dir(output)?;
    let mut observer = BufWriter::new(File::create(output.join("observer.jsonl"))?);
    let mut truth = BufWriter::new(File::create(output.join("truth.jsonl"))?);
    let mut private = BufWriter::new(File::create(output.join("private.jsonl"))?);
    let mut labels: Vec<usize> = (0..queries).map(|i| i % 3).collect();
    labels.shuffle(&mut ChaCha20Rng::seed_from_u64(seed));
    // Untimed warm-up follows the same real path, including full oracle validation.
    let warm = QueryPair::generate(count, 0)?;
    if recover(&first.answer(&warm.first)?, &second.answer(&warm.second)?)? != records[0] {
        return Err("warmup oracle mismatch".into());
    }
    black_box(records[0].clone());
    for (step, label) in labels.into_iter().enumerate() {
        let index = indices[label];
        let generation;
        let server;
        let recovery;
        let result;
        let query_bytes;
        let visible_index;
        if mode == "control" {
            generation = 0;
            let start = Instant::now();
            result = black_box(records[index].clone());
            server = start.elapsed().as_nanos() as u64;
            recovery = 0;
            query_bytes = Vec::new();
            visible_index = Some(index);
        } else {
            let start = Instant::now();
            let pair = QueryPair::generate(count, index)?;
            generation = start.elapsed().as_nanos() as u64;
            let start = Instant::now();
            let a = first.answer(&pair.first)?;
            server = start.elapsed().as_nanos() as u64;
            let b = second.answer(&pair.second)?;
            let start = Instant::now();
            result = recover(&a, &b)?;
            recovery = start.elapsed().as_nanos() as u64;
            query_bytes = pair.first;
            visible_index = None;
        }
        if result != records[index] {
            return Err("full-record oracle mismatch".into());
        }
        emit(
            &mut observer,
            &serde_json::json!({"session":session,"step":step,"server_ns":server,"query_bytes":query_bytes,"visible_index":visible_index}),
        )?;
        emit(
            &mut truth,
            &serde_json::json!({"session":session,"step":step,"label":label,"index":index}),
        )?;
        emit(
            &mut private,
            &serde_json::json!({"session":session,"step":step,"generation_ns":generation,"recovery_ns":recovery,"correct":true}),
        )?;
    }
    Ok(())
}
