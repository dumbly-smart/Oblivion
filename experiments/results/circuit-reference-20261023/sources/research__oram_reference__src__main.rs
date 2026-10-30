// SPDX-License-Identifier: GPL-3.0
// Isolated benchmark adapter; upstream ORAM code is an unmodified dependency.
// mc-oblivious sources: Copyright (c) 2018-2023 The MobileCoin Foundation.
use mc_oblivious_ram::{CircuitORAM4096Z4Creator, PathORAM4096Z4Creator};
use mc_oblivious_traits::{A64Bytes, HeapORAMStorageCreator, ORAM, ORAMCreator, typenum::U1024};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    collections::HashMap,
    error::Error,
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

struct Config {
    algorithm: String,
    blocks: u64,
    operations: usize,
    warmup: usize,
    seed: u64,
    output: PathBuf,
}
impl Config {
    fn parse(args: &[String]) -> Result<Self, Box<dyn Error>> {
        if args.len() != 7 {
            return Err("usage: reference path|circuit BLOCKS OPERATIONS WARMUP WORKLOAD_SEED NEW_OUTPUT.jsonl".into());
        }
        let config = Self {
            algorithm: args[1].clone(),
            blocks: args[2].parse()?,
            operations: args[3].parse()?,
            warmup: args[4].parse()?,
            seed: args[5].parse()?,
            output: PathBuf::from(&args[6]),
        };
        if !["path", "circuit"].contains(&config.algorithm.as_str())
            || !(4..=16384).contains(&config.blocks)
            || !config.blocks.is_power_of_two()
            || !(16..=10000).contains(&config.operations)
            || config.warmup > 1000
        {
            return Err("invalid bounded reference configuration".into());
        }
        Ok(config)
    }
}
fn emit(
    out: &mut BufWriter<std::fs::File>,
    value: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    Ok(())
}
fn measure<C: ORAMCreator<U1024, ChaCha20Rng>>(config: &Config) -> Result<(), Box<dyn Error>> {
    let mut out = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&config.output)?,
    );
    let mut rng = ChaCha20Rng::seed_from_u64(config.seed); // Logical workload only.
    let mut maker = ChaCha20Rng::from_entropy; // A fresh secure OS entropy seed for each requested ORAM RNG.
    let start = Instant::now();
    let mut oram = C::create(config.blocks, 128, &mut maker);
    let setup_ns = start.elapsed().as_nanos() as u64;
    let mut oracle = HashMap::new();
    for index in 0..config.blocks {
        let mut value = A64Bytes::<U1024>::default();
        rng.fill_bytes(&mut value[..]);
        if oram.write(index, &value) != A64Bytes::<U1024>::default() {
            return Err("initialization full-record oracle mismatch".into());
        }
        oracle.insert(index, value);
    }
    for _ in 0..config.warmup {
        let index = rng.gen_range(0..config.blocks);
        if &oram.read(index) != oracle.get(&index).unwrap() {
            return Err("warmup oracle mismatch".into());
        }
    }
    emit(
        &mut out,
        serde_json::json!({"kind":"setup","algorithm":config.algorithm,"blocks":config.blocks,"logical_block_bytes":1024,"storage_block_bytes":4096,"bucket_capacity":4,"stash_capacity":128,"setup_ns":setup_ns,"seed":config.seed,"backend":"HeapORAMStorage; unencrypted trusted heap; algorithm reference only"}),
    )?;
    for step in 0..config.operations {
        let index = rng.gen_range(0..config.blocks);
        let write = rng.gen_bool(0.5);
        let mut value = A64Bytes::<U1024>::default();
        rng.fill_bytes(&mut value[..]);
        let start = Instant::now();
        let old = if write {
            oram.write(index, &value)
        } else {
            oram.read(index)
        };
        let latency_ns = start.elapsed().as_nanos() as u64;
        if &old != oracle.get(&index).unwrap() {
            return Err("measured full-record oracle mismatch".into());
        }
        if write {
            oracle.insert(index, value);
        }
        emit(
            &mut out,
            serde_json::json!({"kind":"access","step":step,"logical_address":index,"write":write,"latency_ns":latency_ns,"stash":oram.stash_size(),"correct":true}),
        )?;
    }
    for index in 0..config.blocks {
        if &oram.read(index) != oracle.get(&index).unwrap() {
            return Err("final full-record audit mismatch".into());
        }
    }
    emit(
        &mut out,
        serde_json::json!({"kind":"summary","measured_checks":config.operations,"initialization_checks":config.blocks,"warmup_checks":config.warmup,"final_audit_checks":config.blocks}),
    )?;
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse(&std::env::args().collect::<Vec<_>>())?;
    match config.algorithm.as_str() {
        "path" => measure::<PathORAM4096Z4Creator<ChaCha20Rng, HeapORAMStorageCreator>>(&config),
        "circuit" => {
            measure::<CircuitORAM4096Z4Creator<ChaCha20Rng, HeapORAMStorageCreator>>(&config)
        }
        _ => unreachable!(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_parser() {
        for args in [
            ["path", "0", "16", "0"],
            ["path", "65", "16", "0"],
            ["path", "64", "0", "0"],
            ["circuit", "64", "16", "1001"],
            ["fake", "64", "16", "0"],
        ] {
            let mut full = vec!["ref".to_string()];
            full.extend(args.map(str::to_string));
            full.extend(["1".to_string(), "unused".to_string()]);
            assert!(Config::parse(&full).is_err());
        }
    }
}
