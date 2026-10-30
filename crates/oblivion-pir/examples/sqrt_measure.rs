//! Sequential in-process payload and scan measurement; no network timing claims.
use oblivion_pir::{
    Database, QueryPair, recover,
    sqrt::{Geometry, Recovery},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

fn record(index: usize, width: usize) -> Vec<u8> {
    (0..width)
        .map(|j| (((index * 131) ^ (j * 17) ^ (index >> (j % 8))) & 255) as u8)
        .collect()
}

fn query(
    g: &Geometry,
    mode: &str,
    count: usize,
    index: usize,
) -> Result<(QueryPair, Option<Recovery>), oblivion_pir::Error> {
    if mode == "sqrt" {
        let (pair, recovery) = g.query(index)?;
        Ok((pair, Some(recovery)))
    } else {
        Ok((QueryPair::generate(count, index)?, None))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: sqrt_measure CONFIG NEW_OUTPUT".into());
    }
    let config: Value = serde_json::from_slice(&fs::read(&args[1])?)?;
    let keys = [
        "version",
        "counts",
        "record_bytes",
        "trials",
        "queries_per_trial",
        "privacy_samples_per_target",
        "seed",
    ];
    let object = config.as_object().ok_or("configuration object required")?;
    if object.len() != keys.len() || object.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err("configuration keys".into());
    }
    let number = |key: &str| -> Result<usize, Box<dyn std::error::Error>> {
        Ok(usize::try_from(
            config[key].as_u64().ok_or("nonnegative integer required")?,
        )?)
    };
    let vector = |key: &str| -> Result<Vec<usize>, Box<dyn std::error::Error>> {
        config[key]
            .as_array()
            .ok_or("array required")?
            .iter()
            .map(|v| Ok(usize::try_from(v.as_u64().ok_or("integer required")?)?))
            .collect()
    };
    let counts = vector("counts")?;
    let widths = vector("record_bytes")?;
    let trials = number("trials")?;
    let queries = number("queries_per_trial")?;
    let privacy_samples = number("privacy_samples_per_target")?;
    let seed = config["seed"].as_u64().ok_or("seed required")?;
    if number("version")? != 1
        || counts.is_empty()
        || counts.len() > 8
        || widths.is_empty()
        || widths.len() > 8
        || trials != 30
        || !(1..=128).contains(&queries)
        || !(1..=4096).contains(&privacy_samples)
        || seed.checked_add(trials as u64).is_none()
    {
        return Err("bounded experiment dimensions".into());
    }
    for &count in &counts {
        for &width in &widths {
            Geometry::new(count, width)?;
        }
    }
    let output = Path::new(&args[2]);
    fs::create_dir(output)?;
    fs::write(
        output.join("config.json"),
        serde_json::to_vec_pretty(&config)?,
    )?;
    let mut raw = BufWriter::new(File::create(output.join("private-samples.jsonl"))?);
    let mut diagnostic = BufWriter::new(File::create(output.join("query-bit-diagnostics.jsonl"))?);
    for &count in &counts {
        for &width in &widths {
            let geometry = Geometry::new(count, width)?;
            for trial in 0..trials {
                let mut rng = ChaCha20Rng::seed_from_u64(seed + trial as u64);
                let indices: Vec<_> = (0..queries).map(|_| rng.gen_range(0..count)).collect();
                let modes = if rng.gen_bool(0.5) {
                    ["xor", "sqrt"]
                } else {
                    ["sqrt", "xor"]
                };
                for (order, mode) in modes.into_iter().enumerate() {
                    // Fresh, independently owned states each mode/trial; setup excluded.
                    let make = || -> Result<Database, oblivion_pir::Error> {
                        let records = (0..count).map(|i| record(i, width)).collect();
                        if mode == "sqrt" {
                            geometry.server(records)
                        } else {
                            Database::new(records)
                        }
                    };
                    let a = make()?;
                    let b = make()?;
                    let (warm, _) = query(&geometry, mode, count, 0)?;
                    a.answer(&warm.first)?;
                    b.answer(&warm.second)?;
                    for (step, &index) in indices.iter().enumerate() {
                        let tick = Instant::now();
                        let (pair, state) = query(&geometry, mode, count, index)?;
                        let generation_ns = tick.elapsed().as_nanos() as u64;
                        let tick = Instant::now();
                        let first = a.answer(&pair.first)?;
                        let server1_ns = tick.elapsed().as_nanos() as u64;
                        let tick = Instant::now();
                        let second = b.answer(&pair.second)?;
                        let server2_ns = tick.elapsed().as_nanos() as u64;
                        let tick = Instant::now();
                        let result = match state {
                            Some(state) => state.recover(&first, &second)?,
                            None => recover(&first, &second)?,
                        };
                        let recovery_ns = tick.elapsed().as_nanos() as u64;
                        if result != record(index, width) {
                            return Err("full-record oracle mismatch".into());
                        }
                        serde_json::to_writer(
                            &mut raw,
                            &json!({"count":count,"record_bytes":width,"trial":trial,"step":step,"mode":mode,"mode_order":order,
                            "private_target_index":index,"generation_ns":generation_ns,"server1_ns":server1_ns,"server2_ns":server2_ns,"recovery_ns":recovery_ns,
                            "query_payload_bytes":pair.first.len()+pair.second.len(),"response_payload_bytes":first.len()+second.len(),
                            "scan_payload_bytes_per_server":a.count()*a.record_bytes(),"rows":a.count(),"response_bytes_per_server":a.record_bytes()}),
                        )?;
                        writeln!(raw)?;
                    }
                    // Diagnostic aggregates only: single-server bit balance is not a privacy proof.
                    for target in [0, count / 3, 2 * count / 3, count - 1] {
                        let mut first_bit = [0usize; 2];
                        let mut tail_bit = [0usize; 2];
                        for _ in 0..privacy_samples {
                            let (pair, _) = query(&geometry, mode, count, target)?;
                            for (server, share) in
                                [&pair.first, &pair.second].into_iter().enumerate()
                            {
                                first_bit[server] += usize::from(share[0] & 1);
                                tail_bit[server] += usize::from(share[share.len() - 1] >> 7);
                            }
                        }
                        serde_json::to_writer(
                            &mut diagnostic,
                            &json!({"count":count,"record_bytes":width,"trial":trial,"mode":mode,"private_target_index":target,
                            "samples":privacy_samples,"ones_first_bit":first_bit,"ones_tail_bit":tail_bit}),
                        )?;
                        writeln!(diagnostic)?;
                    }
                }
            }
            eprintln!("sqrt comparison complete N={count} B={width} trials={trials}");
        }
    }
    raw.flush()?;
    diagnostic.flush()?;
    Ok(())
}
