//! Actual component workloads. Labels and private status never enter observer files.
mod system;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use oblivion_exec::{Class, Executor, Status};
use oblivion_store::{Config, MemoryBackend, PathOram, StorageDirection};
use rand::{Rng, RngCore, SeedableRng, rngs::OsRng, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Experiment {
    version: u16,
    seed: u64,
    trials: usize,
    sessions: usize,
    operations: usize,
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 && args[1] == "system" {
        return system::run(Path::new(&args[2]), Path::new(&args[3]));
    }
    if args.len() != 3 {
        return Err("usage: oblivion-harness CONFIG NEW_OUTPUT_DIRECTORY".into());
    }
    let config: Experiment = serde_json::from_slice(&fs::read(&args[1])?)?;
    if config.version != 1
        || !(2..=100).contains(&config.trials)
        || !(4..=100).contains(&config.sessions)
        || !config.sessions.is_multiple_of(2)
        || !(32..=10000).contains(&config.operations)
        || !config.operations.is_multiple_of(2)
    {
        return Err("invalid experiment configuration".into());
    }
    config
        .seed
        .checked_add((config.trials * config.sessions) as u64)
        .ok_or("seed overflow")?;
    let output = Path::new(&args[2]);
    fs::create_dir(output)?;
    fs::write(
        output.join("config.json"),
        serde_json::to_vec_pretty(&config)?,
    )?;
    for trial in 0..config.trials {
        for session in 0..config.sessions {
            let seed = config.seed + (trial * config.sessions + session) as u64;
            frequency(output, trial, session, seed, config.operations)?;
            traffic(output, trial, session, seed, config.operations)?;
        }
    }
    Ok(())
}
fn files(
    out: &Path,
    attack: &str,
    mode: &str,
    trial: usize,
    session: usize,
) -> Result<(BufWriter<File>, BufWriter<File>)> {
    let path = out.join(format!("{attack}/{mode}/{trial}-{session}"));
    fs::create_dir_all(&path)?;
    Ok((
        BufWriter::new(File::create(path.join("observer.jsonl"))?),
        BufWriter::new(File::create(path.join("ground-truth.jsonl"))?),
    ))
}
fn record(
    observer: &mut impl Write,
    truth: &mut impl Write,
    step: usize,
    tag: usize,
    bytes: usize,
    ns: u64,
    label: usize,
) -> Result<()> {
    serde_json::to_writer(
        &mut *observer,
        &serde_json::json!({"version":1,"step":step,"tag":tag,"bytes":bytes,"latency_ns":ns}),
    )?;
    writeln!(observer)?;
    serde_json::to_writer(&mut *truth, &serde_json::json!({"step":step,"label":label}))?;
    writeln!(truth)?;
    Ok(())
}
fn frequency(out: &Path, trial: usize, session: usize, seed: u64, count: usize) -> Result<()> {
    for mode in ["plaintext", "encrypt_only", "oram"] {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut permutation: Vec<usize> = (0..16).collect();
        permutation.shuffle(&mut rng);
        let plain = vec![vec![0u8; 64]; 16];
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(key.as_mut())?;
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| "key")?;
        let mut ciphertext = Vec::new();
        for (index, block) in plain.iter().enumerate() {
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&(index as u64).to_be_bytes());
            ciphertext.push(
                cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: block,
                            aad: &(index as u64).to_be_bytes(),
                        },
                    )
                    .map_err(|_| "AEAD encryption")?,
            );
        }
        let mut store = PathOram::new(Config::new(16, 64)?, MemoryBackend::default())?;
        store.backend_mut().take_trace();
        let (mut observer, mut truth) = files(out, "frequency", mode, trial, session)?;
        for step in 0..count {
            let label = usize::from(!rng.gen_bool(0.75));
            let address = permutation[label];
            let start = Instant::now();
            let (tag, bytes) = match mode {
                "plaintext" => {
                    std::hint::black_box(&plain[address]);
                    (address, 64)
                }
                "encrypt_only" => {
                    let mut nonce = [0u8; 12];
                    nonce[4..].copy_from_slice(&(address as u64).to_be_bytes());
                    let block = cipher
                        .decrypt(
                            Nonce::from_slice(&nonce),
                            Payload {
                                msg: &ciphertext[address],
                                aad: &(address as u64).to_be_bytes(),
                            },
                        )
                        .map_err(|_| "AEAD decryption")?;
                    std::hint::black_box(block);
                    (address, 80)
                }
                _ => {
                    store.read(label)?;
                    let events = store.backend_mut().take_trace();
                    let leaf = events
                        .iter()
                        .rev()
                        .find(|e| e.direction == StorageDirection::Read)
                        .ok_or("missing trace")?
                        .bucket
                        - 15;
                    (leaf, events.iter().map(|e| e.bytes).sum())
                }
            };
            record(
                &mut observer,
                &mut truth,
                step,
                tag,
                bytes,
                start.elapsed().as_nanos() as u64,
                label,
            )?;
        }
    }
    Ok(())
}
fn traffic(out: &Path, trial: usize, session: usize, seed: u64, count: usize) -> Result<()> {
    for mode in ["unpadded", "padded"] {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut labels: Vec<usize> = (0..count).map(|i| i % 2).collect();
        labels.shuffle(&mut rng);
        let state = Arc::new(Mutex::new(PathOram::new(
            Config::new(16, 64)?,
            MemoryBackend::default(),
        )?));
        state
            .lock()
            .map_err(|_| "lock")?
            .backend_mut()
            .set_tracing(false);
        let mut executor = Executor::new(Class::small()).map_err(|e| e.to_string())?;
        executor
            .register(
                0,
                include_bytes!("../../../examples/wasm-functions/echo.wat"),
            )
            .map_err(|e| e.to_string())?;
        executor
            .register(
                1,
                include_bytes!("../../../examples/wasm-functions/fibonacci.wat"),
            )
            .map_err(|e| e.to_string())?;
        // Exclude initial invocation warm-up from both modes.
        for id in [0, 1] {
            executor.execute_unpadded_baseline(id, &[10; 64], state.clone());
        }
        let (mut observer, mut truth) = files(out, "traffic", mode, trial, session)?;
        for (step, label) in labels.into_iter().enumerate() {
            let result = if mode == "padded" {
                executor.execute(label as u32, &[10; 64], state.clone())
            } else {
                executor.execute_unpadded_baseline(label as u32, &[10; 64], state.clone())
            };
            if result.status != Status::Success {
                return Err(format!("execution failed: {:?}", result.status).into());
            }
            record(
                &mut observer,
                &mut truth,
                step,
                0,
                result.body.len(),
                result.total_ns,
                label,
            )?;
        }
    }
    Ok(())
}
