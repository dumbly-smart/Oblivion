//! Actual component workloads. Labels and private status never enter observer files.
mod system;
mod system_tcp;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use oblivion_exec::{Class, Execution, Executor, Status};
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
    if args.len() == 4 && args[1] == "system-tcp" {
        return system_tcp::run(Path::new(&args[2]), Path::new(&args[3]));
    }
    if args.len() == 5 && args[1] == "system-tcp" {
        return system_tcp::run_with_modes(Path::new(&args[2]), Path::new(&args[3]), &args[4]);
    }
    if args.len() == 5 && args[1] == "system-tcp-worker" {
        let maximum_frame = args[4].parse::<usize>()?;
        return system_tcp::worker(Path::new(&args[2]), &args[3], maximum_frame);
    }
    if args.len() != 3 {
        return Err("usage: oblivion-harness CONFIG NEW_OUTPUT_DIRECTORY | system CONFIG NEW_OUTPUT_DIRECTORY | system-tcp CONFIG NEW_OUTPUT_DIRECTORY [MODE_LIST] | system-tcp-worker OUTPUT MODE MAX_FRAME".into());
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
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum TrafficMode {
    Unpadded,
    Padded,
}
impl TrafficMode {
    fn name(self) -> &'static str {
        match self {
            Self::Unpadded => "unpadded",
            Self::Padded => "padded",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TrafficPhase {
    Warmup,
    Measurement,
}
struct TrafficSample<'a> {
    phase: TrafficPhase,
    mode: TrafficMode,
    step: usize,
    label: usize,
    result: &'a Execution,
}
impl TrafficSample<'_> {
    fn validate(&self) -> Result<()> {
        // These component inputs are fixed at [10;64]. The independent oracle
        // checks guest output; a success status alone is not a correctness test.
        let mut expected = match self.label {
            0 => vec![10; 64],
            1 => 55u32.to_le_bytes().to_vec(),
            _ => return Err("unknown traffic function label".into()),
        };
        let padded = matches!(self.mode, TrafficMode::Padded);
        if padded {
            expected.resize(Class::small().output_bytes, 0);
        }
        if self.result.status == Status::Success {
            if self.result.body != expected {
                return Err("traffic success disagrees with independent output oracle".into());
            }
        } else if self.result.body.len()
            != if padded {
                Class::small().output_bytes
            } else {
                0
            }
            || self.result.body.iter().any(|&byte| byte != 0)
        {
            return Err("traffic runtime error violated masked response shape".into());
        }
        // Timeout/trap/fuel/resource errors are observable outcomes, not reasons
        // to discard a session or retry until a successful dataset is selected.
        Ok(())
    }
    fn record(
        &self,
        observer: &mut impl Write,
        truth: &mut impl Write,
        private: &mut impl Write,
    ) -> Result<()> {
        serde_json::to_writer(
            &mut *private,
            &serde_json::json!({"version":1,"phase":self.phase,"mode":self.mode,"step":self.step,"function":self.label,"status":format!("{:?}",self.result.status),"work_ns":self.result.work_ns,"total_ns":self.result.total_ns,"deadline_missed":self.result.deadline_missed,"output_bytes":self.result.body.len()}),
        )?;
        writeln!(private)?;
        private.flush()?;
        self.validate()?;
        if self.phase == TrafficPhase::Measurement {
            record(
                observer,
                truth,
                self.step,
                0,
                self.result.body.len(),
                self.result.total_ns,
                self.label,
            )?;
        }
        Ok(())
    }
}

fn traffic(out: &Path, trial: usize, session: usize, seed: u64, count: usize) -> Result<()> {
    for mode in [TrafficMode::Unpadded, TrafficMode::Padded] {
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
        let (mut observer, mut truth) = files(out, "traffic", mode.name(), trial, session)?;
        let mut private = BufWriter::new(File::create(out.join(format!(
            "traffic/{}/{trial}-{session}/execution-private.jsonl",
            mode.name()
        )))?);
        // Warm-up is excluded from measured observer/label rows but retained
        // privately; it never retries or selects which measured calls survive.
        for id in [0, 1] {
            let result = executor.execute_unpadded_baseline(id, &[10; 64], state.clone());
            TrafficSample {
                phase: TrafficPhase::Warmup,
                mode: TrafficMode::Unpadded,
                step: id as usize,
                label: id as usize,
                result: &result,
            }
            .record(&mut observer, &mut truth, &mut private)?;
        }
        for (step, label) in labels.into_iter().enumerate() {
            let result = if matches!(mode, TrafficMode::Padded) {
                executor.execute(label as u32, &[10; 64], state.clone())
            } else {
                executor.execute_unpadded_baseline(label as u32, &[10; 64], state.clone())
            };
            TrafficSample {
                phase: TrafficPhase::Measurement,
                mode,
                step,
                label,
                result: &result,
            }
            .record(&mut observer, &mut truth, &mut private)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_guest_timeouts_are_recorded_with_actual_masked_shapes_and_private_status() {
        let mut class = Class::small();
        // Fuel cannot win the race: the actual guest is interrupted by the
        // existing wall-clock class deadline, with no synthetic sleeps/hooks.
        class.fuel = 1_000_000_000_000;
        let mut executor = Executor::new(class).unwrap();
        executor.register(0, br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) (loop br 0) i32.const 0))"#).unwrap();
        let state = Arc::new(Mutex::new(
            PathOram::new(Config::new(16, 64).unwrap(), MemoryBackend::default()).unwrap(),
        ));
        for mode in [TrafficMode::Padded, TrafficMode::Unpadded] {
            let result = if matches!(mode, TrafficMode::Padded) {
                executor.execute(0, &[10; 64], state.clone())
            } else {
                executor.execute_unpadded_baseline(0, &[10; 64], state.clone())
            };
            assert_eq!(result.status, Status::Timeout);
            assert_eq!(
                result.body,
                vec![
                    0;
                    if matches!(mode, TrafficMode::Padded) {
                        64
                    } else {
                        0
                    }
                ]
            );
            let (mut observer, mut truth, mut private) = (Vec::new(), Vec::new(), Vec::new());
            TrafficSample {
                phase: TrafficPhase::Measurement,
                mode,
                step: 7,
                label: 0,
                result: &result,
            }
            .record(&mut observer, &mut truth, &mut private)
            .unwrap();
            let visible: serde_json::Value = serde_json::from_slice(&observer).unwrap();
            let ground: serde_json::Value = serde_json::from_slice(&truth).unwrap();
            let details: serde_json::Value = serde_json::from_slice(&private).unwrap();
            assert_eq!(
                visible,
                serde_json::json!({"version":1,"step":7,"tag":0,"bytes":result.body.len(),"latency_ns":result.total_ns})
            );
            assert_eq!(ground, serde_json::json!({"step":7,"label":0}));
            assert_eq!(details["status"], "Timeout");
            assert_eq!(details["work_ns"], result.work_ns);
            assert_eq!(details["deadline_missed"], result.deadline_missed);
            assert_eq!(details["phase"], "measurement");
        }
    }
    #[test]
    fn traffic_oracle_rejects_corrupt_success_and_unmasked_or_wrong_shape_errors() {
        for mode in [TrafficMode::Padded, TrafficMode::Unpadded] {
            for label in [0, 1] {
                let mut body = if label == 0 {
                    vec![10; 64]
                } else {
                    55u32.to_le_bytes().to_vec()
                };
                if matches!(mode, TrafficMode::Padded) {
                    body.resize(64, 0);
                }
                let mut result = Execution {
                    status: Status::Success,
                    body,
                    work_ns: 7,
                    total_ns: 9,
                    deadline_missed: false,
                };
                let emit = |result: &Execution| {
                    let (mut observer, mut truth, mut private) =
                        (Vec::new(), Vec::new(), Vec::new());
                    let recorded = TrafficSample {
                        phase: TrafficPhase::Measurement,
                        mode,
                        step: 0,
                        label,
                        result,
                    }
                    .record(&mut observer, &mut truth, &mut private);
                    (recorded, observer, truth)
                };
                assert!(emit(&result).0.is_ok());
                result.body[0] ^= 1;
                let (recorded, observer, truth) = emit(&result);
                assert!(recorded.is_err(), "corrupt success must abort");
                assert!(observer.is_empty() && truth.is_empty());
                result.status = Status::Timeout;
                let (recorded, observer, truth) = emit(&result);
                assert!(
                    recorded.is_err(),
                    "nonzero or wrong-length error must abort"
                );
                assert!(observer.is_empty() && truth.is_empty());
                result.body = vec![
                    0;
                    if matches!(mode, TrafficMode::Padded) {
                        63
                    } else {
                        1
                    }
                ];
                let (recorded, observer, truth) = emit(&result);
                assert!(
                    recorded.is_err(),
                    "all-zero errors still need the actual public shape"
                );
                assert!(observer.is_empty() && truth.is_empty());
            }
        }
    }
}
