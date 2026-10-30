//! Executable A–G component-boundary system laboratory. Not packet capture.
use crate::Result;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use oblivion_batcher::{Endpoint, Envelope, EpochBatcher, PAYLOAD_BYTES};
use oblivion_exec::{BlockStorage, Class, Executor, Namespace, Status};
use oblivion_pir::{Database, QueryPair, recover, secure};
use oblivion_store::{Config, MemoryBackend, PathOram, StorageDirection, StorageEvent};
use rand::{RngCore, SeedableRng, rngs::OsRng, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Experiment {
    pub(super) version: u16,
    pub(super) seed: u64,
    pub(super) trials: usize,
    pub(super) sessions: usize,
    pub(super) operations: usize,
    pub(super) epoch_ms: u64,
}
#[derive(Clone, Copy)]
pub(super) struct Mode {
    pub(super) name: &'static str,
    pub(super) encrypted: bool,
    pub(super) oram: bool,
    pub(super) pir: bool,
    pub(super) batching: bool,
    pub(super) padding: bool,
}
pub(super) const MODES: [Mode; 7] = [
    Mode {
        name: "A",
        encrypted: false,
        oram: false,
        pir: false,
        batching: false,
        padding: false,
    },
    Mode {
        name: "B",
        encrypted: true,
        oram: false,
        pir: false,
        batching: false,
        padding: false,
    },
    Mode {
        name: "C",
        encrypted: true,
        oram: true,
        pir: false,
        batching: false,
        padding: false,
    },
    Mode {
        name: "D",
        encrypted: true,
        oram: false,
        pir: true,
        batching: false,
        padding: false,
    },
    Mode {
        name: "E",
        encrypted: true,
        oram: false,
        pir: false,
        batching: true,
        padding: false,
    },
    Mode {
        name: "F",
        encrypted: true,
        oram: false,
        pir: false,
        batching: false,
        padding: true,
    },
    Mode {
        name: "G",
        encrypted: true,
        oram: true,
        pir: true,
        batching: true,
        padding: true,
    },
];
const ECHO: &[u8] = include_bytes!("../../../examples/wasm-functions/echo.wat");
const STATEFUL: &[u8] = include_bytes!("../../../examples/wasm-functions/stateful.wat");

/// Deliberately address-revealing baseline, with genuine AEAD when enabled.
struct Direct {
    blocks: Vec<Vec<u8>>,
    cipher: Option<ChaCha20Poly1305>,
    nonce: u64,
    trace: Vec<StorageEvent>,
    start: Instant,
}
impl Direct {
    fn new(encrypted: bool) -> wasmtime::Result<Self> {
        let mut key = Zeroizing::new([0; 32]);
        OsRng.try_fill_bytes(key.as_mut())?;
        let cipher = encrypted.then(|| ChaCha20Poly1305::new((&*key).into()));
        let mut store = Self {
            blocks: vec![Vec::new(); 8],
            cipher,
            nonce: 0,
            trace: Vec::new(),
            start: Instant::now(),
        };
        for address in 0..8 {
            store.write(address, &[0; 64])?;
        }
        store.trace.clear();
        Ok(store)
    }
    fn event(&mut self, address: usize, direction: StorageDirection) {
        self.trace.push(StorageEvent {
            version: 1,
            elapsed_ns: ns(self.start.elapsed()),
            direction,
            bucket: address,
            bytes: self.blocks[address].len(),
        });
    }
}
impl BlockStorage for Direct {
    fn block_bytes(&self) -> usize {
        64
    }
    fn blocks(&self) -> usize {
        8
    }
    fn read(&mut self, address: usize) -> wasmtime::Result<Vec<u8>> {
        let data = self
            .blocks
            .get(address)
            .ok_or_else(|| wasmtime::Error::msg("address"))?;
        let result = if let Some(cipher) = &self.cipher {
            cipher
                .decrypt(
                    Nonce::from_slice(&data[..12]),
                    Payload {
                        msg: &data[12..],
                        aad: &(address as u64).to_be_bytes(),
                    },
                )
                .map_err(|_| wasmtime::Error::msg("authentication"))?
        } else {
            data.clone()
        };
        self.event(address, StorageDirection::Read);
        Ok(result)
    }
    fn write(&mut self, address: usize, data: &[u8]) -> wasmtime::Result<()> {
        if address >= 8 || data.len() != 64 {
            wasmtime::bail!("address or width");
        }
        let encoded = if let Some(cipher) = &self.cipher {
            let counter = self.nonce;
            self.nonce = self
                .nonce
                .checked_add(1)
                .ok_or_else(|| wasmtime::Error::msg("nonce exhausted"))?;
            let mut nonce = [0; 12];
            nonce[4..].copy_from_slice(&counter.to_be_bytes());
            let mut out = nonce.to_vec();
            out.extend(
                cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: data,
                            aad: &(address as u64).to_be_bytes(),
                        },
                    )
                    .map_err(|_| wasmtime::Error::msg("encryption"))?,
            );
            out
        } else {
            data.to_vec()
        };
        self.blocks[address] = encoded;
        self.event(address, StorageDirection::Write);
        Ok(())
    }
}
struct Stores {
    oram: Option<Arc<Mutex<PathOram<MemoryBackend>>>>,
    direct: Option<Arc<Mutex<Direct>>>,
}
impl Stores {
    fn new(mode: Mode) -> Result<Self> {
        if mode.oram {
            let mut oram = PathOram::new(Config::new(8, 64)?, MemoryBackend::default())?;
            oram.backend_mut().take_trace();
            Ok(Self {
                oram: Some(Arc::new(Mutex::new(oram))),
                direct: None,
            })
        } else {
            Ok(Self {
                oram: None,
                direct: Some(Arc::new(Mutex::new(
                    Direct::new(mode.encrypted).map_err(|e| e.to_string())?,
                ))),
            })
        }
    }
    fn handle(&self) -> Arc<Mutex<dyn BlockStorage>> {
        if let Some(oram) = &self.oram {
            oram.clone()
        } else {
            self.direct
                .as_ref()
                .expect("constructed alternative")
                .clone()
        }
    }
    fn drain(&self) -> Result<Vec<StorageEvent>> {
        if let Some(store) = &self.oram {
            Ok(store
                .lock()
                .map_err(|_| "storage lock")?
                .backend_mut()
                .take_trace())
        } else {
            Ok(std::mem::take(
                &mut self
                    .direct
                    .as_ref()
                    .ok_or("store")?
                    .lock()
                    .map_err(|_| "storage lock")?
                    .trace,
            ))
        }
    }
    fn stats(&self) -> Result<Value> {
        if let Some(store) = &self.oram {
            let store = store.lock().map_err(|_| "storage lock")?;
            Ok(
                json!({"encrypted_storage_bytes":store.config().bucket_count()*store.config().bucket_bytes(),"private_stats":store.private_stats()}),
            )
        } else {
            let store = self
                .direct
                .as_ref()
                .ok_or("store")?
                .lock()
                .map_err(|_| "storage lock")?;
            Ok(
                json!({"encrypted_storage_bytes":store.blocks.iter().map(Vec::len).sum::<usize>(),"private_stats":null}),
            )
        }
    }
}

pub(super) struct WorkerInvocation {
    pub(super) payload: [u8; PAYLOAD_BYTES],
    pub(super) plaintext_response_bytes: usize,
    pub(super) registry_bytes: usize,
    pub(super) registry_index: i32,
    pub(super) registry_ns: u64,
    pub(super) execution_ns: u64,
    pub(super) work_ns: u64,
    pub(super) deadline_missed: bool,
    pub(super) storage_events: Vec<StorageEvent>,
}

/// The actual server-side registry, WASM executor and state store for the
/// separate-process TCP experiment. It intentionally runs inside the trusted
/// executor process; it does not turn the local PIR pair into non-colluding
/// independent services.
pub(super) struct WorkerRuntime {
    mode: Mode,
    stores: Stores,
    executor: Executor,
    records: Vec<Vec<u8>>,
    first: Database,
    second: Database,
    pir_client0: oblivion_pir::secure::Endpoint,
    pir_server0: oblivion_pir::secure::Endpoint,
    pir_client1: oblivion_pir::secure::Endpoint,
    pir_server1: oblivion_pir::secure::Endpoint,
}

impl WorkerRuntime {
    pub(super) fn new(mode: Mode) -> Result<Self> {
        let stores = Stores::new(mode)?;
        let mut executor = Executor::new(Class::small()).map_err(|error| error.to_string())?;
        executor
            .register(0, ECHO)
            .map_err(|error| error.to_string())?;
        executor
            .register(4, STATEFUL)
            .map_err(|error| error.to_string())?;
        let records = (0..5u32)
            .map(|id| {
                let mut record = vec![0; 128];
                let source = if id == 0 { ECHO } else { STATEFUL };
                record[..32].copy_from_slice(&Sha256::digest(source));
                record[32..36].copy_from_slice(&id.to_be_bytes());
                record[36..44].copy_from_slice(&1u64.to_be_bytes());
                record
            })
            .collect::<Vec<_>>();
        let first = Database::new(records.clone())?;
        let second = Database::new(records.clone())?;
        let geometry = secure::Geometry::new(5, 128)?;
        let (pir_client0, pir_server0) = secure::Endpoint::provision(0, geometry)?;
        let (pir_client1, pir_server1) = secure::Endpoint::provision(1, geometry)?;
        Ok(Self {
            mode,
            stores,
            executor,
            records,
            first,
            second,
            pir_client0,
            pir_server0,
            pir_client1,
            pir_server1,
        })
    }

    pub(super) fn invoke(
        &mut self,
        decoded: &[u8; PAYLOAD_BYTES],
        epoch: u64,
        invocation_started: Instant,
    ) -> Result<WorkerInvocation> {
        if decoded[0] > 1 {
            return Err("invalid invocation presence bit".into());
        }
        let real = decoded[0] == 1;
        let requested = u32::from_be_bytes(decoded[1..5].try_into()?);
        let selected = if real { requested } else { 4 };
        if !matches!(selected, 0 | 4) {
            return Err("unknown function identifier".into());
        }

        let registry_started = Instant::now();
        let (record, registry_bytes, registry_index) = if self.mode.pir {
            let shares = QueryPair::generate(5, selected as usize)?;
            let q0 = self.pir_client0.seal_query(epoch, &shares.first)?;
            let q1 = self.pir_client1.seal_query(epoch, &shares.second)?;
            let a0 = self.first.answer(&self.pir_server0.open_query(&q0)?)?;
            let a1 = self.second.answer(&self.pir_server1.open_query(&q1)?)?;
            let a0 = self.pir_server0.seal_answer(&a0)?;
            let a1 = self.pir_server1.seal_answer(&a1)?;
            let bytes = q0.len() + q1.len() + a0.len() + a1.len();
            let record = recover(
                &self.pir_client0.open_answer(&a0)?,
                &self.pir_client1.open_answer(&a1)?,
            )?;
            (record, bytes, -1)
        } else {
            (
                self.records[selected as usize].clone(),
                132,
                selected as i32,
            )
        };
        let registry_ns = ns(registry_started.elapsed());
        if record != self.records[selected as usize] {
            return Err("registry authentication failed".into());
        }

        let mut argument = [0; 64];
        argument.copy_from_slice(&decoded[5..69]);
        let namespace = if real {
            Namespace {
                first: 0,
                blocks: 7,
            }
        } else {
            Namespace {
                first: 7,
                blocks: 1,
            }
        };
        if !self.mode.padding && !real {
            argument[4..8].copy_from_slice(&7u32.to_le_bytes());
        }
        let result = if self.mode.padding {
            self.executor.prepare_scheduled(
                selected,
                &argument,
                self.stores.handle(),
                namespace,
                invocation_started,
            )
        } else {
            self.executor
                .execute_unpadded_baseline(selected, &argument, self.stores.handle())
        };
        if result.status != Status::Success {
            return Err(format!("WASM invocation failed: {:?}", result.status).into());
        }

        let mut payload = [0; PAYLOAD_BYTES];
        let visibility_mask = 0u8.wrapping_sub(u8::from(real));
        for (out, byte) in payload[1..].iter_mut().zip(&result.body) {
            *out = *byte & visibility_mask;
        }
        let events = self.stores.drain()?;
        Ok(WorkerInvocation {
            payload,
            plaintext_response_bytes: if real && selected == 0 { 65 } else { 5 },
            registry_bytes,
            registry_index,
            registry_ns,
            execution_ns: result.total_ns,
            work_ns: result.work_ns,
            deadline_missed: result.deadline_missed,
            storage_events: events,
        })
    }

    pub(super) fn storage_stats(&self) -> Result<Value> {
        self.stores.stats()
    }
}

fn write(writer: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writeln!(writer)?;
    Ok(())
}
fn ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}
fn proc_counters() -> (u64, u64) {
    let stat = fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let fields = stat
        .rsplit_once(") ")
        .map_or("", |(_, s)| s)
        .split_whitespace()
        .collect::<Vec<_>>();
    let number = |index: usize| {
        fields
            .get(index)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let rss = fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    (number(11) + number(12), rss)
}

pub(super) fn load_experiment(config_path: &Path) -> Result<Experiment> {
    if fs::metadata(config_path)?.len() > 16 * 1024 {
        return Err("configuration too large".into());
    }
    let config: Experiment = serde_json::from_slice(&fs::read(config_path)?)?;
    if config.version != 1
        || !(2..=100).contains(&config.trials)
        || !(4..=32).contains(&config.sessions)
        || !config.sessions.is_multiple_of(2)
        || !(4..=4096).contains(&config.operations)
        || !config.operations.is_multiple_of(4)
        || !(2..=1000).contains(&config.epoch_ms)
    {
        return Err("invalid system experiment configuration".into());
    }
    config
        .seed
        .checked_add((config.trials * config.sessions) as u64)
        .ok_or("seed overflow")?;
    Ok(config)
}

pub(super) fn schedule(
    config: &Experiment,
    trial: usize,
    session: usize,
) -> Result<(Vec<usize>, [Mode; 7])> {
    let index = trial
        .checked_mul(config.sessions)
        .and_then(|value| value.checked_add(session))
        .ok_or("session index overflow")?;
    let seed = config
        .seed
        .checked_add(index as u64)
        .ok_or("seed overflow")?;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut labels = (0..config.operations)
        .map(|i| if i % 4 < 2 { 0 } else { i % 4 - 1 })
        .collect::<Vec<_>>();
    labels.shuffle(&mut rng);
    let mut modes = MODES;
    modes.shuffle(&mut rng);
    Ok((labels, modes))
}

pub fn run(config_path: &Path, out: &Path) -> Result<()> {
    let config = load_experiment(config_path)?;
    fs::create_dir(out)?;
    fs::write(out.join("config.json"), serde_json::to_vec_pretty(&config)?)?;
    let mut metrics = BufWriter::new(File::create(out.join("metrics.jsonl"))?);
    for trial in 0..config.trials {
        for session in 0..config.sessions {
            let (labels, modes) = schedule(&config, trial, session)?;
            for mode in modes {
                session_run(out, &mut metrics, &config, trial, session, mode, &labels)?;
            }
        }
        metrics.flush()?;
        eprintln!(
            "system experiment completed trial {}/{}",
            trial + 1,
            config.trials
        );
    }
    Ok(())
}
fn session_run(
    out: &Path,
    metrics: &mut impl Write,
    config: &Experiment,
    trial: usize,
    session: usize,
    mode: Mode,
    labels: &[usize],
) -> Result<()> {
    let path = out.join(mode.name).join(format!("{trial}-{session}"));
    fs::create_dir_all(&path)?;
    let mut observer = BufWriter::new(File::create(path.join("observer.jsonl"))?);
    let mut truth = BufWriter::new(File::create(path.join("ground-truth.jsonl"))?);
    let mut storage_trace = BufWriter::new(File::create(path.join("storage-observer.jsonl"))?);
    let mut network = BufWriter::new(File::create(path.join("network-observer.jsonl"))?);
    let mut private = BufWriter::new(File::create(path.join("private.jsonl"))?);
    let init = Instant::now();
    let stores = Stores::new(mode)?;
    let mut executor = Executor::new(Class::small()).map_err(|e| e.to_string())?;
    executor.register(0, ECHO).map_err(|e| e.to_string())?;
    executor.register(4, STATEFUL).map_err(|e| e.to_string())?;
    let records = (0..5u32)
        .map(|id| {
            let mut record = vec![0; 128];
            let source = if id == 0 { ECHO } else { STATEFUL };
            record[..32].copy_from_slice(&Sha256::digest(source));
            record[32..36].copy_from_slice(&id.to_be_bytes());
            record[36..44].copy_from_slice(&1u64.to_be_bytes());
            record
        })
        .collect::<Vec<_>>();
    let first = Database::new(records.clone())?;
    let second = Database::new(records.clone())?;
    let geometry = secure::Geometry::new(5, 128)?;
    let (mut pir_client0, mut pir_server0) = secure::Endpoint::provision(0, geometry)?;
    let (mut pir_client1, mut pir_server1) = secure::Endpoint::provision(1, geometry)?;
    let (mut client, mut server) = Endpoint::provision(0)?;
    let cold_start_ns = ns(init.elapsed());
    let start = Instant::now();
    let period = Duration::from_millis(config.epoch_ms);
    let mut batcher = EpochBatcher::new(1, period, start)?;
    let mut state_counter = 0u32;
    for (step, &label) in labels.iter().enumerate() {
        let epoch = step as u64;
        let real = label != 0;
        let id = if label == 1 { 0u32 } else { 4u32 };
        let opportunity_started = Instant::now();
        let (cpu_start, _) = proc_counters();
        let mut payload = [0; PAYLOAD_BYTES];
        payload[0] = u8::from(real);
        payload[1..5].copy_from_slice(&id.to_be_bytes());
        payload[5] = 10;
        let active = mode.batching || real;
        let mut request_bytes = 0;
        let mut response_bytes = 0;
        let mut registry_bytes = 0;
        let mut registry_index = -1i32;
        let mut registry_ns = 0;
        let mut execution_ns = 0;
        let mut work_ns = 0;
        let mut late_by_ns = 0;
        let mut deadline_missed = false;
        let mut driver_work_overrun_ns = 0;
        let mut publication_lateness_ns = 0;
        let mut latency_ns = 0;
        let mut validation = None;
        if active {
            let submitted;
            let frame = if mode.encrypted {
                client.send(epoch, &payload)?.as_bytes().to_vec()
            } else {
                payload.to_vec()
            };
            let frame = if mode.batching {
                let due = start + period * (step as u32 + 1);
                if let Some(remaining) = due.checked_duration_since(Instant::now()) {
                    std::thread::sleep(remaining);
                }
                submitted = Instant::now();
                batcher.submit(Envelope::from_bytes(&frame)?)?;
                let batch = batcher.emit(Instant::now())?;
                late_by_ns = batch.late_by_ns;
                batch.envelopes[0].as_bytes().to_vec()
            } else {
                submitted = Instant::now();
                frame
            };
            request_bytes = frame.len();
            write(
                &mut network,
                &json!({"version":1,"step":step,"observer":"invocation","direction":"request","bytes":frame.len(),"elapsed_ns":ns(start.elapsed()),"frame":frame}),
            )?;
            let decoded = if mode.encrypted {
                server.receive(&Envelope::from_bytes(&frame)?)?
            } else {
                payload
            };
            // Only the trusted endpoint interprets payload identity and code.
            let requested = u32::from_be_bytes(decoded[1..5].try_into()?);
            let selected = if decoded[0] == 1 { requested } else { 4 };
            let registry_started = Instant::now();
            let invocation_started = submitted;
            let record = if mode.pir {
                let shares = QueryPair::generate(5, selected as usize)?;
                let q0 = pir_client0.seal_query(epoch, &shares.first)?;
                let q1 = pir_client1.seal_query(epoch, &shares.second)?;
                for (observer, query) in [("pir0", &q0), ("pir1", &q1)] {
                    write(
                        &mut network,
                        &json!({"version":1,"step":step,"observer":observer,"direction":"request","bytes":query.len(),"elapsed_ns":ns(start.elapsed()),"frame":query}),
                    )?;
                }
                let a0 = first.answer(&pir_server0.open_query(&q0)?)?;
                let a1 = second.answer(&pir_server1.open_query(&q1)?)?;
                let a0 = pir_server0.seal_answer(&a0)?;
                let a1 = pir_server1.seal_answer(&a1)?;
                registry_bytes = q0.len() + q1.len() + a0.len() + a1.len();
                for (observer, answer) in [("pir0", &a0), ("pir1", &a1)] {
                    write(
                        &mut network,
                        &json!({"version":1,"step":step,"observer":observer,"direction":"response","bytes":answer.len(),"elapsed_ns":ns(start.elapsed()),"frame":answer}),
                    )?;
                }
                recover(
                    &pir_client0.open_answer(&a0)?,
                    &pir_client1.open_answer(&a1)?,
                )?
            } else {
                registry_index = selected as i32;
                registry_bytes = 4 + 128;
                write(
                    &mut network,
                    &json!({"version":1,"step":step,"observer":"registry","direction":"request","bytes":4,"elapsed_ns":ns(start.elapsed()),"address":selected}),
                )?;
                records[selected as usize].clone()
            };
            registry_ns = ns(registry_started.elapsed());
            if record != records[selected as usize] {
                return Err("registry authentication failed".into());
            }
            let mut argument = [0; 64];
            argument.copy_from_slice(&decoded[5..69]);
            let namespace = if decoded[0] == 1 {
                Namespace {
                    first: 0,
                    blocks: 7,
                }
            } else {
                Namespace {
                    first: 7,
                    blocks: 1,
                }
            };
            if !mode.padding && decoded[0] == 0 {
                argument[4..8].copy_from_slice(&7u32.to_le_bytes());
            }
            let result = if mode.padding {
                executor.prepare_scheduled(
                    selected,
                    &argument,
                    stores.handle(),
                    namespace,
                    invocation_started,
                )
            } else {
                executor.execute_unpadded_baseline(selected, &argument, stores.handle())
            };
            if result.status != Status::Success {
                return Err(format!(
                    "invocation oracle failed: mode{} status{:?}",
                    mode.name, result.status
                )
                .into());
            }
            work_ns = result.work_ns;
            execution_ns = result.total_ns;
            deadline_missed = result.deadline_missed;
            let mut result_payload = [0; PAYLOAD_BYTES];
            result_payload[0] = 0;
            let visibility_mask = 0u8.wrapping_sub(u8::from(real));
            for (out, byte) in result_payload[1..].iter_mut().zip(&result.body) {
                *out = *byte & visibility_mask;
            }
            let response = if mode.encrypted {
                server.send(epoch, &result_payload)?.as_bytes().to_vec()
            } else {
                result_payload[..if real && id == 0 { 65 } else { 5 }].to_vec()
            };
            response_bytes = response.len();
            if mode.padding {
                let deadline =
                    invocation_started + Duration::from_millis(executor.class().deadline_ms);
                driver_work_overrun_ns = ns(Instant::now().saturating_duration_since(deadline));
                deadline_missed |= driver_work_overrun_ns > 0;
                if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                    std::thread::sleep(remaining);
                }
                execution_ns = ns(invocation_started.elapsed());
                publication_lateness_ns = ns(Instant::now().saturating_duration_since(deadline));
            }
            // Response boundary: oracle checking and trace serialization are
            // deliberately outside this timestamp.
            latency_ns = ns(submitted.elapsed());
            write(
                &mut network,
                &json!({"version":1,"step":step,"observer":"invocation","direction":"response","bytes":response.len(),"elapsed_ns":ns(start.elapsed()),"frame":response}),
            )?;
            if mode.encrypted
                && client.receive(&Envelope::from_bytes(&response)?)? != result_payload
            {
                return Err("client response authentication".into());
            }
            validation = Some((argument, result.body));
        }
        if let Some((argument, body)) = validation
            && real
        {
            let expected = if id == 0 {
                argument.to_vec()
            } else {
                state_counter += 1;
                state_counter.to_le_bytes().to_vec()
            };
            if body.len() < expected.len() || body[..expected.len()] != expected {
                return Err("WASM result differs from client oracle".into());
            }
        }
        let events = stores.drain()?;
        let storage_bytes = events.iter().map(|e| e.bytes).sum::<usize>();
        let reads = events
            .iter()
            .filter(|e| e.direction == StorageDirection::Read)
            .collect::<Vec<_>>();
        let leaf = reads.last().map_or(-1, |event| event.bucket as i64);
        let first_storage_ns = events.first().map_or(0, |e| e.elapsed_ns);
        let last_storage_ns = events.last().map_or(0, |e| e.elapsed_ns);
        let first_to_last_ns = last_storage_ns.saturating_sub(first_storage_ns);
        for event in &events {
            write(
                &mut storage_trace,
                &json!({"version":1,"step":step,"elapsed_ns":event.elapsed_ns,"direction":event.direction,"bucket":event.bucket,"bytes":event.bytes}),
            )?;
        }
        let (cpu_end, rss_pages) = proc_counters();
        write(
            &mut observer,
            &json!({"version":1,"step":step,"request_bytes":request_bytes,"response_bytes":response_bytes,"registry_bytes":registry_bytes,"registry_index":registry_index,"storage_events":events.len(),"storage_bytes":storage_bytes,"last_bucket":leaf,"storage_span_ns":first_to_last_ns,"latency_ns":latency_ns,"late_by_ns":late_by_ns,"instance_count":1,"cold_start_ns":if step==0{cold_start_ns}else{0}}),
        )?;
        write(&mut truth, &json!({"step":step,"label":label}))?;
        write(
            &mut private,
            &json!({"step":step,"work_ns":work_ns,"execution_ns":execution_ns,"registry_ns":registry_ns,"deadline_missed":deadline_missed,"driver_work_overrun_ns":driver_work_overrun_ns,"publication_lateness_ns":publication_lateness_ns}),
        )?;
        write(
            metrics,
            &json!({"mode":mode.name,"trial":trial,"session":session,"step":step,"oracle_ok":true,"latency_ns":latency_ns,"registry_ns":registry_ns,"execution_ns":execution_ns,"work_ns":work_ns,"padding_ns":execution_ns.saturating_sub(work_ns),"request_bytes":request_bytes,"response_bytes":response_bytes,"registry_bytes":registry_bytes,"storage_bytes":storage_bytes,"opportunity_wall_ns":ns(opportunity_started.elapsed()),"cpu_ticks":cpu_end.saturating_sub(cpu_start),"rss_pages":rss_pages,"late_by_ns":late_by_ns,"deadline_missed":deadline_missed,"driver_work_overrun_ns":driver_work_overrun_ns,"publication_lateness_ns":publication_lateness_ns}),
        )?;
    }
    write(&mut private, &stores.stats()?)?;
    Ok(())
}
