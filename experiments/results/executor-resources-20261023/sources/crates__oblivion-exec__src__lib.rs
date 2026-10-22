//! Fixed-class Wasmtime execution under an assumed trusted executor boundary.
//! This library is neither a TEE nor a process-isolated service. Padding targets
//! a deadline; OS scheduling, host I/O and cache behavior remain observable.
mod host;
mod staging;
pub use host::BlockStorage;
use host::{Host, Limits};
use sha2::{Digest, Sha256};
pub use staging::Namespace;
use staging::Staged;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use wasmtime::{Engine, Linker, Module, Store, Trap};
use zeroize::Zeroizing;

/// Public class parameters. Validated by Executor::new before allocation.
#[derive(Clone, Debug)]
pub struct Class {
    pub fuel: u64,
    pub memory_bytes: usize,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub deadline_ms: u64,
    pub storage_accesses: usize,
    pub host_call_fuel: u64,
    pub state_blocks: usize,
}
impl Class {
    pub fn small() -> Self {
        Self {
            fuel: 100_000,
            memory_bytes: 65536,
            input_bytes: 64,
            output_bytes: 64,
            deadline_ms: 100,
            storage_accesses: 2,
            host_call_fuel: 1000,
            state_blocks: 8,
        }
    }
    pub fn medium() -> Self {
        Self {
            fuel: 1_000_000,
            memory_bytes: 4 * 65536,
            input_bytes: 256,
            output_bytes: 256,
            deadline_ms: 200,
            storage_accesses: 4,
            host_call_fuel: 1000,
            state_blocks: 8,
        }
    }
    fn validate(&self) -> wasmtime::Result<()> {
        if self.fuel == 0
            || self.memory_bytes < 65536
            || self.memory_bytes > 16 * 1024 * 1024
            || self.input_bytes == 0
            || self.input_bytes > 16384
            || self.output_bytes == 0
            || self.output_bytes > 16384
            || !(2..=1000).contains(&self.deadline_ms)
            || self.storage_accesses > 64
            || self.state_blocks == 0
            || self.state_blocks > 4096
            || self.host_call_fuel == 0
        {
            wasmtime::bail!("invalid execution class");
        }
        Ok(())
    }
}

/// PRIVATE execution status. Must be protected inside an authenticated envelope
/// in a future wire service, never sent as untrusted scheduler metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Success,
    InvalidInput,
    OutOfFuel,
    Trap,
    Timeout,
    Resource,
    Storage,
}

/// PRIVATE result. Body has class-fixed size; network encryption is not provided
/// by this library. Timing fields are trusted instrumentation only.
pub struct Execution {
    pub status: Status,
    pub body: Vec<u8>,
    pub work_ns: u64,
    pub total_ns: u64,
    pub deadline_missed: bool,
}

pub struct Executor {
    class: Class,
    engine: Engine,
    modules: BTreeMap<u32, Module>,
    stop: Arc<AtomicBool>,
    ticker: Option<JoinHandle<()>>,
}
impl Executor {
    pub fn new(class: Class) -> wasmtime::Result<Self> {
        class.validate()?;
        let mut config = wasmtime::Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let clock_engine = engine.clone();
        let ticker = thread::Builder::new()
            .name("oblivion-epoch".into())
            .spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(1));
                    clock_engine.increment_epoch();
                }
            })
            .map_err(wasmtime::Error::new)?;
        Ok(Self {
            class,
            engine,
            modules: BTreeMap::new(),
            stop,
            ticker: Some(ticker),
        })
    }
    /// Bounded trusted deployment step; never compile on the invocation path.
    /// Returned digest authenticates these exact source bytes when provisioned
    /// through a separate trusted channel. A bare hash is not a signature.
    pub fn register(&mut self, id: u32, source: &[u8]) -> wasmtime::Result<[u8; 32]> {
        if source.len() > 1024 * 1024 || self.modules.contains_key(&id) || self.modules.len() >= 256
        {
            wasmtime::bail!("module size, identity or count rejected");
        }
        let module = Module::new(&self.engine, source)?;
        self.modules.insert(id, module);
        Ok(Sha256::digest(source).into())
    }
    pub fn class(&self) -> &Class {
        &self.class
    }

    pub fn execute(
        &mut self,
        id: u32,
        input: &[u8],
        storage: Arc<Mutex<dyn BlockStorage>>,
    ) -> Execution {
        self.execute_scheduled(
            id,
            input,
            storage,
            Namespace {
                first: 0,
                blocks: self.class.state_blocks,
            },
            Instant::now(),
        )
    }
    /// Fixed public state-access schedule. The caller's start time includes
    /// registry work; a late start is reported as a timeout, never hidden.
    /// A backend failure can interrupt this shape and poisons the ORAM controller.
    pub fn execute_scheduled(
        &mut self,
        id: u32,
        input: &[u8],
        storage: Arc<Mutex<dyn BlockStorage>>,
        namespace: Namespace,
        started: Instant,
    ) -> Execution {
        self.scheduled_inner(id, input, storage, namespace, started, true)
    }
    /// PRIVATE trusted-driver preparation. Preserves the public read/commit
    /// phases but returns before final response padding. The caller MUST finish
    /// encryption/instrumentation and wait until `started + class.deadline_ms`
    /// before publishing any response. Never expose this result directly.
    pub fn prepare_scheduled(
        &mut self,
        id: u32,
        input: &[u8],
        storage: Arc<Mutex<dyn BlockStorage>>,
        namespace: Namespace,
        started: Instant,
    ) -> Execution {
        self.scheduled_inner(id, input, storage, namespace, started, false)
    }
    fn scheduled_inner(
        &mut self,
        id: u32,
        input: &[u8],
        storage: Arc<Mutex<dyn BlockStorage>>,
        namespace: Namespace,
        started: Instant,
        publish_padding: bool,
    ) -> Execution {
        let deadline = started + Duration::from_millis(self.class.deadline_ms);
        let commit_at = started + Duration::from_micros(self.class.deadline_ms * 500);
        // Public registry/read boundary, independent of selected function.
        let read_at = started + Duration::from_micros(self.class.deadline_ms * 250);
        if let Some(remaining) = read_at.checked_duration_since(Instant::now()) {
            thread::sleep(remaining);
        }
        let mut body = vec![0; self.class.output_bytes];
        let mut status = Status::Storage;
        let prepared = (|| -> wasmtime::Result<Staged> {
            let mut physical = storage
                .lock()
                .map_err(|_| wasmtime::Error::msg("storage lock"))?;
            let width = physical.block_bytes();
            if self.class.state_blocks > physical.blocks()
                || width
                    .checked_mul(self.class.state_blocks)
                    .and_then(|bytes| bytes.checked_mul(2))
                    .is_none_or(|n| n > self.class.memory_bytes)
                || namespace.blocks == 0
                || namespace
                    .first
                    .checked_add(namespace.blocks)
                    .is_none_or(|n| n > self.class.state_blocks)
            {
                wasmtime::bail!("state geometry or namespace");
            }
            let mut data = Vec::with_capacity(self.class.state_blocks);
            for address in 0..self.class.state_blocks {
                let bytes = physical.read(address)?;
                if bytes.len() != width {
                    wasmtime::bail!("block width");
                }
                data.push(Zeroizing::new(bytes));
            }
            Ok(Staged {
                data,
                namespace,
                width,
            })
        })();
        if let Ok(snapshot) = prepared {
            let original = snapshot.data.clone();
            let staged = Arc::new(Mutex::new(snapshot));
            status = if input.len() != self.class.input_bytes || !self.modules.contains_key(&id) {
                Status::InvalidInput
            } else if Instant::now() >= commit_at {
                Status::Timeout
            } else {
                self.run(
                    &self.modules[&id],
                    input,
                    staged.clone(),
                    commit_at,
                    &mut body,
                )
                .0
            };
            // Guest-dependent time does not determine the physical write phase.
            if let Some(remaining) = commit_at.checked_duration_since(Instant::now()) {
                thread::sleep(remaining);
            }
            let committed = (|| -> wasmtime::Result<()> {
                let staged = staged
                    .lock()
                    .map_err(|_| wasmtime::Error::msg("staging lock"))?;
                let blocks = if status == Status::Success {
                    &staged.data
                } else {
                    &original
                };
                let mut physical = storage
                    .lock()
                    .map_err(|_| wasmtime::Error::msg("storage lock"))?;
                for (address, bytes) in blocks.iter().enumerate() {
                    physical.write(address, bytes)?;
                }
                Ok(())
            })();
            if committed.is_err() {
                status = Status::Storage;
            }
        }
        let work_ns = nanos(started.elapsed());
        if status != Status::Success {
            body.fill(0);
        }
        if publish_padding && let Some(remaining) = deadline.checked_duration_since(Instant::now())
        {
            thread::sleep(remaining);
        }
        Execution {
            status,
            body,
            work_ns,
            total_ns: nanos(started.elapsed()),
            deadline_missed: work_ns > self.class.deadline_ms * 1_000_000,
        }
    }
    /// Deliberately leaky experimental control: return only actual guest bytes,
    /// without wall-clock padding. Never label this mode privacy-preserving.
    pub fn execute_unpadded_baseline(
        &mut self,
        id: u32,
        input: &[u8],
        storage: Arc<Mutex<dyn BlockStorage>>,
    ) -> Execution {
        self.execute_mode(id, input, storage, false)
    }
    fn execute_mode(
        &mut self,
        id: u32,
        input: &[u8],
        storage: Arc<Mutex<dyn BlockStorage>>,
        padded: bool,
    ) -> Execution {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(self.class.deadline_ms);
        let mut body = vec![0; self.class.output_bytes];
        let (status, actual_bytes) = if input.len() != self.class.input_bytes {
            (Status::InvalidInput, 0)
        } else if let Some(module) = self.modules.get(&id) {
            self.run(module, input, storage, deadline, &mut body)
        } else {
            (Status::InvalidInput, 0)
        };
        let work_ns = nanos(started.elapsed());
        if status != Status::Success {
            body.fill(0);
        }
        // Success/error follow the same padding path. No claim of constant-time
        // completion under scheduling jitter, deadline overrun, or host blocking.
        if padded {
            if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                thread::sleep(remaining);
            }
        } else {
            body.truncate(if status == Status::Success {
                actual_bytes
            } else {
                0
            });
        }
        Execution {
            status,
            body,
            work_ns,
            total_ns: nanos(started.elapsed()),
            deadline_missed: work_ns > self.class.deadline_ms * 1_000_000,
        }
    }

    fn run(
        &self,
        module: &Module,
        input: &[u8],
        storage: Arc<Mutex<dyn BlockStorage>>,
        deadline: Instant,
        body: &mut [u8],
    ) -> (Status, usize) {
        let host = Host {
            limits: Limits {
                memory_bytes: self.class.memory_bytes,
                denied: false,
            },
            storage,
            accesses_left: self.class.storage_accesses,
            host_fuel: self.class.host_call_fuel,
            deadline,
            failure: None,
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|h| &mut h.limits);
        if store.set_fuel(self.class.fuel).is_err() {
            return (Status::Resource, 0);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        store.set_epoch_deadline(
            u64::try_from(remaining.as_millis())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        );
        store.epoch_deadline_trap();
        let result = (|| -> wasmtime::Result<usize> {
            let mut linker = Linker::new(&self.engine);
            host::link(&mut linker)?;
            let instance = linker.instantiate(&mut store, module)?;
            let memory = instance
                .get_memory(&mut store, "memory")
                .ok_or_else(|| wasmtime::Error::msg("missing memory"))?;
            // Clear I/O regions before invocation, including any guest data segments.
            memory
                .write(&mut store, 0, input)
                .map_err(wasmtime::Error::new)?;
            memory
                .write(&mut store, 32768, &vec![0; body.len()])
                .map_err(wasmtime::Error::new)?;
            let invoke =
                instance.get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "invoke")?;
            let size = invoke.call(
                &mut store,
                (0, input.len() as i32, 32768, body.len() as i32),
            )?;
            if size < 0 || size as usize > body.len() {
                wasmtime::bail!("invalid guest output length");
            }
            // Only declared bytes are copied; the rest remain zero-padded.
            memory
                .read(&store, 32768, &mut body[..size as usize])
                .map_err(wasmtime::Error::new)?;
            Ok(size as usize)
        })();
        if let Some(failure) = store.data().failure {
            return (failure, 0);
        }
        if store.data().limits.denied {
            return (Status::Resource, 0);
        }
        match result {
            Ok(size) if Instant::now() <= deadline => (Status::Success, size),
            Ok(_) => (Status::Timeout, 0),
            Err(error) => (
                match error.downcast_ref::<Trap>() {
                    Some(Trap::OutOfFuel) => Status::OutOfFuel,
                    Some(Trap::Interrupt) => Status::Timeout,
                    _ => Status::Trap,
                },
                0,
            ),
        }
    }
}
impl Drop for Executor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.ticker.take() {
            let _ = handle.join();
        }
    }
}
fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}
