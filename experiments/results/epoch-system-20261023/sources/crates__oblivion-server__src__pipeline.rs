use crate::{
    Result,
    discovery::{Discovery, NAMES},
    secure_pir,
};
use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, EpochBatcher, PAYLOAD_BYTES};
use oblivion_exec::{Class, Executor, Namespace, Status};
use oblivion_pir::{QueryPair, recover};
use oblivion_store::{Config, MemoryBackend, PathOram};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const SOURCES: [&[u8]; 5] = [
    include_bytes!("../../../examples/wasm-functions/echo.wat"),
    include_bytes!("../../../examples/wasm-functions/sum.wat"),
    include_bytes!("../../../examples/wasm-functions/fibonacci.wat"),
    include_bytes!("../../../examples/wasm-functions/hash.wat"),
    include_bytes!("../../../examples/wasm-functions/stateful.wat"),
];
pub const REGISTRY_VERSION: u64 = 1;
pub fn registry() -> Vec<Vec<u8>> {
    SOURCES
        .iter()
        .enumerate()
        .map(|(id, source)| {
            let mut record = vec![0; 128];
            record[..32].copy_from_slice(&Sha256::digest(source));
            record[32..36].copy_from_slice(&(id as u32).to_be_bytes());
            record[36..44].copy_from_slice(&REGISTRY_VERSION.to_be_bytes());
            record
        })
        .collect()
}

/// A deployment is immutable for the session. The trusted binary pins every
/// record byte, including function identity, module digest, version and padding.
/// This is a local trust anchor, not a remotely signed registry.
struct Deployment {
    records: Vec<Vec<u8>>,
    digest: [u8; 32],
}
impl Deployment {
    fn pinned() -> Self {
        let records = registry();
        let mut hash = Sha256::new();
        hash.update(b"oblivion/registry/deployment/v1");
        hash.update(REGISTRY_VERSION.to_be_bytes());
        for record in &records {
            hash.update(record);
        }
        Self {
            records,
            digest: hash.finalize().into(),
        }
    }
    fn accepts(&self, selected: usize, record: &[u8]) -> bool {
        self.records
            .get(selected)
            .is_some_and(|expected| expected == record)
    }
    fn digest_hex(&self) -> String {
        self.digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

const PIPE_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) struct Process(pub(crate) Child);
impl Process {
    pub(crate) fn finish(&mut self) -> Result<()> {
        let deadline = Instant::now() + PIPE_TIMEOUT;
        loop {
            if let Some(status) = self.0.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err("executor failed".into())
                };
            }
            if Instant::now() >= deadline {
                return Err("executor shutdown timed out".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
pub(crate) fn spawn(mode: &str, arguments: &[&str]) -> Result<Process> {
    Ok(Process(
        Command::new(std::env::current_exe()?)
            .arg(mode)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    ))
}
pub fn demo(output: &Path, real_percent: u32, participants: usize, mixed: bool) -> Result<()> {
    demo_with_discovery(output, real_percent, participants, mixed, false)
}
pub fn demo_with_discovery(
    output: &Path,
    real_percent: u32,
    participants: usize,
    mixed: bool,
    discovery: bool,
) -> Result<()> {
    demo_schedule(
        output,
        real_percent,
        participants,
        mixed,
        discovery,
        150 * participants as u64,
        8,
    )
}

pub fn demo_sweep(
    output: &Path,
    real_percent: u32,
    participants: usize,
    mixed: bool,
    epoch_ms: u64,
    epochs: u64,
) -> Result<()> {
    demo_schedule(
        output,
        real_percent,
        participants,
        mixed,
        false,
        epoch_ms,
        epochs,
    )
}

fn demo_schedule(
    output: &Path,
    real_percent: u32,
    participants: usize,
    mixed: bool,
    discovery: bool,
    epoch_ms: u64,
    epochs: u64,
) -> Result<()> {
    if ![0, 50, 100].contains(&real_percent) || !(1..=4).contains(&participants) {
        return Err("real percent must be 0, 50 or 100; participants 1..4".into());
    }
    if !(100 * participants as u64..=1000).contains(&epoch_ms) || !(1..=128).contains(&epochs) {
        return Err(
            "epoch_ms must cover sequential public slots and be at most1000; epochs1..128".into(),
        );
    }
    fs::create_dir(output)?;
    write_schedule_metadata(output, real_percent, participants, mixed, epoch_ms, epochs)?;
    let mut executor = spawn(
        "executor-worker",
        &[
            output.to_str().ok_or("non-UTF8 path")?,
            &participants.to_string(),
        ],
    )?;
    let mut input = executor.0.stdin.take().ok_or("missing stdin")?;
    let responses = executor.0.stdout.take().ok_or("missing stdout")?;
    // One fixed-frame reader owns the pipe. A stalled worker cannot hold the
    // client forever: recv_timeout triggers Process cleanup and kills/reaps it.
    let (tx, rx) = std::sync::mpsc::sync_channel(4);
    std::thread::spawn(move || {
        let mut responses = responses;
        let mut ready = [0; 1];
        if responses.read_exact(&mut ready).is_err() || tx.send(ready.to_vec()).is_err() {
            return;
        }
        loop {
            let mut bytes = vec![0; ENVELOPE_BYTES];
            if responses.read_exact(&mut bytes).is_err() || tx.send(bytes).is_err() {
                break;
            }
        }
    });
    let mut discoveries = (0..participants)
        .map(|_| {
            if discovery {
                Discovery::new().map(Some)
            } else {
                Ok(None)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let mut clients = Vec::new();
    for slot in 0..participants {
        clients.push(Endpoint::provision_over_pipe(slot as u32, &mut input)?);
    }
    if rx.recv_timeout(Duration::from_secs(10))? != [1] {
        return Err("executor startup failed".into());
    }
    let start = Instant::now();
    let period = Duration::from_millis(epoch_ms);
    let mut batcher = EpochBatcher::new(participants, period, start)?;
    let mut observer = BufWriter::new(File::create(output.join("envelope-observer.jsonl"))?);
    let mut labels = BufWriter::new(File::create(output.join("client-ground-truth.jsonl"))?);
    let mut real = 0u64;
    let mut dummy = 0u64;
    let mut counters = vec![0u32; participants];
    let mut functions = std::collections::BTreeSet::new();
    for epoch in 0..epochs {
        let mut requests = Vec::new();
        let mut ready_frames = Vec::new();
        for (slot, client) in clients.iter_mut().enumerate() {
            let is_real = real_percent == 100
                || (real_percent == 50 && (epoch + slot as u64).is_multiple_of(2));
            let candidate = if mixed {
                ((epoch * participants as u64 + slot as u64) % 5) as u32
            } else {
                4
            };
            let id = if let Some(index) = &mut discoveries[slot] {
                index.select(NAMES[candidate as usize])?
            } else {
                candidate
            };
            let mut argument = [0u8; 64];
            argument[0] = 10;
            let mut payload = [0; PAYLOAD_BYTES];
            payload[0] = u8::from(is_real);
            payload[1..5].copy_from_slice(&id.to_be_bytes());
            payload[5..69].copy_from_slice(&argument);
            let ready_at = Instant::now();
            ready_frames.push(client.send(epoch, &payload)?);
            requests.push((is_real, id, argument, ready_at));
        }
        let due = start + period * (epoch as u32 + 1);
        if let Some(remaining) = due.checked_duration_since(Instant::now()) {
            std::thread::sleep(remaining);
        }
        for frame in ready_frames {
            batcher.submit(frame)?;
        }
        let batch = batcher.emit(Instant::now())?;
        let sent = Instant::now();
        for frame in &batch.envelopes {
            input.write_all(frame.as_bytes())?;
        }
        input.flush()?;
        for (slot, (client, (is_real, id, argument, ready_at))) in
            clients.iter_mut().zip(requests).enumerate()
        {
            let bytes = rx.recv_timeout(Duration::from_secs(5))?;
            let result = client.receive(&Envelope::from_bytes(&bytes)?)?;
            let completed = Instant::now();
            if result[0] != 0 {
                return Err("invocation failed (trusted client result)".into());
            }
            if is_real {
                real += 1;
                functions.insert(id);
                let mut expected = vec![0; 64];
                match id {
                    0 => expected.copy_from_slice(&argument),
                    1 => expected[..4].copy_from_slice(
                        &argument
                            .iter()
                            .map(|&b| u32::from(b))
                            .sum::<u32>()
                            .to_le_bytes(),
                    ),
                    2 => expected[..4].copy_from_slice(&55u32.to_le_bytes()),
                    3 => {
                        let hash = argument.iter().fold(2166136261u32, |h, &b| {
                            (h ^ u32::from(b)).wrapping_mul(16777619)
                        });
                        expected[..4].copy_from_slice(&hash.to_le_bytes());
                    }
                    4 => {
                        counters[slot] += 1;
                        expected[..4].copy_from_slice(&counters[slot].to_le_bytes());
                    }
                    _ => return Err("oracle function".into()),
                }
                if result[1..65] != expected {
                    return Err("WASM result mismatches independent client oracle".into());
                }
            } else {
                dummy += 1;
                if result[1..].iter().any(|&b| b != 0) {
                    return Err("dummy disclosed output".into());
                }
            }
            serde_json::to_writer(
                &mut observer,
                &serde_json::json!({"version":1,"epoch":epoch,"slot":slot,"observer":"batch-pipe","request_bytes":ENVELOPE_BYTES,"response_bytes":ENVELOPE_BYTES,"batch_count":batch.envelopes.len(),"latency_ns":completed.duration_since(sent).as_nanos() as u64,"queue_wait_ns":sent.duration_since(ready_at).as_nanos() as u64,"arrival_to_response_ns":completed.duration_since(ready_at).as_nanos() as u64,"client_ready_ns":ready_at.duration_since(start).as_nanos() as u64,"epoch_due_ns":due.duration_since(start).as_nanos() as u64,"batch_sent_ns":sent.duration_since(start).as_nanos() as u64,"late_by_ns":batch.late_by_ns}),
            )?;
            writeln!(observer)?;
            serde_json::to_writer(
                &mut labels,
                &serde_json::json!({"epoch":epoch,"slot":slot,"real":is_real,"function":id}),
            )?;
            writeln!(labels)?;
        }
    }
    drop(input);
    executor.finish()?;
    if discovery {
        let mut trace = BufWriter::new(File::create(
            output.join("metadata-discovery-observer.jsonl"),
        )?);
        for (slot, index) in discoveries.iter().enumerate() {
            if let Some(index) = index {
                for event in &index.trace {
                    serde_json::to_writer(
                        &mut trace,
                        &serde_json::json!({"slot":slot,"protocol":event}),
                    )?;
                    writeln!(trace)?;
                }
            }
        }
        trace.flush()?;
    }
    let summary = serde_json::json!({"sse_metadata_discovery":discovery,"sse_searches_verified":discoveries.iter().flatten().map(|index|index.verified).sum::<u64>(),"registry_version":REGISTRY_VERSION,"registry_deployment_sha256":Deployment::pinned().digest_hex(),"real_invocations":real,"dummy_invocations":dummy,"last_real_counter":counters[0],"client_state_counters":counters,"participants":participants,"functions_verified":functions.len(),"request_bytes":ENVELOPE_BYTES,"response_bytes":ENVELOPE_BYTES,"processes":4,"encrypted_pir_links":true,"real_percent":real_percent,"epoch_ms":period.as_millis(),"epochs":epochs,"measurement_wall_ns":start.elapsed().as_nanos() as u64,"execution_class_ms":Class::small().deadline_ms,"state_working_set_blocks":8,"logical_oram_operations_per_invocation":16,"limitations":["PIR servers must not collude","inherited pipes simulate trusted provisioning; no hardware TEE","demo state is ephemeral, durable store API tested separately","public sequential slots and bounded eight-block working set; deadline misses and resource leakage remain"]});
    fs::write(
        output.join("client-summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    println!(
        "Completed {real} real and {dummy} dummy invocations across {participants} clients. Results: {}",
        output.display()
    );
    Ok(())
}

/// Keep a full stdout pipe from blocking the executor's main thread forever.
/// Only one fixed frame is outstanding; a missing acknowledgment aborts the
/// process, which also releases the writer thread and its pipe handle.
struct ResponsePipe {
    send: std::sync::mpsc::SyncSender<Vec<u8>>,
    ack: std::sync::mpsc::Receiver<std::result::Result<(), String>>,
}
impl ResponsePipe {
    fn new() -> Self {
        let (send, receive) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        let (ack_tx, ack) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            while let Ok(frame) = receive.recv() {
                let result = output
                    .write_all(&frame)
                    .and_then(|()| output.flush())
                    .map_err(|e| e.to_string());
                let failed = result.is_err();
                if ack_tx.send(result).is_err() || failed {
                    return;
                }
            }
        });
        Self { send, ack }
    }
    fn write_all(&self, bytes: &[u8]) -> Result<()> {
        self.send.send(bytes.to_vec())?;
        self.ack
            .recv_timeout(PIPE_TIMEOUT)
            .map_err(|_| "executor response pipe timed out")??;
        Ok(())
    }
}

pub fn worker(output: &Path, participants: usize) -> Result<()> {
    if !(1..=4).contains(&participants) {
        return Err("participants must be 1..4".into());
    }
    let responses = ResponsePipe::new();
    let (bootstrap_tx, bootstrap_rx) = std::sync::mpsc::sync_channel(1);
    let (frames_tx, frames_rx) = std::sync::mpsc::sync_channel(4);
    // A single pipe owner reads complete bounded frames. Main-thread deadlines
    // bound idle/partial bootstrap and request input. Process exit releases the
    // blocked reader; EOF between frames is the graceful shutdown signal.
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        let endpoints = (0..participants)
            .map(|slot| {
                Endpoint::accept_bootstrap(slot as u32, &mut input).map_err(|e| e.to_string())
            })
            .collect::<std::result::Result<Vec<_>, _>>();
        if bootstrap_tx.send(endpoints).is_err() {
            return;
        }
        loop {
            let mut bytes = [0; ENVELOPE_BYTES];
            let next = (|| -> std::io::Result<Option<Vec<u8>>> {
                if input.read(&mut bytes[..1])? == 0 {
                    return Ok(None);
                }
                input.read_exact(&mut bytes[1..])?;
                Ok(Some(bytes.to_vec()))
            })()
            .map_err(|e| e.to_string());
            let done = !matches!(next, Ok(Some(_)));
            if frames_tx.send(next).is_err() || done {
                return;
            }
        }
    });
    let mut endpoints = bootstrap_rx
        .recv_timeout(PIPE_TIMEOUT)
        .map_err(|_| "executor bootstrap timed out")??;
    let state = Arc::new(Mutex::new(PathOram::new(
        Config::new(8, 64)?,
        MemoryBackend::default(),
    )?));
    let mut executor = Executor::new(Class::small()).map_err(|e| e.to_string())?;
    for (id, source) in SOURCES.iter().enumerate() {
        executor
            .register(id as u32, source)
            .map_err(|e| e.to_string())?;
    }
    state
        .lock()
        .map_err(|_| "storage lock")?
        .backend_mut()
        .take_trace();
    let pinned = Deployment::pinned();
    let mut first = secure_pir::Session::spawn(0)?;
    let mut second = secure_pir::Session::spawn(1)?;
    let mut observer = BufWriter::new(File::create(output.join("storage-observer.jsonl"))?);
    let mut private = BufWriter::new(File::create(output.join("executor-private.jsonl"))?);
    responses.write_all(&[1])?;

    let mut publication = BufWriter::new(File::create(output.join("publication-private.jsonl"))?);
    let mut sequence = 0u64;
    let mut epoch_started = Instant::now();
    while let Some(bytes) = frames_rx
        .recv_timeout(PIPE_TIMEOUT)
        .map_err(|_| "executor request timed out")??
    {
        let frame = Envelope::from_bytes(&bytes)?;
        let request_cpu_start = cpu_time::ProcessTime::try_now()?;
        let received_at = Instant::now();
        let epoch = frame.epoch();
        let slot = sequence as usize % participants;
        if frame.slot() as usize != slot || epoch != sequence / participants as u64 {
            return Err("unexpected slot or epoch".into());
        }
        if slot == 0 {
            epoch_started = received_at;
        }
        let started =
            epoch_started + Duration::from_millis(executor.class().deadline_ms * slot as u64);
        sequence = sequence.checked_add(1).ok_or("sequence exhausted")?;
        let endpoint = &mut endpoints[slot];
        let decoded = endpoint.receive(&frame);
        let authenticated_frame = decoded.is_ok();
        let payload = decoded.unwrap_or([0; PAYLOAD_BYTES]);
        let requested = u32::from_be_bytes(payload[1..5].try_into()?);
        let state_address = u32::from_le_bytes(payload[9..13].try_into()?);
        let valid = authenticated_frame
            && payload[0] <= 1
            && requested < 5
            && !(payload[0] == 1
                && requested == 4
                && state_address >= if participants == 1 { 7 } else { 1 });
        let real = valid && payload[0] == 1;
        let selected = if valid { requested } else { 4 };
        // Every real, valid dummy, or authentication-failed cover frame uses PIR.
        let shares = QueryPair::generate(5, selected as usize)?;
        let answer = first.request(epoch, &shares.first).and_then(|a| {
            second
                .request(epoch, &shares.second)
                .and_then(|b| recover(&a, &b).map_err(Into::into))
        });
        let authenticated = answer
            .as_ref()
            .is_ok_and(|r| pinned.accepts(selected as usize, r));
        let mut argument = [0; 64];
        argument.copy_from_slice(&payload[5..69]);
        // Dummies execute the real stateful WASM code against a reserved block.
        let id = if real && authenticated { selected } else { 4 };
        if !real || !authenticated {
            argument.fill(0);
            argument[4..8].fill(0);
        }
        let namespace = if real && authenticated {
            Namespace {
                first: if participants == 1 { 0 } else { slot * 2 },
                blocks: if participants == 1 { 7 } else { 1 },
            }
        } else {
            Namespace {
                first: if participants == 1 { 7 } else { slot * 2 + 1 },
                blocks: 1,
            }
        };
        let result = executor.prepare_scheduled(id, &argument, state.clone(), namespace, started);
        let mut body = [0; PAYLOAD_BYTES];
        body[0] = u8::from(!valid || !authenticated || result.status != Status::Success);
        let mask = 0u8.wrapping_sub(u8::from(
            real && authenticated && result.status == Status::Success,
        ));
        for (out, byte) in body[1..65].iter_mut().zip(&result.body) {
            *out = *byte & mask;
        }
        let response = endpoint.send(epoch, &body)?;

        for event in state
            .lock()
            .map_err(|_| "storage lock")?
            .backend_mut()
            .take_trace()
        {
            serde_json::to_writer(&mut observer, &event)?;
            writeln!(observer)?;
        }
        serde_json::to_writer(
            &mut private,
            &serde_json::json!({"epoch":epoch,"slot":slot,"real":real,"function":selected,"status":format!("{:?}",result.status),"work_ns":result.work_ns,"prepare_ns":result.total_ns,"deadline_missed":result.deadline_missed,"pir_queries_completed":if answer.is_ok(){2}else{0},"pir_application_frame_bytes":if answer.is_ok(){Some(2*(oblivion_pir::secure::Geometry::new(5,128)?.query_frame_bytes()+oblivion_pir::secure::Geometry::new(5,128)?.answer_frame_bytes()))}else{None}}),
        )?;
        writeln!(private)?;
        observer.flush()?;
        private.flush()?;
        let deadline = started + Duration::from_millis(executor.class().deadline_ms);
        let ready_elapsed_ns = started.elapsed().as_nanos();
        let driver_work_overrun_ns = Instant::now()
            .saturating_duration_since(deadline)
            .as_nanos();
        if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            std::thread::sleep(remaining);
        }
        responses.write_all(response.as_bytes())?;
        serde_json::to_writer(
            &mut publication,
            &serde_json::json!({"epoch":epoch,"slot":slot,"ready_elapsed_ns":ready_elapsed_ns,"driver_work_overrun_ns":driver_work_overrun_ns,"response_elapsed_ns":started.elapsed().as_nanos(),"publication_lateness_ns":Instant::now().saturating_duration_since(deadline).as_nanos(),"executor_process_cpu_ns":request_cpu_start.try_elapsed()?.as_nanos() as u64}),
        )?;
        writeln!(publication)?;
        publication.flush()?;
    }
    if !sequence.is_multiple_of(participants as u64) {
        return Err("incomplete epoch at shutdown".into());
    }
    Ok(())
}

pub(crate) fn write_metadata(
    output: &Path,
    real_percent: u32,
    participants: usize,
    mixed: bool,
) -> Result<()> {
    write_schedule_metadata(
        output,
        real_percent,
        participants,
        mixed,
        150 * participants as u64,
        8,
    )
}

fn write_schedule_metadata(
    output: &Path,
    real_percent: u32,
    participants: usize,
    mixed: bool,
    epoch_ms: u64,
    epochs: u64,
) -> Result<()> {
    fn text_command(program: &str, args: &[&str]) -> String {
        Command::new(program)
            .args(args)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
            .unwrap_or_else(|| "unavailable".into())
    }
    fn collect(directory: &Path, paths: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                collect(&path, paths)?;
            } else if path.is_file() {
                paths.push(path);
            }
        }
        Ok(())
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = Vec::new();
    collect(&root.join("crates"), &mut paths)?;
    paths.extend([root.join("Cargo.toml"), root.join("Cargo.lock")]);
    paths.sort();
    let mut digest = Sha256::new();
    for path in paths {
        digest.update(path.strip_prefix(&root)?.to_string_lossy().as_bytes());
        digest.update([0]);
        digest.update(fs::read(path)?);
        digest.update([0]);
    }
    let source_sha256 = format!("{:x}", digest.finalize());
    let metadata = serde_json::json!({"schema_version":1,"software_version":env!("CARGO_PKG_VERSION"),"git_head":text_command("git",&["rev-parse","HEAD"]),"git_status":text_command("git",&["status","--porcelain"]),"source_tree_sha256":source_sha256,"rustc":text_command("rustc",&["--version","--verbose"]),"platform":text_command("uname",&["-a"]),"cpu":fs::read_to_string("/proc/cpuinfo").unwrap_or_else(|_|"unavailable".into()),"configuration":{"real_percent":real_percent,"epochs":epochs,"participants":participants,"epoch_ms":epoch_ms,"class_ms":Class::small().deadline_ms,"mixed_functions":mixed},"workload_seed":null,"workload":"fixed deterministic real/dummy schedule and constant inputs; no workload RNG; crypto uses OS randomness","trials":1,"statistical_methodology":"integration smoke check with client oracle and raw observer traces; no inference or statistical conclusion","resource_isolation":"shared host, no CPU pinning","output":output.display().to_string()});
    fs::write(
        output.join("metadata.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deployment_pin_rejects_version_rollback_tamper_and_wrong_identity() {
        let deployment = Deployment::pinned();
        let records = registry();
        for (id, record) in records.iter().enumerate() {
            assert!(deployment.accepts(id, record));
            assert!(!deployment.accepts((id + 1) % 5, record));
            let mut stale = record.clone();
            stale[36..44].copy_from_slice(&0u64.to_be_bytes());
            assert!(!deployment.accepts(id, &stale));
            for offset in [0, 32, 36, 44, 127] {
                let mut tampered = record.clone();
                tampered[offset] ^= 1;
                assert!(!deployment.accepts(id, &tampered));
            }
        }
        assert!(!deployment.accepts(5, &records[0]));
        assert_eq!(deployment.digest_hex(), Deployment::pinned().digest_hex());
    }
}
