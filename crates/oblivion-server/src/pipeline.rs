use crate::{
    Result,
    discovery::{Discovery, NAMES},
    secure_pir,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, EpochBatcher, PAYLOAD_BYTES};
use oblivion_exec::{Class, Executor, Namespace, Status};
use oblivion_pir::{QueryPair, recover};
use oblivion_registry::{Record, SignedRegistry, VerifiedRegistry};
use oblivion_server::invocation::{sign_request, verify_request};
use oblivion_store::{Config, MemoryBackend, PathOram, TrustedCheckpoint};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[cfg(unix)]
use oblivion_anchor::{Error as AnchorError, UnixAnchorClient, UnixInvocationAnchor};
#[cfg(unix)]
use oblivion_store::{CheckpointAnchor, CheckpointAnchorRecord};

const SOURCES: [&[u8]; 5] = [
    include_bytes!("../../../examples/wasm-functions/echo.wat"),
    include_bytes!("../../../examples/wasm-functions/sum.wat"),
    include_bytes!("../../../examples/wasm-functions/fibonacci.wat"),
    include_bytes!("../../../examples/wasm-functions/hash.wat"),
    include_bytes!("../../../examples/wasm-functions/stateful.wat"),
];

struct WorkerState {
    store: Arc<Mutex<PathOram<MemoryBackend>>>,
    #[cfg(unix)]
    durable: Option<DurableState>,
}

#[cfg(unix)]
struct DurableState {
    snapshot_dir: std::path::PathBuf,
    generation: Option<u64>,
    invocation_anchor: UnixInvocationAnchor,
}

impl WorkerState {
    fn new(output: &Path) -> Result<Self> {
        let socket = std::env::var_os("OBLIVION_ANCHOR_SOCKET");
        let state_dir = std::env::var_os("OBLIVION_ANCHOR_STATE_DIR");
        if socket.is_some() != state_dir.is_some() {
            return Err(
                "OBLIVION_ANCHOR_SOCKET and OBLIVION_ANCHOR_STATE_DIR must be set together".into(),
            );
        }
        let config = Config::new(8, 64)?;
        #[cfg(unix)]
        if let (Some(socket), Some(state_dir)) = (socket, state_dir) {
            return Self::durable(output, config, socket.into(), state_dir.into());
        }
        #[cfg(not(unix))]
        if socket.is_some() {
            return Err("durable invocation anchors require Unix-domain sockets".into());
        }
        let store = PathOram::new(config, MemoryBackend::default())?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            #[cfg(unix)]
            durable: None,
        })
    }

    #[cfg(unix)]
    fn durable(
        _output: &Path,
        config: Config,
        socket: std::path::PathBuf,
        state_dir: std::path::PathBuf,
    ) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir_all(&state_dir)?;
        let state_metadata = fs::symlink_metadata(&state_dir)?;
        if !state_metadata.is_dir() || state_metadata.file_type().is_symlink() {
            return Err("anchor state directory must be a real directory".into());
        }
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;
        let snapshot_dir = state_dir.join("snapshots");
        fs::create_dir_all(&snapshot_dir)?;
        let snapshot_metadata = fs::symlink_metadata(&snapshot_dir)?;
        if !snapshot_metadata.is_dir() || snapshot_metadata.file_type().is_symlink() {
            return Err("anchor snapshot directory must be a real directory".into());
        }
        fs::set_permissions(&snapshot_dir, fs::Permissions::from_mode(0o700))?;

        let invocation_anchor = UnixAnchorClient::invocation(&socket, "server-state-v1")?;
        let mut checkpoint_anchor = UnixAnchorClient::checkpoint(&socket, "server-state-v1")?;
        let current = checkpoint_anchor.load()?;
        let generation = current.as_ref().map(|record| record.generation());
        let current_snapshot_id = current
            .as_ref()
            .map(|record| record.snapshot_id().to_owned());
        if current.is_none() && fs::read_dir(&snapshot_dir)?.next().transpose()?.is_some() {
            return Err("unanchored snapshots exist but no checkpoint is present".into());
        }
        let store = if let Some(record) = current {
            if !safe_snapshot_id(record.snapshot_id()) {
                return Err("anchor returned an invalid snapshot identifier".into());
            }
            let snapshot = snapshot_dir.join(format!("{}.snapshot", record.snapshot_id()));
            let metadata = fs::symlink_metadata(&snapshot)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("anchored snapshot must be a regular file".into());
            }
            let trusted = TrustedCheckpoint::from_secret_bytes(record.secret_handle())?;
            if trusted.generation() != record.generation() {
                return Err("anchor checkpoint handle generation mismatch".into());
            }
            PathOram::restore(snapshot, &trusted, MemoryBackend::default())?
        } else {
            PathOram::new(config, MemoryBackend::default())?
        };
        prune_snapshots(&snapshot_dir, current_snapshot_id.as_deref())?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            durable: Some(DurableState {
                snapshot_dir,
                generation,
                invocation_anchor,
            }),
        })
    }
}

#[cfg(unix)]
fn safe_snapshot_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(unix)]
fn prune_snapshots(snapshot_dir: &Path, keep_snapshot_id: Option<&str>) -> Result<()> {
    let keep_name = if let Some(snapshot_id) = keep_snapshot_id {
        if !safe_snapshot_id(snapshot_id) {
            return Err("anchor returned an invalid snapshot identifier".into());
        }
        Some(format!("{snapshot_id}.snapshot"))
    } else {
        None
    };
    if let Some(name) = &keep_name {
        let current = snapshot_dir.join(name);
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("anchored snapshot must be a regular file".into());
        }
    }
    let mut removed = false;
    for entry in fs::read_dir(snapshot_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if keep_name
            .as_ref()
            .is_some_and(|keep| name == std::ffi::OsStr::new(keep))
            || !Path::new(&name)
                .extension()
                .is_some_and(|extension| extension == "snapshot")
        {
            continue;
        }
        let file_type = entry.file_type()?;
        if !file_type.is_file() && !file_type.is_symlink() {
            return Err("unexpected non-file entry in anchor snapshot directory".into());
        }
        fs::remove_file(entry.path())?;
        removed = true;
    }
    if removed {
        File::open(snapshot_dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
impl DurableState {
    fn load_receipt(
        &self,
        invocation: &oblivion_anchor::SignedInvocationId,
    ) -> std::result::Result<Option<Vec<u8>>, AnchorError> {
        match self.invocation_anchor.load(invocation) {
            Ok(Some(receipt)) => {
                if receipt.response().len() != PAYLOAD_BYTES {
                    return Err(AnchorError::Protocol);
                }
                Ok(Some(receipt.response().to_vec()))
            }
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn commit(
        &mut self,
        store: &mut PathOram<MemoryBackend>,
        invocation: &oblivion_anchor::SignedInvocationId,
        response: &[u8; PAYLOAD_BYTES],
    ) -> Result<Vec<u8>> {
        let mut random_id = [0; 16];
        OsRng.try_fill_bytes(&mut random_id)?;
        let suffix: String = random_id.iter().map(|byte| format!("{byte:02x}")).collect();
        let snapshot_id = format!("snap-{suffix}");
        let snapshot_path = self.snapshot_dir.join(format!("{snapshot_id}.snapshot"));
        let checkpoint = store.checkpoint(&snapshot_path)?;
        let expected_generation = self.generation;
        let next_generation = expected_generation
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("ORAM checkpoint generation exhausted")?;
        if checkpoint.generation() != next_generation {
            return Err("ORAM checkpoint generation does not follow anchor generation".into());
        }
        let handle = checkpoint.to_secret_bytes();
        let record = CheckpointAnchorRecord::new(&snapshot_id, handle.as_ref())?;
        let receipt =
            match self
                .invocation_anchor
                .commit(invocation, expected_generation, record, response)
            {
                Ok(receipt) => receipt,
                Err(AnchorError::CommitIndeterminate) => {
                    let receipt = self
                        .invocation_anchor
                        .load(invocation)?
                        .ok_or("anchor commit is indeterminate and no receipt can be recovered")?;
                    if receipt.response() != response {
                        return Err("recovered invocation receipt response mismatch".into());
                    }
                    receipt
                }
                Err(error) => return Err(error.into()),
            };
        self.generation = Some(receipt.generation());
        prune_snapshots(&self.snapshot_dir, Some(receipt.snapshot_id()))?;
        Ok(receipt.response().to_vec())
    }
}
pub const REGISTRY_VERSION: u64 = 1;
const REGISTRY_MANIFEST_HEADER_BYTES: usize = 124;
const MAX_REGISTRY_MANIFEST_BYTES: usize = REGISTRY_MANIFEST_HEADER_BYTES
    + oblivion_registry::MAX_RECORDS * oblivion_registry::RECORD_BYTES;
const REGISTRY_MANIFEST_ENV: &str = "OBLIVION_REGISTRY_MANIFEST";
const REGISTRY_PUBLIC_KEY_ENV: &str = "OBLIVION_REGISTRY_PUBLIC_KEY";
const REGISTRY_ANCHOR_SOCKET_ENV: &str = "OBLIVION_REGISTRY_ANCHOR_SOCKET";
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

/// Per-session verified catalog. The executor creates a local demo signer,
/// verifies the signed manifest and rows once, then pins exact row bytes for
/// the PIR responses. This does not establish an external publisher identity.
struct Deployment {
    records: Vec<Vec<u8>>,
}
impl Deployment {
    /// Load an external publisher-signed catalog, or retain the local demo
    /// signer only when neither external trust input is configured.
    fn from_environment() -> Result<Self> {
        let anchor_socket = std::env::var_os(REGISTRY_ANCHOR_SOCKET_ENV);
        match (
            std::env::var_os(REGISTRY_MANIFEST_ENV),
            std::env::var_os(REGISTRY_PUBLIC_KEY_ENV),
        ) {
            (None, None) if anchor_socket.is_none() => Self::create(),
            (None, None) => Err(format!(
                "{REGISTRY_ANCHOR_SOCKET_ENV} requires {REGISTRY_MANIFEST_ENV} and {REGISTRY_PUBLIC_KEY_ENV}"
            )
            .into()),
            (Some(manifest_path), Some(public_key_path)) => {
                let manifest =
                    read_bounded_regular(Path::new(&manifest_path), MAX_REGISTRY_MANIFEST_BYTES)?;
                let key_bytes = read_bounded_regular(Path::new(&public_key_path), 32)?;
                let key_bytes: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| "registry public key must contain exactly 32 bytes")?;
                let publisher = VerifyingKey::from_bytes(&key_bytes)?;
                Self::from_catalog(
                    &manifest,
                    &publisher,
                    anchor_socket.as_deref().map(Path::new),
                )
            }
            _ => Err(format!(
                "{REGISTRY_MANIFEST_ENV} and {REGISTRY_PUBLIC_KEY_ENV} must be configured together"
            )
            .into()),
        }
    }

    fn from_catalog(
        encoded: &[u8],
        publisher: &VerifyingKey,
        anchor_socket: Option<&Path>,
    ) -> Result<Self> {
        let verified = VerifiedRegistry::verify(encoded, publisher)?;
        if verified.len() != SOURCES.len() {
            return Err("signed registry record count does not match dispatch table".into());
        }
        let mut records = Vec::with_capacity(verified.len());
        for (id, source) in SOURCES.iter().enumerate() {
            let record = verified
                .get(u32::try_from(id)?)
                .ok_or("verified catalog is missing a deployment record")?;
            let module_digest: [u8; 32] = Sha256::digest(source).into();
            if record.id() != u32::try_from(id)?
                || record.module_digest() != &module_digest
                || record.location_digest() != &embedded_location_digest(id as u32, &module_digest)
                || record.resource_class() != 0
            {
                return Err("signed registry record does not match embedded deployment".into());
            }
            records.push(record.to_bytes().to_vec());
        }
        if let Some(socket) = anchor_socket {
            #[cfg(unix)]
            {
                let mut anchor = UnixAnchorClient::catalog(socket, "runtime-functions")?;
                verified.activate_catalog(&mut anchor)?;
            }
            #[cfg(not(unix))]
            {
                let _ = socket;
                return Err("registry catalog anchor requires Unix domain sockets".into());
            }
        }
        Ok(Self { records })
    }

    /// Development-only compatibility path. This key is generated in the
    /// executor and cannot authenticate an external publisher.
    fn create() -> Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        OsRng.try_fill_bytes(&mut *seed)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let mut records = Vec::with_capacity(SOURCES.len());
        for (id, source) in SOURCES.iter().enumerate() {
            let module_digest = Sha256::digest(source).into();
            let location_digest = embedded_location_digest(id as u32, &module_digest);
            records.push(Record::sign(
                id as u32,
                REGISTRY_VERSION,
                module_digest,
                location_digest,
                0,
                &signing_key,
            )?);
        }
        let catalog = SignedRegistry::sign(REGISTRY_VERSION, records, &signing_key)?;
        let verified = VerifiedRegistry::verify(&catalog, &signing_key.verifying_key())?;
        let mut encoded_records = Vec::with_capacity(verified.len());
        for id in 0..verified.len() {
            let record = verified
                .get(u32::try_from(id)?)
                .ok_or("verified catalog is missing a deployment record")?;
            encoded_records.push(record.to_bytes().to_vec());
        }
        let records = encoded_records;
        Ok(Self { records })
    }
    fn accepts(&self, selected: usize, record: &[u8]) -> bool {
        // Catalog verification already authenticated these exact bytes. A
        // selected PIR result must match its pinned row before module dispatch.
        self.records
            .get(selected)
            .is_some_and(|expected| expected == record)
    }
    fn contents_digest_hex() -> String {
        let mut hash = Sha256::new();
        hash.update(b"oblivion/registry/deployment/v2");
        for (id, source) in SOURCES.iter().enumerate() {
            let module_digest: [u8; 32] = Sha256::digest(source).into();
            hash.update((id as u32).to_be_bytes());
            hash.update(REGISTRY_VERSION.to_be_bytes());
            hash.update(module_digest);
            hash.update(embedded_location_digest(id as u32, &module_digest));
            hash.update([0; 20]); // Resource class plus canonical reserved bytes.
        }
        let digest: [u8; 32] = hash.finalize().into();
        hex_digest(&digest)
    }
}

fn read_bounded_regular(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > u64::try_from(maximum_bytes)? || metadata.len() == 0
    {
        return Err("registry input must be a non-empty regular file within its size limit".into());
    }
    let capacity = usize::try_from(metadata.len())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(u64::try_from(maximum_bytes)?.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err("registry input changed size or exceeds its size limit".into());
    }
    Ok(bytes)
}

fn embedded_location_digest(id: u32, module_digest: &[u8; 32]) -> [u8; 32] {
    let mut location = Sha256::new();
    location.update(b"oblivion/demo/embedded-location/v1");
    location.update(id.to_be_bytes());
    location.update(module_digest);
    location.finalize().into()
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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
/// Timestamp each complete pipe read before handoff to the trusted client.
/// Consumer decryption/oracle/logging delay must not move this public boundary.
fn read_response_frames(
    mut responses: impl Read,
    tx: std::sync::mpsc::SyncSender<(Vec<u8>, Instant)>,
) {
    let mut ready = [0; 1];
    if responses.read_exact(&mut ready).is_err() {
        return;
    }
    let read_at = Instant::now();
    if tx.send((ready.to_vec(), read_at)).is_err() {
        return;
    }
    loop {
        let mut bytes = vec![0; ENVELOPE_BYTES];
        if responses.read_exact(&mut bytes).is_err() {
            break;
        }
        let read_at = Instant::now();
        if tx.send((bytes, read_at)).is_err() {
            break;
        }
    }
}

#[derive(Clone, Copy)]
enum RunMode {
    Demo { discovery: bool },
    Sweep,
}

/// Validate the entire authenticated reply, retaining masked failures only for
/// research sweeps. A failure is never reinterpreted as a successful guest call.
fn verify_client_reply(
    result: &[u8; PAYLOAD_BYTES],
    mode: RunMode,
    is_real: bool,
    id: u32,
    argument: &[u8; 64],
    counter: &mut u32,
) -> Result<bool> {
    if result[0] == 1 {
        if result[1..].iter().any(|&byte| byte != 0) {
            return Err("runtime error disclosed nonzero payload".into());
        }
        return match mode {
            RunMode::Sweep => Ok(false),
            RunMode::Demo { .. } => Err("invocation failed (trusted client result)".into()),
        };
    }
    if result[0] != 0 {
        return Err("invalid authenticated response status".into());
    }
    let mut expected = [0; PAYLOAD_BYTES];
    let mut next_counter = *counter;
    if is_real {
        match id {
            0 => expected[1..65].copy_from_slice(argument),
            1 => expected[1..5].copy_from_slice(
                &argument
                    .iter()
                    .map(|&byte| u32::from(byte))
                    .sum::<u32>()
                    .to_le_bytes(),
            ),
            2 => expected[1..5].copy_from_slice(&55u32.to_le_bytes()),
            3 => {
                let hash = argument.iter().fold(2166136261u32, |hash, &byte| {
                    (hash ^ u32::from(byte)).wrapping_mul(16777619)
                });
                expected[1..5].copy_from_slice(&hash.to_le_bytes());
            }
            4 => {
                next_counter = counter.checked_add(1).ok_or("client counter exhausted")?;
                expected[1..5].copy_from_slice(&next_counter.to_le_bytes());
            }
            _ => return Err("oracle function".into()),
        }
    }
    if result != &expected {
        return Err("WASM result mismatches independent client oracle".into());
    }
    *counter = next_counter;
    Ok(true)
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
        RunMode::Demo { discovery },
        default_epoch_ms(participants)?,
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
        RunMode::Sweep,
        epoch_ms,
        epochs,
    )
}

fn demo_schedule(
    output: &Path,
    real_percent: u32,
    participants: usize,
    mixed: bool,
    mode: RunMode,
    epoch_ms: u64,
    epochs: u64,
) -> Result<()> {
    let discovery = matches!(mode, RunMode::Demo { discovery: true });
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
    std::thread::spawn(move || read_response_frames(responses, tx));
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
    let mut invocation_keys = Vec::with_capacity(participants);
    for slot in 0..participants {
        clients.push(Endpoint::provision_over_pipe(slot as u32, &mut input)?);
        let mut seed = Zeroizing::new([0; 32]);
        OsRng.try_fill_bytes(&mut *seed)?;
        invocation_keys.push(SigningKey::from_bytes(&seed));
    }
    if rx.recv_timeout(Duration::from_secs(10))?.0 != [1] {
        return Err("executor startup failed".into());
    }
    let start = Instant::now();
    let period = Duration::from_millis(epoch_ms);
    let mut batcher = EpochBatcher::new(participants, period, start)?;
    let mut observer = BufWriter::new(File::create(output.join("envelope-observer.jsonl"))?);
    let mut labels = BufWriter::new(File::create(output.join("client-ground-truth.jsonl"))?);
    let mut client_latency =
        BufWriter::new(File::create(output.join("client-private-latency.jsonl"))?);
    let mut real = 0u64;
    let mut dummy = 0u64;
    let (mut real_successes, mut real_failures, mut dummy_successes, mut dummy_failures) =
        (0u64, 0u64, 0u64, 0u64);
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
            let mut invocation_id = [0; 16];
            OsRng.try_fill_bytes(&mut invocation_id)?;
            sign_request(
                &mut payload,
                slot as u32,
                invocation_id,
                &invocation_keys[slot],
            );
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
            let (bytes, completed) = rx.recv_timeout(Duration::from_secs(5))?;
            let result = client.receive(&Envelope::from_bytes(&bytes)?)?;
            let succeeded =
                verify_client_reply(&result, mode, is_real, id, &argument, &mut counters[slot])?;
            if is_real {
                real += 1;
                if succeeded {
                    real_successes += 1;
                    functions.insert(id);
                } else {
                    real_failures += 1;
                }
            } else {
                dummy += 1;
                if succeeded {
                    dummy_successes += 1;
                } else {
                    dummy_failures += 1;
                }
            }
            serde_json::to_writer(
                &mut observer,
                &serde_json::json!({"version":1,"epoch":epoch,"slot":slot,"observer":"batch-pipe","request_bytes":ENVELOPE_BYTES,"response_bytes":ENVELOPE_BYTES,"batch_count":batch.envelopes.len(),"latency_ns":completed.duration_since(sent).as_nanos() as u64,"epoch_due_ns":due.duration_since(start).as_nanos() as u64,"batch_sent_ns":sent.duration_since(start).as_nanos() as u64,"late_by_ns":batch.late_by_ns}),
            )?;
            writeln!(observer)?;
            serde_json::to_writer(
                &mut client_latency,
                &serde_json::json!({"version":1,"epoch":epoch,"slot":slot,"queue_wait_ns":sent.duration_since(ready_at).as_nanos() as u64,"arrival_to_response_ns":completed.duration_since(ready_at).as_nanos() as u64,"client_ready_ns":ready_at.duration_since(start).as_nanos() as u64}),
            )?;
            writeln!(client_latency)?;
            serde_json::to_writer(
                &mut labels,
                &serde_json::json!({"epoch":epoch,"slot":slot,"real":is_real,"function":id,"success":succeeded}),
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
    let summary = serde_json::json!({"sse_metadata_discovery":discovery,"sse_searches_verified":discoveries.iter().flatten().map(|index|index.verified).sum::<u64>(),"registry_version":REGISTRY_VERSION,"registry_deployment_sha256":Deployment::contents_digest_hex(),"registry_record_bytes":oblivion_registry::RECORD_BYTES,"real_invocations":real,"dummy_invocations":dummy,"offered_invocations":epochs*participants as u64,"completed_invocations":real+dummy,"successful_real_invocations":real_successes,"failed_real_invocations":real_failures,"successful_dummy_invocations":dummy_successes,"failed_dummy_invocations":dummy_failures,"retains_runtime_errors":matches!(mode,RunMode::Sweep),"last_real_counter":counters[0],"client_state_counters":counters,"participants":participants,"functions_verified":functions.len(),"request_bytes":ENVELOPE_BYTES,"response_bytes":ENVELOPE_BYTES,"processes":4,"encrypted_pir_links":true,"real_percent":real_percent,"epoch_ms":period.as_millis(),"epochs":epochs,"measurement_wall_ns":start.elapsed().as_nanos() as u64,"execution_class_ms":Class::small().deadline_ms,"state_working_set_blocks":8,"logical_oram_operations_per_invocation":16,"limitations":["PIR servers must not collude","PIR workers share a host in this local demo","registry signing key is ephemeral and generated inside the trusted executor process; it does not establish an external publisher identity","embedded module-location digests are synthetic; encrypted module-location retrieval is not implemented","registry version has no persistent monotonic anchor in this demo","inherited pipes simulate trusted provisioning; no hardware TEE","demo state is ephemeral, durable store API tested separately","public sequential slots and bounded eight-block working set; deadline misses and resource leakage remain"]});
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
    let mut worker_state = WorkerState::new(output)?;
    let state = worker_state.store.clone();
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
    let pinned = Deployment::from_environment()?;
    let mut first = secure_pir::Session::spawn(0, &pinned.records)?;
    let mut second = secure_pir::Session::spawn(1, &pinned.records)?;
    let pir_geometry = oblivion_pir::secure::Geometry::new(
        pinned.records.len(),
        pinned.records.first().map_or(0, Vec::len),
    )?;
    let pir_application_frame_bytes =
        2 * (pir_geometry.query_frame_bytes() + pir_geometry.answer_frame_bytes());
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
        let invocation = authenticated_frame
            .then(|| verify_request(&payload, frame.slot()))
            .flatten();
        let mut valid = authenticated_frame
            && invocation.is_some()
            && payload[0] <= 1
            && requested < 5
            && !(payload[0] == 1
                && requested == 4
                && state_address >= if participants == 1 { 7 } else { 1 });
        let mut receipt_response = None;
        #[cfg(unix)]
        if valid
            && let (Some(durable), Some(invocation)) =
                (worker_state.durable.as_ref(), invocation.as_ref())
        {
            match durable.load_receipt(invocation) {
                Ok(receipt) => receipt_response = receipt,
                Err(AnchorError::Conflict) => valid = false,
                Err(error) => return Err(error.into()),
            }
        }
        let receipt_replay = receipt_response.is_some();
        let real = valid && payload[0] == 1 && !receipt_replay;
        let selected = if valid && !receipt_replay {
            requested
        } else {
            4
        };
        // Every real, valid dummy, or authentication-failed cover frame uses PIR.
        let shares = QueryPair::generate(5, selected as usize)?;
        let mut completed_pir_queries = 0usize;
        let pir_started = Instant::now();
        let answer = first.request(epoch, &shares.first).and_then(|a| {
            completed_pir_queries += 1;
            second.request(epoch, &shares.second).and_then(|b| {
                completed_pir_queries += 1;
                recover(&a, &b).map_err(Into::into)
            })
        });
        let pir_ns = pir_started.elapsed().as_nanos() as u64;
        let registry_pin_started = Instant::now();
        let authenticated = answer
            .as_ref()
            .is_ok_and(|r| pinned.accepts(selected as usize, r));
        let registry_pin_check_ns = registry_pin_started.elapsed().as_nanos() as u64;
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
        if let Some(saved) = &receipt_response {
            body.copy_from_slice(saved);
        }
        #[cfg(unix)]
        if valid
            && !receipt_replay
            && let (Some(durable), Some(invocation)) =
                (worker_state.durable.as_mut(), invocation.as_ref())
        {
            let mut store = state.lock().map_err(|_| "storage lock")?;
            let committed = durable.commit(&mut store, invocation, &body)?;
            body.copy_from_slice(&committed);
        }
        let response = endpoint.send(epoch, &body)?;

        let storage_events = state
            .lock()
            .map_err(|_| "storage lock")?
            .backend_mut()
            .take_trace();
        let storage_bytes: usize = storage_events.iter().map(|event| event.bytes).sum();
        for event in &storage_events {
            serde_json::to_writer(&mut observer, &event)?;
            writeln!(observer)?;
        }
        serde_json::to_writer(
            &mut private,
            &serde_json::json!({"epoch":epoch,"slot":slot,"real":real,"function":selected,"status":format!("{:?}",result.status),"registry_authenticated":authenticated,"registry_record_bytes":answer.as_ref().ok().map(Vec::len),"pir_ns":pir_ns,"registry_pin_check_ns":registry_pin_check_ns,"request_authenticated":authenticated_frame,"request_valid":valid,"storage_events":storage_events.len(),"storage_bytes":storage_bytes,"work_ns":result.work_ns,"prepare_ns":result.total_ns,"deadline_missed":result.deadline_missed,"pir_queries_completed":completed_pir_queries,"pir_application_frame_bytes":if completed_pir_queries==2{Some(pir_application_frame_bytes)}else{None}}),
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

fn default_epoch_ms(participants: usize) -> Result<u64> {
    if !(1..=4).contains(&participants) {
        return Err("participants must be 1..4".into());
    }
    (participants as u64)
        .checked_mul(150)
        .ok_or_else(|| "default epoch period overflow".into())
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
        default_epoch_ms(participants)?,
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
    fn actual_overdue_executor_error_is_retained_only_by_sweep_and_must_be_masked() {
        let state = Arc::new(Mutex::new(
            PathOram::new(Config::new(8, 64).unwrap(), MemoryBackend::default()).unwrap(),
        ));
        let mut executor = Executor::new(Class::small()).unwrap();
        executor.register(0, SOURCES[0]).unwrap();
        let argument = [10u8; 64];
        let execution = executor.execute_scheduled(
            0,
            &argument,
            state,
            Namespace {
                first: 0,
                blocks: 8,
            },
            Instant::now() - Duration::from_millis(200),
        );
        assert_eq!(execution.status, Status::Timeout);
        let (mut client, mut server) = Endpoint::provision(0).unwrap();
        server
            .receive(&client.send(0, &[0; PAYLOAD_BYTES]).unwrap())
            .unwrap();
        let mut payload = [0; PAYLOAD_BYTES];
        payload[0] = 1;
        payload[1..65].copy_from_slice(&execution.body);
        let decoded = client.receive(&server.send(0, &payload).unwrap()).unwrap();
        let mut counter = 0;
        assert!(
            !verify_client_reply(&decoded, RunMode::Sweep, true, 0, &argument, &mut counter)
                .unwrap()
        );
        assert_eq!(counter, 0);
        assert!(
            verify_client_reply(
                &decoded,
                RunMode::Demo { discovery: false },
                true,
                0,
                &argument,
                &mut counter
            )
            .is_err()
        );
        let mut corrupt = decoded;
        corrupt[127] = 1;
        assert!(
            verify_client_reply(&corrupt, RunMode::Sweep, true, 0, &argument, &mut counter)
                .is_err()
        );
        let mut false_success = decoded;
        false_success[0] = 0;
        assert!(
            verify_client_reply(
                &false_success,
                RunMode::Sweep,
                true,
                0,
                &argument,
                &mut counter
            )
            .is_err()
        );
        let mut success = [0; PAYLOAD_BYTES];
        success[1..65].copy_from_slice(&argument);
        assert!(
            verify_client_reply(&success, RunMode::Sweep, true, 0, &argument, &mut counter)
                .unwrap()
        );
        success[0] = 2;
        assert!(
            verify_client_reply(&success, RunMode::Sweep, true, 0, &argument, &mut counter)
                .is_err()
        );
        let mut stateful = [0; PAYLOAD_BYTES];
        stateful[1..5].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            verify_client_reply(&stateful, RunMode::Sweep, true, 4, &argument, &mut counter)
                .unwrap()
        );
        assert_eq!(counter, 1);
        assert!(
            !verify_client_reply(&decoded, RunMode::Sweep, true, 4, &argument, &mut counter)
                .unwrap()
        );
        assert_eq!(counter, 1);
        assert!(
            verify_client_reply(&stateful, RunMode::Sweep, true, 4, &argument, &mut counter)
                .is_err()
        );
        assert_eq!(counter, 1);
    }

    #[test]
    fn buffered_pipe_frames_keep_reader_timestamps_when_consumer_is_slow() {
        let (read, write) = rustix::pipe::pipe().unwrap();
        let mut writer = File::from(write);
        writer.write_all(&[1]).unwrap();
        writer.write_all(&[7; ENVELOPE_BYTES]).unwrap();
        writer.write_all(&[9; ENVELOPE_BYTES]).unwrap();
        drop(writer);
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        let reader = std::thread::spawn(move || read_response_frames(File::from(read), tx));
        reader.join().unwrap();
        let all_read_before = Instant::now();
        std::thread::sleep(Duration::from_millis(30));
        for expected in [vec![1], vec![7; ENVELOPE_BYTES], vec![9; ENVELOPE_BYTES]] {
            let (bytes, read_at) = rx.recv_timeout(Duration::from_secs(1)).unwrap();
            assert_eq!(bytes, expected);
            assert!(read_at <= all_read_before);
            assert!(read_at.elapsed() >= Duration::from_millis(20));
        }
    }

    #[test]
    fn default_metadata_period_rejects_invalid_participants_before_output() {
        for participants in [0, 5, usize::MAX] {
            assert!(default_epoch_ms(participants).is_err());
        }
        assert_eq!(default_epoch_ms(4).unwrap(), 600);
        let path = std::env::temp_dir().join(format!(
            "oblivion-invalid-metadata-{}",
            rand::random::<u64>()
        ));
        assert!(write_metadata(&path, 50, usize::MAX, false).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn signed_deployment_records_are_verified_and_bind_module_content() {
        let deployment = Deployment::create().unwrap();
        assert_eq!(deployment.records.len(), SOURCES.len());
        for (id, bytes) in deployment.records.iter().enumerate() {
            assert_eq!(bytes.len(), oblivion_registry::RECORD_BYTES);
            assert!(deployment.accepts(id, bytes));
            let record = oblivion_registry::Record::from_bytes(bytes).unwrap();
            assert_eq!(record.id(), id as u32);
            assert_eq!(record.version(), REGISTRY_VERSION);
            assert_eq!(
                record.module_digest().as_slice(),
                Sha256::digest(SOURCES[id]).as_slice()
            );
            assert!(!deployment.accepts((id + 1) % SOURCES.len(), bytes));
            for offset in [0, 4, 12, 44, 96, 159] {
                let mut tampered = bytes.clone();
                tampered[offset] ^= 1;
                assert!(!deployment.accepts(id, &tampered));
            }
        }
        assert_eq!(Deployment::contents_digest_hex().len(), 64);
    }

    fn external_catalog(signing_key: &SigningKey, mismatched_module: Option<usize>) -> Vec<u8> {
        let records = SOURCES
            .iter()
            .enumerate()
            .map(|(id, source)| {
                let mut module_digest: [u8; 32] = Sha256::digest(source).into();
                if mismatched_module == Some(id) {
                    module_digest[0] ^= 1;
                }
                Record::sign(
                    id as u32,
                    7,
                    module_digest,
                    embedded_location_digest(id as u32, &module_digest),
                    0,
                    signing_key,
                )
                .unwrap()
            })
            .collect();
        SignedRegistry::sign(7, records, signing_key).unwrap()
    }

    #[test]
    fn external_catalog_is_pinned_to_publisher_and_embedded_modules() {
        let publisher = SigningKey::from_bytes(&[0x71; 32]);
        let wrong_publisher = SigningKey::from_bytes(&[0x72; 32]).verifying_key();
        let catalog = external_catalog(&publisher, None);
        let deployment =
            Deployment::from_catalog(&catalog, &publisher.verifying_key(), None).unwrap();
        assert_eq!(deployment.records.len(), SOURCES.len());
        for (id, record) in deployment.records.iter().enumerate() {
            assert!(deployment.accepts(id, record));
        }
        assert!(Deployment::from_catalog(&catalog, &wrong_publisher, None).is_err());

        let mismatched = external_catalog(&publisher, Some(2));
        assert!(Deployment::from_catalog(&mismatched, &publisher.verifying_key(), None).is_err());
    }
}
