//! Opt-in encrypted persistence for the otherwise ephemeral SSE client.
//!
//! Rollback detection depends on a durable anchor whose trust boundary is
//! independent of the journal directory. This module supplies the client-side
//! protocol and an anchor trait; it does not make an ordinary local file a
//! rollback-resistant anchor.

use super::{
    Client, DocumentId, Error, IndexId, Limits, SearchRequest, SearchSnapshot, UpdateRequest,
    VERSION, kdf,
};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const JOURNAL_VERSION: u8 = 1;
const JOURNAL_MAGIC: &[u8; 8] = b"OBLSSEJ1";
const MAX_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 64 * 1024 * 1024;
const CHECKPOINT_INTERVAL: usize = 256;
const MAX_REPLAY_RECORDS: usize = CHECKPOINT_INTERVAL;

/// Trusted, durable, rollback-resistant selection of one journal generation.
/// Implementations must bind the slot to its first `index_id`, enforce a
/// strictly consecutive generation with an atomic compare-and-swap, and keep
/// their own state outside the journal directory's rollback domain.
pub trait SseJournalAnchor {
    fn load(&mut self) -> Result<Option<SseJournalAnchorRecord>, SseJournalAnchorError>;

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        next_record: SseJournalAnchorRecord,
    ) -> Result<(), SseJournalAnchorError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SseJournalAnchorError {
    Conflict,
    CommitUnknown,
    Unavailable,
}

/// Public, non-secret pointer stored by the independent anchor service.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SseJournalAnchorRecord {
    index_id: IndexId,
    generation: u64,
    digest: [u8; 32],
}

impl SseJournalAnchorRecord {
    pub fn new(index_id: IndexId, generation: u64, digest: [u8; 32]) -> Self {
        Self {
            index_id,
            generation,
            digest,
        }
    }

    pub fn index_id(&self) -> IndexId {
        self.index_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum JournalError {
    #[error(transparent)]
    Sse(#[from] Error),
    #[error("persistent state is already initialized in the anchor")]
    AlreadyInitialized,
    #[error("persistent state is not initialized in the anchor")]
    NotInitialized,
    #[error("anchor state identifies another SSE index")]
    WrongIndex,
    #[error("another writer advanced the persistent state; reopen before retrying")]
    AnchorConflict,
    #[error("anchor commit outcome is indeterminate; reopen and reconcile before retrying")]
    AnchorCommitUnknown,
    #[error("trusted anchor is unavailable")]
    AnchorUnavailable,
    #[error("persistent client is poisoned; reopen it before further use")]
    Poisoned,
    #[error("journal authentication failed")]
    Authentication,
    #[error("journal encoding or state validation failed")]
    Format,
    #[error("journal resource bound exceeded")]
    Limit,
    #[error("operating-system randomness unavailable")]
    Randomness,
    #[error("journal filesystem operation failed: {0}")]
    Storage(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientState {
    version: u8,
    index_id: IndexId,
    tree_key: [u8; 32],
    value_key: [u8; 32],
    tag_key: [u8; 32],
    keywords: Vec<(Vec<u8>, Vec<u64>)>,
    pending: Option<UpdateRequest>,
    postings: usize,
    limits: Limits,
}

impl Drop for ClientState {
    fn drop(&mut self) {
        self.tree_key.zeroize();
        self.value_key.zeroize();
        self.tag_key.zeroize();
        for (keyword, _) in &mut self.keywords {
            keyword.zeroize();
        }
    }
}

impl ClientState {
    fn from_client(client: &Client) -> Self {
        Self {
            version: JOURNAL_VERSION,
            index_id: client.index_id,
            tree_key: *client.tree_key,
            value_key: *client.value_key,
            tag_key: *client.tag_key,
            keywords: client
                .keywords
                .iter()
                .map(|(keyword, counts)| (keyword.clone(), counts.clone()))
                .collect(),
            pending: client
                .pending
                .as_ref()
                .map(|pending| pending.request.clone()),
            postings: client.postings,
            limits: client.limits,
        }
    }

    fn validate(&self, expected_index: IndexId) -> Result<(), JournalError> {
        if self.version != JOURNAL_VERSION || self.index_id != expected_index {
            return Err(JournalError::WrongIndex);
        }
        self.limits.validate().map_err(JournalError::Sse)?;
        if self.postings > self.limits.postings || self.keywords.len() > self.limits.keywords {
            return Err(JournalError::Format);
        }

        let mut seen = HashSet::with_capacity(self.keywords.len());
        let mut total = 0usize;
        for (keyword, counts) in &self.keywords {
            if keyword.len() > self.limits.keyword_bytes
                || counts.is_empty()
                || counts.len() > self.limits.epochs_per_keyword
                || !seen.insert(keyword)
            {
                return Err(JournalError::Format);
            }
            for &count in counts {
                if count > super::TREE_CAPACITY {
                    return Err(JournalError::Format);
                }
                total = total
                    .checked_add(usize::try_from(count).map_err(|_| JournalError::Format)?)
                    .ok_or(JournalError::Format)?;
            }
        }
        if total != self.postings {
            return Err(JournalError::Format);
        }
        if self.pending.as_ref().is_some_and(|request| {
            request.version != VERSION || request.index_id != expected_index || self.postings == 0
        }) {
            return Err(JournalError::Format);
        }
        Ok(())
    }

    fn client_from_state(&self, expected_index: IndexId) -> Result<Client, JournalError> {
        self.validate(expected_index)?;
        Ok(Client {
            index_id: self.index_id,
            tree_key: Zeroizing::new(self.tree_key),
            value_key: Zeroizing::new(self.value_key),
            tag_key: Zeroizing::new(self.tag_key),
            keywords: self
                .keywords
                .iter()
                .map(|(keyword, counts)| (keyword.clone(), counts.clone()))
                .collect(),
            pending: self.pending.as_ref().map(|request| super::PendingAdd {
                request: request.clone(),
            }),
            postings: self.postings,
            limits: self.limits,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum JournalEntry {
    Checkpoint(ClientState),
    PrepareAdd {
        keyword: Vec<u8>,
        id: DocumentId,
        request: UpdateRequest,
    },
    FinishAdd {
        address: super::Address,
    },
    RotateKeyword {
        keyword: Vec<u8>,
    },
}

impl Drop for JournalEntry {
    fn drop(&mut self) {
        match self {
            Self::Checkpoint(state) => {
                state.tree_key.zeroize();
                state.value_key.zeroize();
                state.tag_key.zeroize();
                for (keyword, _) in &mut state.keywords {
                    keyword.zeroize();
                }
            }
            Self::PrepareAdd { keyword, .. } | Self::RotateKeyword { keyword } => {
                keyword.zeroize();
            }
            Self::FinishAdd { .. } => {}
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFrame {
    version: u8,
    index_id: IndexId,
    generation: u64,
    previous_digest: Option<[u8; 32]>,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

struct LimitedWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    overflowed: bool,
}

impl LimitedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            limit,
            overflowed: false,
        }
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(buffer.len()) else {
            self.overflowed = true;
            return Err(std::io::Error::other(
                "journal serialization bound exceeded",
            ));
        };
        if next_len > self.limit {
            self.overflowed = true;
            return Err(std::io::Error::other(
                "journal serialization bound exceeded",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Restartable SSE client whose state changes are published through an
/// independent compare-and-swap anchor.
pub struct PersistentClient<A: SseJournalAnchor> {
    client: Client,
    directory: PathBuf,
    storage_key: Zeroizing<[u8; 32]>,
    anchor: A,
    generation: u64,
    digest: [u8; 32],
    events_since_checkpoint: usize,
    poisoned: bool,
}

impl<A: SseJournalAnchor> PersistentClient<A> {
    /// Create a new index and publish its initial encrypted checkpoint.
    /// `storage_key` must be kept outside the journal directory.
    pub fn create(
        directory: impl AsRef<Path>,
        storage_key: &[u8; 32],
        limits: Limits,
        mut anchor: A,
    ) -> Result<Self, JournalError> {
        ensure_private_directory(directory.as_ref())?;
        if anchor.load().map_err(map_anchor_error)?.is_some() {
            return Err(JournalError::AlreadyInitialized);
        }
        let client = Client::new(limits)?;
        let mut persistent = Self {
            directory: directory.as_ref().to_path_buf(),
            storage_key: Zeroizing::new(*storage_key),
            anchor,
            generation: 0,
            digest: [0; 32],
            events_since_checkpoint: 0,
            poisoned: false,
            client,
        };
        persistent.commit_initial_checkpoint()?;
        Ok(persistent)
    }

    /// Reopen the state selected by the external anchor. A missing, stale,
    /// altered, unauthenticated, or unsupported record is rejected.
    pub fn open(
        directory: impl AsRef<Path>,
        storage_key: &[u8; 32],
        mut anchor: A,
    ) -> Result<Self, JournalError> {
        ensure_existing_private_directory(directory.as_ref())?;
        let record = anchor
            .load()
            .map_err(map_anchor_error)?
            .ok_or(JournalError::NotInitialized)?;
        let (client, events_since_checkpoint) =
            load_client(directory.as_ref(), storage_key, record)?;
        Ok(Self {
            client,
            directory: directory.as_ref().to_path_buf(),
            storage_key: Zeroizing::new(*storage_key),
            anchor,
            generation: record.generation,
            digest: record.digest,
            events_since_checkpoint,
            poisoned: false,
        })
    }

    pub fn index_id(&self) -> IndexId {
        self.client.index_id()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn prepare_add(
        &mut self,
        keyword: &[u8],
        id: DocumentId,
    ) -> Result<UpdateRequest, JournalError> {
        self.ensure_usable()?;
        let request = self.client.prepare_add(keyword, id)?;
        let entry = JournalEntry::PrepareAdd {
            keyword: keyword.to_vec(),
            id,
            request: request.clone(),
        };
        self.commit_mutation(entry)?;
        Ok(request)
    }

    pub fn retry_pending(&self) -> Result<UpdateRequest, JournalError> {
        self.ensure_usable()?;
        Ok(self.client.retry_pending()?)
    }

    pub fn finish_add(&mut self, address: super::Address) -> Result<(), JournalError> {
        self.ensure_usable()?;
        self.client.finish_add(address)?;
        self.commit_mutation(JournalEntry::FinishAdd { address })
    }

    pub fn rotate_keyword(&mut self, keyword: &[u8]) -> Result<(), JournalError> {
        self.ensure_usable()?;
        self.client.rotate_keyword(keyword)?;
        self.commit_mutation(JournalEntry::RotateKeyword {
            keyword: keyword.to_vec(),
        })
    }

    pub fn prepare_search(
        &self,
        keyword: &[u8],
    ) -> Result<(SearchSnapshot, SearchRequest), JournalError> {
        self.ensure_usable()?;
        Ok(self.client.prepare_search(keyword)?)
    }

    pub fn finish_search(
        &self,
        snapshot: &SearchSnapshot,
        response: super::SearchResponse,
    ) -> Result<Vec<DocumentId>, JournalError> {
        self.ensure_usable()?;
        Ok(self.client.finish_search(snapshot, response)?)
    }

    fn commit_initial_checkpoint(&mut self) -> Result<(), JournalError> {
        let entry = JournalEntry::Checkpoint(ClientState::from_client(&self.client));
        let (bytes, digest) =
            encode_frame(&self.storage_key, self.client.index_id(), 0, None, &entry)?;
        let path = record_path(&self.directory, self.client.index_id(), 0, digest);
        write_record(&self.directory, &path, &bytes)?;
        let record = SseJournalAnchorRecord {
            index_id: self.client.index_id(),
            generation: 0,
            digest,
        };
        if let Err(error) = self.anchor.compare_and_swap(None, record) {
            self.poisoned = true;
            return Err(map_anchor_error(error));
        }
        self.digest = digest;
        Ok(())
    }

    fn commit_mutation(&mut self, mutation: JournalEntry) -> Result<(), JournalError> {
        self.ensure_usable()?;
        let Some(next_generation) = self.generation.checked_add(1) else {
            self.poisoned = true;
            return Err(JournalError::Limit);
        };
        let checkpoint = self.events_since_checkpoint + 1 >= CHECKPOINT_INTERVAL;
        let entry = if checkpoint {
            JournalEntry::Checkpoint(ClientState::from_client(&self.client))
        } else {
            mutation
        };
        let encoded = encode_frame(
            &self.storage_key,
            self.client.index_id(),
            next_generation,
            Some(self.digest),
            &entry,
        );
        let (bytes, digest) = match encoded {
            Ok(encoded) => encoded,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let path = record_path(
            &self.directory,
            self.client.index_id(),
            next_generation,
            digest,
        );
        if let Err(error) = write_record(&self.directory, &path, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        let next_record = SseJournalAnchorRecord {
            index_id: self.client.index_id(),
            generation: next_generation,
            digest,
        };
        if let Err(error) = self
            .anchor
            .compare_and_swap(Some(self.generation), next_record)
        {
            self.poisoned = true;
            return Err(map_anchor_error(error));
        }
        self.generation = next_generation;
        self.digest = digest;
        if checkpoint {
            self.events_since_checkpoint = 0;
            prune_before_checkpoint(&self.directory, self.client.index_id(), next_generation);
        } else {
            self.events_since_checkpoint += 1;
        }
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), JournalError> {
        if self.poisoned {
            Err(JournalError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn map_anchor_error(error: SseJournalAnchorError) -> JournalError {
    match error {
        SseJournalAnchorError::Conflict => JournalError::AnchorConflict,
        SseJournalAnchorError::CommitUnknown => JournalError::AnchorCommitUnknown,
        SseJournalAnchorError::Unavailable => JournalError::AnchorUnavailable,
    }
}

fn load_client(
    directory: &Path,
    storage_key: &[u8; 32],
    record: SseJournalAnchorRecord,
) -> Result<(Client, usize), JournalError> {
    let mut generation = record.generation;
    let mut digest = record.digest;
    let mut reversed = Vec::new();
    let mut client = loop {
        if reversed.len() > MAX_REPLAY_RECORDS {
            return Err(JournalError::Limit);
        }
        let (frame, entry) =
            read_entry(directory, storage_key, record.index_id, generation, digest)?;
        match &entry {
            JournalEntry::Checkpoint(state) => break state.client_from_state(record.index_id)?,
            _ => {
                if generation == 0 {
                    return Err(JournalError::Format);
                }
                let Some(previous_digest) = frame.previous_digest else {
                    return Err(JournalError::Format);
                };
                reversed.push(entry);
                generation -= 1;
                digest = previous_digest;
            }
        }
    };
    let events_since_checkpoint = reversed.len();
    if events_since_checkpoint >= CHECKPOINT_INTERVAL {
        return Err(JournalError::Limit);
    }
    for entry in reversed.iter().rev() {
        replay_entry(&mut client, entry)?;
    }
    Ok((client, events_since_checkpoint))
}

fn replay_entry(client: &mut Client, entry: &JournalEntry) -> Result<(), JournalError> {
    match entry {
        JournalEntry::Checkpoint(_) => Err(JournalError::Format),
        JournalEntry::PrepareAdd {
            keyword,
            id,
            request,
        } => {
            let replayed = client.prepare_add(keyword, *id)?;
            if !same_request(&replayed, request) {
                return Err(JournalError::Authentication);
            }
            Ok(())
        }
        JournalEntry::FinishAdd { address } => Ok(client.finish_add(*address)?),
        JournalEntry::RotateKeyword { keyword } => Ok(client.rotate_keyword(keyword)?),
    }
}

fn same_request(left: &UpdateRequest, right: &UpdateRequest) -> bool {
    left.version == right.version
        && left.index_id == right.index_id
        && left.address == right.address
        && left.ciphertext == right.ciphertext
}

fn encode_frame(
    storage_key: &[u8; 32],
    index_id: IndexId,
    generation: u64,
    previous_digest: Option<[u8; 32]>,
    entry: &JournalEntry,
) -> Result<(Vec<u8>, [u8; 32]), JournalError> {
    let mut writer = LimitedWriter::new(MAX_PLAINTEXT_BYTES);
    if serde_json::to_writer(&mut writer, entry).is_err() {
        return if writer.overflowed {
            Err(JournalError::Limit)
        } else {
            Err(JournalError::Format)
        };
    }
    let plaintext = writer.bytes;
    let key = journal_key(storage_key, &index_id);
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| JournalError::Randomness)?;
    let ciphertext = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| JournalError::Format)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &associated_data(index_id, generation, previous_digest),
            },
        )
        .map_err(|_| JournalError::Authentication)?;
    let frame = JournalFrame {
        version: JOURNAL_VERSION,
        index_id,
        generation,
        previous_digest,
        nonce,
        ciphertext,
    };
    let bytes = serde_json::to_vec(&frame).map_err(|_| JournalError::Format)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(JournalError::Limit);
    }
    let digest = Sha256::digest(&bytes).into();
    Ok((bytes, digest))
}

fn read_entry(
    directory: &Path,
    storage_key: &[u8; 32],
    index_id: IndexId,
    generation: u64,
    expected_digest: [u8; 32],
) -> Result<(JournalFrame, JournalEntry), JournalError> {
    let path = record_path(directory, index_id, generation, expected_digest);
    let bytes = read_record(&path)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != expected_digest {
        return Err(JournalError::Authentication);
    }
    let frame: JournalFrame = serde_json::from_slice(&bytes).map_err(|_| JournalError::Format)?;
    if frame.version != JOURNAL_VERSION
        || frame.index_id != index_id
        || frame.generation != generation
    {
        return Err(JournalError::WrongIndex);
    }
    let key = journal_key(storage_key, &index_id);
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| JournalError::Format)?
            .decrypt(
                Nonce::from_slice(&frame.nonce),
                Payload {
                    msg: &frame.ciphertext,
                    aad: &associated_data(index_id, generation, frame.previous_digest),
                },
            )
            .map_err(|_| JournalError::Authentication)?,
    );
    let entry = serde_json::from_slice(&plaintext).map_err(|_| JournalError::Format)?;
    Ok((frame, entry))
}

fn journal_key(storage_key: &[u8; 32], index_id: &IndexId) -> Zeroizing<[u8; 32]> {
    kdf(
        storage_key,
        index_id,
        b"oblivion/sse/v1/persistent-journal-aead",
    )
}

fn associated_data(
    index_id: IndexId,
    generation: u64,
    previous_digest: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 1 + 16 + 8 + 1 + 32);
    aad.extend_from_slice(JOURNAL_MAGIC);
    aad.push(JOURNAL_VERSION);
    aad.extend_from_slice(&index_id);
    aad.extend_from_slice(&generation.to_be_bytes());
    match previous_digest {
        Some(digest) => {
            aad.push(1);
            aad.extend_from_slice(&digest);
        }
        None => aad.push(0),
    }
    aad
}

fn record_path(directory: &Path, index_id: IndexId, generation: u64, digest: [u8; 32]) -> PathBuf {
    directory.join(format!(
        "{}-{generation:020}-{}.journal",
        hex(&index_id),
        hex(&digest)
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn write_record(directory: &Path, path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(JournalError::Limit);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| JournalError::Storage(error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| JournalError::Storage(error.to_string()))?;
    file.sync_all()
        .map_err(|error| JournalError::Storage(error.to_string()))?;
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| JournalError::Storage(error.to_string()))?;
    Ok(())
}

fn read_record(path: &Path) -> Result<Vec<u8>, JournalError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|_| JournalError::Authentication)?;
    let metadata = file
        .metadata()
        .map_err(|error| JournalError::Storage(error.to_string()))?;
    if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
        return Err(JournalError::Limit);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(JournalError::Authentication);
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| JournalError::Storage(error.to_string()))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(JournalError::Limit);
    }
    Ok(bytes)
}

fn ensure_private_directory(path: &Path) -> Result<(), JournalError> {
    fs::create_dir_all(path).map_err(|error| JournalError::Storage(error.to_string()))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| JournalError::Storage(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(JournalError::Authentication);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| JournalError::Storage(error.to_string()))?;
    }
    Ok(())
}

fn ensure_existing_private_directory(path: &Path) -> Result<(), JournalError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| JournalError::Storage(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(JournalError::Authentication);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(JournalError::Authentication);
        }
    }
    Ok(())
}

fn prune_before_checkpoint(directory: &Path, index_id: IndexId, generation: u64) {
    let prefix = format!("{}-", hex(&index_id));
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) || !name.ends_with(".journal") {
            continue;
        }
        let Some(stored_generation) = name
            .strip_prefix(&prefix)
            .and_then(|rest| rest.split('-').next())
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        if stored_generation < generation {
            let _ = fs::remove_file(entry.path());
        }
    }
    let _ = File::open(directory).and_then(|directory| directory.sync_all());
}

#[cfg(test)]
mod state_tests {
    use super::*;

    #[test]
    fn deserialized_state_rejects_counter_sum_mismatch() {
        let limits = Limits::default();
        let client = Client::new(limits).unwrap();
        let mut state = ClientState::from_client(&client);
        state.keywords.push((b"w".to_vec(), vec![1]));
        assert_eq!(state.validate(client.index_id()), Err(JournalError::Format));
    }

    #[test]
    fn journal_key_is_domain_and_index_separated() {
        let master = [9; 32];
        assert_ne!(
            *journal_key(&master, &[1; 16]),
            *journal_key(&master, &[2; 16])
        );
        assert_ne!(
            *journal_key(&master, &[1; 16]),
            *kdf(&master, &[1; 16], b"oblivion/sse/v1/tree")
        );
    }

    #[test]
    fn bounded_writer_stops_before_allocating_past_its_limit() {
        let payload = vec![u8::MAX; 1024];
        let mut writer = LimitedWriter::new(32);
        assert!(serde_json::to_writer(&mut writer, &payload).is_err());
        assert!(writer.overflowed);
        assert!(writer.bytes.len() <= 32);
    }
}
