//! SQLite-backed atomic anchor state for a separately trusted anchor process.
//!
//! This crate supplies durable compare-and-swap adapters. It does not make a
//! database rollback-resistant: the database and its operator must be trusted
//! independently from the snapshots and storage server being anchored.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use oblivion_registry::{
    self as registry, RegistryCatalogAnchor, RegistryCatalogState, RegistryVersionAnchor,
};
use oblivion_store::{self as store, CheckpointAnchor, CheckpointAnchorRecord};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
mod local;
#[cfg(unix)]
pub use local::{
    UnixAnchorClient, UnixCheckpointAnchor, UnixInvocationAnchor, UnixRegistryAnchor,
    UnixRegistryCatalogAnchor, UnixSseJournalAnchor, serve_unix,
};

mod remote;
pub use remote::{
    AnchorRequestRateLimit, AuthorizationPolicyError, ClientAuthorizationPolicy,
    TlsCheckpointAnchor, TlsInvocationAnchor, TlsRegistryCatalogAnchor, TlsSseJournalAnchor,
    mtls_client_config, mtls_client_config_from_pem, mtls_server_config,
    mtls_server_config_from_pem, serve_mtls, serve_mtls_with_rate_limit, serve_mtls_with_shutdown,
    serve_mtls_with_shutdown_and_rate_limit,
};

const NONCE_BYTES: usize = 12;
const HANDLE_BYTES: usize = 88;
const SSE_JOURNAL_INDEX_ID_BYTES: usize = 16;
const SSE_JOURNAL_DIGEST_BYTES: usize = 32;
const SSE_JOURNAL_PLAINTEXT_BYTES: usize = SSE_JOURNAL_INDEX_ID_BYTES + SSE_JOURNAL_DIGEST_BYTES;
const SSE_JOURNAL_CIPHERTEXT_BYTES: usize = SSE_JOURNAL_PLAINTEXT_BYTES + 16;
const MAX_SLOT_BYTES: usize = 128;
pub const INVOCATION_ID_BYTES: usize = 16;
pub const INVOCATION_DIGEST_BYTES: usize = 32;
pub const MAX_INVOCATION_RESPONSE_BYTES: usize = 64 * 1024;
const SCHEMA_VERSION: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("anchor slot must be 1 to 128 ASCII letters, digits, dots, underscores, or hyphens")]
    InvalidSlot,
    #[error("anchor version or generation is outside the supported SQLite integer range")]
    IntegerRange,
    #[error("anchor database operation failed: {0}")]
    Database(String),
    #[error("anchor secret encryption or authentication failed")]
    Cryptography,
    #[error("anchor state changed or the requested value is not the next generation")]
    Conflict,
    #[error("anchor transaction commit result is indeterminate")]
    CommitIndeterminate,
    #[error("authenticated remote anchor request rate limit exceeded")]
    RateLimited,
    #[error("remote anchor request rate limit configuration is invalid")]
    InvalidRequestRateLimit,
    #[error("operating-system randomness unavailable")]
    Randomness,
    #[error("stored checkpoint handle is malformed")]
    InvalidHandle,
    #[error("invocation identity signature is invalid")]
    InvalidInvocationSignature,
    #[error("stored invocation receipt is malformed or unauthentic")]
    InvalidInvocationReceipt,
    #[error("anchored registry catalog digest must contain exactly 32 bytes")]
    InvalidCatalogDigest,
    #[error("invocation response exceeds the configured receipt bound")]
    InvocationResponseTooLarge,
    #[error("anchor database schema version {0} is unsupported")]
    UnsupportedSchema(u32),
    #[error("anchor service socket operation failed: {0}")]
    Socket(String),
    #[error("another durable worker already holds this invocation slot")]
    InvocationWriterAlreadyActive,
    #[error("invocation writer lock operation failed: {0}")]
    InvocationWriterLock(String),
    #[error("anchor service protocol message is malformed or unsupported")]
    Protocol,
    #[error("anchor socket mode must be 0600 or 0660")]
    InvalidSocketMode,
    #[error("anchor database path must refer to a regular file, not a symlink or special file")]
    InvalidDatabasePath,
}

impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.to_string())
    }
}

/// Persistent anchor database. `master_key` must come from a separate trusted
/// secret source and must not be stored beside the SQLite database.
pub struct AnchorDatabase {
    connection: Connection,
    master_key: Zeroizing<[u8; 32]>,
}

/// The current SSE journal head stored by the independent anchor service.
/// The index identifier and digest are encrypted in SQLite; generation is
/// retained in clear text so the service can perform an atomic SQL CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SseJournalState {
    index_id: [u8; SSE_JOURNAL_INDEX_ID_BYTES],
    generation: u64,
    digest: [u8; SSE_JOURNAL_DIGEST_BYTES],
}

impl SseJournalState {
    pub fn new(
        index_id: [u8; SSE_JOURNAL_INDEX_ID_BYTES],
        generation: u64,
        digest: [u8; SSE_JOURNAL_DIGEST_BYTES],
    ) -> Result<Self, Error> {
        i64::try_from(generation).map_err(|_| Error::IntegerRange)?;
        Ok(Self {
            index_id,
            generation,
            digest,
        })
    }

    pub fn index_id(&self) -> &[u8; SSE_JOURNAL_INDEX_ID_BYTES] {
        &self.index_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn digest(&self) -> &[u8; SSE_JOURNAL_DIGEST_BYTES] {
        &self.digest
    }
}

/// Stable client-signed invocation identity. The signature authenticates
/// control of the public key for this ID and request digest; it does not grant
/// function-level authorization.
#[derive(Clone)]
pub struct SignedInvocationId {
    public_key: [u8; 32],
    invocation_id: [u8; INVOCATION_ID_BYTES],
    request_digest: [u8; INVOCATION_DIGEST_BYTES],
    signature: [u8; 64],
}

impl SignedInvocationId {
    pub fn new(
        public_key: [u8; 32],
        invocation_id: [u8; INVOCATION_ID_BYTES],
        request_digest: [u8; INVOCATION_DIGEST_BYTES],
        signature: [u8; 64],
    ) -> Self {
        Self {
            public_key,
            invocation_id,
            request_digest,
            signature,
        }
    }

    /// Canonical message clients sign for an invocation ID and request digest.
    pub fn signing_message(
        invocation_id: &[u8; INVOCATION_ID_BYTES],
        request_digest: &[u8; INVOCATION_DIGEST_BYTES],
    ) -> Vec<u8> {
        let mut message = b"OBLIVION::INVOCATION-ID::v1\0".to_vec();
        message.extend_from_slice(invocation_id);
        message.extend_from_slice(request_digest);
        message
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn invocation_id(&self) -> &[u8; INVOCATION_ID_BYTES] {
        &self.invocation_id
    }

    pub fn request_digest(&self) -> &[u8; INVOCATION_DIGEST_BYTES] {
        &self.request_digest
    }

    pub(crate) fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    fn verify(&self) -> Result<(), Error> {
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| Error::InvalidInvocationSignature)?;
        key.verify_strict(
            &Self::signing_message(&self.invocation_id, &self.request_digest),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::InvalidInvocationSignature)
    }
}

/// Durable result bound to a signed invocation and checkpoint generation.
pub struct InvocationReceipt {
    snapshot_id: Box<str>,
    generation: u64,
    response: Zeroizing<Vec<u8>>,
}

impl InvocationReceipt {
    pub(crate) fn from_parts(
        snapshot_id: String,
        generation: u64,
        response: Vec<u8>,
    ) -> Result<Self, Error> {
        let response = Zeroizing::new(response);
        if !valid_snapshot_id(&snapshot_id)
            || generation == 0
            || response.len() > MAX_INVOCATION_RESPONSE_BYTES
        {
            return Err(Error::InvalidInvocationReceipt);
        }
        Ok(Self {
            snapshot_id: snapshot_id.into_boxed_str(),
            generation,
            response,
        })
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn response(&self) -> &[u8] {
        self.response.as_slice()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredInvocationReceipt {
    request_digest: [u8; INVOCATION_DIGEST_BYTES],
    snapshot_id: String,
    generation: u64,
    response: Vec<u8>,
}

type StoredSseJournalRow = (i64, i64, Vec<u8>, i64, Vec<u8>);

impl AnchorDatabase {
    pub fn open(path: impl AsRef<Path>, master_key: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let schema_version: u32 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match schema_version {
            0 => {
                let tx = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS checkpoint_anchor (
                slot TEXT PRIMARY KEY NOT NULL,
                snapshot_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation > 0),
                nonce BLOB NOT NULL CHECK (length(nonce) = 12),
                ciphertext BLOB NOT NULL CHECK (length(ciphertext) = 104)
            );
            CREATE TABLE IF NOT EXISTS registry_anchor (
                slot TEXT PRIMARY KEY NOT NULL,
                version INTEGER NOT NULL CHECK (version > 0)
            );
            CREATE TABLE IF NOT EXISTS registry_catalog_anchor (
                slot TEXT PRIMARY KEY NOT NULL,
                version INTEGER NOT NULL CHECK (version > 0),
                digest BLOB CHECK (digest IS NULL OR length(digest) = 32)
            );
            CREATE TABLE IF NOT EXISTS used_nonce (
                nonce BLOB PRIMARY KEY NOT NULL CHECK (length(nonce) = 12)
            );
            CREATE TABLE IF NOT EXISTS invocation_receipt (
                slot TEXT NOT NULL,
                lookup_token BLOB NOT NULL CHECK (length(lookup_token) = 32),
                nonce BLOB NOT NULL CHECK (length(nonce) = 12),
                ciphertext BLOB NOT NULL,
                PRIMARY KEY (slot, lookup_token)
            );
            PRAGMA user_version = 3;",
                )?;
                tx.commit()?;
            }
            1 => {
                let tx = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
                tx.execute_batch(
                    "CREATE TABLE invocation_receipt (
                slot TEXT NOT NULL,
                lookup_token BLOB NOT NULL CHECK (length(lookup_token) = 32),
                nonce BLOB NOT NULL CHECK (length(nonce) = 12),
                ciphertext BLOB NOT NULL,
                PRIMARY KEY (slot, lookup_token)
            );
            CREATE TABLE registry_catalog_anchor (
                slot TEXT PRIMARY KEY NOT NULL,
                version INTEGER NOT NULL CHECK (version > 0),
                digest BLOB CHECK (digest IS NULL OR length(digest) = 32)
            );
            INSERT INTO registry_catalog_anchor(slot, version, digest)
                SELECT slot, version, NULL FROM registry_anchor;
            PRAGMA user_version = 3;",
                )?;
                tx.commit()?;
            }
            2 => {
                let tx = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
                tx.execute_batch(
                    "CREATE TABLE registry_catalog_anchor (
                slot TEXT PRIMARY KEY NOT NULL,
                version INTEGER NOT NULL CHECK (version > 0),
                digest BLOB CHECK (digest IS NULL OR length(digest) = 32)
            );
            INSERT INTO registry_catalog_anchor(slot, version, digest)
                SELECT slot, version, NULL FROM registry_anchor;
            PRAGMA user_version = 3;",
                )?;
                tx.commit()?;
            }
            3 => {}
            SCHEMA_VERSION => {}
            other => return Err(Error::UnsupportedSchema(other)),
        }
        if schema_version < SCHEMA_VERSION {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
            tx.execute_batch(
                "CREATE TABLE sse_journal_anchor (
                    slot TEXT PRIMARY KEY NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation >= 0),
                    nonce BLOB NOT NULL CHECK (length(nonce) = 12),
                    ciphertext BLOB NOT NULL CHECK (length(ciphertext) = 64)
                );
                PRAGMA user_version = 4;",
            )?;
            tx.commit()?;
        }
        Ok(Self {
            connection,
            master_key,
        })
    }

    pub fn checkpoint_anchor(&mut self, slot: &str) -> Result<CheckpointSlot<'_>, Error> {
        validate_slot(slot)?;
        Ok(CheckpointSlot {
            connection: &mut self.connection,
            master_key: &self.master_key,
            slot: slot.to_owned(),
        })
    }

    pub fn registry_anchor(&mut self, slot: &str) -> Result<RegistrySlot<'_>, Error> {
        validate_slot(slot)?;
        Ok(RegistrySlot {
            connection: &mut self.connection,
            slot: slot.to_owned(),
        })
    }

    pub fn registry_catalog_anchor(
        &mut self,
        slot: &str,
    ) -> Result<RegistryCatalogSlot<'_>, Error> {
        validate_slot(slot)?;
        Ok(RegistryCatalogSlot {
            connection: &mut self.connection,
            slot: slot.to_owned(),
        })
    }

    pub fn sse_journal_anchor(&mut self, slot: &str) -> Result<SseJournalSlot<'_>, Error> {
        validate_slot(slot)?;
        Ok(SseJournalSlot {
            connection: &mut self.connection,
            master_key: &self.master_key,
            slot: slot.to_owned(),
        })
    }

    /// Load a previously committed result for this signed invocation. A
    /// matching ID with a different request digest is rejected as a conflict.
    pub fn load_invocation_receipt(
        &self,
        slot: &str,
        invocation: &SignedInvocationId,
    ) -> Result<Option<InvocationReceipt>, Error> {
        validate_slot(slot)?;
        invocation.verify()?;
        let lookup = invocation_lookup_token(&self.master_key, slot, invocation)?;
        load_invocation_receipt(
            &self.connection,
            &self.master_key,
            slot,
            &lookup,
            invocation.request_digest(),
        )
    }

    /// Atomically advance a checkpoint and persist the exact invocation
    /// response. Retries of the same signed ID and request return the first
    /// receipt, even if the caller's proposed checkpoint is now stale.
    pub fn commit_invocation(
        &mut self,
        slot: &str,
        invocation: &SignedInvocationId,
        expected_generation: Option<u64>,
        next_record: CheckpointAnchorRecord,
        response: &[u8],
    ) -> Result<InvocationReceipt, Error> {
        validate_slot(slot)?;
        invocation.verify()?;
        if response.len() > MAX_INVOCATION_RESPONSE_BYTES {
            return Err(Error::InvocationResponseTooLarge);
        }
        let lookup = invocation_lookup_token(&self.master_key, slot, invocation)?;
        if let Some(receipt) = load_invocation_receipt(
            &self.connection,
            &self.master_key,
            slot,
            &lookup,
            invocation.request_digest(),
        )? {
            return Ok(receipt);
        }

        let next_generation = expected_generation
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::IntegerRange)?;
        if next_record.generation() != next_generation {
            return Err(Error::Conflict);
        }
        let expected_i64 = expected_generation
            .map(i64::try_from)
            .transpose()
            .map_err(|_| Error::IntegerRange)?;
        let next_i64 = i64::try_from(next_generation).map_err(|_| Error::IntegerRange)?;

        let checkpoint_nonce = reserve_nonce(&mut self.connection)?;
        let checkpoint_key = derive_key(&self.master_key, b"checkpoint", slot)?;
        let checkpoint_cipher = ChaCha20Poly1305::new(checkpoint_key.as_ref().into());
        let checkpoint_ciphertext = checkpoint_cipher
            .encrypt(
                Nonce::from_slice(&checkpoint_nonce),
                Payload {
                    msg: next_record.secret_handle(),
                    aad: &checkpoint_aad(slot, next_record.snapshot_id(), next_generation),
                },
            )
            .map_err(|_| Error::Cryptography)?;

        let mut stored = StoredInvocationReceipt {
            request_digest: *invocation.request_digest(),
            snapshot_id: next_record.snapshot_id().to_owned(),
            generation: next_generation,
            response: response.to_vec(),
        };
        let encoded = serde_json::to_vec(&stored);
        stored.response.zeroize();
        let plaintext = Zeroizing::new(encoded.map_err(|_| Error::InvalidInvocationReceipt)?);
        let receipt_nonce = reserve_nonce(&mut self.connection)?;
        let receipt_key = derive_key(&self.master_key, b"invocation-receipt", slot)?;
        let receipt_cipher = ChaCha20Poly1305::new(receipt_key.as_ref().into());
        let receipt_ciphertext = receipt_cipher
            .encrypt(
                Nonce::from_slice(&receipt_nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &invocation_receipt_aad(slot, &lookup),
                },
            )
            .map_err(|_| Error::Cryptography)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = load_invocation_receipt(
            &tx,
            &self.master_key,
            slot,
            &lookup,
            invocation.request_digest(),
        )? {
            return Ok(receipt);
        }
        let current: Option<i64> = tx
            .query_row(
                "SELECT generation FROM checkpoint_anchor WHERE slot = ?1",
                [slot],
                |row| row.get(0),
            )
            .optional()?;
        if current != expected_i64 {
            return Err(Error::Conflict);
        }
        match current {
            None => {
                tx.execute(
                    "INSERT INTO checkpoint_anchor(slot, snapshot_id, generation, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![slot, next_record.snapshot_id(), next_i64, checkpoint_nonce.as_slice(), checkpoint_ciphertext],
                )?;
            }
            Some(_) => {
                tx.execute(
                    "UPDATE checkpoint_anchor SET snapshot_id = ?2, generation = ?3, nonce = ?4, ciphertext = ?5 WHERE slot = ?1",
                    params![slot, next_record.snapshot_id(), next_i64, checkpoint_nonce.as_slice(), checkpoint_ciphertext],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO invocation_receipt(slot, lookup_token, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4)",
            params![slot, lookup.as_slice(), receipt_nonce.as_slice(), receipt_ciphertext],
        )?;
        tx.commit().map_err(|_| Error::CommitIndeterminate)?;
        Ok(InvocationReceipt {
            snapshot_id: next_record.snapshot_id().into(),
            generation: next_generation,
            response: Zeroizing::new(response.to_vec()),
        })
    }
}

pub struct CheckpointSlot<'a> {
    connection: &'a mut Connection,
    master_key: &'a [u8; 32],
    slot: String,
}

impl CheckpointAnchor for CheckpointSlot<'_> {
    fn load(&mut self) -> Result<Option<CheckpointAnchorRecord>, store::Error> {
        load_checkpoint(self.connection, self.master_key, &self.slot).map_err(map_store_error)
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        next_record: CheckpointAnchorRecord,
    ) -> Result<(), store::Error> {
        compare_and_swap_checkpoint(
            self.connection,
            self.master_key,
            &self.slot,
            expected_generation,
            next_record,
        )
        .map_err(map_store_error)
    }
}

pub struct SseJournalSlot<'a> {
    connection: &'a mut Connection,
    master_key: &'a [u8; 32],
    slot: String,
}

impl SseJournalSlot<'_> {
    pub fn load(&mut self) -> Result<Option<SseJournalState>, Error> {
        load_sse_journal(self.connection, self.master_key, &self.slot)
    }

    pub fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        next: SseJournalState,
    ) -> Result<(), Error> {
        compare_and_swap_sse_journal(
            self.connection,
            self.master_key,
            &self.slot,
            expected_generation,
            next,
        )
    }
}

pub struct RegistrySlot<'a> {
    connection: &'a mut Connection,
    slot: String,
}

impl RegistryVersionAnchor for RegistrySlot<'_> {
    fn current_version(&mut self) -> Result<Option<u64>, registry::Error> {
        current_registry_version(self.connection, &self.slot).map_err(map_registry_error)
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<u64>,
        next: u64,
    ) -> Result<(), registry::Error> {
        compare_and_swap_registry(self.connection, &self.slot, expected, next)
            .map_err(map_registry_error)
    }
}

pub struct RegistryCatalogSlot<'a> {
    connection: &'a mut Connection,
    slot: String,
}

impl RegistryCatalogAnchor for RegistryCatalogSlot<'_> {
    fn current_catalog(&mut self) -> Result<Option<RegistryCatalogState>, registry::Error> {
        current_registry_catalog(self.connection, &self.slot).map_err(map_registry_error)
    }

    fn compare_and_swap_catalog(
        &mut self,
        expected: Option<RegistryCatalogState>,
        next_version: u64,
        next_digest: [u8; 32],
    ) -> Result<(), registry::Error> {
        compare_and_swap_registry_catalog(
            self.connection,
            &self.slot,
            expected,
            next_version,
            next_digest,
        )
        .map_err(map_registry_error)
    }
}

fn validate_slot(slot: &str) -> Result<(), Error> {
    if slot.is_empty()
        || slot.len() > MAX_SLOT_BYTES
        || !slot
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidSlot);
    }
    Ok(())
}

fn derive_key(
    master_key: &[u8; 32],
    purpose: &[u8],
    slot: &str,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"oblivion-anchor-sqlite-v1"), master_key);
    let mut info = Vec::with_capacity(purpose.len() + slot.len() + 1);
    info.extend_from_slice(purpose);
    info.push(0);
    info.extend_from_slice(slot.as_bytes());
    let mut key = Zeroizing::new([0; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| Error::Cryptography)?;
    Ok(key)
}

fn sse_journal_aad(slot: &str, generation: u64) -> Vec<u8> {
    let mut aad = b"oblivion-anchor-sse-journal-v1\0".to_vec();
    aad.extend_from_slice(&(slot.len() as u32).to_be_bytes());
    aad.extend_from_slice(slot.as_bytes());
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

fn load_sse_journal(
    connection: &Connection,
    master_key: &[u8; 32],
    slot: &str,
) -> Result<Option<SseJournalState>, Error> {
    let row: Option<StoredSseJournalRow> = connection
        .query_row(
            "SELECT generation, length(nonce), substr(nonce, 1, 13),
                    length(ciphertext), substr(ciphertext, 1, 65)
             FROM sse_journal_anchor WHERE slot = ?1",
            [slot],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((generation, nonce_len, nonce, ciphertext_len, ciphertext)) = row else {
        return Ok(None);
    };
    let generation = u64::try_from(generation).map_err(|_| Error::Cryptography)?;
    if nonce_len != NONCE_BYTES as i64 || ciphertext_len != SSE_JOURNAL_CIPHERTEXT_BYTES as i64 {
        return Err(Error::Cryptography);
    }
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| Error::Cryptography)?;
    if ciphertext.len() != SSE_JOURNAL_CIPHERTEXT_BYTES {
        return Err(Error::Cryptography);
    }
    let key = derive_key(master_key, b"sse-journal", slot)?;
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new(key.as_ref().into())
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &sse_journal_aad(slot, generation),
                },
            )
            .map_err(|_| Error::Cryptography)?,
    );
    if plaintext.len() != SSE_JOURNAL_PLAINTEXT_BYTES {
        return Err(Error::Cryptography);
    }
    let index_id = plaintext[..SSE_JOURNAL_INDEX_ID_BYTES]
        .try_into()
        .map_err(|_| Error::Cryptography)?;
    let digest = plaintext[SSE_JOURNAL_INDEX_ID_BYTES..]
        .try_into()
        .map_err(|_| Error::Cryptography)?;
    SseJournalState::new(index_id, generation, digest).map(Some)
}

fn compare_and_swap_sse_journal(
    connection: &mut Connection,
    master_key: &[u8; 32],
    slot: &str,
    expected_generation: Option<u64>,
    next: SseJournalState,
) -> Result<(), Error> {
    let expected_next = match expected_generation {
        None => 0,
        Some(generation) => generation.checked_add(1).ok_or(Error::IntegerRange)?,
    };
    if next.generation != expected_next {
        return Err(Error::Conflict);
    }
    let next_i64 = i64::try_from(next.generation).map_err(|_| Error::IntegerRange)?;
    let expected_i64 = expected_generation
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Error::IntegerRange)?;

    let nonce = reserve_nonce(connection)?;
    let key = derive_key(master_key, b"sse-journal", slot)?;
    let mut plaintext = Zeroizing::new([0u8; SSE_JOURNAL_PLAINTEXT_BYTES]);
    plaintext[..SSE_JOURNAL_INDEX_ID_BYTES].copy_from_slice(&next.index_id);
    plaintext[SSE_JOURNAL_INDEX_ID_BYTES..].copy_from_slice(&next.digest);
    let ciphertext = ChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &sse_journal_aad(slot, next.generation),
            },
        )
        .map_err(|_| Error::Cryptography)?;

    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = load_sse_journal(&tx, master_key, slot)?;
    if current.map(|state| state.generation) != expected_generation
        || current.is_some_and(|state| state.index_id != next.index_id)
    {
        return Err(Error::Conflict);
    }
    let changed = match expected_i64 {
        None => tx.execute(
            "INSERT INTO sse_journal_anchor(slot, generation, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4)",
            params![slot, next_i64, nonce.as_slice(), ciphertext],
        )?,
        Some(expected) => tx.execute(
            "UPDATE sse_journal_anchor SET generation = ?2, nonce = ?3, ciphertext = ?4 WHERE slot = ?1 AND generation = ?5",
            params![slot, next_i64, nonce.as_slice(), ciphertext, expected],
        )?,
    };
    if changed != 1 {
        return Err(Error::Conflict);
    }
    tx.commit().map_err(|_| Error::CommitIndeterminate)?;
    Ok(())
}

fn invocation_lookup_token(
    master_key: &[u8; 32],
    slot: &str,
    invocation: &SignedInvocationId,
) -> Result<[u8; 32], Error> {
    let key = derive_key(master_key, b"invocation-lookup", slot)?;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref()).map_err(|_| Error::Cryptography)?;
    mac.update(b"oblivion-anchor-invocation-lookup-v1\0");
    mac.update(invocation.public_key());
    mac.update(invocation.invocation_id());
    let digest = mac.finalize().into_bytes();
    let mut lookup = [0; 32];
    lookup.copy_from_slice(&digest);
    Ok(lookup)
}

fn invocation_receipt_aad(slot: &str, lookup: &[u8; 32]) -> Vec<u8> {
    let mut aad = b"oblivion-anchor-invocation-receipt-v1\0".to_vec();
    aad.extend_from_slice(slot.as_bytes());
    aad.push(0);
    aad.extend_from_slice(lookup);
    aad
}

fn load_invocation_receipt(
    connection: &Connection,
    master_key: &[u8; 32],
    slot: &str,
    lookup: &[u8; 32],
    request_digest: &[u8; INVOCATION_DIGEST_BYTES],
) -> Result<Option<InvocationReceipt>, Error> {
    let row: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT nonce, ciphertext FROM invocation_receipt WHERE slot = ?1 AND lookup_token = ?2",
            params![slot, lookup.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((nonce, ciphertext)) = row else {
        return Ok(None);
    };
    let nonce: [u8; NONCE_BYTES] = nonce
        .try_into()
        .map_err(|_| Error::InvalidInvocationReceipt)?;
    let key = derive_key(master_key, b"invocation-receipt", slot)?;
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &invocation_receipt_aad(slot, lookup),
                },
            )
            .map_err(|_| Error::InvalidInvocationReceipt)?,
    );
    let stored: StoredInvocationReceipt = serde_json::from_slice(plaintext.as_slice())
        .map_err(|_| Error::InvalidInvocationReceipt)?;
    let response = Zeroizing::new(stored.response);
    if stored.request_digest != *request_digest
        || stored.generation == 0
        || !valid_snapshot_id(&stored.snapshot_id)
        || response.len() > MAX_INVOCATION_RESPONSE_BYTES
    {
        return if stored.request_digest != *request_digest {
            Err(Error::Conflict)
        } else {
            Err(Error::InvalidInvocationReceipt)
        };
    }
    Ok(Some(InvocationReceipt {
        snapshot_id: stored.snapshot_id.into_boxed_str(),
        generation: stored.generation,
        response,
    }))
}

fn valid_snapshot_id(snapshot_id: &str) -> bool {
    !snapshot_id.is_empty()
        && snapshot_id.len() <= MAX_SLOT_BYTES
        && snapshot_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn reserve_nonce(connection: &mut Connection) -> Result<[u8; NONCE_BYTES], Error> {
    loop {
        let mut nonce = [0; NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Randomness)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO used_nonce(nonce) VALUES (?1)",
            params![nonce.as_slice()],
        )?;
        tx.commit()?;
        if inserted == 1 {
            return Ok(nonce);
        }
    }
}

fn checkpoint_aad(slot: &str, snapshot_id: &str, generation: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + slot.len() + snapshot_id.len());
    aad.extend_from_slice(b"oblivion-checkpoint-anchor-v1\0");
    aad.extend_from_slice(&(slot.len() as u32).to_be_bytes());
    aad.extend_from_slice(slot.as_bytes());
    aad.extend_from_slice(&(snapshot_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(snapshot_id.as_bytes());
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

fn load_checkpoint(
    connection: &Connection,
    master_key: &[u8; 32],
    slot: &str,
) -> Result<Option<CheckpointAnchorRecord>, Error> {
    let row: Option<(String, i64, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT snapshot_id, generation, nonce, ciphertext FROM checkpoint_anchor WHERE slot = ?1",
            [slot],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((snapshot_id, generation, nonce, ciphertext)) = row else {
        return Ok(None);
    };
    let generation = u64::try_from(generation).map_err(|_| Error::InvalidHandle)?;
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| Error::InvalidHandle)?;
    let key = derive_key(master_key, b"checkpoint", slot)?;
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &checkpoint_aad(slot, &snapshot_id, generation),
                },
            )
            .map_err(|_| Error::Cryptography)?,
    );
    if plaintext.len() != HANDLE_BYTES {
        return Err(Error::InvalidHandle);
    }
    CheckpointAnchorRecord::new(&snapshot_id, &plaintext)
        .map(Some)
        .map_err(|_| Error::InvalidHandle)
}

fn compare_and_swap_checkpoint(
    connection: &mut Connection,
    master_key: &[u8; 32],
    slot: &str,
    expected_generation: Option<u64>,
    next_record: CheckpointAnchorRecord,
) -> Result<(), Error> {
    let next_generation = next_record.generation();
    let expected_next = match expected_generation {
        None => 1,
        Some(value) => value.checked_add(1).ok_or(Error::IntegerRange)?,
    };
    if next_generation != expected_next {
        return Err(Error::Conflict);
    }
    let next_i64 = i64::try_from(next_generation).map_err(|_| Error::IntegerRange)?;
    let expected_i64 = expected_generation
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Error::IntegerRange)?;
    let nonce = reserve_nonce(connection)?;
    let key = derive_key(master_key, b"checkpoint", slot)?;
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: next_record.secret_handle(),
                aad: &checkpoint_aad(slot, next_record.snapshot_id(), next_generation),
            },
        )
        .map_err(|_| Error::Cryptography)?;

    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current: Option<i64> = tx
        .query_row(
            "SELECT generation FROM checkpoint_anchor WHERE slot = ?1",
            [slot],
            |row| row.get(0),
        )
        .optional()?;
    if current != expected_i64 {
        return Err(Error::Conflict);
    }
    match current {
        None => {
            tx.execute(
                "INSERT INTO checkpoint_anchor(slot, snapshot_id, generation, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![slot, next_record.snapshot_id(), next_i64, nonce.as_slice(), ciphertext],
            )?;
        }
        Some(_) => {
            tx.execute(
                "UPDATE checkpoint_anchor SET snapshot_id = ?2, generation = ?3, nonce = ?4, ciphertext = ?5 WHERE slot = ?1",
                params![slot, next_record.snapshot_id(), next_i64, nonce.as_slice(), ciphertext],
            )?;
        }
    }
    // The transaction outcome can be ambiguous after an I/O error. Callers
    // must reload the anchor instead of assuming either outcome.
    tx.commit().map_err(|_| Error::CommitIndeterminate)?;
    Ok(())
}

fn current_registry_version(connection: &Connection, slot: &str) -> Result<Option<u64>, Error> {
    connection
        .query_row(
            "SELECT version FROM registry_anchor WHERE slot = ?1",
            [slot],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|version| u64::try_from(version).map_err(|_| Error::IntegerRange))
        .transpose()
}

fn compare_and_swap_registry(
    connection: &mut Connection,
    slot: &str,
    expected: Option<u64>,
    next: u64,
) -> Result<(), Error> {
    if next == 0 || expected.is_some_and(|current| next <= current) {
        return Err(Error::Conflict);
    }
    let next_i64 = i64::try_from(next).map_err(|_| Error::IntegerRange)?;
    let expected_i64 = expected
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Error::IntegerRange)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current: Option<i64> = tx
        .query_row(
            "SELECT version FROM registry_anchor WHERE slot = ?1",
            [slot],
            |row| row.get(0),
        )
        .optional()?;
    if current != expected_i64 {
        return Err(Error::Conflict);
    }
    match current {
        None => {
            tx.execute(
                "INSERT INTO registry_anchor(slot, version) VALUES (?1, ?2)",
                params![slot, next_i64],
            )?;
        }
        Some(_) => {
            tx.execute(
                "UPDATE registry_anchor SET version = ?2 WHERE slot = ?1",
                params![slot, next_i64],
            )?;
        }
    }
    // Preserve the same explicit uncertainty semantics for version callers.
    tx.commit().map_err(|_| Error::CommitIndeterminate)?;
    Ok(())
}

fn current_registry_catalog(
    connection: &Connection,
    slot: &str,
) -> Result<Option<RegistryCatalogState>, Error> {
    let stored: Option<(i64, Option<Vec<u8>>)> = connection
        .query_row(
            "SELECT version, digest FROM registry_catalog_anchor WHERE slot = ?1",
            [slot],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    stored
        .map(|(version, digest)| {
            let version = u64::try_from(version).map_err(|_| Error::IntegerRange)?;
            let digest = digest
                .map(|bytes| bytes.try_into().map_err(|_| Error::InvalidCatalogDigest))
                .transpose()?;
            RegistryCatalogState::new(version, digest)
                .map_err(|error| Error::Database(error.to_string()))
        })
        .transpose()
}

fn compare_and_swap_registry_catalog(
    connection: &mut Connection,
    slot: &str,
    expected: Option<RegistryCatalogState>,
    next_version: u64,
    next_digest: [u8; 32],
) -> Result<(), Error> {
    if next_version == 0 || expected.is_some_and(|state| next_version <= state.version()) {
        return Err(Error::Conflict);
    }
    let next_i64 = i64::try_from(next_version).map_err(|_| Error::IntegerRange)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = current_registry_catalog(&tx, slot)?;
    if current != expected {
        return Err(Error::Conflict);
    }
    match current {
        None => {
            tx.execute(
                "INSERT INTO registry_catalog_anchor(slot, version, digest) VALUES (?1, ?2, ?3)",
                params![slot, next_i64, next_digest.as_slice()],
            )?;
        }
        Some(_) => {
            tx.execute(
                "UPDATE registry_catalog_anchor SET version = ?2, digest = ?3 WHERE slot = ?1",
                params![slot, next_i64, next_digest.as_slice()],
            )?;
        }
    }
    tx.commit().map_err(|_| Error::CommitIndeterminate)?;
    Ok(())
}

fn map_store_error(error: Error) -> store::Error {
    match error {
        Error::Conflict => store::Error::AnchorConflict,
        Error::CommitIndeterminate => store::Error::AnchorCommitUnknown,
        other => store::Error::Backend(other.to_string()),
    }
}

fn map_registry_error(error: Error) -> registry::Error {
    match error {
        Error::Conflict => registry::Error::AnchorConflict,
        Error::CommitIndeterminate => registry::Error::AnchorCommitUnknown,
        other => registry::Error::Anchor(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use oblivion_registry::{Record, SignedRegistry, VerifiedRegistry};
    use oblivion_store::{Config, MemoryBackend, PathOram, TrustedCheckpoint};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "oblivion-anchor-{label}-{}-{nonce}.sqlite",
            std::process::id()
        ))
    }

    fn handle(generation: u64) -> [u8; HANDLE_BYTES] {
        let mut bytes = [0; HANDLE_BYTES];
        bytes[..8].copy_from_slice(b"OBLTRST1");
        bytes[8..16].copy_from_slice(&generation.to_le_bytes());
        bytes[16..24].copy_from_slice(&48_u64.to_le_bytes());
        bytes[24..56].fill(generation as u8);
        bytes[56..].fill(0xA5);
        bytes
    }

    fn journal_state(index_id: u8, generation: u64, digest: u8) -> SseJournalState {
        SseJournalState::new([index_id; 16], generation, [digest; 32]).unwrap()
    }

    #[test]
    fn schema_v3_migrates_and_journal_anchor_survives_reopen() {
        let path = path("sse-journal-migration");
        let catalog_digest = [0x31; 32];
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE registry_catalog_anchor (
                         slot TEXT PRIMARY KEY NOT NULL,
                         version INTEGER NOT NULL CHECK (version > 0),
                         digest BLOB CHECK (digest IS NULL OR length(digest) = 32)
                     );
                     CREATE TABLE used_nonce (
                         nonce BLOB PRIMARY KEY NOT NULL CHECK (length(nonce) = 12)
                     );
                     INSERT INTO registry_catalog_anchor(slot, version, digest)
                         VALUES ('catalog-a', 4, X'3131313131313131313131313131313131313131313131313131313131313131');
                     PRAGMA user_version = 3;",
                )
                .unwrap();
        }

        let initial = journal_state(0x11, 0, 0x21);
        {
            let mut database = AnchorDatabase::open(&path, Zeroizing::new([0x41; 32])).unwrap();
            let mut catalog = database.registry_catalog_anchor("catalog-a").unwrap();
            assert_eq!(
                catalog.current_catalog().unwrap(),
                Some(RegistryCatalogState::new(4, Some(catalog_digest)).unwrap())
            );

            let mut anchor = database.sse_journal_anchor("app-index-a").unwrap();
            assert_eq!(anchor.load().unwrap(), None);
            anchor.compare_and_swap(None, initial).unwrap();
            assert_eq!(anchor.load().unwrap(), Some(initial));
        }

        let mut database = AnchorDatabase::open(&path, Zeroizing::new([0x41; 32])).unwrap();
        assert_eq!(
            database
                .sse_journal_anchor("app-index-a")
                .unwrap()
                .load()
                .unwrap(),
            Some(initial)
        );
        drop(database);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sse_journal_slot_enforces_consecutive_generation_and_index_binding() {
        let path = path("sse-journal-cas");
        let mut database = AnchorDatabase::open(&path, Zeroizing::new([0x42; 32])).unwrap();
        let mut anchor = database.sse_journal_anchor("app-index-b").unwrap();
        let initial = journal_state(0x12, 0, 0x22);
        assert!(matches!(
            anchor.compare_and_swap(None, journal_state(0x12, 1, 0x23)),
            Err(Error::Conflict)
        ));
        anchor.compare_and_swap(None, initial).unwrap();

        let next = journal_state(0x12, 1, 0x23);
        anchor.compare_and_swap(Some(0), next).unwrap();
        assert!(matches!(
            anchor.compare_and_swap(Some(0), journal_state(0x12, 1, 0x24)),
            Err(Error::Conflict)
        ));
        assert!(matches!(
            anchor.compare_and_swap(Some(1), journal_state(0x99, 2, 0x25)),
            Err(Error::Conflict)
        ));
        assert_eq!(anchor.load().unwrap(), Some(next));
        drop(anchor);
        assert_eq!(
            database
                .sse_journal_anchor("independent-slot")
                .unwrap()
                .load()
                .unwrap(),
            None
        );
        drop(database);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sse_journal_anchor_concurrent_cas_has_one_winner() {
        use std::sync::{Arc, Barrier};

        let path = path("sse-journal-concurrent-cas");
        {
            let mut database = AnchorDatabase::open(&path, Zeroizing::new([0x45; 32])).unwrap();
            database
                .sse_journal_anchor("shared-index")
                .unwrap()
                .compare_and_swap(None, journal_state(0x15, 0, 0x35))
                .unwrap();
        }
        let barrier = Arc::new(Barrier::new(2));
        let writers = [0x36, 0x37].map(|digest| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut database = AnchorDatabase::open(&path, Zeroizing::new([0x45; 32])).unwrap();
                let mut anchor = database.sse_journal_anchor("shared-index").unwrap();
                barrier.wait();
                anchor
                    .compare_and_swap(Some(0), journal_state(0x15, 1, digest))
                    .is_ok()
            })
        });
        let successes = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);

        let mut database = AnchorDatabase::open(&path, Zeroizing::new([0x45; 32])).unwrap();
        let state = database
            .sse_journal_anchor("shared-index")
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.generation(), 1);
        assert!([0x36; 32] == *state.digest() || [0x37; 32] == *state.digest());
        drop(database);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sse_journal_anchor_rejects_wrong_key_and_ciphertext_tampering() {
        let path = path("sse-journal-corruption");
        let state = journal_state(0x13, 0, 0x33);
        {
            let mut database = AnchorDatabase::open(&path, Zeroizing::new([0x43; 32])).unwrap();
            database
                .sse_journal_anchor("app-index-c")
                .unwrap()
                .compare_and_swap(None, state)
                .unwrap();
        }
        let database_bytes = std::fs::read(&path).unwrap();
        assert!(
            !database_bytes
                .windows(16)
                .any(|window| window == [0x13; 16])
        );
        assert!(
            !database_bytes
                .windows(32)
                .any(|window| window == [0x33; 32])
        );
        {
            let mut wrong_key = AnchorDatabase::open(&path, Zeroizing::new([0x44; 32])).unwrap();
            assert!(matches!(
                wrong_key.sse_journal_anchor("app-index-c").unwrap().load(),
                Err(Error::Cryptography)
            ));
        }
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute(
                    "UPDATE sse_journal_anchor SET ciphertext = zeroblob(64) WHERE slot = 'app-index-c'",
                    [],
                )
                .unwrap();
        }
        let mut database = AnchorDatabase::open(&path, Zeroizing::new([0x43; 32])).unwrap();
        assert!(matches!(
            database.sse_journal_anchor("app-index-c").unwrap().load(),
            Err(Error::Cryptography)
        ));
        drop(database);
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .pragma_update(None, "ignore_check_constraints", true)
                .unwrap();
            connection
                .execute(
                    "UPDATE sse_journal_anchor SET ciphertext = zeroblob(1048576) WHERE slot = 'app-index-c'",
                    [],
                )
                .unwrap();
        }
        let mut database = AnchorDatabase::open(&path, Zeroizing::new([0x43; 32])).unwrap();
        assert!(matches!(
            database.sse_journal_anchor("app-index-c").unwrap().load(),
            Err(Error::Cryptography)
        ));
        drop(database);
        let _ = std::fs::remove_file(path);
    }

    fn invocation(seed: u8, id: [u8; 16], request_digest: [u8; 32]) -> SignedInvocationId {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let signature = signing_key
            .sign(&SignedInvocationId::signing_message(&id, &request_digest))
            .to_bytes();
        SignedInvocationId::new(
            signing_key.verifying_key().to_bytes(),
            id,
            request_digest,
            signature,
        )
    }

    #[test]
    fn invocation_receipt_and_checkpoint_commit_atomically_and_replay_durably() {
        let path = path("invocation-receipt");
        let master_key = [0x91; 32];
        let token = invocation(7, [0x42; 16], [0x53; 32]);
        let initial_response = b"first fixed-shape response".to_vec();
        {
            let mut db = AnchorDatabase::open(&path, Zeroizing::new(master_key)).unwrap();
            let oversized = invocation(7, [0x41; 16], [0x52; 32]);
            assert!(matches!(
                db.commit_invocation(
                    "store-a",
                    &oversized,
                    None,
                    CheckpointAnchorRecord::new("oversized", &handle(1)).unwrap(),
                    &vec![0; MAX_INVOCATION_RESPONSE_BYTES + 1],
                ),
                Err(Error::InvocationResponseTooLarge)
            ));
            let receipt = db
                .commit_invocation(
                    "store-a",
                    &token,
                    None,
                    CheckpointAnchorRecord::new("snapshot-1", &handle(1)).unwrap(),
                    &initial_response,
                )
                .unwrap();
            assert_eq!(receipt.snapshot_id(), "snapshot-1");
            assert_eq!(receipt.generation(), 1);
            assert_eq!(receipt.response(), initial_response);

            let invalid_signature = SignedInvocationId::new(
                *token.public_key(),
                *token.invocation_id(),
                *token.request_digest(),
                [0; 64],
            );
            assert!(matches!(
                db.load_invocation_receipt("store-a", &invalid_signature),
                Err(Error::InvalidInvocationSignature)
            ));

            let replay = db
                .commit_invocation(
                    "store-a",
                    &token,
                    Some(1),
                    CheckpointAnchorRecord::new("snapshot-2", &handle(2)).unwrap(),
                    b"response from a duplicate execution",
                )
                .unwrap();
            assert_eq!(replay.snapshot_id(), receipt.snapshot_id());
            assert_eq!(replay.generation(), receipt.generation());
            assert_eq!(replay.response(), receipt.response());

            let other_client = invocation(8, [0x42; 16], [0x53; 32]);
            assert!(
                db.load_invocation_receipt("store-a", &other_client)
                    .unwrap()
                    .is_none()
            );

            let conflict = invocation(7, [0x42; 16], [0x54; 32]);
            assert!(matches!(
                db.load_invocation_receipt("store-a", &conflict),
                Err(Error::Conflict)
            ));

            let uncommitted = invocation(7, [0x43; 16], [0x53; 32]);
            assert!(matches!(
                db.commit_invocation(
                    "store-a",
                    &uncommitted,
                    None,
                    CheckpointAnchorRecord::new("snapshot-stale", &handle(1)).unwrap(),
                    b"must not be receipted",
                ),
                Err(Error::Conflict)
            ));
            assert!(
                db.load_invocation_receipt("store-a", &uncommitted)
                    .unwrap()
                    .is_none()
            );
        }

        let database_bytes = std::fs::read(&path).unwrap();
        assert!(
            !database_bytes
                .windows(initial_response.len())
                .any(|window| window == initial_response)
        );

        let db = AnchorDatabase::open(&path, Zeroizing::new(master_key)).unwrap();
        let recovered = db
            .load_invocation_receipt("store-a", &token)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.snapshot_id(), "snapshot-1");
        assert_eq!(recovered.generation(), 1);
        assert_eq!(recovered.response(), initial_response);
        drop(db);
        let mut db = AnchorDatabase::open(&path, Zeroizing::new(master_key)).unwrap();
        let checkpoint = db
            .checkpoint_anchor("store-a")
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.snapshot_id(), "snapshot-1");
        assert_eq!(checkpoint.generation(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invocation_transaction_rolls_back_checkpoint_if_either_insert_fails() {
        let path = path("invocation-atomicity");
        let master_key = [0xB1; 32];
        let first = invocation(21, [0x61; 16], [0x71; 32]);
        let second = invocation(21, [0x62; 16], [0x72; 32]);
        let mut db = AnchorDatabase::open(&path, Zeroizing::new(master_key)).unwrap();

        db.connection
            .execute_batch(
                "CREATE TRIGGER fail_checkpoint_insert BEFORE INSERT ON checkpoint_anchor
                 BEGIN SELECT RAISE(ABORT, 'injected checkpoint failure'); END;",
            )
            .unwrap();
        assert!(matches!(
            db.commit_invocation(
                "store-a",
                &first,
                None,
                CheckpointAnchorRecord::new("snapshot-1", &handle(1)).unwrap(),
                b"response-1",
            ),
            Err(Error::Database(_))
        ));
        assert!(
            db.checkpoint_anchor("store-a")
                .unwrap()
                .load()
                .unwrap()
                .is_none()
        );
        assert!(
            db.load_invocation_receipt("store-a", &first)
                .unwrap()
                .is_none()
        );
        db.connection
            .execute_batch("DROP TRIGGER fail_checkpoint_insert;")
            .unwrap();

        db.connection
            .execute_batch(
                "CREATE TRIGGER fail_receipt_insert BEFORE INSERT ON invocation_receipt
                 BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;",
            )
            .unwrap();
        assert!(matches!(
            db.commit_invocation(
                "store-a",
                &second,
                None,
                CheckpointAnchorRecord::new("snapshot-2", &handle(1)).unwrap(),
                b"response-2",
            ),
            Err(Error::Database(_))
        ));
        assert!(
            db.checkpoint_anchor("store-a")
                .unwrap()
                .load()
                .unwrap()
                .is_none()
        );
        assert!(
            db.load_invocation_receipt("store-a", &second)
                .unwrap()
                .is_none()
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn checkpoint_cas_persists_encrypted_secret_and_rejects_stale_writers() {
        let path = path("checkpoint");
        let master_key = [0x31; 32];
        let secret = handle(1);
        {
            let mut db = AnchorDatabase::open(&path, Zeroizing::new(master_key)).unwrap();
            let mut slot = db.checkpoint_anchor("store-a").unwrap();
            assert!(slot.load().unwrap().is_none());
            let record = CheckpointAnchorRecord::new("snapshot-a", &secret).unwrap();
            slot.compare_and_swap(None, record).unwrap();
            assert!(
                slot.compare_and_swap(
                    None,
                    CheckpointAnchorRecord::new("snapshot-old", &secret).unwrap()
                )
                .is_err()
            );
        }
        let file = std::fs::read(&path).unwrap();
        assert!(!file.windows(secret.len()).any(|window| window == secret));
        {
            let mut db = AnchorDatabase::open(&path, Zeroizing::new(master_key)).unwrap();
            let mut slot = db.checkpoint_anchor("store-a").unwrap();
            let loaded = slot.load().unwrap().unwrap();
            assert_eq!(loaded.snapshot_id(), "snapshot-a");
            assert_eq!(loaded.generation(), 1);
            assert_eq!(loaded.secret_handle(), secret);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn registry_versions_are_monotonic_persistent_and_namespaced() {
        let path = path("registry");
        let mut db = AnchorDatabase::open(&path, Zeroizing::new([0x72; 32])).unwrap();
        let mut a = db.registry_anchor("registry-a").unwrap();
        assert_eq!(a.current_version().unwrap(), None);
        a.compare_and_swap(None, 1).unwrap();
        assert!(a.compare_and_swap(None, 1).is_err());
        assert_eq!(a.current_version().unwrap(), Some(1));
        drop(a);
        let mut b = db.registry_anchor("registry-b").unwrap();
        assert_eq!(b.current_version().unwrap(), None);
        drop(b);
        assert!(db.checkpoint_anchor("../other").is_err());
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn checkpoint_authentication_rejects_wrong_key_and_ciphertext_tampering() {
        let path = path("tamper");
        let key = [0x19; 32];
        let secret = handle(1);
        {
            let mut db = AnchorDatabase::open(&path, Zeroizing::new(key)).unwrap();
            db.checkpoint_anchor("store-a")
                .unwrap()
                .compare_and_swap(
                    None,
                    CheckpointAnchorRecord::new("snapshot-a", &secret).unwrap(),
                )
                .unwrap();
        }
        {
            let mut wrong_key = AnchorDatabase::open(&path, Zeroizing::new([0x20; 32])).unwrap();
            assert!(
                wrong_key
                    .checkpoint_anchor("store-a")
                    .unwrap()
                    .load()
                    .is_err()
            );
        }
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute(
                    "UPDATE checkpoint_anchor SET ciphertext = zeroblob(104) WHERE slot = 'store-a'",
                    [],
                )
                .unwrap();
        }
        let mut db = AnchorDatabase::open(&path, Zeroizing::new(key)).unwrap();
        assert!(db.checkpoint_anchor("store-a").unwrap().load().is_err());
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_initialization_has_exactly_one_cas_winner() {
        use std::sync::{Arc, Barrier};

        let path = path("race");
        let key = [0x44; 32];
        drop(AnchorDatabase::open(&path, Zeroizing::new(key)).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = (1..=2)
            .map(|writer| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut db = AnchorDatabase::open(path, Zeroizing::new(key)).unwrap();
                    let secret = handle(1);
                    let record =
                        CheckpointAnchorRecord::new(&format!("snapshot-{writer}"), &secret)
                            .unwrap();
                    let mut slot = db.checkpoint_anchor("shared-store").unwrap();
                    barrier.wait();
                    slot.compare_and_swap(None, record).is_ok()
                })
            })
            .collect();
        let wins = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(wins, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn restoring_an_old_database_copy_rolls_back_registry_freshness() {
        let path = path("rollback");
        let backup = path.with_extension("backup");
        let key = [0x55; 32];
        {
            let mut db = AnchorDatabase::open(&path, Zeroizing::new(key)).unwrap();
            db.registry_anchor("registry")
                .unwrap()
                .compare_and_swap(None, 1)
                .unwrap();
        }
        std::fs::copy(&path, &backup).unwrap();
        {
            let mut db = AnchorDatabase::open(&path, Zeroizing::new(key)).unwrap();
            db.registry_anchor("registry")
                .unwrap()
                .compare_and_swap(Some(1), 2)
                .unwrap();
        }
        std::fs::copy(&backup, &path).unwrap();
        let mut rolled_back = AnchorDatabase::open(&path, Zeroizing::new(key)).unwrap();
        let mut registry = rolled_back.registry_anchor("registry").unwrap();
        assert_eq!(registry.current_version().unwrap(), Some(1));
        registry.compare_and_swap(Some(1), 2).unwrap();
        drop(registry);
        drop(rolled_back);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(backup);
    }

    #[test]
    fn commit_indeterminacy_maps_to_typed_errors_for_both_anchor_contracts() {
        assert!(matches!(
            map_store_error(Error::CommitIndeterminate),
            store::Error::AnchorCommitUnknown
        ));
        assert!(matches!(
            map_registry_error(Error::CommitIndeterminate),
            registry::Error::AnchorCommitUnknown
        ));
    }

    #[test]
    fn unknown_database_schema_is_rejected_without_mutation() {
        let path = path("schema-version");
        {
            let connection = Connection::open(&path).unwrap();
            connection.pragma_update(None, "user_version", 99).unwrap();
        }
        assert!(matches!(
            AnchorDatabase::open(&path, Zeroizing::new([0x5a; 32])),
            Err(Error::UnsupportedSchema(99))
        ));
        let connection = Connection::open(&path).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 99);
        drop(connection);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn schema_one_database_migrates_receipt_table_transactionally() {
        let path = path("schema-one-migration");
        {
            let _db = AnchorDatabase::open(&path, Zeroizing::new([0xA7; 32])).unwrap();
        }
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TABLE invocation_receipt; DROP TABLE registry_catalog_anchor;
                 DROP TABLE sse_journal_anchor; PRAGMA user_version = 1;",
            )
            .unwrap();
        drop(connection);

        let db = AnchorDatabase::open(&path, Zeroizing::new([0xA7; 32])).unwrap();
        let token = invocation(12, [0x21; 16], [0x32; 32]);
        assert!(
            db.load_invocation_receipt("store-a", &token)
                .unwrap()
                .is_none()
        );
        let schema_version: u32 = db
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(schema_version, 4);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sqlite_checkpoint_anchor_drives_real_oram_recovery_and_stale_writer_rejection() {
        let root = path("oram-recovery");
        std::fs::create_dir(&root).unwrap();
        let database = root.join("anchor.sqlite");
        let checkpoint_one = root.join("checkpoint-one.bin");
        let checkpoint_two = root.join("checkpoint-two.bin");
        let stale_checkpoint = root.join("stale-checkpoint.bin");
        let key = [0x63; 32];
        let config = Config::new(8, 16).unwrap();
        let mut store = PathOram::new(config.clone(), MemoryBackend::default()).unwrap();
        store.write(3, &[3; 16]).unwrap();
        {
            let mut db = AnchorDatabase::open(&database, Zeroizing::new(key)).unwrap();
            let mut anchor = db.checkpoint_anchor("state-a").unwrap();
            store
                .checkpoint_anchored(&checkpoint_one, "snapshot-one", &mut anchor)
                .unwrap();
        }
        let (mut live, mut stale) = {
            let mut db = AnchorDatabase::open(&database, Zeroizing::new(key)).unwrap();
            let mut anchor = db.checkpoint_anchor("state-a").unwrap();
            let record = anchor.load().unwrap().unwrap();
            let trusted = TrustedCheckpoint::from_secret_bytes(record.secret_handle()).unwrap();
            (
                PathOram::restore(&checkpoint_one, &trusted, MemoryBackend::default()).unwrap(),
                PathOram::restore(&checkpoint_one, &trusted, MemoryBackend::default()).unwrap(),
            )
        };
        live.write(3, &[9; 16]).unwrap();
        live.write(4, &[4; 16]).unwrap();
        {
            let mut db = AnchorDatabase::open(&database, Zeroizing::new(key)).unwrap();
            let mut anchor = db.checkpoint_anchor("state-a").unwrap();
            live.checkpoint_anchored(&checkpoint_two, "snapshot-two", &mut anchor)
                .unwrap();
            assert!(
                stale
                    .checkpoint_anchored(&stale_checkpoint, "snapshot-stale", &mut anchor)
                    .is_err()
            );
        }
        let mut db = AnchorDatabase::open(&database, Zeroizing::new(key)).unwrap();
        let mut anchor = db.checkpoint_anchor("state-a").unwrap();
        let current = anchor.load().unwrap().unwrap();
        assert_eq!(current.snapshot_id(), "snapshot-two");
        let trusted = TrustedCheckpoint::from_secret_bytes(current.secret_handle()).unwrap();
        let mut restored =
            PathOram::restore(&checkpoint_two, &trusted, MemoryBackend::default()).unwrap();
        assert_eq!(restored.read(3).unwrap(), vec![9; 16]);
        assert_eq!(restored.read(4).unwrap(), vec![4; 16]);
        drop(anchor);
        drop(db);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn sqlite_registry_anchor_drives_signed_monotonic_activation() {
        let path = path("registry-activation");
        let signing = SigningKey::from_bytes(&[0x29; 32]);
        let verifying = signing.verifying_key();
        let catalog = |version| {
            let record = Record::sign(0, version, [0x31; 32], [0x42; 32], 0, &signing).unwrap();
            SignedRegistry::sign(version, vec![record], &signing).unwrap()
        };
        {
            let mut db = AnchorDatabase::open(&path, Zeroizing::new([0x73; 32])).unwrap();
            let mut anchor = db.registry_anchor("functions").unwrap();
            VerifiedRegistry::verify(&catalog(1), &verifying)
                .unwrap()
                .activate(&mut anchor)
                .unwrap();
            assert!(
                VerifiedRegistry::verify(&catalog(1), &verifying)
                    .unwrap()
                    .activate(&mut anchor)
                    .is_err()
            );
            VerifiedRegistry::verify(&catalog(2), &verifying)
                .unwrap()
                .activate(&mut anchor)
                .unwrap();
        }
        let mut db = AnchorDatabase::open(&path, Zeroizing::new([0x73; 32])).unwrap();
        assert_eq!(
            db.registry_anchor("functions")
                .unwrap()
                .current_version()
                .unwrap(),
            Some(2)
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sqlite_registry_catalog_anchor_persists_digest_cas() {
        let path = path("registry-catalog-anchor");
        let digest_one = [0x31; 32];
        let digest_two = [0x32; 32];
        {
            let mut db = AnchorDatabase::open(&path, Zeroizing::new([0x75; 32])).unwrap();
            let mut anchor = db.registry_catalog_anchor("functions").unwrap();
            assert_eq!(anchor.current_catalog().unwrap(), None);
            anchor
                .compare_and_swap_catalog(None, 4, digest_one)
                .unwrap();
            let expected = RegistryCatalogState::new(4, Some(digest_one)).unwrap();
            assert_eq!(anchor.current_catalog().unwrap(), Some(expected));
            assert!(matches!(
                anchor.compare_and_swap_catalog(Some(expected), 4, digest_two),
                Err(registry::Error::AnchorConflict)
            ));
            anchor
                .compare_and_swap_catalog(Some(expected), 5, digest_two)
                .unwrap();
            assert_eq!(
                anchor.current_catalog().unwrap(),
                Some(RegistryCatalogState::new(5, Some(digest_two)).unwrap())
            );
        }
        let mut db = AnchorDatabase::open(&path, Zeroizing::new([0x75; 32])).unwrap();
        assert_eq!(
            db.registry_catalog_anchor("functions")
                .unwrap()
                .current_catalog()
                .unwrap(),
            Some(RegistryCatalogState::new(5, Some(digest_two)).unwrap())
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn schema_two_migration_preserves_version_as_legacy_catalog_floor() {
        let path = path("schema-two-catalog-migration");
        {
            let db = AnchorDatabase::open(&path, Zeroizing::new([0x76; 32])).unwrap();
            db.connection
                .execute(
                    "INSERT INTO registry_anchor(slot, version) VALUES ('functions', 7)",
                    [],
                )
                .unwrap();
            db.connection
                .execute_batch(
                    "DROP TABLE registry_catalog_anchor; DROP TABLE sse_journal_anchor;
                     PRAGMA user_version = 2;",
                )
                .unwrap();
        }
        let mut db = AnchorDatabase::open(&path, Zeroizing::new([0x76; 32])).unwrap();
        let legacy = RegistryCatalogState::new(7, None).unwrap();
        assert_eq!(
            db.registry_catalog_anchor("functions")
                .unwrap()
                .current_catalog()
                .unwrap(),
            Some(legacy)
        );
        let schema_version: u32 = db
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(schema_version, 4);
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
