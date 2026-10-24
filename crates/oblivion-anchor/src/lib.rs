//! SQLite-backed atomic anchor state for a separately trusted anchor process.
//!
//! This crate supplies durable compare-and-swap adapters. It does not make a
//! database rollback-resistant: the database and its operator must be trusted
//! independently from the snapshots and storage server being anchored.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use oblivion_registry::{self as registry, RegistryVersionAnchor};
use oblivion_store::{self as store, CheckpointAnchor, CheckpointAnchorRecord};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::Sha256;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

#[cfg(unix)]
mod local;
#[cfg(unix)]
pub use local::{UnixAnchorClient, UnixCheckpointAnchor, UnixRegistryAnchor, serve_unix};

const NONCE_BYTES: usize = 12;
const HANDLE_BYTES: usize = 88;
const MAX_SLOT_BYTES: usize = 128;
const SCHEMA_VERSION: u32 = 1;

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
    #[error("operating-system randomness unavailable")]
    Randomness,
    #[error("stored checkpoint handle is malformed")]
    InvalidHandle,
    #[error("anchor database schema version {0} is unsupported")]
    UnsupportedSchema(u32),
    #[error("anchor service socket operation failed: {0}")]
    Socket(String),
    #[error("anchor service protocol message is malformed or unsupported")]
    Protocol,
    #[error("anchor socket mode must be 0600 or 0660")]
    InvalidSocketMode,
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
            CREATE TABLE IF NOT EXISTS used_nonce (
                nonce BLOB PRIMARY KEY NOT NULL CHECK (length(nonce) = 12)
            );
            PRAGMA user_version = 1;",
                )?;
                tx.commit()?;
            }
            SCHEMA_VERSION => {}
            other => return Err(Error::UnsupportedSchema(other)),
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
    use ed25519_dalek::SigningKey;
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
}
