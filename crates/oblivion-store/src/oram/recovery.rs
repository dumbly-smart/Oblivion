use super::*;
use crate::file_backend::io_error;
use chacha20poly1305::aead::AeadInPlace;
use sha2::Digest;
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Bound on the complete encrypted checkpoint, including trusted metadata.
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const HEADER: usize = 32;
const HANDLE: usize = 88;
const SNAPSHOT_ID_MAX_BYTES: usize = 128;

/// External trusted freshness anchor AND decryption secret. Store this only in
/// trusted storage, independently of the snapshot. Its Debug output is redacted.
/// A caller who rolls back this handle and the snapshot defeats freshness.
pub struct TrustedCheckpoint {
    generation: u64,
    digest: [u8; 32],
    key: Zeroizing<[u8; 32]>,
    snapshot_bytes: usize,
}
impl fmt::Debug for TrustedCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrustedCheckpoint([REDACTED])")
    }
}
impl TrustedCheckpoint {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn snapshot_digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Export a SECRET handle for storage in an external trusted anchor service.
    /// Never place this beside the untrusted snapshot as a freshness mechanism.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; HANDLE]> {
        let mut bytes = Zeroizing::new([0; HANDLE]);
        bytes[..8].copy_from_slice(b"OBLTRST1");
        bytes[8..16].copy_from_slice(&self.generation.to_le_bytes());
        bytes[16..24].copy_from_slice(&(self.snapshot_bytes as u64).to_le_bytes());
        bytes[24..56].copy_from_slice(&self.digest);
        bytes[56..88].copy_from_slice(self.key.as_ref());
        bytes
    }
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != HANDLE || &bytes[..8] != b"OBLTRST1" {
            return Err(Error::Integrity);
        }
        let generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let snapshot_bytes = usize::try_from(u64::from_le_bytes(bytes[16..24].try_into().unwrap()))
            .map_err(|_| Error::Integrity)?;
        if generation == 0 || !(HEADER + 16..=MAX_SNAPSHOT_BYTES).contains(&snapshot_bytes) {
            return Err(Error::Integrity);
        }
        Ok(Self {
            generation,
            snapshot_bytes,
            digest: bytes[24..56].try_into().unwrap(),
            key: Zeroizing::new(bytes[56..88].try_into().unwrap()),
        })
    }
}

/// Adapter for independently protected, durable, rollback-resistant storage.
/// Implementations must keep returned and published handle bytes secret and
/// make `compare_and_swap` atomic and durable. Errors other than
/// `AnchorCommitUnknown` mean the replacement definitely did not commit. An
/// indeterminate result requires reloading the anchor and reconciling before
/// continuing. A local file beside the snapshot is not a trusted anchor.
pub trait CheckpointAnchor {
    /// Return the current snapshot identifier and secret handle, if initialized.
    fn load(&mut self) -> Result<Option<CheckpointAnchorRecord>, Error>;

    /// Atomically replace the snapshot identifier and secret handle only when
    /// its current generation equals `expected_generation`. Implementations
    /// should reject nonconsecutive generations and bind the slot to one store.
    /// `Err(AnchorCommitUnknown)` means the caller must reload and reconcile the
    /// anchor before continuing; the controller is poisoned by this outcome.
    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        next_record: CheckpointAnchorRecord,
    ) -> Result<(), Error>;
}

/// Atomically stored snapshot reference and key-bearing trusted handle.
/// Identifiers are opaque stable tokens, restricted to ASCII letters, digits,
/// dot, underscore and hyphen; they are never interpreted as filesystem paths.
pub struct CheckpointAnchorRecord {
    snapshot_id: Box<str>,
    generation: u64,
    handle: Zeroizing<[u8; HANDLE]>,
}
impl CheckpointAnchorRecord {
    pub fn new(snapshot_id: &str, secret_handle: &[u8]) -> Result<Self, Error> {
        if !Self::valid_snapshot_id(snapshot_id) {
            return Err(Error::Configuration);
        }
        let trusted = TrustedCheckpoint::from_secret_bytes(secret_handle)?;
        let generation = trusted.generation();
        let mut handle = Zeroizing::new([0; HANDLE]);
        handle.copy_from_slice(secret_handle);
        Ok(Self {
            snapshot_id: snapshot_id.into(),
            generation,
            handle,
        })
    }

    fn valid_snapshot_id(snapshot_id: &str) -> bool {
        !snapshot_id.is_empty()
            && snapshot_id.len() <= SNAPSHOT_ID_MAX_BYTES
            && snapshot_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn secret_handle(&self) -> &[u8] {
        self.handle.as_ref()
    }
}
impl fmt::Debug for CheckpointAnchorRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckpointAnchorRecord")
            .field("snapshot_id", &self.snapshot_id)
            .field("generation", &self.generation)
            .field("secret_handle", &"[REDACTED]")
            .finish()
    }
}

impl<B: Backend> PathOram<B> {
    /// Full-tree checkpoint, separate from invocation paths. A fresh one-use
    /// snapshot key is generated internally on each attempt, including retries.
    /// Success means file and containing directory fsync completed; the caller
    /// must then durably publish the returned handle in external trusted storage.
    pub fn checkpoint(&mut self, path: impl AsRef<Path>) -> Result<TrustedCheckpoint, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let generation = self
            .checkpoint_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let mut plain = self.encode_checkpoint()?;
        let total = HEADER
            .checked_add(plain.len())
            .and_then(|n| n.checked_add(16))
            .filter(|&n| n <= MAX_SNAPSHOT_BYTES)
            .ok_or(Error::Configuration)?;
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(b"OBLSNAP1");
        header[8..16].copy_from_slice(&generation.to_le_bytes());
        header[16..24].copy_from_slice(&(plain.len() as u64).to_le_bytes());
        let mut key = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(key.as_mut())
            .map_err(|_| Error::Randomness)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Integrity)?;
        // This fresh key is used exactly once, so its all-zero nonce is unique.
        cipher
            .encrypt_in_place(Nonce::from_slice(&[0; 12]), &header, &mut *plain)
            .map_err(|_| Error::Authentication)?;
        let mut digest = Sha256::new();
        digest.update(header);
        digest.update(plain.as_slice());
        let digest = digest.finalize().into();
        atomic_publish(path.as_ref(), &header, &plain)?;
        self.checkpoint_generation = generation;
        Ok(TrustedCheckpoint {
            generation,
            digest,
            key,
            snapshot_bytes: total,
        })
    }

    /// Publish a checkpoint through an external trusted freshness anchor.
    /// `path` must be a new, immutable snapshot path for each generation. A
    /// failed compare-and-swap can leave an unanchored snapshot at that path;
    /// it is safe to discard. The adapter must provide an atomic durable CAS.
    /// This method does not make an untrusted filesystem rollback resistant.
    pub fn checkpoint_anchored<A: CheckpointAnchor>(
        &mut self,
        path: impl AsRef<Path>,
        snapshot_id: &str,
        anchor: &mut A,
    ) -> Result<TrustedCheckpoint, Error> {
        if !CheckpointAnchorRecord::valid_snapshot_id(snapshot_id) {
            return Err(Error::Configuration);
        }
        let current = anchor
            .load()?
            .map(|record| TrustedCheckpoint::from_secret_bytes(record.secret_handle()))
            .transpose()?;
        let expected = current.as_ref().map(TrustedCheckpoint::generation);
        let local_generation =
            (self.checkpoint_generation != 0).then_some(self.checkpoint_generation);
        if expected != local_generation {
            return Err(Error::AnchorConflict);
        }

        let checkpoint = self.checkpoint(path)?;
        let handle = checkpoint.to_secret_bytes();
        let next_record = CheckpointAnchorRecord::new(snapshot_id, handle.as_ref())?;
        if let Err(error) = anchor.compare_and_swap(expected, next_record) {
            if matches!(error, Error::AnchorCommitUnknown) {
                self.poisoned = true;
                return Err(error);
            }
            // Definite non-commit: retain the previous generation and allow a
            // safe retry. Indeterminate outcomes above require restore.
            self.checkpoint_generation = expected.unwrap_or(0);
            return Err(error);
        }
        Ok(checkpoint)
    }

    fn encode_checkpoint(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // Check the exact bound before allocating the complete image.
        let stash_bytes = self
            .stash
            .len()
            .checked_mul(8 + self.config.block_bytes)
            .ok_or(Error::Configuration)?;
        let size = 88usize
            .checked_add(self.config.blocks * 8)
            .and_then(|n| n.checked_add(self.config.bucket_count() * 8))
            .and_then(|n| n.checked_add(stash_bytes))
            .and_then(|n| n.checked_add(self.config.storage_bytes()))
            .filter(|&n| n <= MAX_SNAPSHOT_BYTES - HEADER - 16)
            .ok_or(Error::Configuration)?;
        if self.stash.len() > self.config.stash_limit
            || self.position.len() != self.config.blocks
            || self.versions.len() != self.config.bucket_count()
            || self.position.iter().any(|&p| p >= self.config.leaves)
            || self.stash.iter().any(|(&id, data)| {
                id >= self.config.blocks || data.len() != self.config.block_bytes
            })
            || self.max_stash < self.stash.len()
            || self.max_stash > self.config.stash_limit.min(self.config.blocks)
        {
            self.poisoned = true;
            return Err(Error::Integrity);
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(size + 16));
        for n in [
            self.config.blocks,
            self.config.block_bytes,
            self.config.z,
            self.config.stash_limit,
        ] {
            put(&mut plain, n as u64);
        }
        plain.extend_from_slice(self.bucket_key.as_ref());
        put(&mut plain, self.nonce);
        put(&mut plain, self.max_stash as u64);
        for &n in &self.position {
            put(&mut plain, n as u64);
        }
        for &n in &self.versions {
            put(&mut plain, n);
        }
        put(&mut plain, self.stash.len() as u64);
        for (&id, bytes) in &self.stash {
            put(&mut plain, id as u64);
            plain.extend_from_slice(bytes);
        }
        let mut seen = self.stash.clone();
        let mut nonces = std::collections::BTreeSet::new();
        for bucket in 0..self.config.bucket_count() {
            let result = (|| {
                let sealed = self.backend.read_bucket(bucket)?;
                let body = self.open(bucket, self.versions[bucket], &sealed)?;
                self.decode_into(bucket, (bucket + 1).ilog2() as usize, &body, &mut seen)?;
                validate_nonce(&sealed, self.nonce, &mut nonces)?;
                Ok::<_, Error>(sealed)
            })();
            match result {
                Ok(sealed) => plain.extend_from_slice(&sealed),
                Err(e) => {
                    self.poisoned = true;
                    return Err(e);
                }
            }
        }
        if plain.len() != size {
            return Err(Error::Integrity);
        }
        Ok(plain)
    }

    /// Restore only with the latest independently protected trusted handle.
    /// Authenticates the whole snapshot before backend mutation. Recovery rotates
    /// the bucket key and re-encrypts every bucket, avoiding nonce reuse even if
    /// the old controller continued writing after the checkpoint was taken.
    pub fn restore(
        path: impl AsRef<Path>,
        trusted: &TrustedCheckpoint,
        backend: B,
    ) -> Result<Self, Error> {
        let mut file = File::open(path).map_err(io_error)?;
        if file.metadata().map_err(io_error)?.len() != trusted.snapshot_bytes as u64
            || trusted.snapshot_bytes > MAX_SNAPSHOT_BYTES
        {
            return Err(Error::Authentication);
        }
        let mut bytes = Zeroizing::new(vec![0; trusted.snapshot_bytes]);
        file.read_exact(&mut bytes).map_err(io_error)?;
        let mut extra = [0];
        if file.read(&mut extra).map_err(io_error)? != 0 {
            return Err(Error::Authentication);
        }
        if Sha256::digest(bytes.as_slice()).as_slice() != trusted.digest {
            return Err(Error::Authentication);
        }
        let header = bytes[..HEADER].to_vec();
        if &header[..8] != b"OBLSNAP1"
            || header[8..16] != trusted.generation.to_le_bytes()
            || header[24..32] != [0; 8]
            || u64::from_le_bytes(header[16..24].try_into().unwrap())
                != (bytes.len() - HEADER - 16) as u64
        {
            return Err(Error::Authentication);
        }
        // Move ciphertext into a bounded buffer. Clear the outer copy promptly.
        let mut plain = Zeroizing::new(bytes[HEADER..].to_vec());
        drop(bytes);
        let cipher =
            ChaCha20Poly1305::new_from_slice(trusted.key.as_ref()).map_err(|_| Error::Integrity)?;
        cipher
            .decrypt_in_place(Nonce::from_slice(&[0; 12]), &header, &mut *plain)
            .map_err(|_| Error::Authentication)?;
        let mut reader = Decoder {
            bytes: &plain,
            offset: 0,
        };
        let config = Config::with_parameters(
            reader.usize()?,
            reader.usize()?,
            reader.usize()?,
            reader.usize()?,
        )?;
        let minimum = 88usize
            .checked_add(config.blocks * 8)
            .and_then(|n| n.checked_add(config.bucket_count() * 8))
            .and_then(|n| n.checked_add(config.storage_bytes()))
            .ok_or(Error::Integrity)?;
        if plain.len() < minimum {
            return Err(Error::Integrity);
        }
        let bucket_key: Zeroizing<[u8; 32]> =
            Zeroizing::new(reader.take(32)?.try_into().map_err(|_| Error::Integrity)?);
        let nonce = reader.u64()?;
        let max_stash = reader.usize()?;
        let mut position = Vec::with_capacity(config.blocks);
        for _ in 0..config.blocks {
            let leaf = reader.usize()?;
            if leaf >= config.leaves {
                return Err(Error::Integrity);
            }
            position.push(leaf);
        }
        let mut versions = Vec::with_capacity(config.bucket_count());
        for _ in 0..config.bucket_count() {
            versions.push(reader.u64()?);
        }
        let stash_count = reader.usize()?;
        if stash_count > config.stash_limit.min(config.blocks)
            || max_stash < stash_count
            || max_stash > config.stash_limit.min(config.blocks)
        {
            return Err(Error::Integrity);
        }
        let mut stash = BTreeMap::new();
        for _ in 0..stash_count {
            let id = reader.usize()?;
            if id >= config.blocks {
                return Err(Error::Integrity);
            }
            let block = Zeroizing::new(reader.take(config.block_bytes)?.to_vec());
            if stash.insert(id, block).is_some() {
                return Err(Error::Integrity);
            }
        }
        if reader.bytes.len() - reader.offset != config.storage_bytes() {
            return Err(Error::Integrity);
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(bucket_key.as_ref()).map_err(|_| Error::Integrity)?;
        let mut store = Self {
            config,
            backend,
            cipher,
            bucket_key,
            checkpoint_generation: trusted.generation,
            nonce,
            versions,
            position,
            stash,
            poisoned: false,
            max_stash,
        };
        // Authenticate/validate every original bucket and nonce before any writes.
        let mut seen = store.stash.clone();
        let mut nonces = std::collections::BTreeSet::new();
        let buckets = &reader.bytes[reader.offset..];
        for (bucket, sealed) in buckets.chunks_exact(store.config.bucket_bytes).enumerate() {
            validate_nonce(sealed, store.nonce, &mut nonces)?;
            let body = store.open(bucket, store.versions[bucket], sealed)?;
            store.decode_into(bucket, (bucket + 1).ilog2() as usize, &body, &mut seen)?;
        }
        // Decrypt under the old key, encrypt under a newly generated key. The old
        // key is never used for encryption by the restored controller.
        let old_cipher = store.cipher.clone();
        let mut new_key = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(new_key.as_mut())
            .map_err(|_| Error::Randomness)?;
        store.cipher =
            ChaCha20Poly1305::new_from_slice(new_key.as_ref()).map_err(|_| Error::Integrity)?;
        store.bucket_key = new_key;
        store.nonce = 0;
        for (bucket, sealed) in buckets.chunks_exact(store.config.bucket_bytes).enumerate() {
            let body = Zeroizing::new(
                old_cipher
                    .decrypt(
                        Nonce::from_slice(&sealed[..12]),
                        Payload {
                            msg: &sealed[12..],
                            aad: &Self::aad(bucket, store.versions[bucket]),
                        },
                    )
                    .map_err(|_| Error::Authentication)?,
            );
            let encrypted = store.seal(bucket, store.versions[bucket], &body)?;
            store.backend.write_bucket(bucket, &encrypted)?;
        }
        Ok(store)
    }
}
fn put(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(length).ok_or(Error::Integrity)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(Error::Integrity)?;
        self.offset = end;
        Ok(bytes)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn usize(&mut self) -> Result<usize, Error> {
        usize::try_from(self.u64()?).map_err(|_| Error::Integrity)
    }
}
fn validate_nonce(
    sealed: &[u8],
    next: u64,
    seen: &mut std::collections::BTreeSet<u64>,
) -> Result<(), Error> {
    if sealed.len() < 12 || sealed[..4] != [0; 4] {
        return Err(Error::Integrity);
    }
    let nonce = u64::from_be_bytes(sealed[4..12].try_into().unwrap());
    if nonce >= next || !seen.insert(nonce) {
        return Err(Error::Integrity);
    }
    Ok(())
}

struct Temporary {
    path: PathBuf,
    published: bool,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn atomic_publish(path: &Path, header: &[u8], body: &[u8]) -> Result<(), Error> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or(Error::Configuration)?;
    let mut suffix = [0; 16];
    OsRng
        .try_fill_bytes(&mut suffix)
        .map_err(|_| Error::Randomness)?;
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let temporary = parent.join(format!(".{}.{suffix}.checkpoint", name.to_string_lossy()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(io_error)?;
    let mut guard = Temporary {
        path: temporary,
        published: false,
    };
    file.write_all(header).map_err(io_error)?;
    file.write_all(body).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    drop(file);
    fs::rename(&guard.path, path).map_err(io_error)?;
    guard.published = true;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(io_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBackend;
    struct Snapshot(PathBuf);
    impl Snapshot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "oblivion-private-recovery-{}-{}",
                std::process::id(),
                OsRng.next_u64()
            ));
            Self(path)
        }
    }
    impl Drop for Snapshot {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    #[test]
    fn restore_preserves_maps_versions_stash_and_rotates_keys_before_encrypting() {
        let snapshot = Snapshot::new();
        let mut store =
            PathOram::new(Config::new(16, 16).unwrap(), MemoryBackend::default()).unwrap();
        for i in 0..16 {
            store.write(i, &[i as u8; 16]).unwrap();
        }
        let old_key = Zeroizing::new(*store.bucket_key);
        let versions = store.versions.clone();
        let position = store.position.clone();
        let stash = store.stash.clone();
        let max_stash = store.max_stash;
        let trusted = store.checkpoint(&snapshot.0).unwrap();
        store.write(0, &[42; 16]).unwrap();
        let mut recovered =
            PathOram::restore(&snapshot.0, &trusted, MemoryBackend::default()).unwrap();
        assert_ne!(*recovered.bucket_key, *old_key);
        assert_eq!(recovered.versions, versions);
        assert_eq!(recovered.position, position);
        assert_eq!(recovered.stash, stash);
        assert_eq!(recovered.max_stash, max_stash);
        assert_eq!(recovered.nonce, recovered.config.bucket_count() as u64);
        let nonce = recovered.nonce;
        recovered.read(0).unwrap();
        assert_eq!(
            recovered.nonce,
            nonce + recovered.config.path_buckets() as u64
        );
        let again = PathOram::restore(&snapshot.0, &trusted, MemoryBackend::default()).unwrap();
        assert_ne!(*again.bucket_key, *recovered.bucket_key);
    }
    fn replace_authenticated_plain(
        snapshot: &Snapshot,
        trusted: &mut TrustedCheckpoint,
        mutate: impl FnOnce(&mut [u8]),
    ) {
        let bytes = fs::read(&snapshot.0).unwrap();
        let header = &bytes[..HEADER];
        let cipher = ChaCha20Poly1305::new_from_slice(trusted.key.as_ref()).unwrap();
        let mut plain = cipher
            .decrypt(
                Nonce::from_slice(&[0; 12]),
                Payload {
                    msg: &bytes[HEADER..],
                    aad: header,
                },
            )
            .unwrap();
        mutate(&mut plain);
        // Test-only forgery using trusted key, to exercise validation after AEAD.
        let mut key = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(key.as_mut());
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&[0; 12]),
                Payload {
                    msg: &plain,
                    aad: header,
                },
            )
            .unwrap();
        let mut forged = header.to_vec();
        forged.extend_from_slice(&encrypted);
        trusted.digest = Sha256::digest(&forged).into();
        trusted.key = key;
        fs::write(&snapshot.0, forged).unwrap();
    }
    #[test]
    fn authenticated_malformed_geometry_state_and_nonce_are_rejected() {
        for mode in 0..4 {
            let snapshot = Snapshot::new();
            let mut store =
                PathOram::new(Config::new(4, 8).unwrap(), MemoryBackend::default()).unwrap();
            let mut trusted = store.checkpoint(&snapshot.0).unwrap();
            replace_authenticated_plain(&snapshot, &mut trusted, |plain| {
                let offset = match mode {
                    0 => 0,
                    1 => 64,
                    2 => 80,
                    _ => 80 + 4 * 8 + 7 * 8,
                };
                plain[offset..offset + 8]
                    .copy_from_slice(&(if mode == 1 { 0 } else { u64::MAX }).to_le_bytes());
            });
            assert!(PathOram::restore(&snapshot.0, &trusted, MemoryBackend::default()).is_err());
        }
    }
}
