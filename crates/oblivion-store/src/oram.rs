mod recovery;
use crate::{Backend, Config, Error};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
pub use recovery::{CheckpointAnchor, MAX_SNAPSHOT_BYTES, TrustedCheckpoint};
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// PRIVATE instrumentation. Never send to the storage observer.
#[derive(Clone, Debug, serde::Serialize)]
pub struct PrivateStats {
    pub stash_blocks: usize,
    pub max_stash_blocks: usize,
    pub trusted_metadata_bytes: usize,
    pub configured_stash_payload_bytes: usize,
}

pub struct PathOram<B: Backend> {
    config: Config,
    backend: B,
    cipher: ChaCha20Poly1305,
    bucket_key: Zeroizing<[u8; 32]>,
    checkpoint_generation: u64,
    nonce: u64,
    versions: Vec<u64>,
    position: Vec<usize>,
    stash: BTreeMap<usize, Zeroizing<Vec<u8>>>,
    poisoned: bool,
    max_stash: usize,
}

impl<B: Backend> PathOram<B> {
    /// Creates a fresh store, overwriting its configured bucket range. Keys and
    /// trusted state must be protected together using checkpoint/restore.
    pub fn new(config: Config, backend: B) -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| Error::Randomness)?;
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(b"oblivion/v1"), seed.as_ref())
            .expand(b"path-oram/bucket-aead", key.as_mut())
            .map_err(|_| Error::Configuration)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Configuration)?;
        let mut position = Vec::with_capacity(config.blocks);
        for _ in 0..config.blocks {
            position.push(random_leaf(config.leaves)?);
        }
        let versions = vec![0; config.bucket_count()];
        let mut store = Self {
            config,
            backend,
            cipher,
            bucket_key: key,
            checkpoint_generation: 0,
            nonce: 0,
            versions,
            position,
            stash: BTreeMap::new(),
            poisoned: false,
            max_stash: 0,
        };
        let dummy = Zeroizing::new(store.empty_bucket());
        for bucket in 0..store.config.bucket_count() {
            let sealed = store.seal(bucket, 0, &dummy)?;
            store.backend.write_bucket(bucket, &sealed)?;
        }
        Ok(store)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
    /// Access to the UNTRUSTED backend, useful for transports and trace draining.
    /// Mutating ciphertext can invalidate this controller on its next access.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
    pub fn private_stats(&self) -> PrivateStats {
        PrivateStats {
            stash_blocks: self.stash.len(),
            max_stash_blocks: self.max_stash,
            trusted_metadata_bytes: self.position.len() * size_of::<usize>()
                + self.versions.len() * 8,
            configured_stash_payload_bytes: self.config.stash_limit.min(self.config.blocks)
                * self.config.block_bytes,
        }
    }

    pub fn read(&mut self, address: usize) -> Result<Vec<u8>, Error> {
        self.access(address, None)
    }
    pub fn write(&mut self, address: usize, data: &[u8]) -> Result<(), Error> {
        self.access(address, Some(data)).map(|_| ())
    }

    fn access(&mut self, address: usize, data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if address >= self.config.blocks {
            return Err(Error::Address);
        }
        if data.is_some_and(|v| v.len() != self.config.block_bytes) {
            return Err(Error::BlockSize);
        }
        let result = self.access_inner(address, data);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn access_inner(&mut self, address: usize, data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let old_leaf = self.position[address];
        let path: Vec<usize> = (0..=self.config.height)
            .map(|d| self.config.node(old_leaf, d))
            .collect();
        // Authenticate the entire path under the old position map first.
        let mut candidate = self.stash.clone();
        for (depth, &bucket) in path.iter().enumerate() {
            let sealed = self.backend.read_bucket(bucket)?;
            let plain = self.open(bucket, self.versions[bucket], &sealed)?;
            self.decode_into(bucket, depth, &plain, &mut candidate)?;
        }
        let new_leaf = random_leaf(self.config.leaves)?;
        self.position[address] = new_leaf;
        let block = candidate
            .entry(address)
            .or_insert_with(|| Zeroizing::new(vec![0; self.config.block_bytes]));
        let previous = block.to_vec();
        if let Some(value) = data {
            block.copy_from_slice(value);
        }
        let mut output = Vec::with_capacity(path.len());
        for depth in (0..path.len()).rev() {
            let bucket = path[depth];
            let selected: Vec<usize> = candidate
                .keys()
                .copied()
                .filter(|&id| self.config.node(self.position[id], depth) == bucket)
                .take(self.config.z)
                .collect();
            let mut plain = Zeroizing::new(self.empty_bucket());
            for (slot, id) in selected.into_iter().enumerate() {
                let offset = slot * (8 + self.config.block_bytes);
                plain[offset..offset + 8].copy_from_slice(&(id as u64).to_le_bytes());
                let value = candidate.remove(&id).ok_or(Error::Integrity)?;
                plain[offset + 8..offset + 8 + self.config.block_bytes].copy_from_slice(&value);
            }
            let version = self.versions[bucket]
                .checked_add(1)
                .ok_or(Error::Exhausted)?;
            let sealed = self.seal(bucket, version, &plain)?;
            output.push((bucket, version, sealed));
        }
        if candidate.len() > self.config.stash_limit {
            return Err(Error::StashOverflow);
        }
        // Same root-to-leaf physical write order for logical reads and writes.
        for (bucket, version, sealed) in output.into_iter().rev() {
            self.backend.write_bucket(bucket, &sealed)?;
            self.versions[bucket] = version;
        }
        self.stash = candidate;
        self.max_stash = self.max_stash.max(self.stash.len());
        Ok(previous)
    }

    fn empty_bucket(&self) -> Vec<u8> {
        let mut plain = vec![0; self.config.z * (8 + self.config.block_bytes)];
        for slot in plain.chunks_exact_mut(8 + self.config.block_bytes) {
            slot[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        plain
    }
    fn aad(bucket: usize, version: u64) -> Vec<u8> {
        let mut aad = b"oblivion/path-oram/v1".to_vec();
        aad.extend_from_slice(&(bucket as u64).to_le_bytes());
        aad.extend_from_slice(&version.to_le_bytes());
        aad
    }
    fn seal(&mut self, bucket: usize, version: u64, plain: &[u8]) -> Result<Vec<u8>, Error> {
        let counter = self.nonce;
        self.nonce = self.nonce.checked_add(1).ok_or(Error::Exhausted)?;
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        let encrypted = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &Self::aad(bucket, version),
                },
            )
            .map_err(|_| Error::Authentication)?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&encrypted);
        Ok(result)
    }
    fn open(
        &self,
        bucket: usize,
        version: u64,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if sealed.len() != self.config.bucket_bytes {
            return Err(Error::Authentication);
        }
        self.cipher
            .decrypt(
                Nonce::from_slice(&sealed[..12]),
                Payload {
                    msg: &sealed[12..],
                    aad: &Self::aad(bucket, version),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Authentication)
    }
    fn decode_into(
        &self,
        bucket: usize,
        depth: usize,
        plain: &[u8],
        into: &mut BTreeMap<usize, Zeroizing<Vec<u8>>>,
    ) -> Result<(), Error> {
        for slot in plain.chunks_exact(8 + self.config.block_bytes) {
            let id = u64::from_le_bytes(slot[..8].try_into().map_err(|_| Error::Integrity)?);
            if id == u64::MAX {
                continue;
            }
            let id = usize::try_from(id).map_err(|_| Error::Integrity)?;
            if id >= self.config.blocks
                || self.config.node(self.position[id], depth) != bucket
                || into.contains_key(&id)
            {
                return Err(Error::Integrity);
            }
            into.insert(id, Zeroizing::new(slot[8..].to_vec()));
        }
        Ok(())
    }

    /// Expensive PRIVATE diagnostic: authenticates every bucket and verifies
    /// uniqueness/placement. Adds a full-tree scan to the observer trace. Never
    /// enable this in measured invocation paths or expose the result externally.
    pub fn check_invariants(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let result = self.check_invariants_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn check_invariants_inner(&mut self) -> Result<(), Error> {
        if self.stash.len() > self.config.stash_limit
            || self.position.iter().any(|&p| p >= self.config.leaves)
        {
            return Err(Error::Integrity);
        }
        let mut seen = self.stash.clone();
        for bucket in 0..self.config.bucket_count() {
            let depth = (bucket + 1).ilog2() as usize;
            let sealed = self.backend.read_bucket(bucket)?;
            let plain = self.open(bucket, self.versions[bucket], &sealed)?;
            self.decode_into(bucket, depth, &plain, &mut seen)?;
        }
        Ok(())
    }
}

fn random_leaf(leaves: usize) -> Result<usize, Error> {
    let mut bytes = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::Randomness)?;
    // Power-of-two geometry makes masking unbiased, without rejection loops.
    Ok((u64::from_le_bytes(bytes) & (leaves as u64 - 1)) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBackend;
    #[test]
    fn exhausted_nonce_fails_closed_without_reset() {
        let mut store =
            PathOram::new(Config::new(4, 8).unwrap(), MemoryBackend::default()).unwrap();
        store.nonce = u64::MAX;
        assert!(matches!(store.read(0), Err(Error::Exhausted)));
        assert!(matches!(store.read(0), Err(Error::Poisoned)));
    }
    #[test]
    fn authenticated_invalid_and_duplicate_identifiers_are_rejected() {
        for duplicate in [false, true] {
            let mut store =
                PathOram::new(Config::new(4, 8).unwrap(), MemoryBackend::default()).unwrap();
            let mut plain = store.empty_bucket();
            plain[..8].copy_from_slice(&(if duplicate { 0u64 } else { 99u64 }).to_le_bytes());
            if duplicate {
                plain[16..24].copy_from_slice(&0u64.to_le_bytes());
            }
            let sealed = store.seal(0, 0, &plain).unwrap();
            store.backend.write_bucket(0, &sealed).unwrap();
            assert!(matches!(store.read(0), Err(Error::Integrity)));
            assert!(matches!(store.read(0), Err(Error::Poisoned)));
        }
    }
    #[test]
    fn authenticated_block_outside_assigned_path_is_rejected() {
        let mut store =
            PathOram::new(Config::new(4, 8).unwrap(), MemoryBackend::default()).unwrap();
        store.position[0] = 0;
        store.position[1] = 3;
        let mut plain = store.empty_bucket();
        plain[..8].copy_from_slice(&1u64.to_le_bytes());
        let sealed = store.seal(3, 0, &plain).unwrap();
        store.backend.write_bucket(3, &sealed).unwrap();
        assert!(matches!(store.read(0), Err(Error::Integrity)));
    }
}
