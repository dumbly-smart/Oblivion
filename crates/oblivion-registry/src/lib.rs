//! Signed, fixed-size function registry records with rollback-aware activation.
//!
//! This crate authenticates registry bytes. It does not distribute signing
//! keys, provide a remote monotonic counter, or hide which record the trusted
//! executor ultimately selects.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

const MAGIC: &[u8; 8] = b"OBLREG01";
const WIRE_VERSION: u16 = 1;
const MANIFEST_HEADER: usize = 124;
const RECORD_FIELDS: usize = 77;
pub const RECORD_BYTES: usize = 160;
pub const MAX_RECORDS: usize = 65_536;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed or unsupported registry encoding")]
    Malformed,
    #[error("registry signature verification failed")]
    Signature,
    #[error("registry records have mixed or invalid versions")]
    VersionMismatch,
    #[error("registry function IDs must be unique and strictly increasing")]
    DuplicateFunctionId,
    #[error("registry has no records or exceeds the configured record bound")]
    RecordCount,
    #[error("registry version is not newer than the trusted version")]
    Rollback,
    #[error("trusted registry version changed during activation")]
    AnchorConflict,
    #[error("trusted registry version anchor failure: {0}")]
    Anchor(String),
}

/// A function record signed by the registry authority.
///
/// Wire encoding is 160 bytes: id, version, module digest, encrypted-location
/// digest, resource class, 19 reserved zero bytes, and a 64-byte Ed25519
/// signature. All integers use big-endian encoding.
pub struct Record {
    id: u32,
    version: u64,
    module_digest: [u8; 32],
    location_digest: [u8; 32],
    resource_class: u8,
    signature: [u8; 64],
}

impl Record {
    pub fn sign(
        id: u32,
        version: u64,
        module_digest: [u8; 32],
        location_digest: [u8; 32],
        resource_class: u8,
        key: &SigningKey,
    ) -> Result<Self, Error> {
        if version == 0 || resource_class > 7 {
            return Err(Error::Malformed);
        }
        let message = record_message(
            id,
            version,
            &module_digest,
            &location_digest,
            resource_class,
        );
        let signature = key.sign(&message).to_bytes();
        Ok(Self {
            id,
            version,
            module_digest,
            location_digest,
            resource_class,
            signature,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RECORD_BYTES || bytes[77..96].iter().any(|byte| *byte != 0) {
            return Err(Error::Malformed);
        }
        let version = u64::from_be_bytes(bytes[4..12].try_into().map_err(|_| Error::Malformed)?);
        let resource_class = bytes[76];
        if version == 0 || resource_class > 7 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            id: u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| Error::Malformed)?),
            version,
            module_digest: bytes[12..44].try_into().map_err(|_| Error::Malformed)?,
            location_digest: bytes[44..76].try_into().map_err(|_| Error::Malformed)?,
            resource_class,
            signature: bytes[96..160].try_into().map_err(|_| Error::Malformed)?,
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), Error> {
        let message = record_message(
            self.id,
            self.version,
            &self.module_digest,
            &self.location_digest,
            self.resource_class,
        );
        key.verify_strict(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::Signature)
    }

    pub fn to_bytes(&self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        bytes[0..4].copy_from_slice(&self.id.to_be_bytes());
        bytes[4..12].copy_from_slice(&self.version.to_be_bytes());
        bytes[12..44].copy_from_slice(&self.module_digest);
        bytes[44..76].copy_from_slice(&self.location_digest);
        bytes[76] = self.resource_class;
        bytes[96..160].copy_from_slice(&self.signature);
        bytes
    }

    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn module_digest(&self) -> &[u8; 32] {
        &self.module_digest
    }
    pub fn location_digest(&self) -> &[u8; 32] {
        &self.location_digest
    }
    pub fn resource_class(&self) -> u8 {
        self.resource_class
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("module_digest", &self.module_digest)
            .field("location_digest", &self.location_digest)
            .field("resource_class", &self.resource_class)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Encodes a complete signed catalog. Records must be validly signed by `key`,
/// have the same version, and be strictly ordered by function ID.
pub struct SignedRegistry;

impl SignedRegistry {
    pub fn sign(version: u64, records: Vec<Record>, key: &SigningKey) -> Result<Vec<u8>, Error> {
        validate_records(version, &records, &key.verifying_key())?;
        let count = u32::try_from(records.len()).map_err(|_| Error::RecordCount)?;
        let record_bytes = records
            .iter()
            .flat_map(Record::to_bytes)
            .collect::<Vec<_>>();
        let digest: [u8; 32] = Sha256::digest(&record_bytes).into();
        let message = manifest_message(version, count, &digest);
        let signature = key.sign(&message).to_bytes();

        let mut encoded = Vec::with_capacity(MANIFEST_HEADER + record_bytes.len());
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0; 2]);
        encoded.extend_from_slice(&version.to_be_bytes());
        encoded.extend_from_slice(&count.to_be_bytes());
        encoded.extend_from_slice(&[0; 4]);
        encoded.extend_from_slice(&digest);
        encoded.extend_from_slice(&signature);
        encoded.extend_from_slice(&record_bytes);
        Ok(encoded)
    }
}

/// A registry whose manifest and every record have been verified.
pub struct VerifiedRegistry {
    version: u64,
    records: Vec<Record>,
}

impl VerifiedRegistry {
    pub fn verify(encoded: &[u8], key: &VerifyingKey) -> Result<Self, Error> {
        if encoded.len() < MANIFEST_HEADER
            || &encoded[..8] != MAGIC
            || encoded[8..10] != WIRE_VERSION.to_be_bytes()
            || encoded[10..12] != [0; 2]
            || encoded[24..28] != [0; 4]
        {
            return Err(Error::Malformed);
        }
        let version = u64::from_be_bytes(encoded[12..20].try_into().map_err(|_| Error::Malformed)?);
        let count = usize::try_from(u32::from_be_bytes(
            encoded[20..24].try_into().map_err(|_| Error::Malformed)?,
        ))
        .map_err(|_| Error::RecordCount)?;
        if version == 0 || count == 0 || count > MAX_RECORDS {
            return Err(Error::RecordCount);
        }
        let record_bytes = count
            .checked_mul(RECORD_BYTES)
            .and_then(|size| MANIFEST_HEADER.checked_add(size))
            .ok_or(Error::RecordCount)?;
        if encoded.len() != record_bytes {
            return Err(Error::Malformed);
        }

        let count_u32 = u32::try_from(count).map_err(|_| Error::RecordCount)?;
        let digest: [u8; 32] = encoded[28..60].try_into().map_err(|_| Error::Malformed)?;
        let message = manifest_message(version, count_u32, &digest);
        let signature =
            Signature::from_bytes(encoded[60..124].try_into().map_err(|_| Error::Malformed)?);
        key.verify_strict(&message, &signature)
            .map_err(|_| Error::Signature)?;

        let body = &encoded[MANIFEST_HEADER..];
        if Sha256::digest(body).as_slice() != digest {
            return Err(Error::Signature);
        }
        let mut records = Vec::with_capacity(count);
        let (record_chunks, remainder) = body.as_chunks::<RECORD_BYTES>();
        if !remainder.is_empty() || record_chunks.len() != count {
            return Err(Error::Malformed);
        }
        for bytes in record_chunks {
            records.push(Record::from_bytes(bytes)?);
        }
        validate_records(version, &records, key)?;
        Ok(Self { version, records })
    }

    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn get(&self, id: u32) -> Option<&Record> {
        self.records
            .binary_search_by_key(&id, Record::id)
            .ok()
            .map(|index| &self.records[index])
    }

    /// Advance an independently protected monotonic version anchor. The
    /// signature validates contents; only this anchor prevents replay of an
    /// older, still-valid catalog.
    pub fn activate<A: RegistryVersionAnchor>(&self, anchor: &mut A) -> Result<(), Error> {
        let current = anchor.current_version()?;
        if current.is_some_and(|version| self.version <= version) {
            return Err(Error::Rollback);
        }
        anchor.compare_and_swap(current, self.version)
    }
}

/// Adapter for trusted, durable, rollback-resistant version storage.
pub trait RegistryVersionAnchor {
    fn current_version(&mut self) -> Result<Option<u64>, Error>;
    fn compare_and_swap(&mut self, expected: Option<u64>, next: u64) -> Result<(), Error>;
}

fn validate_records(version: u64, records: &[Record], key: &VerifyingKey) -> Result<(), Error> {
    if version == 0 || records.is_empty() || records.len() > MAX_RECORDS {
        return Err(Error::RecordCount);
    }
    let mut previous = None;
    for record in records {
        if record.version != version {
            return Err(Error::VersionMismatch);
        }
        if previous.is_some_and(|id| record.id <= id) {
            return Err(Error::DuplicateFunctionId);
        }
        record.verify(key)?;
        previous = Some(record.id);
    }
    Ok(())
}

fn record_message(
    id: u32,
    version: u64,
    module_digest: &[u8; 32],
    location_digest: &[u8; 32],
    resource_class: u8,
) -> [u8; RECORD_FIELDS + 27] {
    let mut message = [0; RECORD_FIELDS + 27];
    message[..27].copy_from_slice(b"oblivion/registry/record/v1");
    message[27..31].copy_from_slice(&id.to_be_bytes());
    message[31..39].copy_from_slice(&version.to_be_bytes());
    message[39..71].copy_from_slice(module_digest);
    message[71..103].copy_from_slice(location_digest);
    message[103] = resource_class;
    message
}

fn manifest_message(version: u64, count: u32, digest: &[u8; 32]) -> [u8; 73] {
    let mut message = [0; 73];
    message[..29].copy_from_slice(b"oblivion/registry/manifest/v1");
    message[29..37].copy_from_slice(&version.to_be_bytes());
    message[37..41].copy_from_slice(&count.to_be_bytes());
    message[41..73].copy_from_slice(digest);
    message
}
