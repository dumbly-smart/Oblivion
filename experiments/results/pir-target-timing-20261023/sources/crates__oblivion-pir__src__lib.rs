//! Two-server XOR PIR. Privacy requires non-collusion; answers are not authenticated.
//! Each server scans every record. Database size, timing and dimensions are public.
pub mod secure;
pub mod sqrt;
pub mod wire;
use rand::{RngCore, rngs::OsRng};

pub const MAX_DATABASE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_RECORDS: usize = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid or excessive database dimensions")]
    Database,
    #[error("target index out of range")]
    Index,
    #[error("malformed query or response")]
    Shape,
    #[error("secure randomness unavailable")]
    Randomness,
    #[error("invalid wire protocol version or header")]
    Protocol,
    #[error("authentication failed")]
    Authentication,
    #[error("replayed or unexpected sequence")]
    Sequence,
    #[error("transport failed: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Database {
    records: Vec<Vec<u8>>,
    record_bytes: usize,
}
impl Database {
    pub fn new(records: Vec<Vec<u8>>) -> Result<Self, Error> {
        let record_bytes = records.first().map_or(0, Vec::len);
        dimensions(records.len(), record_bytes)?;
        if records.iter().any(|r| r.len() != record_bytes) {
            return Err(Error::Database);
        }
        Ok(Self {
            records,
            record_bytes,
        })
    }
    pub fn count(&self) -> usize {
        self.records.len()
    }
    pub fn record_bytes(&self) -> usize {
        self.record_bytes
    }
    pub fn answer(&self, query: &[u8]) -> Result<Vec<u8>, Error> {
        if query.len() != self.count().div_ceil(8) {
            return Err(Error::Shape);
        }
        let mut result = vec![0; self.record_bytes];
        for (i, record) in self.records.iter().enumerate() {
            let mask = 0u8.wrapping_sub((query[i / 8] >> (i % 8)) & 1);
            for (out, byte) in result.iter_mut().zip(record) {
                *out ^= byte & mask;
            }
        }
        Ok(result)
    }
}

/// Secret-bearing query pair: no Debug/serialization implementation. Do not log
/// both shares at any observer; their XOR directly identifies the target.
pub struct QueryPair {
    pub first: Vec<u8>,
    pub second: Vec<u8>,
}
impl QueryPair {
    pub fn generate(count: usize, index: usize) -> Result<Self, Error> {
        if count == 0 || count > MAX_RECORDS {
            return Err(Error::Database);
        }
        if index >= count {
            return Err(Error::Index);
        }
        let mut first = vec![0; count.div_ceil(8)];
        OsRng
            .try_fill_bytes(&mut first)
            .map_err(|_| Error::Randomness)?;
        let mut second = first.clone();
        second[index / 8] ^= 1 << (index % 8);
        Ok(Self { first, second })
    }
}

pub fn recover(first: &[u8], second: &[u8]) -> Result<Vec<u8>, Error> {
    if first.is_empty() || first.len() != second.len() || first.len() > MAX_RECORD_BYTES {
        return Err(Error::Shape);
    }
    Ok(first.iter().zip(second).map(|(a, b)| a ^ b).collect())
}

pub(crate) fn dimensions(count: usize, record_bytes: usize) -> Result<(), Error> {
    if count == 0
        || count > MAX_RECORDS
        || record_bytes == 0
        || record_bytes > MAX_RECORD_BYTES
        || count
            .checked_mul(record_bytes)
            .is_none_or(|v| v > MAX_DATABASE_BYTES)
    {
        return Err(Error::Database);
    }
    Ok(())
}
