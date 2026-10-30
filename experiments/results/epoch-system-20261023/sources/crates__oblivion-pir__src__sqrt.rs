//! Matrix-packed two-server XOR PIR, adapted from CGKS's generic transformation.
//! Queries select a row privately; the column stays exclusively in client state.
//! Each server returns one masked full row and scans every padded byte.
use crate::{Database, Error, MAX_DATABASE_BYTES, MAX_RECORD_BYTES, QueryPair, dimensions};

/// Public, square record layout. This balances record dimensions, not wire bytes.
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    count: usize,
    record_bytes: usize,
    side: usize,
    row_bytes: usize,
    padded_bytes: usize,
}

/// Private client recovery state. No serialization or Debug implementation.
pub struct Recovery {
    geometry: Geometry,
    column: usize,
}

impl Geometry {
    pub fn new(count: usize, record_bytes: usize) -> Result<Self, Error> {
        dimensions(count, record_bytes)?;
        let root = count.isqrt();
        let side = root + usize::from(root * root != count);
        let row_bytes = side.checked_mul(record_bytes).ok_or(Error::Database)?;
        let padded_bytes = side.checked_mul(row_bytes).ok_or(Error::Database)?;
        if row_bytes > MAX_RECORD_BYTES || padded_bytes > MAX_DATABASE_BYTES {
            return Err(Error::Database);
        }
        Ok(Self {
            count,
            record_bytes,
            side,
            row_bytes,
            padded_bytes,
        })
    }

    pub fn rows(&self) -> usize {
        self.side
    }
    pub fn columns(&self) -> usize {
        self.side
    }
    pub fn row_bytes(&self) -> usize {
        self.row_bytes
    }
    pub fn padded_bytes(&self) -> usize {
        self.padded_bytes
    }

    /// Construct one independently owned server state, with zero-filled padding.
    pub fn server(&self, records: Vec<Vec<u8>>) -> Result<Database, Error> {
        if records.len() != self.count || records.iter().any(|r| r.len() != self.record_bytes) {
            return Err(Error::Database);
        }
        let mut rows = vec![vec![0; self.row_bytes]; self.side];
        for (index, record) in records.into_iter().enumerate() {
            let column = index % self.side;
            let start = column * self.record_bytes;
            rows[index / self.side][start..start + self.record_bytes].copy_from_slice(&record);
        }
        Database::new(rows)
    }

    /// Return only uniform subset shares for transport, retaining column locally.
    pub fn query(&self, index: usize) -> Result<(QueryPair, Recovery), Error> {
        if index >= self.count {
            return Err(Error::Index);
        }
        let shares = QueryPair::generate(self.side, index / self.side)?;
        Ok((
            shares,
            Recovery {
                geometry: *self,
                column: index % self.side,
            },
        ))
    }
}

impl Recovery {
    /// Recover the whole selected row internally, then return the requested record.
    /// Responses are unauthenticated; privacy assumes two non-colluding servers.
    pub fn recover(&self, first: &[u8], second: &[u8]) -> Result<Vec<u8>, Error> {
        if first.len() != self.geometry.row_bytes || second.len() != self.geometry.row_bytes {
            return Err(Error::Shape);
        }
        let row = crate::recover(first, second)?;
        let start = self.column * self.geometry.record_bytes;
        Ok(row[start..start + self.geometry.record_bytes].to_vec())
    }
}
