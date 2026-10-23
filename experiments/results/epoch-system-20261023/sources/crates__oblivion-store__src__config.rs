use crate::Error;

/// Public geometry. Allocation caps are prototype limits, not cryptographic parameters.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "Parameters")]
pub struct Config {
    pub(crate) blocks: usize,
    pub(crate) block_bytes: usize,
    pub(crate) z: usize,
    pub(crate) stash_limit: usize,
    pub(crate) leaves: usize,
    pub(crate) height: usize,
    pub(crate) bucket_bytes: usize,
}

#[derive(serde::Deserialize)]
struct Parameters {
    blocks: usize,
    block_bytes: usize,
    z: usize,
    stash_limit: usize,
}
impl TryFrom<Parameters> for Config {
    type Error = Error;
    fn try_from(p: Parameters) -> Result<Self, Error> {
        Self::with_parameters(p.blocks, p.block_bytes, p.z, p.stash_limit)
    }
}

impl Config {
    pub fn new(blocks: usize, block_bytes: usize) -> Result<Self, Error> {
        Self::with_parameters(blocks, block_bytes, 4, 128)
    }

    pub fn with_parameters(
        blocks: usize,
        block_bytes: usize,
        z: usize,
        stash_limit: usize,
    ) -> Result<Self, Error> {
        if blocks == 0
            || blocks > 1 << 20
            || block_bytes == 0
            || block_bytes > 1 << 20
            || z == 0
            || z > 16
            || stash_limit == 0
            || stash_limit > 1 << 20
        {
            return Err(Error::Configuration);
        }
        let leaves = blocks
            .checked_next_power_of_two()
            .ok_or(Error::Configuration)?;
        let bucket_bytes = block_bytes
            .checked_add(8)
            .and_then(|v| v.checked_mul(z))
            .and_then(|v| v.checked_add(28))
            .ok_or(Error::Configuration)?;
        let storage = (2 * leaves - 1)
            .checked_mul(bucket_bytes)
            .ok_or(Error::Configuration)?;
        if storage > 256 * 1024 * 1024 {
            return Err(Error::Configuration);
        }
        Ok(Self {
            blocks,
            block_bytes,
            z,
            stash_limit,
            leaves,
            height: leaves.trailing_zeros() as usize,
            bucket_bytes,
        })
    }
    pub fn blocks(&self) -> usize {
        self.blocks
    }
    pub fn block_bytes(&self) -> usize {
        self.block_bytes
    }
    pub fn bucket_bytes(&self) -> usize {
        self.bucket_bytes
    }
    pub fn bucket_count(&self) -> usize {
        2 * self.leaves - 1
    }
    pub fn leaves(&self) -> usize {
        self.leaves
    }
    pub fn path_buckets(&self) -> usize {
        self.height + 1
    }
    pub fn storage_bytes(&self) -> usize {
        self.bucket_count() * self.bucket_bytes
    }
    pub fn access_bytes(&self) -> usize {
        2 * self.path_buckets() * self.bucket_bytes
    }
    pub(crate) fn node(&self, leaf: usize, depth: usize) -> usize {
        ((1usize << depth) - 1) + (leaf >> (self.height - depth))
    }
}
