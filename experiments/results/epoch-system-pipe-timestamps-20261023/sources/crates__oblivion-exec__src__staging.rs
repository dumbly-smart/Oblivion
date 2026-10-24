use crate::BlockStorage;
use zeroize::Zeroizing;

/// Trusted deployment configuration, never taken from an untrusted invocation.
/// Guest address zero maps to `first`; accesses cannot cross the namespace.
#[derive(Clone, Copy, Debug)]
pub struct Namespace {
    pub first: usize,
    pub blocks: usize,
}

pub(crate) struct Staged {
    pub data: Vec<Zeroizing<Vec<u8>>>,
    pub namespace: Namespace,
    pub width: usize,
}
impl BlockStorage for Staged {
    fn block_bytes(&self) -> usize {
        self.width
    }
    fn blocks(&self) -> usize {
        self.namespace.blocks
    }
    fn read(&mut self, address: usize) -> wasmtime::Result<Vec<u8>> {
        if address >= self.namespace.blocks {
            wasmtime::bail!("namespace address");
        }
        Ok(self.data[self.namespace.first + address].to_vec())
    }
    fn write(&mut self, address: usize, data: &[u8]) -> wasmtime::Result<()> {
        if address >= self.namespace.blocks || data.len() != self.width {
            wasmtime::bail!("namespace address or width");
        }
        self.data[self.namespace.first + address].copy_from_slice(data);
        Ok(())
    }
}
