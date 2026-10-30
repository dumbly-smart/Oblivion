use crate::Error;
use std::time::Instant;

/// Untrusted bucket interface. Implementations must bound reads to the configured
/// bucket size before allocating; returned data is authenticated by the controller.
/// Writes may fail after a partial mutation; the controller then fails closed.
pub trait Backend {
    fn read_bucket(&mut self, bucket: usize) -> Result<Vec<u8>, Error>;
    fn write_bucket(&mut self, bucket: usize, bytes: &[u8]) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageDirection {
    Read,
    Write,
}

/// Observer-visible storage interface event, with no logical operation labels.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StorageEvent {
    pub version: u16,
    pub elapsed_ns: u64,
    pub direction: StorageDirection,
    pub bucket: usize,
    pub bytes: usize,
}

/// In-process untrusted storage model. Trace collection is opt-in and drainable.
/// It is not a process-isolated deployment or a measurement of network packets.
pub struct MemoryBackend {
    buckets: Vec<Vec<u8>>,
    trace: Option<Vec<StorageEvent>>,
    started: Instant,
}
impl Default for MemoryBackend {
    fn default() -> Self {
        Self {
            buckets: Vec::new(),
            trace: Some(Vec::new()),
            started: Instant::now(),
        }
    }
}
impl MemoryBackend {
    pub fn take_trace(&mut self) -> Vec<StorageEvent> {
        self.trace.as_mut().map(std::mem::take).unwrap_or_default()
    }
    pub fn set_tracing(&mut self, enabled: bool) {
        self.trace = enabled.then(Vec::new);
    }
    fn record(&mut self, direction: StorageDirection, bucket: usize, bytes: usize) {
        if let Some(trace) = &mut self.trace {
            trace.push(StorageEvent {
                version: 1,
                elapsed_ns: self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                direction,
                bucket,
                bytes,
            });
        }
    }
}
impl Backend for MemoryBackend {
    fn read_bucket(&mut self, bucket: usize) -> Result<Vec<u8>, Error> {
        let data = self
            .buckets
            .get(bucket)
            .ok_or_else(|| Error::Backend("missing bucket".into()))?
            .clone();
        self.record(StorageDirection::Read, bucket, data.len());
        Ok(data)
    }
    fn write_bucket(&mut self, bucket: usize, bytes: &[u8]) -> Result<(), Error> {
        // Sequential initialization is allowed; sparse arbitrary allocation is not.
        if bucket == self.buckets.len() {
            self.buckets.push(bytes.to_vec());
        } else {
            *self
                .buckets
                .get_mut(bucket)
                .ok_or_else(|| Error::Backend("invalid bucket".into()))? = bytes.to_vec();
        }
        self.record(StorageDirection::Write, bucket, bytes.len());
        Ok(())
    }
}
