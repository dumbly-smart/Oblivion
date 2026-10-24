//! Fixed-shape authenticated envelopes and bounded deterministic epoch queues.
//! The untrusted batcher has no payload keys. Public participation and cadence
//! remain visible. Missing-client random cover must receive equivalent dummy
//! processing in the trusted downstream pipeline; this queue cannot ensure that.
mod envelope;
pub use envelope::{ENVELOPE_BYTES, Endpoint, Envelope, PAYLOAD_BYTES};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid public protocol header or length")]
    Protocol,
    #[error("authentication failed")]
    Authentication,
    #[error("epoch replay or nonce reuse attempt")]
    Replay,
    #[error("randomness unavailable")]
    Randomness,
    #[error("invalid or excessive epoch configuration")]
    Configuration,
    #[error("wrong scheduling epoch or participant")]
    Epoch,
    #[error("participant queue already occupied")]
    Duplicate,
    #[error("epoch is not due")]
    Early,
    #[error("epoch counter exhausted")]
    Exhausted,
}

pub struct Batch {
    pub epoch: u64,
    pub envelopes: Vec<Envelope>,
    /// Public participation information. Never confuse with real/dummy labels.
    pub missing_slots: Vec<u32>,
    pub late_by_ns: u64,
}

pub struct EpochBatcher {
    period: Duration,
    deadline: Instant,
    epoch: u64,
    pending: Vec<Option<Envelope>>,
}
impl EpochBatcher {
    pub fn new(slots: usize, period: Duration, start: Instant) -> Result<Self, Error> {
        if !(1..=1024).contains(&slots)
            || period < Duration::from_millis(2)
            || period > Duration::from_secs(60)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            period,
            deadline: start.checked_add(period).ok_or(Error::Configuration)?,
            epoch: 0,
            pending: vec![None; slots],
        })
    }
    /// Exactly one pending frame per enrolled slot. Future/late epochs and
    /// duplicates are rejected, providing bounded memory and explicit backpressure.
    pub fn submit(&mut self, frame: Envelope) -> Result<(), Error> {
        if frame.kind() != 1 || frame.epoch() != self.epoch {
            return Err(Error::Epoch);
        }
        let slot = self
            .pending
            .get_mut(frame.slot() as usize)
            .ok_or(Error::Epoch)?;
        if slot.is_some() {
            return Err(Error::Duplicate);
        }
        *slot = Some(frame);
        Ok(())
    }
    /// Supply a monotonic scheduler clock. This determines queue emission;
    /// actual OS scheduling/delivery jitter is not controlled by this library.
    /// Late epochs are emitted in order, never silently skipped or resized.
    pub fn emit(&mut self, now: Instant) -> Result<Batch, Error> {
        if now < self.deadline {
            return Err(Error::Early);
        }
        let next_epoch = self.epoch.checked_add(1).ok_or(Error::Exhausted)?;
        let next_deadline = self
            .deadline
            .checked_add(self.period)
            .ok_or(Error::Exhausted)?;
        let mut envelopes = Vec::with_capacity(self.pending.len());
        let mut missing_slots = Vec::new();
        // Generate all cover before removing queued work; randomness failure
        // preserves the pending batch for an explicit retry.
        for (slot, entry) in self.pending.iter().enumerate() {
            if let Some(frame) = entry {
                envelopes.push(frame.clone());
            } else {
                envelopes.push(Envelope::cover(self.epoch, slot as u32)?);
                missing_slots.push(slot as u32);
            }
        }
        let batch = Batch {
            epoch: self.epoch,
            envelopes,
            missing_slots,
            late_by_ns: now
                .duration_since(self.deadline)
                .as_nanos()
                .min(u64::MAX as u128) as u64,
        };
        self.pending.fill(None);
        self.epoch = next_epoch;
        self.deadline = next_deadline;
        Ok(batch)
    }
}
