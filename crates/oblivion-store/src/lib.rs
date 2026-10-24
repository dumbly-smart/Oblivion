//! Encrypted non-recursive Path ORAM with a trusted, single-owner controller.
//!
//! Protects logical addresses at the bucket interface, not controller timing or
//! host memory. Trusted versions detect storage replay only during this session.
//! Durable checkpoints require an externally protected trusted checkpoint handle.
//! Rolling back both that handle and the snapshot is not prevented by AEAD.
mod backend;
mod config;
mod file_backend;
mod oram;

pub use backend::{Backend, MemoryBackend, StorageDirection, StorageEvent};
pub use config::Config;
pub use file_backend::FileBackend;
pub use oram::{
    CheckpointAnchor, CheckpointAnchorRecord, MAX_SNAPSHOT_BYTES, PathOram, PrivateStats,
    TrustedCheckpoint,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid or excessive configuration")]
    Configuration,
    #[error("logical address out of range")]
    Address,
    #[error("incorrect fixed block size")]
    BlockSize,
    #[error("bucket authentication or freshness check failed")]
    Authentication,
    #[error("invalid bucket or controller invariant")]
    Integrity,
    #[error("stash capacity exceeded")]
    StashOverflow,
    #[error("controller is invalid after an uncertain operation; restore a trusted checkpoint")]
    Poisoned,
    #[error("secure randomness unavailable")]
    Randomness,
    #[error("nonce or version counter exhausted")]
    Exhausted,
    #[error("trusted checkpoint anchor changed or does not match this controller")]
    AnchorConflict,
    #[error("backend failure: {0}")]
    Backend(String),
}
