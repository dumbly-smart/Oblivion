//! Adapter from the local SQLite anchor service to the SSE persistence trait.

use crate::{SseJournalAnchor, SseJournalAnchorError, SseJournalAnchorRecord};
#[cfg(unix)]
use oblivion_anchor::UnixSseJournalAnchor;
use oblivion_anchor::{Error as AnchorError, SseJournalState, TlsSseJournalAnchor};

#[cfg(unix)]
impl SseJournalAnchor for UnixSseJournalAnchor {
    fn load(&mut self) -> Result<Option<SseJournalAnchorRecord>, SseJournalAnchorError> {
        UnixSseJournalAnchor::load(self)
            .map(|state| {
                state.map(|state| {
                    SseJournalAnchorRecord::new(
                        *state.index_id(),
                        state.generation(),
                        *state.digest(),
                    )
                })
            })
            .map_err(map_anchor_error)
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        next_record: SseJournalAnchorRecord,
    ) -> Result<(), SseJournalAnchorError> {
        let state = SseJournalState::new(
            next_record.index_id(),
            next_record.generation(),
            next_record.digest(),
        )
        .map_err(|_| SseJournalAnchorError::Unavailable)?;
        UnixSseJournalAnchor::compare_and_swap(self, expected_generation, state)
            .map_err(map_anchor_error)
    }
}

impl SseJournalAnchor for TlsSseJournalAnchor {
    fn load(&mut self) -> Result<Option<SseJournalAnchorRecord>, SseJournalAnchorError> {
        TlsSseJournalAnchor::load(self)
            .map(|state| {
                state.map(|state| {
                    SseJournalAnchorRecord::new(
                        *state.index_id(),
                        state.generation(),
                        *state.digest(),
                    )
                })
            })
            .map_err(map_anchor_error)
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        next_record: SseJournalAnchorRecord,
    ) -> Result<(), SseJournalAnchorError> {
        let state = SseJournalState::new(
            next_record.index_id(),
            next_record.generation(),
            next_record.digest(),
        )
        .map_err(|_| SseJournalAnchorError::Unavailable)?;
        TlsSseJournalAnchor::compare_and_swap(self, expected_generation, state)
            .map_err(map_anchor_error)
    }
}

fn map_anchor_error(error: AnchorError) -> SseJournalAnchorError {
    match error {
        AnchorError::Conflict => SseJournalAnchorError::Conflict,
        AnchorError::CommitIndeterminate => SseJournalAnchorError::CommitUnknown,
        _ => SseJournalAnchorError::Unavailable,
    }
}
