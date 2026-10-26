use oblivion_sse::{
    JournalError, Limits, PersistentClient, Server, SseJournalAnchor, SseJournalAnchorError,
    SseJournalAnchorRecord,
};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

const KEY: [u8; 32] = [0x5a; 32];

#[derive(Clone, Default)]
struct MemoryAnchor(Arc<Mutex<Option<SseJournalAnchorRecord>>>);

impl SseJournalAnchor for MemoryAnchor {
    fn load(&mut self) -> Result<Option<SseJournalAnchorRecord>, SseJournalAnchorError> {
        Ok(*self.0.lock().unwrap())
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        next_record: SseJournalAnchorRecord,
    ) -> Result<(), SseJournalAnchorError> {
        let mut current = self.0.lock().unwrap();
        let actual = current.map(|record| record.generation());
        let expected_next = expected_generation.map_or(Some(0), |value| value.checked_add(1));
        if actual != expected_generation || expected_next != Some(next_record.generation()) {
            return Err(SseJournalAnchorError::Conflict);
        }
        *current = Some(next_record);
        Ok(())
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "oblivion-sse-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn journal_files(directory: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "journal"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn assert_same_request(left: &oblivion_sse::UpdateRequest, right: &oblivion_sse::UpdateRequest) {
    assert_eq!(left.version, right.version);
    assert_eq!(left.index_id, right.index_id);
    assert_eq!(left.address, right.address);
    assert_eq!(left.ciphertext, right.ciphertext);
}

#[test]
fn pending_update_reopens_as_identical_retry_and_acknowledged_state_searches() {
    let directory = TempDir::new();
    let anchor = MemoryAnchor::default();
    let mut client =
        PersistentClient::create(directory.path(), &KEY, Limits::default(), anchor.clone())
            .unwrap();
    let mut server = Server::new(client.index_id(), Limits::default()).unwrap();
    let original = client.prepare_add(b"durable-keyword", 42).unwrap();

    // The server commits the update but the client loses the acknowledgment.
    let first_ack = server.insert(original.clone()).unwrap();
    drop(client);

    let mut recovered = PersistentClient::open(directory.path(), &KEY, anchor.clone()).unwrap();
    let retry = recovered.retry_pending().unwrap();
    assert_same_request(&original, &retry);
    let retry_ack = server.insert(retry).unwrap();
    assert_eq!(first_ack, retry_ack);
    recovered.finish_add(retry_ack).unwrap();
    drop(recovered);

    let restored = PersistentClient::open(directory.path(), &KEY, anchor).unwrap();
    let (snapshot, search_request) = restored.prepare_search(b"durable-keyword").unwrap();
    let response = server.search(&search_request).unwrap();
    assert_eq!(
        restored.finish_search(&snapshot, response).unwrap(),
        vec![42]
    );
}

#[test]
fn journal_records_do_not_contain_plaintext_keyword_or_storage_key() {
    let directory = TempDir::new();
    let mut client = PersistentClient::create(
        directory.path(),
        &KEY,
        Limits::default(),
        MemoryAnchor::default(),
    )
    .unwrap();
    client.prepare_add(b"do-not-write-this-keyword", 7).unwrap();

    for path in journal_files(directory.path()) {
        let bytes = fs::read(path).unwrap();
        assert!(
            !bytes
                .windows(b"do-not-write-this-keyword".len())
                .any(|window| window == b"do-not-write-this-keyword")
        );
        assert!(!bytes.windows(KEY.len()).any(|window| window == KEY));
    }
}

#[test]
fn wrong_key_corruption_and_rollback_are_rejected() {
    let directory = TempDir::new();
    let anchor = MemoryAnchor::default();
    let mut client =
        PersistentClient::create(directory.path(), &KEY, Limits::default(), anchor.clone())
            .unwrap();
    let mut server = Server::new(client.index_id(), Limits::default()).unwrap();
    let request = client.prepare_add(b"key", 9).unwrap();
    let ack = server.insert(request).unwrap();
    client.finish_add(ack).unwrap();
    drop(client);

    let wrong_key = [0x33; 32];
    assert!(PersistentClient::open(directory.path(), &wrong_key, anchor.clone()).is_err());

    let files = journal_files(directory.path());
    assert!(files.len() >= 3);
    let latest = files.last().unwrap();
    let latest_bytes = fs::read(latest).unwrap();
    let old_bytes = fs::read(&files[0]).unwrap();
    fs::write(latest, old_bytes).unwrap();
    assert!(PersistentClient::open(directory.path(), &KEY, anchor.clone()).is_err());

    fs::write(latest, &latest_bytes).unwrap();
    let mut corrupted = latest_bytes;
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    fs::write(latest, corrupted).unwrap();
    assert!(PersistentClient::open(directory.path(), &KEY, anchor).is_err());
}

#[test]
fn only_one_writer_from_a_generation_can_publish() {
    let directory = TempDir::new();
    let anchor = MemoryAnchor::default();
    drop(
        PersistentClient::create(directory.path(), &KEY, Limits::default(), anchor.clone())
            .unwrap(),
    );

    let mut first = PersistentClient::open(directory.path(), &KEY, anchor.clone()).unwrap();
    let mut stale = PersistentClient::open(directory.path(), &KEY, anchor.clone()).unwrap();
    let winner = first.prepare_add(b"keyword", 1).unwrap();
    assert!(matches!(
        stale.prepare_add(b"keyword", 2),
        Err(JournalError::AnchorConflict)
    ));
    assert!(matches!(stale.retry_pending(), Err(JournalError::Poisoned)));

    let recovered = PersistentClient::open(directory.path(), &KEY, anchor).unwrap();
    assert_same_request(&winner, &recovered.retry_pending().unwrap());
}

#[test]
fn oversized_latest_record_is_rejected_before_reading_it() {
    let directory = TempDir::new();
    let anchor = MemoryAnchor::default();
    drop(
        PersistentClient::create(directory.path(), &KEY, Limits::default(), anchor.clone())
            .unwrap(),
    );
    let latest = journal_files(directory.path()).pop().unwrap();
    OpenOptions::new()
        .write(true)
        .open(latest)
        .unwrap()
        .set_len(40 * 1024 * 1024)
        .unwrap();
    assert!(PersistentClient::open(directory.path(), &KEY, anchor).is_err());
}

#[test]
fn checkpoint_compacts_the_chain_and_recovers_its_state() {
    let directory = TempDir::new();
    let anchor = MemoryAnchor::default();
    let mut client =
        PersistentClient::create(directory.path(), &KEY, Limits::default(), anchor.clone())
            .unwrap();
    let mut server = Server::new(client.index_id(), Limits::default()).unwrap();
    for id in 0..128 {
        let request = client.prepare_add(b"checkpointed", id).unwrap();
        let ack = server.insert(request).unwrap();
        client.finish_add(ack).unwrap();
    }
    assert_eq!(client.generation(), 256);
    assert_eq!(journal_files(directory.path()).len(), 1);
    drop(client);

    let restored = PersistentClient::open(directory.path(), &KEY, anchor).unwrap();
    let (snapshot, request) = restored.prepare_search(b"checkpointed").unwrap();
    assert_eq!(
        restored
            .finish_search(&snapshot, server.search(&request).unwrap())
            .unwrap(),
        (0..128).collect::<Vec<_>>()
    );
}
