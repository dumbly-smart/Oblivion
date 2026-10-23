use oblivion_store::{Config, FileBackend, MemoryBackend, PathOram, TrustedCheckpoint};
use rand::RngCore;
use std::path::PathBuf;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "oblivion-recovery-{}-{}",
            std::process::id(),
            rand::rngs::OsRng.next_u64()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn real_file_checkpoint_restore_and_continued_writes() {
    let directory = Directory::new();
    let config = Config::new(32, 64).unwrap();
    let backend = FileBackend::create(directory.path("working"), &config).unwrap();
    let mut store = PathOram::new(config.clone(), backend).unwrap();
    for address in 0..32 {
        store.write(address, &[address as u8; 64]).unwrap();
    }
    let checkpoint = store.checkpoint(directory.path("snapshot")).unwrap();
    assert_eq!(checkpoint.generation(), 1);
    let secret = checkpoint.to_secret_bytes();
    let checkpoint = TrustedCheckpoint::from_secret_bytes(secret.as_ref()).unwrap();
    // The live controller can continue. Restoring the older point must not reuse
    // its key/nonces, even though writes happened after that checkpoint.
    store.write(0, &[99; 64]).unwrap();
    let restored_backend = FileBackend::create(directory.path("restored"), &config).unwrap();
    let mut restored =
        PathOram::restore(directory.path("snapshot"), &checkpoint, restored_backend).unwrap();
    for address in 0..32 {
        assert_eq!(restored.read(address).unwrap(), vec![address as u8; 64]);
    }
    restored.write(7, &[77; 64]).unwrap();
    restored.check_invariants().unwrap();
    let next = restored.checkpoint(directory.path("snapshot2")).unwrap();
    assert_eq!(next.generation(), 2);
    let mut again =
        PathOram::restore(directory.path("snapshot2"), &next, MemoryBackend::default()).unwrap();
    assert_eq!(again.read(7).unwrap(), vec![77; 64]);
    assert_eq!(store.read(0).unwrap(), vec![99; 64]);
}

#[test]
fn stale_anchors_corruption_truncation_and_mixed_snapshots_fail_closed() {
    let directory = Directory::new();
    let mut store = PathOram::new(Config::new(8, 16).unwrap(), MemoryBackend::default()).unwrap();
    store.write(0, &[1; 16]).unwrap();
    let first = store.checkpoint(directory.path("first")).unwrap();
    store.write(0, &[2; 16]).unwrap();
    let latest = store.checkpoint(directory.path("latest")).unwrap();
    assert!(PathOram::restore(directory.path("first"), &latest, MemoryBackend::default()).is_err());
    assert!(PathOram::restore(directory.path("latest"), &first, MemoryBackend::default()).is_err());
    let bytes = std::fs::read(directory.path("latest")).unwrap();
    for mode in 0..4 {
        let mut bad = bytes.clone();
        match mode {
            0 => bad[0] ^= 1,
            1 => {
                let last = bad.len() - 1;
                bad[last] ^= 1;
            }
            2 => {
                bad.truncate(bad.len() - 1);
            }
            _ => {
                let old = std::fs::read(directory.path("first")).unwrap();
                let middle = bad.len() / 2;
                bad[middle..].copy_from_slice(&old[middle..]);
            }
        }
        std::fs::write(directory.path("bad"), bad).unwrap();
        assert!(
            PathOram::restore(directory.path("bad"), &latest, MemoryBackend::default()).is_err()
        );
    }
    assert!(TrustedCheckpoint::from_secret_bytes(&[0; 100]).is_err());
}

#[test]
fn publication_failure_preserves_controller_and_previous_checkpoint() {
    let directory = Directory::new();
    let mut store = PathOram::new(Config::new(8, 16).unwrap(), MemoryBackend::default()).unwrap();
    let trusted = store.checkpoint(directory.path("good")).unwrap();
    assert!(store.checkpoint(directory.path("missing/failed")).is_err());
    std::fs::create_dir(directory.path("is-directory")).unwrap();
    assert!(store.checkpoint(directory.path("is-directory")).is_err());
    store.write(1, &[9; 16]).unwrap();
    let mut old =
        PathOram::restore(directory.path("good"), &trusted, MemoryBackend::default()).unwrap();
    assert_eq!(old.read(1).unwrap(), vec![0; 16]);
    let next = store.checkpoint(directory.path("good")).unwrap();
    assert_eq!(next.generation(), 2);
    assert!(PathOram::restore(directory.path("good"), &trusted, MemoryBackend::default()).is_err());
}

#[test]
fn file_backend_bounds_and_truncated_files() {
    use oblivion_store::Backend;
    let directory = Directory::new();
    let config = Config::new(8, 16).unwrap();
    let path = directory.path("buckets");
    let mut backend = FileBackend::create(&path, &config).unwrap();
    assert!(FileBackend::create(&path, &config).is_err());
    assert!(backend.read_bucket(config.bucket_count()).is_err());
    assert!(backend.write_bucket(0, &[0; 1]).is_err());
    backend
        .write_bucket(0, &vec![7; config.bucket_bytes()])
        .unwrap();
    backend.sync_all().unwrap();
    drop(backend);
    let mut backend = FileBackend::open(&path, &config).unwrap();
    assert_eq!(
        backend.read_bucket(0).unwrap(),
        vec![7; config.bucket_bytes()]
    );
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(1)
        .unwrap();
    assert!(backend.read_bucket(0).is_err());
    assert!(FileBackend::open(&path, &config).is_err());
}

#[test]
fn trusted_handle_is_redacted_and_oversized_inputs_are_rejected() {
    let directory = Directory::new();
    let mut store = PathOram::new(Config::new(4, 8).unwrap(), MemoryBackend::default()).unwrap();
    let trusted = store.checkpoint(directory.path("checkpoint")).unwrap();
    assert_eq!(format!("{trusted:?}"), "TrustedCheckpoint([REDACTED])");
    let mut bytes = trusted.to_secret_bytes();
    bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(TrustedCheckpoint::from_secret_bytes(bytes.as_ref()).is_err());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(directory.path("checkpoint"))
        .unwrap();
    file.set_len((oblivion_store::MAX_SNAPSHOT_BYTES as u64) + 1)
        .unwrap();
    assert!(
        PathOram::restore(
            directory.path("checkpoint"),
            &trusted,
            MemoryBackend::default()
        )
        .is_err()
    );
}

#[test]
fn partial_restore_failure_returns_no_controller_and_allows_fresh_retry() {
    use oblivion_store::{Backend, Error};
    struct FailAfterFirst {
        memory: MemoryBackend,
        writes: usize,
    }
    impl Backend for FailAfterFirst {
        fn read_bucket(&mut self, bucket: usize) -> Result<Vec<u8>, Error> {
            self.memory.read_bucket(bucket)
        }
        fn write_bucket(&mut self, bucket: usize, bytes: &[u8]) -> Result<(), Error> {
            if self.writes == 1 {
                return Err(Error::Backend("injected partial restore failure".into()));
            }
            self.writes += 1;
            self.memory.write_bucket(bucket, bytes)
        }
    }
    let directory = Directory::new();
    let mut store = PathOram::new(Config::new(8, 16).unwrap(), MemoryBackend::default()).unwrap();
    store.write(3, &[55; 16]).unwrap();
    let trusted = store.checkpoint(directory.path("snapshot")).unwrap();
    let failing = FailAfterFirst {
        memory: MemoryBackend::default(),
        writes: 0,
    };
    assert!(PathOram::restore(directory.path("snapshot"), &trusted, failing).is_err());
    let mut recovered = PathOram::restore(
        directory.path("snapshot"),
        &trusted,
        MemoryBackend::default(),
    )
    .unwrap();
    assert_eq!(recovered.read(3).unwrap(), vec![55; 16]);
}

#[test]
fn checkpoint_detects_bucket_corruption_and_poisoned_controller_is_not_published() {
    use oblivion_store::Backend;
    let directory = Directory::new();
    let mut store = PathOram::new(Config::new(8, 16).unwrap(), MemoryBackend::default()).unwrap();
    let mut root = store.backend_mut().read_bucket(0).unwrap();
    root[15] ^= 1;
    store.backend_mut().write_bucket(0, &root).unwrap();
    assert!(store.checkpoint(directory.path("never-published")).is_err());
    assert!(!directory.path("never-published").exists());
    assert!(store.read(0).is_err());
    assert!(
        store
            .checkpoint(directory.path("also-never-published"))
            .is_err()
    );
}
