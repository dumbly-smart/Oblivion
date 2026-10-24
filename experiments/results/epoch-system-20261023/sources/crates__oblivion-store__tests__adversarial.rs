use oblivion_store::{Backend, Config, Error, MemoryBackend, PathOram, StorageDirection};

#[test]
fn fixed_shape_and_fresh_ciphertext_for_reads_and_writes() {
    let config = Config::new(8, 16).unwrap();
    let expected_bytes = config.bucket_bytes();
    let mut store = PathOram::new(config, MemoryBackend::default()).unwrap();
    store.backend_mut().take_trace();
    let before = store.backend_mut().read_bucket(0).unwrap();
    store.backend_mut().take_trace();
    for step in 0..40 {
        if step % 2 == 0 {
            store.read(3).unwrap();
        } else {
            store.write(3, &[9; 16]).unwrap();
        }
        let trace = store.backend_mut().take_trace();
        assert_eq!(trace.len(), 8); // height 3: four reads, four writes
        for (i, event) in trace.iter().enumerate() {
            assert_eq!(event.version, 1);
            assert_eq!(event.bytes, expected_bytes);
            assert_eq!(
                event.direction,
                if i < 4 {
                    StorageDirection::Read
                } else {
                    StorageDirection::Write
                }
            );
        }
        assert_eq!(trace[0].bucket, 0);
        // Both phases traverse the same path; write order is root to leaf.
        assert_eq!(
            trace[..4].iter().map(|e| e.bucket).collect::<Vec<_>>(),
            trace[4..].iter().map(|e| e.bucket).collect::<Vec<_>>()
        );
    }
    assert_ne!(before, store.backend_mut().read_bucket(0).unwrap());
}

#[test]
fn corruption_and_replay_fail_closed() {
    for replay in [false, true] {
        let mut store =
            PathOram::new(Config::new(8, 16).unwrap(), MemoryBackend::default()).unwrap();
        let old_root = store.backend_mut().read_bucket(0).unwrap();
        store.write(0, &[8; 16]).unwrap();
        let mut damaged = if replay {
            old_root
        } else {
            store.backend_mut().read_bucket(0).unwrap()
        };
        if !replay {
            damaged[15] ^= 0x40;
        }
        store.backend_mut().write_bucket(0, &damaged).unwrap();
        assert!(matches!(store.read(0), Err(Error::Authentication)));
        assert!(matches!(store.read(0), Err(Error::Poisoned)));
    }
}

#[test]
fn truncated_or_substituted_bucket_is_rejected() {
    for replacement in [vec![0; 3], vec![0; 12]] {
        let mut store =
            PathOram::new(Config::new(2, 16).unwrap(), MemoryBackend::default()).unwrap();
        store.backend_mut().write_bucket(0, &replacement).unwrap();
        assert!(store.read(1).is_err());
        assert!(matches!(store.read(1), Err(Error::Poisoned)));
    }
    let mut store = PathOram::new(Config::new(2, 16).unwrap(), MemoryBackend::default()).unwrap();
    let other = store.backend_mut().read_bucket(1).unwrap();
    store.backend_mut().write_bucket(0, &other).unwrap();
    assert!(matches!(store.read(0), Err(Error::Authentication)));
}

#[derive(Default)]
struct FailingBackend {
    memory: MemoryBackend,
    writes_until_failure: Option<usize>,
    fail_read: bool,
}
impl Backend for FailingBackend {
    fn read_bucket(&mut self, bucket: usize) -> Result<Vec<u8>, Error> {
        if self.fail_read {
            return Err(Error::Backend("offline".into()));
        }
        self.memory.read_bucket(bucket)
    }
    fn write_bucket(&mut self, bucket: usize, bytes: &[u8]) -> Result<(), Error> {
        if let Some(remaining) = &mut self.writes_until_failure {
            if *remaining == 0 {
                return Err(Error::Backend("partial write".into()));
            }
            *remaining -= 1;
        }
        self.memory.write_bucket(bucket, bytes)
    }
}

#[test]
fn partial_write_and_read_failure_poison_controller() {
    let mut store = PathOram::new(Config::new(8, 16).unwrap(), FailingBackend::default()).unwrap();
    store.backend_mut().writes_until_failure = Some(1);
    assert!(matches!(store.write(1, &[1; 16]), Err(Error::Backend(_))));
    store.backend_mut().writes_until_failure = None;
    assert!(matches!(store.read(1), Err(Error::Poisoned)));
    let mut store = PathOram::new(Config::new(8, 16).unwrap(), FailingBackend::default()).unwrap();
    store.backend_mut().fail_read = true;
    assert!(matches!(store.read(1), Err(Error::Backend(_))));
    assert!(matches!(store.read(1), Err(Error::Poisoned)));
}

#[test]
fn invalid_configuration_and_inputs_are_bounded() {
    for (n, size) in [(0, 1), (1, 0), (usize::MAX, 8), (8, usize::MAX)] {
        assert!(Config::new(n, size).is_err());
    }
    assert!(Config::with_parameters(8, 16, 0, 128).is_err());
    let mut store = PathOram::new(Config::new(8, 16).unwrap(), MemoryBackend::default()).unwrap();
    store.backend_mut().take_trace();
    assert!(matches!(store.read(8), Err(Error::Address)));
    assert!(matches!(store.write(0, &[1]), Err(Error::BlockSize)));
    assert!(store.backend_mut().take_trace().is_empty());
    assert_eq!(store.read(0).unwrap(), vec![0; 16]);
}
