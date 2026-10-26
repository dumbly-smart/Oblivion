use oblivion_exec::{Class, Executor, Status};
use oblivion_store::{Config, MemoryBackend, PathOram, StorageDirection};
use std::sync::{Arc, Mutex};

fn state() -> Arc<Mutex<PathOram<MemoryBackend>>> {
    let mut oram = PathOram::new(Config::new(8, 64).unwrap(), MemoryBackend::default()).unwrap();
    oram.backend_mut().take_trace();
    Arc::new(Mutex::new(oram))
}

fn storage_test_class() -> Class {
    let mut class = Class::small();
    // These tests verify storage structure and namespaces, not deadline
    // conformance. Keep scheduler contention from turning them into timeout
    // tests; deadline behavior is covered separately in execution.rs.
    class.deadline_ms = 1000;
    class
}

#[test]
fn protected_functions_and_failures_have_identical_storage_structure() {
    let storage = state();
    let mut executor = Executor::new(storage_test_class()).unwrap();
    executor
        .register(
            0,
            include_bytes!("../../../examples/wasm-functions/echo.wat"),
        )
        .unwrap();
    executor
        .register(
            4,
            include_bytes!("../../../examples/wasm-functions/stateful.wat"),
        )
        .unwrap();
    executor.register(5,br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) unreachable))"#).unwrap();
    executor.register(6,br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) (loop br 0) i32.const 0))"#).unwrap();
    for (id, input, status) in [
        (0, vec![0; 64], Status::Success),
        (4, vec![0; 64], Status::Success),
        (5, vec![0; 64], Status::Trap),
        (6, vec![0; 64], Status::OutOfFuel),
        (99, vec![0; 64], Status::InvalidInput),
        (0, vec![], Status::InvalidInput),
    ] {
        let result = executor.execute(id, &input, storage.clone());
        assert_eq!(result.status, status);
        let events = storage.lock().unwrap().backend_mut().take_trace();
        // Eight prefetch reads plus eight commit writes, each an actual full
        // ORAM operation of four bucket reads and four encrypted bucket writes.
        assert_eq!(events.len(), 128, "function/status {id}/{status:?}");
        for operation in events.as_chunks::<8>().0 {
            assert!(
                operation[..4]
                    .iter()
                    .all(|e| e.direction == StorageDirection::Read)
            );
            assert!(
                operation[4..]
                    .iter()
                    .all(|e| e.direction == StorageDirection::Write)
            );
            assert!(operation.iter().all(|e| e.bytes == 316));
        }
    }
}
#[test]
fn guest_write_followed_by_trap_is_not_committed() {
    let storage = state();
    let mut executor = Executor::new(Class::small()).unwrap();
    executor.register(0,br#"(module (import "oblivion" "write" (func $write (param i32 i32))) (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) i32.const 32768 i32.const 91 i32.store i32.const 0 i32.const 32768 call $write unreachable))"#).unwrap();
    assert_eq!(
        executor.execute(0, &[0; 64], storage.clone()).status,
        Status::Trap
    );
    assert_eq!(storage.lock().unwrap().read(0).unwrap(), vec![0; 64]);
}

#[test]
fn namespaces_prevent_guest_cross_client_and_dummy_accesses() {
    use oblivion_exec::Namespace;
    use std::time::Instant;
    let storage = state();
    let mut executor = Executor::new(storage_test_class()).unwrap();
    executor
        .register(
            4,
            include_bytes!("../../../examples/wasm-functions/stateful.wat"),
        )
        .unwrap();
    for first in [0, 1, 1, 7] {
        assert_eq!(
            executor
                .execute_scheduled(
                    4,
                    &[0; 64],
                    storage.clone(),
                    Namespace { first, blocks: 1 },
                    Instant::now()
                )
                .status,
            Status::Success
        );
    }
    let mut argument = [0; 64];
    argument[4] = 1;
    assert_eq!(
        executor
            .execute_scheduled(
                4,
                &argument,
                storage.clone(),
                Namespace {
                    first: 0,
                    blocks: 1
                },
                Instant::now()
            )
            .status,
        Status::Storage
    );
    assert_eq!(storage.lock().unwrap().read(0).unwrap()[0], 1);
    assert_eq!(storage.lock().unwrap().read(1).unwrap()[0], 2);
    assert_eq!(storage.lock().unwrap().read(7).unwrap()[0], 1);
    assert_eq!(
        executor
            .execute_scheduled(
                4,
                &[0; 64],
                storage,
                Namespace {
                    first: usize::MAX,
                    blocks: 1
                },
                Instant::now()
            )
            .status,
        Status::Storage
    );
}

#[test]
fn staging_budget_accounts_for_rollback_and_mutable_copies() {
    let mut oram = PathOram::new(Config::new(8, 8192).unwrap(), MemoryBackend::default()).unwrap();
    oram.backend_mut().take_trace();
    let storage = Arc::new(Mutex::new(oram));
    let mut executor = Executor::new(Class::small()).unwrap();
    executor
        .register(
            0,
            include_bytes!("../../../examples/wasm-functions/echo.wat"),
        )
        .unwrap();
    assert_eq!(
        executor.execute(0, &[0; 64], storage.clone()).status,
        Status::Storage
    );
    assert!(
        storage
            .lock()
            .unwrap()
            .backend_mut()
            .take_trace()
            .is_empty()
    );
}

#[test]
fn trusted_driver_can_prepare_before_owning_the_response_publication_deadline() {
    use oblivion_exec::Namespace;
    use std::time::{Duration, Instant};
    let storage = state();
    let mut executor = Executor::new(Class::small()).unwrap();
    executor
        .register(
            0,
            include_bytes!("../../../examples/wasm-functions/echo.wat"),
        )
        .unwrap();
    let start = Instant::now();
    let result = executor.prepare_scheduled(
        0,
        &[7; 64],
        storage,
        Namespace {
            first: 0,
            blocks: 8,
        },
        start,
    );
    assert_eq!(result.status, Status::Success);
    assert_eq!(result.body, vec![7; 64]);
    assert!(start.elapsed() >= Duration::from_millis(50));
    // Caller must reserve and enforce the remaining class interval before
    // publishing this PRIVATE object. This is not an externally padded API.
    assert!(result.total_ns < 1_000_000_000);
}
