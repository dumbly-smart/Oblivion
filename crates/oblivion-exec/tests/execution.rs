use oblivion_exec::{Class, Executor, Status};
use oblivion_store::{Config, MemoryBackend, PathOram};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn storage() -> Arc<Mutex<PathOram<MemoryBackend>>> {
    Arc::new(Mutex::new(
        PathOram::new(Config::new(8, 64).unwrap(), MemoryBackend::default()).unwrap(),
    ))
}

#[test]
fn executes_five_real_modules_with_fixed_responses_and_padding() {
    let mut engine = Executor::new(Class::small()).unwrap();
    let state = storage();
    for (id, bytes) in [
        include_bytes!("../../../examples/wasm-functions/echo.wat").as_slice(),
        include_bytes!("../../../examples/wasm-functions/sum.wat").as_slice(),
        include_bytes!("../../../examples/wasm-functions/fibonacci.wat").as_slice(),
        include_bytes!("../../../examples/wasm-functions/hash.wat").as_slice(),
        include_bytes!("../../../examples/wasm-functions/stateful.wat").as_slice(),
    ]
    .iter()
    .enumerate()
    {
        engine.register(id as u32, bytes).unwrap();
    }
    let mut input = [0u8; 64];
    input[0] = 10;
    for id in 0..5 {
        let start = Instant::now();
        let result = engine.execute(id, &input, state.clone());
        assert_eq!(result.status, Status::Success, "module {id}");
        assert_eq!(result.body.len(), 64);
        assert!(start.elapsed() >= Duration::from_millis(10));
        if id == 0 {
            assert_eq!(result.body, input);
        }
        if id == 1 {
            assert_eq!(result.body[0], 10);
        }
        if id == 2 {
            assert_eq!(u32::from_le_bytes(result.body[..4].try_into().unwrap()), 55);
        }
        if id == 3 {
            assert!(result.body.iter().any(|&b| b != 0));
        }
    }
    assert_eq!(state.lock().unwrap().read(0).unwrap()[0], 1);
    engine.execute(4, &input, state.clone());
    assert_eq!(state.lock().unwrap().read(0).unwrap()[0], 2);
}

#[test]
fn invalid_input_traps_fuel_and_memory_failures_have_uniform_shape() {
    let mut engine = Executor::new(Class::small()).unwrap();
    let state = storage();
    engine.register(1,br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) unreachable))"#).unwrap();
    engine.register(2,br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) (loop br 0) i32.const 0))"#).unwrap();
    engine.register(3,br#"(module (memory (export "memory") 2) (func (export "invoke") (param i32 i32 i32 i32) (result i32) i32.const 0))"#).unwrap();
    engine.register(4,br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) i32.const 1 memory.grow drop i32.const 0))"#).unwrap();
    for (id, status) in [
        (1, Status::Trap),
        (2, Status::OutOfFuel),
        (3, Status::Resource),
        (4, Status::Resource),
        (99, Status::InvalidInput),
    ] {
        let result = engine.execute(id, &[0; 64], state.clone());
        assert_eq!(result.status, status);
        assert_eq!(result.body, vec![0; 64]);
    }
    assert_eq!(
        engine.execute(1, &[], state.clone()).status,
        Status::InvalidInput
    );
    assert!(engine.register(0, b"not wasm").is_err());
    assert!(engine.register(0, &vec![0; 1024 * 1024 + 1]).is_err());
}

#[test]
fn deadline_interrupts_guest_with_large_fuel_budget() {
    let mut class = Class::small();
    class.fuel = 1_000_000_000_000;
    let mut engine = Executor::new(class).unwrap();
    engine.register(0,br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) (loop br 0) i32.const 0))"#).unwrap();
    let started = Instant::now();
    let result = engine.execute(0, &[0; 64], storage());
    assert_eq!(result.status, Status::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(result.body, vec![0; 64]);
}

#[test]
fn deliberately_unpadded_baseline_returns_actual_guest_length() {
    let mut executor = Executor::new(Class::small()).unwrap();
    executor
        .register(
            0,
            include_bytes!("../../../examples/wasm-functions/sum.wat"),
        )
        .unwrap();
    let result = executor.execute_unpadded_baseline(0, &[1; 64], storage());
    assert_eq!(result.status, Status::Success);
    assert_eq!(result.body, 64u32.to_le_bytes());
    assert_eq!(executor.execute(0, &[1; 64], storage()).body.len(), 64);
}

#[test]
fn medium_class_runs_real_modules_and_pads_errors_to_its_own_public_size() {
    let class = Class::medium();
    let deadline = class.deadline_ms;
    let output_bytes = class.output_bytes;
    let input = vec![7; class.input_bytes];
    let mut engine = Executor::new(class).unwrap();
    engine
        .register(
            0,
            include_bytes!("../../../examples/wasm-functions/echo.wat"),
        )
        .unwrap();
    let state = storage();
    let result = engine.execute(0, &input, state.clone());
    assert_eq!(result.status, Status::Success);
    assert_eq!(result.body, input);
    assert_eq!(result.body.len(), output_bytes);
    assert!(result.total_ns >= deadline * 1_000_000);
    let invalid = engine.execute(99, &input, state);
    assert_eq!(invalid.status, Status::InvalidInput);
    assert_eq!(invalid.body, vec![0; output_bytes]);
    assert!(invalid.total_ns >= deadline * 1_000_000);
}
