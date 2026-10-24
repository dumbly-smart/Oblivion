//! Actual Wasmtime class/first-call/warm-call fixture; private measurement output.
use cpu_time::{ProcessTime, ThreadTime};
use oblivion_exec::{Class, Executor, Status};
use oblivion_store::{Config, MemoryBackend, PathOram};
use rand::{SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;
use serde_json::json;
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 4,
        "usage: resource_measure small|medium|small_lowfuel control|protected SEED"
    );
    let class = match args[1].as_str() {
        "small" => Class::small(),
        "medium" => Class::medium(),
        "small_lowfuel" => {
            let mut c = Class::small();
            c.deadline_ms = 25;
            c.fuel = 100;
            c
        }
        _ => anyhow::bail!("class"),
    };
    let protected = match args[2].as_str() {
        "control" => false,
        "protected" => true,
        _ => anyhow::bail!("mode"),
    };
    let seed: u64 = args[3].parse()?;
    let process_start = Instant::now();
    let engine_cpu_start = ProcessTime::try_now()?;
    let engine_start = Instant::now();
    let mut executor = Executor::new(class.clone())?;
    let engine_ns = engine_start.elapsed().as_nanos() as u64;
    let engine_cpu_ns = engine_cpu_start.try_elapsed()?.as_nanos() as u64;
    let modules: [&[u8];6] = [include_bytes!("../../../examples/wasm-functions/echo.wat"), include_bytes!("../../../examples/wasm-functions/sum.wat"), include_bytes!("../../../examples/wasm-functions/fibonacci.wat"), include_bytes!("../../../examples/wasm-functions/hash.wat"), include_bytes!("../../../examples/wasm-functions/stateful.wat"), br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) (loop br 0) i32.const 0))"#];
    let mut compile_ns = Vec::new();
    let mut compile_cpu_ns = Vec::new();
    for (id, module) in modules.iter().enumerate() {
        let cpu_start = ProcessTime::try_now()?;
        let start = Instant::now();
        executor.register(id as u32, module)?;
        compile_ns.push(start.elapsed().as_nanos() as u64);
        compile_cpu_ns.push(cpu_start.try_elapsed()?.as_nanos() as u64);
    }
    let storage = Arc::new(Mutex::new(PathOram::new(
        Config::new(8, 64)?,
        MemoryBackend::default(),
    )?));
    storage.lock().unwrap().backend_mut().take_trace();
    let mut order: Vec<u32> = (0..6).collect();
    order.shuffle(&mut ChaCha20Rng::seed_from_u64(seed));
    let mut input = vec![0u8; class.input_bytes];
    input[0] = 10;
    let mut calls = Vec::new();
    let mut state = 0u32;
    for id in order {
        for phase in ["first", "warm"] {
            let cpu_start = ProcessTime::try_now()?;
            let thread_cpu_start = ThreadTime::try_now()?;
            let start = Instant::now();
            let result = if protected {
                executor.execute(id, &input, storage.clone())
            } else {
                executor.execute_unpadded_baseline(id, &input, storage.clone())
            };
            let wall_ns = start.elapsed().as_nanos() as u64;
            let thread_cpu_ns = thread_cpu_start.try_elapsed()?.as_nanos() as u64;
            let process_cpu_ns = cpu_start.try_elapsed()?.as_nanos() as u64;
            let events = storage.lock().unwrap().backend_mut().take_trace();
            let expected_status = if id == 5 || args[1] == "small_lowfuel" && id != 0 {
                Status::OutOfFuel
            } else {
                Status::Success
            };
            anyhow::ensure!(
                result.status == expected_status,
                "status {id}: {:?}",
                result.status
            );
            let mut expected = vec![0; class.output_bytes];
            if expected_status == Status::Success {
                match id {
                    0 => expected.copy_from_slice(&input),
                    1 => expected[..4].copy_from_slice(&10u32.to_le_bytes()),
                    2 => expected[..4].copy_from_slice(&55u32.to_le_bytes()),
                    3 => {
                        let h = input.iter().fold(2166136261u32, |h, &b| {
                            (h ^ u32::from(b)).wrapping_mul(16777619)
                        });
                        expected[..4].copy_from_slice(&h.to_le_bytes());
                    }
                    4 => {
                        state += 1;
                        expected[..4].copy_from_slice(&state.to_le_bytes());
                    }
                    _ => {}
                }
            }
            if !protected {
                expected.truncate(if expected_status != Status::Success {
                    0
                } else if id == 0 {
                    class.input_bytes
                } else {
                    4
                });
            }
            anyhow::ensure!(result.body == expected, "output oracle {id}");
            // Independent state oracle lies outside measured execution/trace boundary.
            for address in 0..8 {
                let block = storage.lock().unwrap().read(address)?;
                let mut oracle = vec![0; 64];
                if address == 0 {
                    oracle[..4].copy_from_slice(&state.to_le_bytes());
                }
                anyhow::ensure!(block == oracle, "state oracle");
            }
            storage.lock().unwrap().backend_mut().take_trace();
            if protected {
                anyhow::ensure!(events.len() == 128, "protected trace shape");
            }
            calls.push(json!({"function":id,"phase":phase,"wall_ns":wall_ns,"process_cpu_ns":process_cpu_ns,"thread_cpu_ns":thread_cpu_ns,"work_ns":result.work_ns,"total_ns":result.total_ns,"deadline_missed":result.deadline_missed,"status":format!("{:?}",result.status),"body_bytes":result.body.len(),"storage_events":events.len(),"oracle_passed":true}));
        }
    }
    println!(
        "{}",
        json!({"schema":2,"class":args[1],"mode":args[2],"seed":seed,"fuel":class.fuel,"deadline_ms":class.deadline_ms,"input_bytes":class.input_bytes,"output_bytes":class.output_bytes,"memory_limit_bytes":class.memory_bytes,"engine_ns":engine_ns,"engine_cpu_ns":engine_cpu_ns,"compile_cpu_ns":compile_cpu_ns,"compile_ns":compile_ns,"fixture_wall_ns":process_start.elapsed().as_nanos() as u64,"calls":calls})
    );
    Ok(())
}
