//! Independent timing/size fixture; labels and statuses stay in private records.
use oblivion_batcher::{Endpoint, PAYLOAD_BYTES};
use oblivion_exec::{Class, Executor, Status};
use oblivion_store::{Config, MemoryBackend, PathOram};
use rand::{SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;
use serde_json::json;
use std::{
    fs,
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 4,
        "usage: timing_measure NEW_OUTPUT SEED control|protected"
    );
    let output = Path::new(&args[1]);
    let seed = args[2].parse::<u64>()?;
    let control = match args[3].as_str() {
        "control" => true,
        "protected" => false,
        _ => anyhow::bail!("mode"),
    };
    fs::create_dir(output)?;
    let startup = Instant::now();
    let mut executor = Executor::new(Class::small())?;
    let modules: [&[u8];8]=[
        include_bytes!("../../../examples/wasm-functions/echo.wat"),
        include_bytes!("../../../examples/wasm-functions/sum.wat"),
        include_bytes!("../../../examples/wasm-functions/fibonacci.wat"),
        include_bytes!("../../../examples/wasm-functions/hash.wat"),
        include_bytes!("../../../examples/wasm-functions/stateful.wat"),
        br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) unreachable))"#,
        br#"(module (memory (export "memory") 1) (func (export "invoke") (param i32 i32 i32 i32) (result i32) (loop br 0) i32.const 0))"#,
        br#"(module (memory (export "memory") 2) (func (export "invoke") (param i32 i32 i32 i32) (result i32) i32.const 0))"#,
    ];
    for (id, module) in modules.iter().enumerate() {
        executor.register(id as u32, module)?;
    }
    let storage = Arc::new(Mutex::new(PathOram::new(
        Config::new(8, 64)?,
        MemoryBackend::default(),
    )?));
    storage.lock().unwrap().backend_mut().take_trace();
    let (mut client, mut server) = Endpoint::provision(0)?;
    let startup_ns = startup.elapsed().as_nanos() as u64;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut order: Vec<u32> = (0..8).collect();
    order.shuffle(&mut rng);
    let mut observer = fs::File::create(output.join("observer.jsonl"))?;
    let mut truth = fs::File::create(output.join("ground-truth.jsonl"))?;
    let mut input = [0u8; 64];
    input[0] = 10;
    for (epoch, id) in order.into_iter().enumerate() {
        let mut payload = [0; PAYLOAD_BYTES];
        payload[..4].copy_from_slice(&id.to_be_bytes());
        payload[4..68].copy_from_slice(&input);
        let request = client.send(epoch as u64, &payload)?;
        let started = Instant::now();
        let decoded = server.receive(&request)?;
        let selected = u32::from_be_bytes(decoded[..4].try_into()?);
        let execution = if control {
            executor.execute_unpadded_baseline(selected, &decoded[4..68], storage.clone())
        } else {
            executor.execute(selected, &decoded[4..68], storage.clone())
        };
        let mut reply = [0u8; PAYLOAD_BYTES];
        reply[0] = u8::from(execution.status != Status::Success);
        reply[1..1 + execution.body.len()].copy_from_slice(&execution.body);
        let response = server.send(epoch as u64, &reply)?;
        // The observable response exists now. Oracle, decryption and all JSON
        // serialization are deliberately outside this measured boundary.
        let response_ns = started.elapsed().as_nanos() as u64;
        let events = storage.lock().unwrap().backend_mut().take_trace();
        let expected_status = match id {
            0..=4 => Status::Success,
            5 => Status::Trap,
            6 => Status::OutOfFuel,
            _ => Status::Resource,
        };
        anyhow::ensure!(
            execution.status == expected_status,
            "unexpected class status {id}: {:?}",
            execution.status
        );
        let mut expected = vec![0u8; 64];
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
            4 => expected[..4].copy_from_slice(&1u32.to_le_bytes()),
            _ => {}
        }
        let received = client.receive(&response)?;
        anyhow::ensure!(
            received[0] == u8::from(id >= 5) && received[1..65] == expected,
            "oracle mismatch"
        );
        let row = json!({"version":1,"step":epoch,"response_ns":response_ns,"request_bytes":request.as_bytes().len(),"response_bytes":response.as_bytes().len(),"request_ciphertext":request.as_bytes().as_slice(),"response_ciphertext":response.as_bytes().as_slice(),"storage":events,"visible_selector":if control{Some(id)}else{None}});
        serde_json::to_writer(&mut observer, &row)?;
        writeln!(observer)?;
        serde_json::to_writer(
            &mut truth,
            &json!({"step":epoch,"class":id,"status":format!("{:?}",execution.status),"oracle_passed":true,"deadline_missed":execution.deadline_missed,"work_ns":execution.work_ns}),
        )?;
        writeln!(truth)?;
    }
    fs::write(
        output.join("metadata.json"),
        serde_json::to_vec_pretty(
            &json!({"seed":seed,"mode":args[3],"startup_ns":startup_ns,"class_ms":100,"observations":8,"cryptography":"OS randomness; seed only shuffles workload"}),
        )?,
    )?;
    Ok(())
}
