use oblivion_store::{Config, MemoryBackend, PathOram};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn unwritten_blocks_are_zero_and_writes_persist() {
    let config = Config::new(16, 32).unwrap();
    let mut store = PathOram::new(config, MemoryBackend::default()).unwrap();
    assert_eq!(store.read(7).unwrap(), vec![0; 32]);
    store.write(7, &[42; 32]).unwrap();
    for _ in 0..100 {
        assert_eq!(store.read(7).unwrap(), vec![42; 32]);
        store.check_invariants().unwrap();
    }
}

fn oracle_workload(operations: usize, blocks: usize, seed: u64) {
    let config = Config::new(blocks, 32).unwrap();
    let mut store = PathOram::new(config, MemoryBackend::default()).unwrap();
    let mut oracle = vec![vec![0; 32]; blocks];
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    for step in 0..operations {
        let address = rng.gen_range(0..blocks);
        if rng.gen_bool(0.5) {
            let data: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
            store.write(address, &data).unwrap();
            oracle[address] = data;
        } else {
            assert_eq!(store.read(address).unwrap(), oracle[address], "step {step}");
        }
        if step % 100 == 0 {
            store.check_invariants().unwrap();
            store.backend_mut().take_trace();
        }
    }
    for (address, expected) in oracle.iter().enumerate() {
        assert_eq!(&store.read(address).unwrap(), expected);
    }
    store.check_invariants().unwrap();
}

#[test]
fn randomized_oracle() {
    for (blocks, seed) in [(1, 1), (7, 2), (64, 3), (127, 4)] {
        oracle_workload(2_000, blocks, seed);
    }
}

#[test]
#[ignore = "million-operation stress tier; run in release mode"]
fn million_operation_oracle() {
    oracle_workload(1_000_000, 256, 0x0b11_7100);
}
