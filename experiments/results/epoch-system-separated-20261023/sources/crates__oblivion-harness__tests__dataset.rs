use rand::RngCore;
use std::{fs, process::Command};
fn rows(path: &std::path::Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
#[test]
fn component_dataset_uses_actual_lengths_and_separate_labels() {
    let root =
        std::env::temp_dir().join(format!("oblivion-dataset-{}", rand::rngs::OsRng.next_u64()));
    fs::create_dir(&root).unwrap();
    let config = root.join("config.json");
    let out = root.join("out");
    fs::write(
        &config,
        r#"{"version":1,"seed":12,"trials":2,"sessions":4,"operations":32}"#,
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_oblivion-harness"))
        .args([config.to_str().unwrap(), out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let plain = rows(&out.join("traffic/unpadded/0-0/observer.jsonl"));
    let defended = rows(&out.join("traffic/padded/0-0/observer.jsonl"));
    assert_eq!(plain.len(), 32);
    assert_eq!(defended.len(), 32);
    assert!(plain.iter().any(|r| r["bytes"] == 4));
    assert!(plain.iter().any(|r| r["bytes"] == 64));
    assert!(
        defended
            .iter()
            .all(|r| r["bytes"] == 64 && r["latency_ns"].as_u64().unwrap() >= 10_000_000)
    );
    assert!(defended.iter().all(|r| r.get("label").is_none()));
    let truth = rows(&out.join("traffic/padded/0-0/ground-truth.jsonl"));
    assert_eq!(truth.iter().filter(|r| r["label"] == 1).count(), 16);
    let oram = rows(&out.join("frequency/oram/0-0/observer.jsonl"));
    assert!(
        oram.iter()
            .all(|r| r["bytes"] == 3160 && r["tag"].as_u64().unwrap() < 16)
    );
    fs::write(
        &config,
        r#"{"version":2,"seed":12,"trials":2,"sessions":4,"operations":32}"#,
    )
    .unwrap();
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_oblivion-harness"))
            .args([
                config.to_str().unwrap(),
                root.join("invalid").to_str().unwrap()
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!root.join("invalid").exists());
    let _ = fs::remove_dir_all(root);
}
