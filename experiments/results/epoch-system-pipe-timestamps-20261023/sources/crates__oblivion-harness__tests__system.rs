use rand::RngCore;
use std::{fs, process::Command};
fn rows(path: &std::path::Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
#[test]
fn actual_ablation_paths_emit_joint_observers_and_separate_truth() {
    let root =
        std::env::temp_dir().join(format!("oblivion-system-{}", rand::rngs::OsRng.next_u64()));
    fs::create_dir(&root).unwrap();
    let config = root.join("config.json");
    let out = root.join("out");
    fs::write(
        &config,
        r#"{"version":1,"seed":12,"trials":2,"sessions":4,"operations":4,"epoch_ms":110}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-harness"))
        .args(["system", config.to_str().unwrap(), out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for mode in ["A", "B", "C", "D", "E", "F", "G"] {
        let path = out.join(mode).join("0-0");
        let obs = rows(&path.join("observer.jsonl"));
        let truth = rows(&path.join("ground-truth.jsonl"));
        assert_eq!(obs.len(), 4);
        assert_eq!(truth.len(), 4);
        assert!(obs.iter().all(|r| r.get("label").is_none()
            && r.get("real").is_none()
            && r.get("status").is_none()));
        if mode == "G" {
            assert!(obs.iter().all(|r| r["storage_events"] == 128
                && r["request_bytes"] == 164
                && r["response_bytes"] == 164
                && r["registry_index"] == -1));
        }
        if mode == "A" {
            assert!(obs.iter().any(|r| r["request_bytes"] == 0));
        }
        if mode == "D" {
            assert!(obs.iter().all(|r| r["registry_index"] == -1));
        }
        let storage = rows(&path.join("storage-observer.jsonl"));
        assert!(storage.iter().all(|r| r.get("label").is_none()));
    }
    let metrics = rows(&out.join("metrics.jsonl"));
    assert_eq!(metrics.len(), 2 * 4 * 7 * 4);
    assert!(metrics.iter().all(|r| r["oracle_ok"] == true));
    fs::remove_dir_all(root).unwrap();
}
