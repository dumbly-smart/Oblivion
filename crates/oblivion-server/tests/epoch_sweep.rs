use oblivion_batcher::ENVELOPE_BYTES;
use rand::RngCore;
use std::{fs, process::Command};
fn output_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "oblivion-epoch-sweep-{}",
        rand::rngs::OsRng.next_u64()
    ))
}
#[test]
fn schedule_rejects_invalid_bounds_before_creating_output() {
    for (real, participants, period, count) in [
        ("50", "2", "199", "4"),
        ("50", "1", "1001", "4"),
        ("50", "0", "200", "4"),
        ("51", "1", "200", "4"),
        ("50", "1", "200", "0"),
        ("50", "1", "200", "129"),
    ] {
        let path = output_path();
        let result = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
            .args([
                "demo-sweep",
                path.to_str().unwrap(),
                real,
                participants,
                period,
                count,
                "mixed",
            ])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!path.exists());
    }
}
#[test]
fn actual_sweep_uses_exact_metadata_oracles_and_arrival_latency() {
    let path = output_path();
    let result = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args([
            "demo-sweep",
            path.to_str().unwrap(),
            "50",
            "2",
            "250",
            "2",
            "mixed",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(metadata["configuration"]["epoch_ms"], 250);
    assert_eq!(metadata["configuration"]["epochs"], 2);
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("client-summary.json")).unwrap()).unwrap();
    assert_eq!(summary["real_invocations"], 2);
    assert_eq!(summary["dummy_invocations"], 2);
    assert_eq!(summary["epochs"], 2);
    let observer = fs::read_to_string(path.join("envelope-observer.jsonl")).unwrap();
    assert_eq!(observer.lines().count(), 4);
    for line in observer.lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        for forbidden in ["queue_wait_ns", "arrival_to_response_ns", "client_ready_ns"] {
            assert!(
                row.get(forbidden).is_none(),
                "private client timing in observer"
            );
        }
        let timings = fs::read_to_string(path.join("client-private-latency.jsonl")).unwrap();
        let private: serde_json::Value = timings
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|private| private["epoch"] == row["epoch"] && private["slot"] == row["slot"])
            .unwrap();
        assert!(private["queue_wait_ns"].as_u64().unwrap() > 0);
        assert_eq!(
            private["arrival_to_response_ns"].as_u64().unwrap(),
            private["queue_wait_ns"].as_u64().unwrap() + row["latency_ns"].as_u64().unwrap()
        );
        assert_eq!(row["request_bytes"], ENVELOPE_BYTES);
        assert_eq!(row["response_bytes"], ENVELOPE_BYTES);
    }
    assert_eq!(
        summary["successful_real_invocations"].as_u64().unwrap()
            + summary["failed_real_invocations"].as_u64().unwrap(),
        2
    );
    assert_eq!(
        summary["successful_dummy_invocations"].as_u64().unwrap()
            + summary["failed_dummy_invocations"].as_u64().unwrap(),
        2
    );
    let expected_events: u64 = fs::read_to_string(path.join("executor-private.jsonl"))
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["storage_events"]
                .as_u64()
                .unwrap()
        })
        .sum();
    assert_eq!(
        fs::read_to_string(path.join("storage-observer.jsonl"))
            .unwrap()
            .lines()
            .count() as u64,
        expected_events
    );
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn original_demo_defaults_remain_eight_epochs_and_150ms_per_client() {
    let path = output_path();
    let result = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["demo", path.to_str().unwrap(), "50"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(metadata["configuration"]["epoch_ms"], 150);
    assert_eq!(metadata["configuration"]["epochs"], 8);
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("client-summary.json")).unwrap()).unwrap();
    assert_eq!(summary["real_invocations"], 4);
    assert_eq!(summary["last_real_counter"], 4);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn enormous_legacy_participant_count_is_rejected_without_panic_or_output() {
    for mode in ["demo", "demo-sse"] {
        let path = output_path();
        let result = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
            .args([mode, path.to_str().unwrap(), "50", &usize::MAX.to_string()])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!path.exists());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!stderr.contains("panicked"), "{stderr}");
    }
}
