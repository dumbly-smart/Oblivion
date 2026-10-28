#![cfg(unix)]

use oblivion_anchor::{UnixAnchorClient, serve_unix};
use oblivion_sse::{JournalError, Limits, PersistentClient, Server, UpdateRequest};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const ANCHOR_KEY: [u8; 32] = [0xB6; 32];
const CLIENT_KEY: [u8; 32] = [0xA5; 32];
const CHILD_MODE_ENV: &str = "OBLIVION_TEST_SSE_ANCHOR_CHILD";
const ROOT_ENV: &str = "OBLIVION_TEST_SSE_ANCHOR_ROOT";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "oblivion-sse-anchor-service-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct AnchorProcess {
    child: Child,
    socket: PathBuf,
}

impl AnchorProcess {
    fn stop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
        }
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket);
    }
}

impl Drop for AnchorProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

fn start_anchor(root: &Path) -> AnchorProcess {
    let socket = root.join("anchor.sock");
    let executable = std::env::current_exe().unwrap();
    let mut child = Command::new(executable)
        .args(["--exact", "anchor_service_child", "--nocapture"])
        .env(CHILD_MODE_ENV, "1")
        .env(ROOT_ENV, root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("anchor child exited before readiness: {status}");
        }
        if let Ok(mut anchor) = UnixAnchorClient::sse_journal(&socket, "integration-index")
            && anchor.load().is_ok()
        {
            return AnchorProcess { child, socket };
        }
        assert!(
            Instant::now() < deadline,
            "anchor service did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn anchor_service_child() {
    if std::env::var_os(CHILD_MODE_ENV).is_none() {
        return;
    }
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
    let result = serve_unix(
        root.join("anchor.sock"),
        root.join("anchor.sqlite"),
        Zeroizing::new(ANCHOR_KEY),
        0o600,
    );
    panic!("anchor service unexpectedly stopped: {result:?}");
}

#[test]
fn persistent_sse_state_survives_anchor_process_restart() {
    let root = TestDirectory::new();
    let journal = root.path().join("journal");
    fs::create_dir(&journal).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o700)).unwrap();

    let mut service = start_anchor(root.path());
    let anchor =
        UnixAnchorClient::sse_journal(root.path().join("anchor.sock"), "integration-index")
            .unwrap();
    let mut client =
        PersistentClient::create(&journal, &CLIENT_KEY, Limits::default(), anchor).unwrap();
    let mut server = Server::new(client.index_id(), Limits::default()).unwrap();
    let original = client.prepare_add(b"durable-keyword", 42).unwrap();
    drop(client);

    service.stop();
    let mut service = start_anchor(root.path());
    let mut recovered = PersistentClient::open(
        &journal,
        &CLIENT_KEY,
        UnixAnchorClient::sse_journal(root.path().join("anchor.sock"), "integration-index")
            .unwrap(),
    )
    .unwrap();
    let mut stale = PersistentClient::open(
        &journal,
        &CLIENT_KEY,
        UnixAnchorClient::sse_journal(root.path().join("anchor.sock"), "integration-index")
            .unwrap(),
    )
    .unwrap();
    let retry = recovered.retry_pending().unwrap();
    assert_same_request(&original, &retry);
    let ack = server.insert(retry).unwrap();
    recovered.finish_add(ack).unwrap();
    assert!(matches!(
        stale.finish_add(ack),
        Err(JournalError::AnchorConflict)
    ));
    drop(stale);
    drop(recovered);

    service.stop();
    let _service = start_anchor(root.path());
    let anchor =
        UnixAnchorClient::sse_journal(root.path().join("anchor.sock"), "integration-index")
            .unwrap();
    let restored = PersistentClient::open(&journal, &CLIENT_KEY, anchor).unwrap();
    let (snapshot, search) = restored.prepare_search(b"durable-keyword").unwrap();
    let response = server.search(&search).unwrap();
    assert_eq!(
        restored.finish_search(&snapshot, response).unwrap(),
        vec![42]
    );
}

#[test]
fn journal_benchmark_uses_real_anchor_and_fresh_process_recovery() {
    let root = TestDirectory::new();
    let mut service = start_anchor(root.path());
    let config = root.path().join("benchmark-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "schema_version": 1,
            "index_sizes": [4, 129],
            "trials": 1,
            "recovery_repetitions": 1,
            "schedule_seed": 20261028
        })
        .to_string(),
    )
    .unwrap();
    let output_dir = root.path().join("benchmark-output");
    let result = Command::new(env!("CARGO_BIN_EXE_sse-journal-benchmark"))
        .args([
            "run",
            service.socket.to_str().unwrap(),
            config.to_str().unwrap(),
            output_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "benchmark failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("report.json")).unwrap()).unwrap();
    let samples = report["samples"].as_array().unwrap();
    let small = samples
        .iter()
        .find(|sample| sample["index_size"] == 4)
        .unwrap();
    let checkpointed = samples
        .iter()
        .find(|sample| sample["index_size"] == 129)
        .unwrap();
    assert_eq!(small["journal_records_written"], 9);
    assert_eq!(small["generation"], 8);
    assert!(small["journal_record_bytes_written"].as_u64().unwrap() > 0);
    assert!(small["retained_journal_bytes"].as_u64().unwrap() > 0);
    assert_ne!(
        small["recovery_child_pids"][0].as_u64().unwrap(),
        u64::from(std::process::id())
    );
    assert!(small["recovery_open_ns"][0].as_u64().unwrap() > 0);
    assert_eq!(checkpointed["journal_records_written"], 259);
    assert_eq!(checkpointed["generation"], 258);
    assert_eq!(
        checkpointed["checkpoint_generations"],
        serde_json::json!([0, 256])
    );
    assert_eq!(checkpointed["retained_journal_records"], 3);
    assert!(
        checkpointed["journal_record_bytes_written"]
            .as_u64()
            .unwrap()
            > checkpointed["retained_journal_bytes"].as_u64().unwrap()
    );
    assert!(
        report["summary"][0]["recovery_open_trial_median_ns"]["p50"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    service.stop();
}

fn assert_same_request(left: &UpdateRequest, right: &UpdateRequest) {
    assert_eq!(left.version, right.version);
    assert_eq!(left.index_id, right.index_id);
    assert_eq!(left.address, right.address);
    assert_eq!(left.ciphertext, right.ciphertext);
}
