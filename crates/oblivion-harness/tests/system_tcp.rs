use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, PAYLOAD_BYTES};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn rows(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn launch_a_worker(output_dir: &std::path::Path) -> (ChildGuard, SocketAddr) {
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_oblivion-harness"))
            .args([
                "system-tcp-worker",
                output_dir.to_str().unwrap(),
                "A",
                "192",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| line);
        let _ = ready_tx.send(result);
    });
    let ready = ready_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("worker did not announce readiness")
        .unwrap();
    let address: SocketAddr = ready
        .strip_prefix("READY ")
        .expect("worker readiness line has the READY prefix")
        .trim()
        .parse()
        .expect("worker readiness line contains a socket address");
    (child, address)
}

fn bootstrap(child: &mut ChildGuard) -> Endpoint {
    let mut stdin = child.0.stdin.take().unwrap();
    let endpoint = Endpoint::provision_over_pipe(0, &mut stdin).unwrap();
    drop(stdin);
    endpoint
}

fn wait_for_exit(child: &mut ChildGuard) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "worker did not exit within the bounded wait"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn worker_is_loopback_only_bootstraps_privately_and_exits_on_client_eof() {
    let output_dir =
        std::env::temp_dir().join(format!("oblivion-tcp-worker-{}", rand::random::<u64>()));
    let (mut child, address) = launch_a_worker(&output_dir);
    assert!(address.ip().is_loopback(), "worker bound to {address}");

    let _client_endpoint = bootstrap(&mut child);

    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    drop(socket);

    let status = wait_for_exit(&mut child);
    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "worker exited with {status}: {stderr}");
    std::fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn worker_rejects_oversized_frame_before_waiting_for_body() {
    let output_dir =
        std::env::temp_dir().join(format!("oblivion-tcp-oversize-{}", rand::random::<u64>()));
    let (mut child, address) = launch_a_worker(&output_dir);
    let _client_endpoint = bootstrap(&mut child);
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    socket.write_all(&193_u32.to_be_bytes()).unwrap();
    drop(socket);

    let status = wait_for_exit(&mut child);
    assert!(
        !status.success(),
        "oversized frame was accepted by the worker"
    );
    let socket_observer =
        std::fs::read_to_string(output_dir.join("socket-observer.jsonl")).unwrap();
    assert!(socket_observer.is_empty());
    std::fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn worker_rejects_short_mode_incompatible_prefix_before_waiting_for_body() {
    let output_dir = std::env::temp_dir().join(format!(
        "oblivion-tcp-short-frame-{}",
        rand::random::<u64>()
    ));
    let (mut child, address) = launch_a_worker(&output_dir);
    let _client_endpoint = bootstrap(&mut child);
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.write_all(&191_u32.to_be_bytes()).unwrap();

    let mut probe = [0_u8; 1];
    assert_eq!(socket.read(&mut probe).unwrap(), 0);
    let status = wait_for_exit(&mut child);
    assert!(
        !status.success(),
        "short mode-incompatible frame was accepted"
    );
    let socket_observer =
        std::fs::read_to_string(output_dir.join("socket-observer.jsonl")).unwrap();
    assert!(socket_observer.is_empty());
    std::fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn tcp_system_runs_every_ablation_mode_with_fixed_observer_frames() {
    let root = std::env::temp_dir().join(format!("oblivion-tcp-system-{}", rand::random::<u64>()));
    std::fs::create_dir(&root).unwrap();
    let config = root.join("config.json");
    let output_dir = root.join("out");
    std::fs::write(
        &config,
        r#"{"version":1,"seed":29,"trials":2,"sessions":4,"operations":4,"epoch_ms":2}"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-harness"))
        .args([
            "system-tcp",
            config.to_str().unwrap(),
            output_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    for mode in ["A", "B", "C", "D", "E", "F", "G"] {
        let session = output_dir.join(mode).join("0-0");
        let socket_events = rows(&session.join("socket-observer.jsonl"));
        let server_observer = rows(&session.join("observer.jsonl"));
        let truth = rows(&session.join("ground-truth.jsonl"));
        assert_eq!(truth.len(), 4, "mode {mode}");
        let real = truth.iter().filter(|row| row["label"] != 0).count();
        let sent = if matches!(mode, "E" | "G") { 4 } else { real };
        assert_eq!(socket_events.len(), sent * 2, "mode {mode}");
        assert_eq!(server_observer.len(), sent, "mode {mode}");
        if matches!(mode, "D" | "G") {
            assert!(
                server_observer
                    .iter()
                    .all(|row| row["registry_index"] == -1)
            );
        }
        if mode == "G" {
            assert!(
                server_observer
                    .iter()
                    .all(|row| row["storage_events"] == 128)
            );
            let storage_events = rows(&session.join("storage-observer.jsonl"));
            assert_eq!(storage_events.len(), 4 * 128);
            assert!(storage_events.iter().all(|row| row.get("step").is_none()));
        }
        for (index, event) in socket_events.iter().enumerate() {
            assert_eq!(
                event["direction"],
                if index % 2 == 0 {
                    "request"
                } else {
                    "response"
                }
            );
            assert!(event.get("label").is_none());
            assert!(event.get("real").is_none());
            assert!(event.get("function").is_none());
            assert!(event.get("step").is_none());
            let body_len = event["frame"].as_array().unwrap().len();
            assert_eq!(event["bytes"], body_len + 4);
            if mode == "A" && index % 2 == 0 {
                assert_eq!(body_len, PAYLOAD_BYTES);
            } else if mode == "A" {
                assert!(matches!(body_len, 5 | 65));
            } else {
                assert_eq!(body_len, ENVELOPE_BYTES);
            }
        }
    }
    let metrics = rows(&output_dir.join("metrics.jsonl"));
    assert_eq!(metrics.len(), 2 * 4 * 7 * 4);
    assert!(metrics.iter().all(|row| row["oracle_ok"] == true));
    std::fs::remove_dir_all(root).unwrap();
}
