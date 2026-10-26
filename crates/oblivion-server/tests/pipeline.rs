use ed25519_dalek::SigningKey;
use oblivion_batcher::ENVELOPE_BYTES;
use oblivion_server::invocation::sign_request;
use rand::RngCore;
use std::{fs, process::Command};

// Called only by failed assertions for these synthetic integration fixtures.
// Never attach private runtime records to the public protocol or observer log.
fn fixture_diagnostics(path: &std::path::Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let mut message = format!("synthetic fixture retained at {}", path.display());
    for name in ["executor-private.jsonl", "publication-private.jsonl"] {
        let tail = (|| -> std::io::Result<String> {
            let mut file = fs::File::open(path.join(name))?;
            let offset = file.metadata()?.len().saturating_sub(1024);
            file.seek(SeekFrom::Start(offset))?;
            let mut bytes = Vec::new();
            file.take(1024).read_to_end(&mut bytes)?;
            let text = String::from_utf8_lossy(&bytes);
            let mut rows: Vec<_> = text.lines().rev().take(4).collect();
            rows.reverse();
            Ok(rows.join("\n"))
        })();
        match tail {
            Ok(rows) => message.push_str(&format!("\n{name} (last <=1024 bytes/4 rows):\n{rows}")),
            Err(error) => message.push_str(&format!("\n{name}: unavailable ({error})")),
        }
    }
    message
}

fn sign_fixture(payload: &mut [u8; oblivion_batcher::PAYLOAD_BYTES], epoch: u64) {
    let key = SigningKey::from_bytes(&[0x63; 32]);
    let mut invocation_id = [0; 16];
    invocation_id[..8].copy_from_slice(&epoch.to_be_bytes());
    sign_request(payload, 0, invocation_id, &key);
}

#[test]
fn worker_uses_external_catalog_and_fails_before_ready_for_wrong_key() {
    use ed25519_dalek::SigningKey;
    use oblivion_batcher::Endpoint;
    use oblivion_registry::{Record, SignedRegistry};
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::process::Stdio;

    let root = std::env::temp_dir().join(format!(
        "oblivion-external-registry-{}",
        rand::rngs::OsRng.next_u64()
    ));
    fs::create_dir(&root).unwrap();
    let sources: [&[u8]; 5] = [
        include_bytes!("../../../examples/wasm-functions/echo.wat"),
        include_bytes!("../../../examples/wasm-functions/sum.wat"),
        include_bytes!("../../../examples/wasm-functions/fibonacci.wat"),
        include_bytes!("../../../examples/wasm-functions/hash.wat"),
        include_bytes!("../../../examples/wasm-functions/stateful.wat"),
    ];
    let publisher = SigningKey::from_bytes(&[0x81; 32]);
    let records = sources
        .iter()
        .enumerate()
        .map(|(id, source)| {
            let module_digest: [u8; 32] = Sha256::digest(source).into();
            let mut location = Sha256::new();
            location.update(b"oblivion/demo/embedded-location/v1");
            location.update((id as u32).to_be_bytes());
            location.update(module_digest);
            let location_digest = location.finalize().into();
            Record::sign(id as u32, 9, module_digest, location_digest, 0, &publisher).unwrap()
        })
        .collect();
    let manifest = SignedRegistry::sign(9, records, &publisher).unwrap();
    let manifest_path = root.join("catalog.bin");
    let public_key_path = root.join("publisher.pub");
    fs::write(&manifest_path, manifest).unwrap();
    fs::write(&public_key_path, publisher.verifying_key().to_bytes()).unwrap();

    let run_worker =
        |name: &str, manifest: &std::path::Path, public_key: Option<&std::path::Path>| {
            let output_dir = root.join(name);
            fs::create_dir(&output_dir).unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_oblivion-server"));
            command
                .args(["executor-worker", output_dir.to_str().unwrap()])
                .env_remove("OBLIVION_ANCHOR_SOCKET")
                .env_remove("OBLIVION_ANCHOR_STATE_DIR")
                .env("OBLIVION_REGISTRY_MANIFEST", manifest)
                .env_remove("OBLIVION_REGISTRY_PUBLIC_KEY");
            if let Some(public_key) = public_key {
                command.env("OBLIVION_REGISTRY_PUBLIC_KEY", public_key);
            }
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = child.stdout.take().unwrap();
            let _client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
            let mut readiness = [0; 1];
            let result = output.read_exact(&mut readiness);
            drop(input);
            (result, readiness, child.wait().unwrap())
        };

    let (ready_result, readiness, success) =
        run_worker("valid", &manifest_path, Some(&public_key_path));
    assert!(ready_result.is_ok());
    assert_eq!(readiness, [1]);
    assert!(success.success());

    let wrong_signer = SigningKey::from_bytes(&[0x82; 32]);
    let wrong_key_path = root.join("wrong-publisher.pub");
    fs::write(&wrong_key_path, wrong_signer.verifying_key().to_bytes()).unwrap();
    let (ready_result, _, failure) = run_worker("wrong-key", &manifest_path, Some(&wrong_key_path));
    assert!(ready_result.is_err(), "worker must not announce readiness");
    assert!(!failure.success());

    let (ready_result, _, failure) = run_worker("partial-config", &manifest_path, None);
    assert!(
        ready_result.is_err(),
        "partial config must fail before readiness"
    );
    assert!(!failure.success());

    let oversized_key_path = root.join("oversized.pub");
    fs::write(&oversized_key_path, [0; 33]).unwrap();
    let (ready_result, _, failure) =
        run_worker("oversized-key", &manifest_path, Some(&oversized_key_path));
    assert!(
        ready_result.is_err(),
        "oversized key must fail before readiness"
    );
    assert!(!failure.success());

    let oversized_manifest_path = root.join("oversized-catalog.bin");
    fs::write(&oversized_manifest_path, vec![0; 124 + 65_536 * 160 + 1]).unwrap();
    let (ready_result, _, failure) = run_worker(
        "oversized-manifest",
        &oversized_manifest_path,
        Some(&public_key_path),
    );
    assert!(
        ready_result.is_err(),
        "oversized manifest must fail before readiness"
    );
    assert!(!failure.success());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn failure_diagnostics_are_bounded_and_keep_private_tail_or_missing_reason() {
    let path = std::env::temp_dir().join(format!(
        "oblivion-diagnostic-{}",
        rand::rngs::OsRng.next_u64()
    ));
    fs::create_dir(&path).unwrap();
    fs::write(
        path.join("executor-private.jsonl"),
        format!(
            "old-record\n{}\n{{\"status\":\"Timeout\",\"epoch\":7}}\n",
            "x".repeat(10000)
        ),
    )
    .unwrap();
    let message = fixture_diagnostics(&path);
    assert!(message.contains("Timeout"));
    assert!(message.contains("publication-private.jsonl: unavailable"));
    assert!(!message.contains("old-record"));
    assert!(message.len() < 8192);
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn actual_process_pipeline_real_dummy_and_oram_state() {
    let path = std::env::temp_dir().join(format!(
        "oblivion-pipeline-{}",
        rand::rngs::OsRng.next_u64()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["demo", path.to_str().unwrap(), "50"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture_diagnostics(&path)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("client-summary.json")).unwrap()).unwrap();
    assert_eq!(summary["real_invocations"], 4);
    assert_eq!(summary["dummy_invocations"], 4);
    assert_eq!(summary["last_real_counter"], 4);
    assert_eq!(summary["request_bytes"], ENVELOPE_BYTES);
    assert_eq!(summary["encrypted_pir_links"], true);
    let rows = fs::read_to_string(path.join("storage-observer.jsonl")).unwrap();
    assert_eq!(rows.lines().count(), 8 * 16 * 8); // 8 invocations, 16 ORAM accesses, 8 bucket events
    let _ = fs::remove_dir_all(path);
}

#[test]
fn invalid_selection_and_reserved_dummy_address_do_not_mutate_user_state() {
    use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, PAYLOAD_BYTES};
    use std::{
        io::{Read, Write},
        process::Stdio,
    };
    let path =
        std::env::temp_dir().join(format!("oblivion-invalid-{}", rand::rngs::OsRng.next_u64()));
    fs::create_dir(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["executor-worker", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
    let mut ready = [0; 1];
    output.read_exact(&mut ready).unwrap();
    assert_eq!(ready, [1]);
    for (epoch, id, address, expected_error, expected_counter) in [
        (0, 99u32, 0u32, true, 0),
        (1, 4, 0, false, 1),
        (2, 4, 7, true, 0),
        (3, 4, 0, false, 2),
    ] {
        let mut payload = [0; PAYLOAD_BYTES];
        payload[0] = 1;
        payload[1..5].copy_from_slice(&id.to_be_bytes());
        payload[9..13].copy_from_slice(&address.to_le_bytes());
        sign_fixture(&mut payload, epoch);
        input
            .write_all(client.send(epoch, &payload).unwrap().as_bytes())
            .unwrap();
        input.flush().unwrap();
        let mut frame = [0; ENVELOPE_BYTES];
        output.read_exact(&mut frame).unwrap();
        let result = client
            .receive(&Envelope::from_bytes(&frame).unwrap())
            .unwrap();
        assert_eq!(
            result[0],
            u8::from(expected_error),
            "{}",
            fixture_diagnostics(&path)
        );
        if !expected_error {
            assert_eq!(
                u32::from_le_bytes(result[1..5].try_into().unwrap()),
                expected_counter
            );
        }
    }
    drop(input);
    assert!(child.wait().unwrap().success());
    let _ = fs::remove_dir_all(path);
}

#[test]
fn invocation_without_a_valid_signed_identity_is_rejected() {
    use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, PAYLOAD_BYTES};
    use std::{
        io::{Read, Write},
        process::Stdio,
    };
    let path = std::env::temp_dir().join(format!(
        "oblivion-unsigned-invocation-{}",
        rand::rngs::OsRng.next_u64()
    ));
    fs::create_dir(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["executor-worker", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
    let mut ready = [0; 1];
    output.read_exact(&mut ready).unwrap();
    assert_eq!(ready, [1]);

    let mut payload = [0; PAYLOAD_BYTES];
    payload[0] = 1;
    payload[1..5].copy_from_slice(&4u32.to_be_bytes());
    let frame = client.send(0, &payload).unwrap();
    input.write_all(frame.as_bytes()).unwrap();
    input.flush().unwrap();
    let mut bytes = [0; ENVELOPE_BYTES];
    output.read_exact(&mut bytes).unwrap();
    let response = client
        .receive(&Envelope::from_bytes(&bytes).unwrap())
        .unwrap();
    assert_eq!(response[0], 1, "{}", fixture_diagnostics(&path));

    drop(input);
    assert!(child.wait().unwrap().success());
    let private: serde_json::Value = serde_json::from_str(
        fs::read_to_string(path.join("executor-private.jsonl"))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(private["request_authenticated"], true);
    assert_eq!(private["request_valid"], false);
    let _ = fs::remove_dir_all(path);
}

#[cfg(unix)]
#[test]
fn partial_anchor_configuration_fails_before_worker_readiness() {
    use oblivion_batcher::Endpoint;
    use std::{io::Read, process::Stdio};
    let path = std::env::temp_dir().join(format!(
        "oblivion-partial-anchor-{}",
        rand::rngs::OsRng.next_u64()
    ));
    fs::create_dir(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["executor-worker", path.to_str().unwrap()])
        .env("OBLIVION_ANCHOR_SOCKET", path.join("anchor.sock"))
        .env_remove("OBLIVION_ANCHOR_STATE_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let _client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
    let mut ready = [0; 1];
    let ready_bytes = output.read(&mut ready).unwrap();
    drop(input);
    assert!(!child.wait().unwrap().success());
    assert_eq!(ready_bytes, 0, "partial anchor configuration was accepted");
    let _ = fs::remove_dir_all(path);
}

#[cfg(unix)]
#[test]
fn durable_worker_commits_and_replays_signed_invocations_after_restart() {
    use ed25519_dalek::SigningKey;
    use oblivion_anchor::{UnixAnchorClient, serve_unix};
    use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, PAYLOAD_BYTES};
    use oblivion_server::invocation::sign_request;
    use std::{
        io::{Read, Write},
        os::unix::fs::PermissionsExt,
        process::Stdio,
        time::Duration,
    };
    use zeroize::Zeroizing;

    fn run_worker(
        output_dir: &std::path::Path,
        state_dir: &std::path::Path,
        socket: &std::path::Path,
        requests: &[(u64, [u8; PAYLOAD_BYTES])],
    ) -> Vec<[u8; PAYLOAD_BYTES]> {
        fs::create_dir(output_dir).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
            .args(["executor-worker", output_dir.to_str().unwrap()])
            .env("OBLIVION_ANCHOR_SOCKET", socket)
            .env("OBLIVION_ANCHOR_STATE_DIR", state_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        let mut client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
        let mut ready = [0; 1];
        output.read_exact(&mut ready).unwrap();
        assert_eq!(ready, [1]);
        let mut results = Vec::new();
        for (epoch, payload) in requests {
            input
                .write_all(client.send(*epoch, payload).unwrap().as_bytes())
                .unwrap();
            input.flush().unwrap();
            let mut response = [0; ENVELOPE_BYTES];
            output.read_exact(&mut response).unwrap();
            results.push(
                client
                    .receive(&Envelope::from_bytes(&response).unwrap())
                    .unwrap(),
            );
        }
        drop(input);
        assert!(child.wait().unwrap().success());
        results
    }

    let root = std::env::temp_dir().join(format!(
        "oblivion-durable-worker-{}",
        rand::rngs::OsRng.next_u64()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("anchor.sock");
    let database = root.join("anchor.sqlite");
    let server_socket = socket.clone();
    let server_database = database.clone();
    let _anchor = std::thread::spawn(move || {
        serve_unix(
            server_socket,
            server_database,
            Zeroizing::new([0x87; 32]),
            0o600,
        )
        .unwrap();
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "anchor service did not bind its socket");

    let state_dir = root.join("state");
    let key = SigningKey::from_bytes(&[0x75; 32]);
    let mut first_payload = [0; PAYLOAD_BYTES];
    first_payload[0] = 1;
    first_payload[1..5].copy_from_slice(&4u32.to_be_bytes());
    first_payload[5] = 10;
    let token = sign_request(&mut first_payload, 0, [0x31; 16], &key);
    let first_response = run_worker(
        &root.join("first-run"),
        &state_dir,
        &socket,
        &[(0, first_payload)],
    )[0];
    assert_eq!(first_response[0], 0);
    assert_eq!(
        u32::from_le_bytes(first_response[1..5].try_into().unwrap()),
        1
    );

    let anchor = UnixAnchorClient::invocation(&socket, "server-state-v1").unwrap();
    let receipt = anchor
        .load(&token)
        .unwrap()
        .expect("worker committed response receipt");
    assert_eq!(receipt.response(), first_response);

    let mut new_payload = [0; PAYLOAD_BYTES];
    new_payload[0] = 1;
    new_payload[1..5].copy_from_slice(&4u32.to_be_bytes());
    new_payload[5] = 10;
    sign_request(&mut new_payload, 0, [0x32; 16], &key);
    let mut conflicting_payload = first_payload;
    conflicting_payload[5] ^= 1;
    sign_request(&mut conflicting_payload, 0, [0x31; 16], &key);
    let replay_and_new = run_worker(
        &root.join("second-run"),
        &state_dir,
        &socket,
        &[
            (0, first_payload),
            (1, new_payload),
            (2, conflicting_payload),
        ],
    );
    assert_eq!(replay_and_new[0], first_response);
    assert_eq!(replay_and_new[1][0], 0);
    assert_eq!(
        u32::from_le_bytes(replay_and_new[1][1..5].try_into().unwrap()),
        2
    );
    assert_eq!(replay_and_new[2][0], 1);
    assert!(replay_and_new[2][1..].iter().all(|&byte| byte == 0));
    let private_rows: Vec<serde_json::Value> =
        fs::read_to_string(root.join("second-run").join("executor-private.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    assert_eq!(private_rows[2]["request_valid"], false);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn multiple_clients_execute_mixed_functions_with_isolated_state_and_fixed_traces() {
    let path =
        std::env::temp_dir().join(format!("oblivion-mixed-{}", rand::rngs::OsRng.next_u64()));
    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["demo", path.to_str().unwrap(), "50", "3", "mixed"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture_diagnostics(&path)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("client-summary.json")).unwrap()).unwrap();
    assert_eq!(summary["participants"], 3);
    assert_eq!(summary["real_invocations"], 12);
    assert_eq!(summary["dummy_invocations"], 12);
    assert_eq!(summary["functions_verified"], 5);
    assert_eq!(
        summary["client_state_counters"],
        serde_json::json!([0, 1, 1])
    );
    let rows = fs::read_to_string(path.join("storage-observer.jsonl")).unwrap();
    assert_eq!(rows.lines().count(), 24 * 16 * 8);
    let rows = fs::read_to_string(path.join("envelope-observer.jsonl")).unwrap();
    for row in rows.lines() {
        let row: serde_json::Value = serde_json::from_str(row).unwrap();
        assert_eq!(row["batch_count"], 3);
        assert_eq!(row["request_bytes"], ENVELOPE_BYTES);
        assert_eq!(row["response_bytes"], ENVELOPE_BYTES);
    }
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn sse_metadata_discovery_precedes_real_mixed_invocation() {
    let path = std::env::temp_dir().join(format!(
        "oblivion-sse-demo-{}",
        rand::rngs::OsRng.next_u64()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["demo-sse", path.to_str().unwrap(), "100", "2", "mixed"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture_diagnostics(&path)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("client-summary.json")).unwrap()).unwrap();
    assert_eq!(summary["sse_metadata_discovery"], true);
    assert_eq!(summary["sse_searches_verified"], 16);
    assert_eq!(
        fs::read_to_string(path.join("metadata-discovery-observer.jsonl"))
            .unwrap()
            .lines()
            .count(),
        26
    );
    assert_eq!(summary["functions_verified"], 5);
    assert_eq!(summary["registry_version"], 1);
    assert_eq!(summary["registry_record_bytes"], 160);
    assert_eq!(
        summary["registry_deployment_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let private_rows: Vec<serde_json::Value> =
        fs::read_to_string(path.join("executor-private.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    assert_eq!(private_rows.len(), 16);
    assert!(private_rows.iter().all(|row| {
        row["registry_authenticated"] == true
            && row["registry_record_bytes"] == 160
            && row["pir_ns"].as_u64().is_some()
            && row["registry_pin_check_ns"].as_u64().is_some()
    }));
    assert_eq!(
        fs::read_to_string(path.join("storage-observer.jsonl"))
            .unwrap()
            .lines()
            .count(),
        16 * 16 * 8
    );
    fs::remove_dir_all(path).unwrap();
}

fn bounded_exit(
    child: &mut std::process::Child,
    limit: std::time::Duration,
) -> std::process::ExitStatus {
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() >= limit {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("worker exceeded lifecycle bound");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn executor_bootstrap_and_partial_frames_have_bounded_lifetimes() {
    use oblivion_batcher::Endpoint;
    use std::{
        io::{Read, Write},
        process::Stdio,
        time::Duration,
    };
    for partial_frame in [false, true] {
        let path =
            std::env::temp_dir().join(format!("oblivion-dropped-{}", rand::rngs::OsRng.next_u64()));
        fs::create_dir(&path).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
            .args(["executor-worker", path.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        if partial_frame {
            let _client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
            child
                .stdout
                .take()
                .unwrap()
                .read_exact(&mut [0; 1])
                .unwrap();
            input.write_all(&[0; 12]).unwrap();
            input.flush().unwrap();
        }
        assert!(!bounded_exit(&mut child, Duration::from_secs(4)).success());
        drop(input);
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn duplicate_and_skipped_epochs_fail_closed_without_second_execution() {
    use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, PAYLOAD_BYTES};
    use std::{
        io::{Read, Write},
        process::Stdio,
        time::Duration,
    };
    for duplicate in [true, false] {
        let path = std::env::temp_dir().join(format!(
            "oblivion-sequence-{}",
            rand::rngs::OsRng.next_u64()
        ));
        fs::create_dir(&path).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
            .args(["executor-worker", path.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        let mut client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
        output.read_exact(&mut [0; 1]).unwrap();
        let mut payload = [0; PAYLOAD_BYTES];
        payload[0] = 1;
        payload[1..5].copy_from_slice(&4u32.to_be_bytes());
        sign_fixture(&mut payload, 0);
        let initial = client.send(0, &payload).unwrap();
        input.write_all(initial.as_bytes()).unwrap();
        input.flush().unwrap();
        output.read_exact(&mut [0; ENVELOPE_BYTES]).unwrap();
        let next = if duplicate {
            initial
        } else {
            sign_fixture(&mut payload, 2);
            client.send(2, &payload).unwrap()
        };
        input.write_all(next.as_bytes()).unwrap();
        input.flush().unwrap();
        assert!(!bounded_exit(&mut child, Duration::from_secs(3)).success());
        assert_eq!(
            fs::read_to_string(path.join("storage-observer.jsonl"))
                .unwrap()
                .lines()
                .count(),
            16 * 8
        );
        fs::remove_dir_all(path).unwrap();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn lost_pir_server_returns_authenticated_zero_error_without_user_state() {
    use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, PAYLOAD_BYTES};
    use std::{
        io::{Read, Write},
        process::Stdio,
        time::Duration,
    };
    let path = std::env::temp_dir().join(format!("oblivion-loss-{}", rand::rngs::OsRng.next_u64()));
    fs::create_dir(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["executor-worker", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
    output.read_exact(&mut [0; 1]).unwrap();
    let children = fs::read_to_string(format!("/proc/{0}/task/{0}/children", child.id())).unwrap();
    let children: Vec<_> = children.split_whitespace().collect();
    assert_eq!(children.len(), 2);
    assert!(
        Command::new("kill")
            .args(["-KILL", children[0]])
            .status()
            .unwrap()
            .success()
    );
    std::thread::sleep(Duration::from_millis(50));
    let mut payload = [0; PAYLOAD_BYTES];
    payload[0] = 1;
    payload[1..5].copy_from_slice(&4u32.to_be_bytes());
    sign_fixture(&mut payload, 0);
    input
        .write_all(client.send(0, &payload).unwrap().as_bytes())
        .unwrap();
    input.flush().unwrap();
    let mut bytes = [0; ENVELOPE_BYTES];
    output.read_exact(&mut bytes).unwrap();
    let result = client
        .receive(&Envelope::from_bytes(&bytes).unwrap())
        .unwrap();
    // Ensure cleanup even when the assertion catches a disclosed dummy result.
    drop(input);
    assert!(bounded_exit(&mut child, Duration::from_secs(3)).success());
    assert_eq!(result[0], 1, "{}", fixture_diagnostics(&path));
    assert!(
        result[1..].iter().all(|&b| b == 0),
        "PIR failure must not disclose dummy output"
    );
    assert_eq!(
        fs::read_to_string(path.join("storage-observer.jsonl"))
            .unwrap()
            .lines()
            .count(),
        16 * 8
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn abandoned_response_pipe_cannot_hold_executor_forever() {
    use oblivion_batcher::{Endpoint, PAYLOAD_BYTES};
    use std::{
        io::{Read, Write},
        process::Stdio,
        time::Duration,
    };
    let path = std::env::temp_dir().join(format!(
        "oblivion-backpressure-{}",
        rand::rngs::OsRng.next_u64()
    ));
    fs::create_dir(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["executor-worker", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
    output.read_exact(&mut [0; 1]).unwrap();
    #[cfg(target_os = "linux")]
    rustix::pipe::fcntl_setpipe_size(&output, 4096).unwrap();
    // Holding stdout open without consuming responses eventually fills its pipe.
    std::thread::spawn(move || {
        for epoch in 0..512 {
            let frame = client.send(epoch, &[0; PAYLOAD_BYTES]).unwrap();
            if input.write_all(frame.as_bytes()).is_err() {
                return;
            }
        }
    });
    assert!(!bounded_exit(&mut child, Duration::from_secs(12)).success());
    drop(output);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn orphaned_pir_worker_exits_after_idle_bound() {
    use oblivion_pir::secure::{Endpoint, Geometry};
    use std::{
        io::{BufRead, BufReader, Write},
        process::Stdio,
        time::Duration,
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["secure-pir-worker", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(b"OBLPIR01").unwrap();
    input.write_all(&5u32.to_be_bytes()).unwrap();
    input.write_all(&128u32.to_be_bytes()).unwrap();
    for id in 0..5u8 {
        input.write_all(&[id; 128]).unwrap();
    }
    let _endpoint =
        Endpoint::provision_over_pipe(0, Geometry::new(5, 128).unwrap(), &mut input).unwrap();
    drop(input);
    let mut address = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    assert!(address.starts_with("127.0.0.1:"));
    assert!(bounded_exit(&mut child, Duration::from_secs(7)).success());
}

#[test]
fn late_frame_after_idle_timeout_cannot_resume_session() {
    use oblivion_batcher::{Endpoint, PAYLOAD_BYTES};
    use std::{
        io::{Read, Write},
        process::Stdio,
        time::Duration,
    };
    let path = std::env::temp_dir().join(format!("oblivion-late-{}", rand::rngs::OsRng.next_u64()));
    fs::create_dir(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["executor-worker", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
    output.read_exact(&mut [0; 1]).unwrap();
    assert!(!bounded_exit(&mut child, Duration::from_secs(4)).success());
    assert!(
        input
            .write_all(client.send(0, &[0; PAYLOAD_BYTES]).unwrap().as_bytes())
            .is_err()
    );
    assert!(
        fs::read_to_string(path.join("storage-observer.jsonl"))
            .unwrap()
            .is_empty()
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn tampered_authenticated_frame_runs_cover_and_next_real_state_is_untouched() {
    use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, PAYLOAD_BYTES};
    use std::{
        io::{Read, Write},
        process::Stdio,
        time::Duration,
    };
    let path =
        std::env::temp_dir().join(format!("oblivion-tamper-{}", rand::rngs::OsRng.next_u64()));
    fs::create_dir(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["executor-worker", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut client = Endpoint::provision_over_pipe(0, &mut input).unwrap();
    output.read_exact(&mut [0; 1]).unwrap();
    for epoch in 0..2 {
        let mut payload = [0; PAYLOAD_BYTES];
        payload[0] = 1;
        payload[1..5].copy_from_slice(&4u32.to_be_bytes());
        sign_fixture(&mut payload, epoch);
        let mut bytes = client.send(epoch, &payload).unwrap().as_bytes().to_vec();
        if epoch == 0 {
            bytes[ENVELOPE_BYTES - 1] ^= 1;
        }
        input.write_all(&bytes).unwrap();
        input.flush().unwrap();
        let mut response = [0; ENVELOPE_BYTES];
        output.read_exact(&mut response).unwrap();
        let result = client
            .receive(&Envelope::from_bytes(&response).unwrap())
            .unwrap();
        if epoch == 0 {
            assert_eq!(result[0], 1, "{}", fixture_diagnostics(&path));
            assert!(result[1..].iter().all(|&b| b == 0));
        } else {
            assert_eq!(result[0], 0, "{}", fixture_diagnostics(&path));
            assert_eq!(u32::from_le_bytes(result[1..5].try_into().unwrap()), 1);
        }
    }
    drop(input);
    assert!(bounded_exit(&mut child, Duration::from_secs(3)).success());
    assert_eq!(
        fs::read_to_string(path.join("storage-observer.jsonl"))
            .unwrap()
            .lines()
            .count(),
        2 * 16 * 8
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn eof_midway_through_multi_client_epoch_is_rejected() {
    use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, PAYLOAD_BYTES};
    use std::{
        io::{Read, Write},
        process::Stdio,
        time::Duration,
    };
    let path = std::env::temp_dir().join(format!(
        "oblivion-incomplete-{}",
        rand::rngs::OsRng.next_u64()
    ));
    fs::create_dir(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["executor-worker", path.to_str().unwrap(), "2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut first = Endpoint::provision_over_pipe(0, &mut input).unwrap();
    let _second = Endpoint::provision_over_pipe(1, &mut input).unwrap();
    output.read_exact(&mut [0; 1]).unwrap();
    input
        .write_all(first.send(0, &[0; PAYLOAD_BYTES]).unwrap().as_bytes())
        .unwrap();
    input.flush().unwrap();
    output.read_exact(&mut [0; ENVELOPE_BYTES]).unwrap();
    drop(input);
    assert!(!bounded_exit(&mut child, Duration::from_secs(3)).success());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn open_loop_arrivals_continue_while_executor_is_busy_and_queue_is_bounded() {
    let path = std::env::temp_dir().join(format!(
        "oblivion-openloop-{}",
        rand::rngs::OsRng.next_u64()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["open-loop", path.to_str().unwrap(), "2", "12", "1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture_diagnostics(&path)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("open-loop-summary.json")).unwrap()).unwrap();
    assert_eq!(summary["offered"], 12);
    assert!(summary["dropped"].as_u64().unwrap() > 0);
    assert_eq!(
        summary["admitted"].as_u64().unwrap() + summary["dropped"].as_u64().unwrap(),
        12
    );
    assert_eq!(summary["errors"], 0);
    assert!(summary["max_queue_wait_ns"].as_u64().unwrap() > 0);
    let offers: Vec<serde_json::Value> = fs::read_to_string(path.join("offered-arrivals.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let completions: Vec<serde_json::Value> =
        fs::read_to_string(path.join("open-loop-latencies.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    assert_eq!(offers.len(), 12);
    assert_eq!(
        completions.len() as u64,
        summary["admitted"].as_u64().unwrap()
    );
    assert!(
        offers.last().unwrap()["offered_ns"].as_u64().unwrap()
            < completions[0]["completed_ns"].as_u64().unwrap(),
        "arrivals must not wait for first execution"
    );
    assert_eq!(
        fs::read_to_string(path.join("storage-observer.jsonl"))
            .unwrap()
            .lines()
            .count(),
        completions.len() * 16 * 8
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn open_loop_underload_completes_every_offered_stateful_request() {
    let path = std::env::temp_dir().join(format!(
        "oblivion-openloop-low-{}",
        rand::rngs::OsRng.next_u64()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-server"))
        .args(["open-loop", path.to_str().unwrap(), "150", "4", "2"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture_diagnostics(&path)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("open-loop-summary.json")).unwrap()).unwrap();
    assert_eq!(summary["offered"], 4);
    assert_eq!(summary["admitted"], 4);
    assert_eq!(summary["successes"], 4);
    assert_eq!(summary["dropped"], 0);
    assert_eq!(summary["errors"], 0);
    #[cfg(target_os = "linux")]
    {
        assert!(summary["cpu_seconds_observed"].is_number());
        assert!(summary["peak_sampled_aggregate_rss_kib"].as_u64().unwrap() > 0);
    }
    fs::remove_dir_all(path).unwrap();
}
