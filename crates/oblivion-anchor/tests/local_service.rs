#![cfg(unix)]

use oblivion_anchor::UnixAnchorClient;
use oblivion_registry::{RegistryCatalogAnchor, RegistryCatalogState, RegistryVersionAnchor};
use oblivion_store::{CheckpointAnchor, Config, FileBackend, PathOram, TrustedCheckpoint};
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[test]
fn cli_service_runs_as_process_with_restricted_socket_and_persistent_registry_cas() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "oblivion-anchor-service-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let socket = root.join("anchor.sock");
    let database = root.join("anchor.sqlite");
    let key_file = root.join("master.key");
    std::fs::write(&key_file, [0x38; 32]).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut service = Command::new(env!("CARGO_BIN_EXE_oblivion-anchor"))
        .args([
            "serve",
            socket.to_str().unwrap(),
            database.to_str().unwrap(),
            key_file.to_str().unwrap(),
            "0600",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut ready = false;
    for _ in 0..500 {
        if socket.exists() {
            ready = true;
            break;
        }
        if let Some(status) = service.try_wait().unwrap() {
            panic!("anchor service exited before readiness: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ready, "anchor service did not create its Unix socket");
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let mut registry = UnixAnchorClient::registry(&socket, "registry").unwrap();
    assert_eq!(registry.current_version().unwrap(), None);
    registry.compare_and_swap(None, 4).unwrap();
    assert_eq!(registry.current_version().unwrap(), Some(4));

    let mut catalog = UnixAnchorClient::catalog(&socket, "functions").unwrap();
    assert_eq!(catalog.current_catalog().unwrap(), None);
    let digest = [0x52; 32];
    catalog.compare_and_swap_catalog(None, 8, digest).unwrap();
    assert_eq!(
        catalog.current_catalog().unwrap(),
        Some(RegistryCatalogState::new(8, Some(digest)).unwrap())
    );

    service.kill().unwrap();
    service.wait().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_rejects_group_readable_master_key_before_binding_socket() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "oblivion-anchor-key-mode-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let socket = root.join("anchor.sock");
    let key_file = root.join("master.key");
    std::fs::write(&key_file, [0x38; 32]).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o640)).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_oblivion-anchor"))
        .args([
            "serve",
            socket.to_str().unwrap(),
            root.join("anchor.sqlite").to_str().unwrap(),
            key_file.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
    assert!(!socket.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_opens_master_key_without_following_symlinks() {
    use std::os::unix::fs::symlink;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "oblivion-anchor-key-link-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let socket = root.join("anchor.sock");
    let target = root.join("target.key");
    let key_file = root.join("master.key");
    std::fs::write(&target, [0x38; 32]).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &key_file).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-anchor"))
        .args([
            "serve",
            socket.to_str().unwrap(),
            root.join("anchor.sqlite").to_str().unwrap(),
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot open master key file"));
    assert!(!socket.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_rejects_master_key_files_with_non_32_byte_lengths() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "oblivion-anchor-key-length-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();

    for length in [0, 31, 33] {
        let socket = root.join(format!("anchor-{length}.sock"));
        let database = root.join(format!("anchor-{length}.sqlite"));
        let key_file = root.join(format!("master-{length}.key"));
        std::fs::write(&key_file, vec![0x38; length]).unwrap();
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oblivion-anchor"))
            .args([
                "serve",
                socket.to_str().unwrap(),
                database.to_str().unwrap(),
                key_file.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "length {length}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("exactly 32 raw bytes"));
        assert!(!socket.exists());
    }

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_rejects_symlink_database_path_before_binding_socket() {
    use std::os::unix::fs::symlink;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "oblivion-anchor-db-link-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let socket = root.join("anchor.sock");
    let target = root.join("target.sqlite");
    let database = root.join("anchor.sqlite");
    let key_file = root.join("master.key");
    std::fs::write(&target, b"keep this target untouched").unwrap();
    std::fs::write(&key_file, [0x38; 32]).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &database).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_oblivion-anchor"))
        .args([
            "serve",
            socket.to_str().unwrap(),
            database.to_str().unwrap(),
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("database path must refer to a regular file"),
        "executable {:?}, status {:?}, unexpected stderr: {:?}",
        env!("CARGO_BIN_EXE_oblivion-anchor"),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!socket.exists());
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"keep this target untouched"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_service_restart_recovers_a_real_path_oram_checkpoint() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "oblivion-anchor-oram-restart-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let socket = root.join("anchor.sock");
    let database = root.join("anchor.sqlite");
    let key_file = root.join("master.key");
    let snapshot = root.join("snapshot-1");
    std::fs::write(&key_file, [0x39; 32]).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let spawn_service = || {
        Command::new(env!("CARGO_BIN_EXE_oblivion-anchor"))
            .args([
                "serve",
                socket.to_str().unwrap(),
                database.to_str().unwrap(),
                key_file.to_str().unwrap(),
                "0600",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let wait_until_ready = |service: &mut std::process::Child| {
        for _ in 0..500 {
            if socket.exists() {
                return;
            }
            if let Some(status) = service.try_wait().unwrap() {
                panic!("anchor service exited before readiness: {status}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("anchor service did not create its Unix socket");
    };

    let mut service = spawn_service();
    wait_until_ready(&mut service);
    let config = Config::new(8, 16).unwrap();
    let mut store = PathOram::new(
        config.clone(),
        FileBackend::create(root.join("working-store"), &config).unwrap(),
    )
    .unwrap();
    store.write(3, &[0xa7; 16]).unwrap();
    let mut anchor = UnixAnchorClient::checkpoint(&socket, "oram-state").unwrap();
    let checkpoint = store
        .checkpoint_anchored(&snapshot, "snapshot-1", &mut anchor)
        .unwrap();
    assert_eq!(checkpoint.generation(), 1);

    service.kill().unwrap();
    service.wait().unwrap();
    std::fs::remove_file(&socket).unwrap();
    let mut service = spawn_service();
    wait_until_ready(&mut service);
    let mut anchor = UnixAnchorClient::checkpoint(&socket, "oram-state").unwrap();
    let record = anchor.load().unwrap().unwrap();
    let trusted = TrustedCheckpoint::from_secret_bytes(record.secret_handle()).unwrap();
    assert_eq!(record.snapshot_id(), "snapshot-1");
    assert_eq!(trusted.generation(), 1);
    let backend = FileBackend::create(root.join("recovered-store"), &config).unwrap();
    let mut restored = PathOram::restore(&snapshot, &trusted, backend).unwrap();
    assert_eq!(restored.read(3).unwrap(), vec![0xa7; 16]);

    service.kill().unwrap();
    service.wait().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
