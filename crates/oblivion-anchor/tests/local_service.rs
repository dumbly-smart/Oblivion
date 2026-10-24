#![cfg(unix)]

use oblivion_anchor::UnixAnchorClient;
use oblivion_registry::RegistryVersionAnchor;
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
