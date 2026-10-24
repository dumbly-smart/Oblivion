#[cfg(unix)]
fn main() {
    if let Err(error) = run() {
        eprintln!("oblivion-anchor: {error}");
        std::process::exit(2);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("oblivion-anchor: Unix-domain sockets are required");
    std::process::exit(2);
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
    use zeroize::Zeroizing;

    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("usage: oblivion-anchor serve SOCKET DATABASE MASTER_KEY_FILE [0600|0660]");
        return Ok(());
    }
    if !(4..=5).contains(&args.len()) || args[0] != "serve" {
        return Err(
            "expected `serve SOCKET DATABASE MASTER_KEY_FILE [0600|0660]` (use --help)".into(),
        );
    }
    let socket = PathBuf::from(&args[1]);
    let database = PathBuf::from(&args[2]);
    let key_path = PathBuf::from(&args[3]);
    let socket_mode_arg = args
        .get(4)
        .map(|value| value.to_string_lossy().into_owned());
    let socket_mode = match socket_mode_arg.as_deref() {
        None | Some("0600") => 0o600,
        Some("0660") => 0o660,
        Some(_) => return Err("socket mode must be 0600 or 0660".into()),
    };
    let metadata = fs::symlink_metadata(&key_path)
        .map_err(|error| format!("cannot inspect master key file: {error}"))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("master key must be a regular file with no group/world permissions".into());
    }
    let key_bytes = Zeroizing::new(
        fs::read(&key_path).map_err(|error| format!("cannot read master key file: {error}"))?,
    );
    if key_bytes.len() != 32 {
        return Err("master key file must contain exactly 32 raw bytes".into());
    }
    let mut master_key = Zeroizing::new([0; 32]);
    master_key.copy_from_slice(&key_bytes);
    oblivion_anchor::serve_unix(socket, database, master_key, socket_mode)
        .map_err(|error| error.to_string())
}
