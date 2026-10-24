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
    use std::{
        fs::OpenOptions,
        io::Read,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::PathBuf,
    };
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
    // Open without following a symlink, and use nonblocking mode so a FIFO or
    // device path cannot hang startup before descriptor validation.
    let mut key_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&key_path)
        .map_err(|error| format!("cannot open master key file: {error}"))?;
    let metadata = key_file
        .metadata()
        .map_err(|error| format!("cannot inspect opened master key file: {error}"))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("master key must be a regular file with no group/world permissions".into());
    }
    let mut key_bytes = Zeroizing::new([0; 32]);
    key_file
        .read_exact(&mut *key_bytes)
        .map_err(|error| format!("master key file must contain exactly 32 raw bytes: {error}"))?;
    let mut trailing = [0];
    if key_file
        .read(&mut trailing)
        .map_err(|error| format!("cannot finish reading master key file: {error}"))?
        != 0
    {
        return Err("master key file must contain exactly 32 raw bytes".into());
    }
    let mut master_key = Zeroizing::new([0; 32]);
    master_key.copy_from_slice(&*key_bytes);
    oblivion_anchor::serve_unix(socket, database, master_key, socket_mode)
        .map_err(|error| error.to_string())
}
