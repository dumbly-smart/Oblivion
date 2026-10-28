use std::{
    fs::{self, OpenOptions},
    io::Read,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
};

use oblivion_anchor::{AnchorDatabase, mtls_server_config_from_pem, serve_mtls};
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run() {
        eprintln!("oblivion-anchor-remote: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!(
            "usage: oblivion-anchor-remote serve ADDRESS DATABASE MASTER_KEY_FILE SERVER_CERT_PEM SERVER_KEY_PEM CLIENT_CA_PEM"
        );
        return Ok(());
    }
    if args.len() != 7 || args[0] != "serve" {
        return Err("expected `serve ADDRESS DATABASE MASTER_KEY_FILE SERVER_CERT_PEM SERVER_KEY_PEM CLIENT_CA_PEM` (use --help)".into());
    }

    let address: SocketAddr = args[1]
        .to_str()
        .ok_or_else(|| "listen address must be UTF-8".to_owned())?
        .parse()
        .map_err(|error| format!("invalid listen address: {error}"))?;
    let database_path = PathBuf::from(&args[2]);
    validate_database_path(&database_path)?;
    let master_key = read_master_key(Path::new(&args[3]))?;
    let tls = mtls_server_config_from_pem(&args[4], &args[5], &args[6])
        .map_err(|error| format!("invalid mutual-TLS configuration: {error}"))?;
    let database = AnchorDatabase::open(&database_path, master_key)
        .map_err(|error| format!("cannot open witness database: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&database_path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot restrict witness database permissions: {error}"))?;
    }
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("cannot bind witness listener: {error}"))?;
    serve_mtls(listener, database, tls).map_err(|error| error.to_string())
}

fn validate_database_path(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(
            "witness database path must be a regular file, not a symlink or special file".into(),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect witness database path: {error}")),
    }
}

fn read_master_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options
            .open(path)
            .map_err(|error| format!("cannot open witness master-key file: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("cannot inspect opened witness master-key file: {error}"))?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "witness master key must be a regular file with no group/world permissions".into(),
            );
        }
        read_exact_key(file)
    }
    #[cfg(not(unix))]
    {
        let file = options
            .open(path)
            .map_err(|error| format!("cannot open witness master-key file: {error}"))?;
        if !file
            .metadata()
            .map_err(|error| format!("cannot inspect witness master-key file: {error}"))?
            .file_type()
            .is_file()
        {
            return Err("witness master key must be a regular file".into());
        }
        read_exact_key(file)
    }
}

fn read_exact_key(mut file: impl Read) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0; 32]);
    file.read_exact(&mut *key).map_err(|error| {
        format!("witness master key must contain exactly 32 raw bytes: {error}")
    })?;
    let mut trailing = [0];
    if file
        .read(&mut trailing)
        .map_err(|error| format!("cannot finish reading witness master key: {error}"))?
        != 0
    {
        return Err("witness master key must contain exactly 32 raw bytes".into());
    }
    Ok(key)
}
