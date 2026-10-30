use oblivion_pir::{Database, MAX_DATABASE_BYTES, wire::serve_connection};
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener},
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: pir-server LOOPBACK_ADDRESS DATABASE_FILE RECORD_BYTES".into());
    }
    let address: SocketAddr = args[1].parse()?;
    if !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback())
        && !matches!(address.ip(), IpAddr::V6(ip) if ip.is_loopback())
    {
        return Err("experimental unencrypted transport requires loopback".into());
    }
    let width: usize = args[3].parse()?;
    if width == 0 || width > oblivion_pir::MAX_RECORD_BYTES {
        return Err("invalid record width".into());
    }
    let mut bytes = Vec::new();
    File::open(&args[2])?
        .take(MAX_DATABASE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DATABASE_BYTES || bytes.len() % width != 0 {
        return Err("invalid database size".into());
    }
    let database = Database::new(bytes.chunks_exact(width).map(<[u8]>::to_vec).collect())?;
    let listener = TcpListener::bind(address)?;
    println!("{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        let _ = serve_connection(&mut stream, &database);
    }
    Ok(())
}
