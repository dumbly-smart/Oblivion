//! Generic local worker. Usage: secure-pir-server DATABASE SLOT.
//! Geometry and session keys arrive exclusively through inherited stdin.
use oblivion_pir::{
    Database,
    secure::{Endpoint, serve_connection},
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    time::Duration,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments.len() != 3 {
        return Err("usage: secure-pir-server DATABASE SLOT".into());
    }
    let slot = arguments[2].parse()?;
    let timeout = Duration::from_secs(2);
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = send.send(Endpoint::accept_bootstrap(slot, &mut std::io::stdin()));
    });
    let mut endpoint = receive.recv_timeout(timeout)??;
    let geometry = endpoint.geometry();
    let expected = geometry.count() * geometry.record_bytes();
    let mut file = std::fs::File::open(&arguments[1])?;
    if file.metadata()?.len() != expected as u64 {
        return Err("database size does not match trusted geometry".into());
    }
    let mut bytes = vec![0; expected];
    file.read_exact(&mut bytes)?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err("database changed during startup".into());
    }
    let database = Database::new(
        bytes
            .chunks_exact(geometry.record_bytes())
            .map(<[u8]>::to_vec)
            .collect(),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let _ = serve_connection(&mut stream, &database, &mut endpoint, timeout);
    }
    Ok(())
}
