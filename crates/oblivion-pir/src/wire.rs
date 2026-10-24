//! Local experimental protocol, v1. Header is 16 bytes: magic OBLP, version u16
//! big endian, kind u8 (1 query / 2 answer), reserved zero, count u32, width u32.
//! One request per TCP connection. No TLS, authentication, or replay defense;
//! intended for localhost isolated-server experiments only. Malformed input
//! closes the connection. This is not the final padded invocation protocol.
use crate::{Database, Error, dimensions};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

fn header(kind: u8, count: usize, width: usize) -> [u8; 16] {
    let mut h = [0; 16];
    h[..4].copy_from_slice(b"OBLP");
    h[4..6].copy_from_slice(&1u16.to_be_bytes());
    h[6] = kind;
    h[8..12].copy_from_slice(&(count as u32).to_be_bytes());
    h[12..16].copy_from_slice(&(width as u32).to_be_bytes());
    h
}

pub fn request(
    address: SocketAddr,
    count: usize,
    width: usize,
    query: &[u8],
) -> Result<Vec<u8>, Error> {
    dimensions(count, width)?;
    if query.len() != count.div_ceil(8) {
        return Err(Error::Shape);
    }
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(&header(1, count, width))?;
    stream.write_all(query)?;
    let mut h = [0; 16];
    stream.read_exact(&mut h)?;
    if h != header(2, count, width) {
        return Err(Error::Protocol);
    }
    let mut answer = vec![0; width];
    stream.read_exact(&mut answer)?;
    Ok(answer)
}

pub fn serve_connection(stream: &mut TcpStream, database: &Database) -> Result<(), Error> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut h = [0; 16];
    stream.read_exact(&mut h)?;
    if h != header(1, database.count(), database.record_bytes()) {
        return Err(Error::Protocol);
    }
    let mut query = vec![0; database.count().div_ceil(8)];
    stream.read_exact(&mut query)?;
    let answer = database.answer(&query)?;
    stream.write_all(&header(2, database.count(), database.record_bytes()))?;
    stream.write_all(&answer)?;
    Ok(())
}
