//! Local process adapter for the generic authenticated PIR session protocol.
//! Bootstrap keys cross inherited private pipes. OS processes are no hardware TEE.
use crate::Result;
use oblivion_pir::{
    Database, MAX_DATABASE_BYTES, MAX_RECORD_BYTES, MAX_RECORDS,
    secure::{Client, Endpoint, Geometry, serve_connection},
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(2);
const DATABASE_MAGIC: &[u8; 8] = b"OBLPIR01";
const DATABASE_HEADER_BYTES: usize = 16;

pub struct Session {
    child: Child,
    client: Client,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Session {
    pub fn spawn(slot: u32, records: &[Vec<u8>]) -> Result<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        command.args(["secure-pir-worker", &slot.to_string()]);
        Self::spawn_command(command, slot, records, TIMEOUT)
    }
    fn spawn_command(
        mut command: Command,
        slot: u32,
        records: &[Vec<u8>],
        timeout: Duration,
    ) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let setup = (|| -> Result<Client> {
            let mut pipe = child.stdin.take().ok_or("missing bootstrap pipe")?;
            let geometry = write_database(&mut pipe, records)?;
            let endpoint = Endpoint::provision_over_pipe(slot, geometry, &mut pipe)?;
            drop(pipe);
            let stdout = child.stdout.take().ok_or("missing address pipe")?;
            let address = bounded_address(stdout, timeout)?;
            Ok(Client::new(address, endpoint, timeout)?)
        })();
        match setup {
            Ok(client) => Ok(Self { child, client }),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }
    pub fn request(&mut self, epoch: u64, share: &[u8]) -> Result<Vec<u8>> {
        Ok(self.client.request(epoch, share)?)
    }
}

fn bounded_address(mut pipe: impl Read + Send + 'static, timeout: Duration) -> Result<SocketAddr> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| -> Result<SocketAddr> {
            let mut line = Vec::new();
            for _ in 0..128 {
                let mut byte = [0];
                pipe.read_exact(&mut byte)?;
                if byte[0] == b'\n' {
                    return Ok(std::str::from_utf8(&line)?.parse()?);
                }
                line.push(byte[0]);
            }
            Err("PIR address exceeds startup bound".into())
        })();
        let _ = send.send(result.map_err(|e| e.to_string()));
    });
    receive
        .recv_timeout(timeout)
        .map_err(|_| "PIR worker startup timed out")?
        .map_err(Into::into)
}

pub fn serve(slot: u32) -> Result<()> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| -> Result<_> {
            let mut input = std::io::stdin();
            let database = read_database(&mut input)?;
            let geometry = Geometry::new(database.count(), database.record_bytes())?;
            let endpoint = Endpoint::accept_bootstrap(slot, &mut input)?;
            Ok((database, geometry, endpoint))
        })()
        .map_err(|error| error.to_string());
        let _ = send.send(result);
    });
    let (database, geometry, mut endpoint) = receive
        .recv_timeout(TIMEOUT)
        .map_err(|_| "PIR bootstrap timed out")??;
    if geometry != Geometry::new(database.count(), database.record_bytes())?
        || endpoint.geometry() != geometry
    {
        return Err("PIR bootstrap geometry does not match database".into());
    }
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    listener.set_nonblocking(true)?;
    // Orphaned local workers release their socket after five seconds without
    // a connection. Every accepted stream separately has bounded protocol I/O.
    let mut last_connection = Instant::now();
    while last_connection.elapsed() < Duration::from_secs(5) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = serve_connection(&mut stream, &database, &mut endpoint, TIMEOUT);
                last_connection = Instant::now();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_database(writer: &mut impl Write, records: &[Vec<u8>]) -> Result<Geometry> {
    let database = Database::new(records.to_vec())?;
    let geometry = Geometry::new(database.count(), database.record_bytes())?;
    writer.write_all(DATABASE_MAGIC)?;
    writer.write_all(&u32::try_from(database.count())?.to_be_bytes())?;
    writer.write_all(&u32::try_from(database.record_bytes())?.to_be_bytes())?;
    for record in records {
        writer.write_all(record)?;
    }
    writer.flush()?;
    Ok(geometry)
}

fn read_database(reader: &mut impl Read) -> Result<Database> {
    let mut header = [0; DATABASE_HEADER_BYTES];
    reader.read_exact(&mut header)?;
    if &header[..8] != DATABASE_MAGIC {
        return Err("invalid PIR database bootstrap header".into());
    }
    let count = u32::from_be_bytes(header[8..12].try_into()?) as usize;
    let record_bytes = u32::from_be_bytes(header[12..16].try_into()?) as usize;
    let total_bytes = count
        .checked_mul(record_bytes)
        .ok_or("PIR database size overflow")?;
    if count == 0
        || count > MAX_RECORDS
        || record_bytes == 0
        || record_bytes > MAX_RECORD_BYTES
        || total_bytes > MAX_DATABASE_BYTES
    {
        return Err("PIR database exceeds configured bounds".into());
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let mut record = vec![0; record_bytes];
        reader.read_exact(&mut record)?;
        records.push(record);
    }
    Ok(Database::new(records)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn startup_wait_is_bounded_and_child_is_reaped() {
        let mut command = Command::new("sh");
        command.args(["-c", "exec sleep 10"]);
        let start = Instant::now();
        let records = [vec![0; 1]];
        assert!(Session::spawn_command(command, 0, &records, Duration::from_millis(50)).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn startup_rejects_unbounded_address_and_dead_child() {
        assert!(bounded_address(std::io::Cursor::new(vec![b'1'; 129]), TIMEOUT).is_err());
        let mut command = Command::new("sh");
        command.args(["-c", "exit 0"]);
        let records = [vec![0; 1]];
        assert!(Session::spawn_command(command, 0, &records, TIMEOUT).is_err());
    }

    #[test]
    fn database_bootstrap_rejects_invalid_dimensions_before_allocation() {
        let mut header = [0; DATABASE_HEADER_BYTES];
        header[..8].copy_from_slice(DATABASE_MAGIC);
        header[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        header[12..16].copy_from_slice(&160u32.to_be_bytes());
        assert!(read_database(&mut &header[..]).is_err());
    }
}
