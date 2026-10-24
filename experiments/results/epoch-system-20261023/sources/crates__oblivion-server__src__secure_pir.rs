//! Local process adapter for the generic authenticated PIR session protocol.
//! Bootstrap keys cross inherited private pipes. OS processes are no hardware TEE.
use crate::{Result, pipeline::registry};
use oblivion_pir::{
    Database,
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
    pub fn spawn(slot: u32) -> Result<Self> {
        let database = Database::new(registry())?;
        let geometry = Geometry::new(database.count(), database.record_bytes())?;
        let mut command = Command::new(std::env::current_exe()?);
        command.args(["secure-pir-worker", &slot.to_string()]);
        Self::spawn_command(command, slot, geometry, TIMEOUT)
    }
    fn spawn_command(
        mut command: Command,
        slot: u32,
        geometry: Geometry,
        timeout: Duration,
    ) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let setup = (|| -> Result<Client> {
            let mut pipe = child.stdin.take().ok_or("missing bootstrap pipe")?;
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
        let _ = send.send(
            Endpoint::accept_bootstrap(slot, &mut std::io::stdin()).map_err(|e| e.to_string()),
        );
    });
    let mut endpoint = receive
        .recv_timeout(TIMEOUT)
        .map_err(|_| "PIR bootstrap timed out")??;
    let database = Database::new(registry())?;
    if endpoint.geometry() != Geometry::new(database.count(), database.record_bytes())? {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    #[test]
    fn startup_wait_is_bounded_and_child_is_reaped() {
        let mut command = Command::new("sh");
        command.args(["-c", "exec sleep 10"]);
        let start = Instant::now();
        assert!(
            Session::spawn_command(
                command,
                0,
                Geometry::new(1, 1).unwrap(),
                Duration::from_millis(50)
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn startup_rejects_unbounded_address_and_dead_child() {
        assert!(bounded_address(std::io::Cursor::new(vec![b'1'; 129]), TIMEOUT).is_err());
        let mut command = Command::new("sh");
        command.args(["-c", "exit 0"]);
        assert!(Session::spawn_command(command, 0, Geometry::new(1, 1).unwrap(), TIMEOUT).is_err());
    }
}
