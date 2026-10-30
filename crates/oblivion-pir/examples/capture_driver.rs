//! Dedicated loopback-only process workload. No keys or query shares are logged.
use oblivion_pir::{
    Database, QueryPair, recover,
    secure::{Client, Endpoint, Geometry, serve_connection},
};
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const COUNT: usize = 5;
const WIDTH: usize = 128;
const TIMEOUT: Duration = Duration::from_secs(2);
fn record(id: usize) -> Vec<u8> {
    (0..WIDTH)
        .map(|offset| (id as u8).wrapping_mul(29) ^ (offset as u8))
        .collect()
}
fn database() -> Result<Database> {
    Ok(Database::new((0..COUNT).map(record).collect())?)
}
fn unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos()
}
struct Session {
    child: Child,
    client: Client,
    address: SocketAddr,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Session {
    fn spawn(slot: u32) -> Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(["worker", &slot.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let setup = (|| -> Result<(Client, SocketAddr)> {
            let endpoint = Endpoint::provision_over_pipe(
                slot,
                Geometry::new(COUNT, WIDTH)?,
                &mut child.stdin.take().ok_or("missing stdin")?,
            )?;
            let stdout = child.stdout.take().ok_or("missing stdout")?;
            let (send, receive) = mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stdout);
                let mut line = String::new();
                let result = reader.read_line(&mut line).map(|_| line);
                let _ = send.send(result);
            });
            let line = receive.recv_timeout(TIMEOUT)??;
            if line.len() > 128 {
                return Err("address line oversized".into());
            }
            let address: SocketAddr = line.trim().parse()?;
            Ok((Client::new(address, endpoint, TIMEOUT)?, address))
        })();
        match setup {
            Ok((client, address)) => Ok(Self {
                child,
                client,
                address,
            }),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }
}
fn worker(slot: u32) -> Result<()> {
    let endpoint = Endpoint::accept_bootstrap(slot, &mut std::io::stdin())?;
    let mut endpoint = endpoint;
    let database = database()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    println!("{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    let mut last = Instant::now();
    while last.elapsed() < Duration::from_secs(5) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = serve_connection(&mut stream, &database, &mut endpoint, TIMEOUT);
                last = Instant::now();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn retrieve(first: &mut Client, second: &mut Client, step: u64, target: usize) -> Result<()> {
    let queries = QueryPair::generate(COUNT, target)?;
    let a = first.request(step, &queries.first)?;
    let b = second.request(step, &queries.second)?;
    if recover(&a, &b)? != record(target) {
        return Err("PIR plaintext oracle mismatch".into());
    }
    Ok(())
}
fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).is_some_and(|arg| arg == "worker") {
        return worker(args.get(2).ok_or("missing slot")?.parse()?);
    }
    if args.len() != 4 {
        return Err("usage: capture_driver NEW_OUTPUT_DIRECTORY QUERIES SEED".into());
    }
    let output = Path::new(&args[1]);
    let queries: usize = args[2].parse()?;
    let seed: u64 = args[3].parse()?;
    if !(10..=10000).contains(&queries) || !queries.is_multiple_of(COUNT) {
        return Err("queries must be 10..10000 and divisible by 5".into());
    }
    fs::create_dir(output)?;
    let mut first = Session::spawn(0)?;
    let mut second = Session::spawn(1)?;
    let geometry = Geometry::new(COUNT, WIDTH)?;
    println!(
        "{}",
        serde_json::json!({"ready":true,"ports":[first.address.port(),second.address.port()],"records":COUNT,"record_bytes":WIDTH,"query_frame_bytes":geometry.query_frame_bytes(),"answer_frame_bytes":geometry.answer_frame_bytes(),"queries":queries})
    );
    std::io::stdout().flush()?;
    let mut command = String::new();
    std::io::stdin().read_line(&mut command)?;
    if command.trim() != "continue" {
        return Err("capture parent did not continue".into());
    }
    let mut targets = (0..queries).map(|step| step % COUNT).collect::<Vec<_>>();
    targets.shuffle(&mut StdRng::seed_from_u64(seed));
    let mut truth = BufWriter::new(File::create(output.join("client-ground-truth.jsonl"))?);
    let mut frames = BufWriter::new(File::create(output.join("application-frames.jsonl"))?);
    let start = Instant::now();
    for (step, target) in targets.into_iter().enumerate() {
        let began = unix_ns();
        let timer = Instant::now();
        retrieve(&mut first.client, &mut second.client, step as u64, target)?;
        let ended = unix_ns();
        serde_json::to_writer(
            &mut truth,
            &serde_json::json!({"step":step,"target":target,"started_unix_ns":began,"finished_unix_ns":ended,"latency_ns":timer.elapsed().as_nanos()}),
        )?;
        writeln!(truth)?;
        serde_json::to_writer(
            &mut frames,
            &serde_json::json!({"step":step,"servers":2,"query_frame_bytes":geometry.query_frame_bytes(),"answer_frame_bytes":geometry.answer_frame_bytes(),"verified":true}),
        )?;
        writeln!(frames)?;
    }
    truth.flush()?;
    frames.flush()?;
    fs::write(
        output.join("client-summary.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"queries":queries,"verified":queries,"seed":seed,"records":COUNT,"record_bytes":WIDTH,"wall_ns":start.elapsed().as_nanos(),"query_frame_bytes":geometry.query_frame_bytes(),"answer_frame_bytes":geometry.answer_frame_bytes(),"scope":"two fresh OS-keyed loopback worker processes; inherited private key pipes; no TEE or independent operators"}),
        )?,
    )?;
    println!(
        "{}",
        serde_json::json!({"complete":true,"verified":queries})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_tcp_queries_match_oracle_with_both_fresh_keyed_servers() {
        let mut clients = Vec::new();
        let mut workers = Vec::new();
        for slot in 0..2 {
            let (client, mut server) =
                Endpoint::provision(slot, Geometry::new(COUNT, WIDTH).unwrap()).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            workers.push(std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                serve_connection(&mut stream, &database().unwrap(), &mut server, TIMEOUT).unwrap();
            }));
            clients.push(Client::new(address, client, TIMEOUT).unwrap());
        }
        let (mut first, mut second) = (clients.remove(0), clients.remove(0));
        retrieve(&mut first, &mut second, 0, 3).unwrap();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}
