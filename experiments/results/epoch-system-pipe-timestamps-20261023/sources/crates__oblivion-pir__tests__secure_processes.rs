use oblivion_pir::{
    QueryPair, recover,
    secure::{Client, Endpoint, Geometry},
};
use rand::RngCore;
use std::{
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

struct Worker {
    child: Child,
    file: PathBuf,
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.file);
    }
}
impl Worker {
    fn spawn(bytes: &[u8], geometry: Geometry, slot: u32) -> (Self, Client) {
        let file = std::env::temp_dir().join(format!(
            "oblivion-secure-pir-{}-{}.db",
            std::process::id(),
            rand::rngs::OsRng.next_u64()
        ));
        std::fs::write(&file, bytes).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_secure-pir-server"))
            .arg(&file)
            .arg(slot.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut worker = Self { child, file };
        let mut pipe = worker.child.stdin.take().unwrap();
        let endpoint = Endpoint::provision_over_pipe(slot, geometry, &mut pipe).unwrap();
        drop(pipe);
        let stdout = worker.child.stdout.take().unwrap();
        let (send, receive) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout.take(128))
                .read_line(&mut line)
                .map(|_| line);
            let _ = send.send(result);
        });
        let address: SocketAddr = receive
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let client = Client::new(address, endpoint, Duration::from_secs(3)).unwrap();
        (worker, client)
    }
}
use std::io::Read;

#[test]
fn private_pipe_bootstrap_large_process_retrieval_and_server_loss() {
    let geometry = Geometry::new(10_000, 1024).unwrap();
    let bytes: Vec<u8> = (0..10_000)
        .flat_map(|i| vec![(i % 251) as u8; 1024])
        .collect();
    let (_first, mut client_a) = Worker::spawn(&bytes, geometry, 0);
    let (mut second, mut client_b) = Worker::spawn(&bytes, geometry, 1);
    for index in [0, 7, 9999] {
        let query = QueryPair::generate(geometry.count(), index).unwrap();
        let a = client_a.request(0, &query.first).unwrap();
        let b = client_b.request(0, &query.second).unwrap();
        assert_eq!(recover(&a, &b).unwrap(), vec![(index % 251) as u8; 1024]);
    }
    second.child.kill().unwrap();
    second.child.wait().unwrap();
    assert!(
        client_b
            .request(1, &vec![0; geometry.query_bytes()])
            .is_err()
    );
}
