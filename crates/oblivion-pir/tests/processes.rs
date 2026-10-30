use oblivion_pir::{QueryPair, recover, wire};
use rand::RngCore;
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

struct Server {
    child: Child,
    file: PathBuf,
    address: SocketAddr,
}
impl Server {
    fn start(bytes: &[u8], width: usize) -> Self {
        let file = std::env::temp_dir().join(format!(
            "oblivion-pir-{}-{}.db",
            std::process::id(),
            rand::rngs::OsRng.next_u64()
        ));
        fs::write(&file, bytes).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_pir-server"))
            .args(["127.0.0.1:0", file.to_str().unwrap(), &width.to_string()])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address = line.trim().parse().unwrap();
        Self {
            child,
            file,
            address,
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.file);
    }
}

#[test]
fn separate_process_retrieval_malformed_request_and_server_failure() {
    let records: Vec<u8> = (0..19).flat_map(|i| vec![i; 128]).collect();
    let first = Server::start(&records, 128);
    let mut second = Server::start(&records, 128);
    for index in [0, 7, 18] {
        let queries = QueryPair::generate(19, index).unwrap();
        let a = wire::request(first.address, 19, 128, &queries.first).unwrap();
        let b = wire::request(second.address, 19, 128, &queries.second).unwrap();
        assert_eq!(recover(&a, &b).unwrap(), vec![index as u8; 128]);
    }
    let mut bad = TcpStream::connect(first.address).unwrap();
    bad.set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    bad.write_all(&[0; 16]).unwrap();
    bad.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    bad.read_to_end(&mut response).unwrap();
    assert!(response.is_empty());
    let query = QueryPair::generate(19, 3).unwrap();
    assert_eq!(
        wire::request(first.address, 19, 128, &query.first)
            .unwrap()
            .len(),
        128
    );
    second.child.kill().unwrap();
    second.child.wait().unwrap();
    assert!(wire::request(second.address, 19, 128, &query.second).is_err());
}
