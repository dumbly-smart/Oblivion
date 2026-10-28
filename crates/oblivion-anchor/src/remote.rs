//! Mutual-TLS transport to an independently administered freshness witness.
//!
//! This service preserves the anchor database's durability assumptions. TLS
//! authenticates the peer and protects the network exchange; it does not make
//! the witness database rollback-resistant.

use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{Arc, mpsc::Receiver},
    thread,
    time::{Duration, Instant},
};

use rustls::{
    ClientConfig, RootCertStore, ServerConfig, StreamOwned,
    client::ClientConnection,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::ServerConnection,
    server::WebPkiClientVerifier,
};
use serde::{Deserialize, Serialize};

use crate::{AnchorDatabase, Error, SseJournalState};

const MAX_FRAME_BYTES: usize = 512 * 1024;
const PROTOCOL_VERSION: u8 = 1;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_POLL: Duration = Duration::from_millis(10);

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Load {
        slot: String,
    },
    CompareAndSwap {
        slot: String,
        expected_generation: Option<u64>,
        state: WireState,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Loaded { state: Option<WireState> },
    Updated,
    Error { code: WireError },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    version: u8,
    request: Request,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    version: u8,
    response: Response,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireState {
    index_id: Vec<u8>,
    generation: u64,
    digest: Vec<u8>,
}

impl From<SseJournalState> for WireState {
    fn from(state: SseJournalState) -> Self {
        Self {
            index_id: state.index_id().to_vec(),
            generation: state.generation(),
            digest: state.digest().to_vec(),
        }
    }
}

impl TryFrom<WireState> for SseJournalState {
    type Error = Error;

    fn try_from(state: WireState) -> Result<Self, Self::Error> {
        let index_id: [u8; 16] = state.index_id.try_into().map_err(|_| Error::Protocol)?;
        let digest: [u8; 32] = state.digest.try_into().map_err(|_| Error::Protocol)?;
        Self::new(index_id, state.generation, digest)
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireError {
    Conflict,
    CommitIndeterminate,
    Unavailable,
    Protocol,
}

/// Build a TLS server configuration that requires a client certificate from
/// `client_roots`. The supplied chain and key are the witness identity.
pub fn mtls_server_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    client_roots: RootCertStore,
) -> Result<Arc<ServerConfig>, Error> {
    if certificate_chain.is_empty() || client_roots.is_empty() {
        return Err(Error::Protocol);
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|error| Error::Socket(format!("invalid client certificate roots: {error}")))?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate_chain, private_key)
        .map_err(|error| Error::Socket(format!("invalid witness TLS identity: {error}")))?;
    Ok(Arc::new(config))
}

/// Build a TLS client configuration that authenticates the witness against
/// `server_roots` and presents the supplied client identity.
pub fn mtls_client_config(
    server_roots: RootCertStore,
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<ClientConfig>, Error> {
    if certificate_chain.is_empty() || server_roots.is_empty() {
        return Err(Error::Protocol);
    }
    let config = ClientConfig::builder()
        .with_root_certificates(server_roots)
        .with_client_auth_cert(certificate_chain, private_key)
        .map_err(|error| Error::Socket(format!("invalid client TLS identity: {error}")))?;
    Ok(Arc::new(config))
}

/// Load a witness certificate, private key, and the client CA roots from PEM
/// files. The private key must be a regular, non-symlink file with no
/// group/world permissions on Unix.
pub fn mtls_server_config_from_pem(
    certificate_path: impl AsRef<Path>,
    private_key_path: impl AsRef<Path>,
    client_ca_path: impl AsRef<Path>,
) -> Result<Arc<ServerConfig>, Error> {
    let certificates = read_certificates(certificate_path.as_ref())?;
    let private_key = read_private_key(private_key_path.as_ref())?;
    let roots = read_root_store(client_ca_path.as_ref())?;
    mtls_server_config(certificates, private_key, roots)
}

/// Load the witness CA roots, client certificate, and client private key from
/// PEM files. The private key must be a regular, non-symlink file with no
/// group/world permissions on Unix.
pub fn mtls_client_config_from_pem(
    server_ca_path: impl AsRef<Path>,
    certificate_path: impl AsRef<Path>,
    private_key_path: impl AsRef<Path>,
) -> Result<Arc<ClientConfig>, Error> {
    let roots = read_root_store(server_ca_path.as_ref())?;
    let certificates = read_certificates(certificate_path.as_ref())?;
    let private_key = read_private_key(private_key_path.as_ref())?;
    mtls_client_config(roots, certificates, private_key)
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let file = open_pem_file(path, false)?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Error::Socket(error.to_string()))?;
    if certificates.is_empty() {
        return Err(Error::Protocol);
    }
    Ok(certificates)
}

fn read_root_store(path: &Path) -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    for certificate in read_certificates(path)? {
        roots
            .add(certificate)
            .map_err(|error| Error::Socket(format!("invalid CA certificate: {error}")))?;
    }
    if roots.is_empty() {
        return Err(Error::Protocol);
    }
    Ok(roots)
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
    let file = open_pem_file(path, true)?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|error| Error::Socket(error.to_string()))?
        .ok_or(Error::Protocol)
}

fn open_pem_file(path: &Path, private: bool) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let file = options
            .open(path)
            .map_err(|error| Error::Socket(error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| Error::Socket(error.to_string()))?;
        if !metadata.file_type().is_file() {
            return Err(Error::Socket("TLS PEM path must be a regular file".into()));
        }
        if private && metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Socket(
                "private TLS key permissions must exclude group and other".into(),
            ));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        if std::fs::symlink_metadata(path)
            .map_err(|error| Error::Socket(error.to_string()))?
            .file_type()
            .is_symlink()
        {
            return Err(Error::Socket("TLS PEM path must not be a symlink".into()));
        }
        let file = options
            .open(path)
            .map_err(|error| Error::Socket(error.to_string()))?;
        if !file
            .metadata()
            .map_err(|error| Error::Socket(error.to_string()))?
            .file_type()
            .is_file()
        {
            return Err(Error::Socket("TLS PEM path must be a regular file".into()));
        }
        let _ = private;
        Ok(file)
    }
}

/// A synchronous SSE anchor client using a mutually authenticated TLS
/// connection. Each operation uses a fresh bounded connection and fails
/// closed if TLS, framing, or the witness protocol fails.
pub struct TlsSseJournalAnchor {
    address: SocketAddr,
    server_name: ServerName<'static>,
    slot: String,
    config: Arc<ClientConfig>,
}

impl TlsSseJournalAnchor {
    pub fn new(
        address: SocketAddr,
        server_name: &str,
        slot: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Self, Error> {
        super::validate_slot(slot)?;
        let server_name =
            ServerName::try_from(server_name.to_owned()).map_err(|_| Error::Protocol)?;
        Ok(Self {
            address,
            server_name,
            slot: slot.to_owned(),
            config,
        })
    }

    pub fn load(&mut self) -> Result<Option<SseJournalState>, Error> {
        match self.exchange(Request::Load {
            slot: self.slot.clone(),
        })? {
            Response::Loaded { state } => state.map(TryInto::try_into).transpose(),
            Response::Error { code } => Err(error_from_wire(code)),
            Response::Updated => Err(Error::Protocol),
        }
    }

    pub fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        state: SseJournalState,
    ) -> Result<(), Error> {
        match self.exchange(Request::CompareAndSwap {
            slot: self.slot.clone(),
            expected_generation,
            state: state.into(),
        })? {
            Response::Updated => Ok(()),
            Response::Error { code } => Err(error_from_wire(code)),
            Response::Loaded { .. } => Err(Error::Protocol),
        }
    }

    fn exchange(&self, request: Request) -> Result<Response, Error> {
        let frame = serde_json::to_vec(&RequestEnvelope {
            version: PROTOCOL_VERSION,
            request,
        })
        .map_err(|_| Error::Protocol)?;
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err(Error::Protocol);
        }
        let stream = TcpStream::connect_timeout(&self.address, IO_TIMEOUT)
            .map_err(|error| Error::Socket(error.to_string()))?;
        let stream = DeadlineStream::with_timeout(stream, IO_TIMEOUT);
        let connection = ClientConnection::new(self.config.clone(), self.server_name.clone())
            .map_err(|error| Error::Socket(error.to_string()))?;
        let mut stream = StreamOwned::new(connection, stream);
        write_frame(&mut stream, &frame)?;
        let response = read_frame(&mut stream)?;
        let response: ResponseEnvelope =
            serde_json::from_slice(&response).map_err(|_| Error::Protocol)?;
        if response.version != PROTOCOL_VERSION {
            return Err(Error::Protocol);
        }
        Ok(response.response)
    }
}

/// Serve TLS anchor requests until `shutdown` receives a message. The listener
/// is polled so a shutdown request is observed even when the service is idle.
pub fn serve_mtls_with_shutdown(
    listener: TcpListener,
    mut database: AnchorDatabase,
    config: Arc<ServerConfig>,
    shutdown: Receiver<()>,
) -> Result<(), Error> {
    serve_mtls_inner(listener, &mut database, config, Some(shutdown))
}

/// Serve TLS anchor requests indefinitely. Use
/// [`serve_mtls_with_shutdown`] when the caller needs orderly shutdown.
pub fn serve_mtls(
    listener: TcpListener,
    mut database: AnchorDatabase,
    config: Arc<ServerConfig>,
) -> Result<(), Error> {
    serve_mtls_inner(listener, &mut database, config, None)
}

fn serve_mtls_inner(
    listener: TcpListener,
    database: &mut AnchorDatabase,
    config: Arc<ServerConfig>,
    shutdown: Option<Receiver<()>>,
) -> Result<(), Error> {
    listener
        .set_nonblocking(true)
        .map_err(|error| Error::Socket(error.to_string()))?;
    loop {
        if let Some(receiver) = &shutdown {
            match receiver.try_recv() {
                Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(()),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        match listener.accept() {
            Ok((stream, _peer)) => {
                let _ = serve_connection(stream, database, &config);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Socket(error.to_string())),
        }
    }
}

fn serve_connection(
    stream: TcpStream,
    database: &mut AnchorDatabase,
    config: &Arc<ServerConfig>,
) -> Result<(), Error> {
    let stream = DeadlineStream::with_timeout(stream, IO_TIMEOUT);
    let connection =
        ServerConnection::new(config.clone()).map_err(|error| Error::Socket(error.to_string()))?;
    let mut stream = StreamOwned::new(connection, stream);
    let request_bytes = read_frame(&mut stream)?;
    let response = match decode_request(&request_bytes) {
        Ok(request) => serve_request(database, request),
        Err(code) => Response::Error { code },
    };
    let frame = serde_json::to_vec(&ResponseEnvelope {
        version: PROTOCOL_VERSION,
        response,
    })
    .map_err(|_| Error::Protocol)?;
    write_frame(&mut stream, &frame)?;
    stream
        .flush()
        .map_err(|error| Error::Socket(error.to_string()))
}

fn decode_request(frame: &[u8]) -> Result<Request, WireError> {
    match serde_json::from_slice::<RequestEnvelope>(frame) {
        Ok(envelope) if envelope.version == PROTOCOL_VERSION => Ok(envelope.request),
        _ => Err(WireError::Protocol),
    }
}

fn serve_request(database: &mut AnchorDatabase, request: Request) -> Response {
    match request {
        Request::Load { slot } => match database
            .sse_journal_anchor(&slot)
            .and_then(|mut anchor| anchor.load())
        {
            Ok(state) => Response::Loaded {
                state: state.map(Into::into),
            },
            Err(error) => Response::Error {
                code: wire_from_error(error),
            },
        },
        Request::CompareAndSwap {
            slot,
            expected_generation,
            state,
        } => {
            let state = match SseJournalState::try_from(state) {
                Ok(state) => state,
                Err(_) => {
                    return Response::Error {
                        code: WireError::Protocol,
                    };
                }
            };
            match database
                .sse_journal_anchor(&slot)
                .and_then(|mut anchor| anchor.compare_and_swap(expected_generation, state))
            {
                Ok(()) => Response::Updated,
                Err(error) => Response::Error {
                    code: wire_from_error(error),
                },
            }
        }
    }
}

fn wire_from_error(error: Error) -> WireError {
    match error {
        Error::Conflict => WireError::Conflict,
        Error::CommitIndeterminate => WireError::CommitIndeterminate,
        Error::Protocol | Error::InvalidSlot => WireError::Protocol,
        _ => WireError::Unavailable,
    }
}

fn error_from_wire(error: WireError) -> Error {
    match error {
        WireError::Conflict => Error::Conflict,
        WireError::CommitIndeterminate => Error::CommitIndeterminate,
        WireError::Unavailable => Error::Socket("remote anchor unavailable".into()),
        WireError::Protocol => Error::Protocol,
    }
}

fn read_frame(stream: &mut (impl Read + Write)) -> Result<Vec<u8>, Error> {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .map_err(|error| Error::Socket(error.to_string()))?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(Error::Protocol);
    }
    let mut frame = vec![0; length];
    stream
        .read_exact(&mut frame)
        .map_err(|error| Error::Socket(error.to_string()))?;
    Ok(frame)
}

fn write_frame(stream: &mut (impl Read + Write), frame: &[u8]) -> Result<(), Error> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(Error::Protocol);
    }
    let length = u32::try_from(frame.len()).map_err(|_| Error::Protocol)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(frame))
        .map_err(|error| Error::Socket(error.to_string()))
}

/// TCP transport with absolute per-connection read and write deadlines.
///
/// `TcpStream::set_*_timeout` alone bounds each blocking syscall, so a peer
/// that sends one byte just before each timeout can keep a serial listener
/// occupied indefinitely. Recompute the socket timeout from a fixed deadline
/// before every syscall to bound the whole TLS handshake and frame exchange.
struct DeadlineStream {
    stream: TcpStream,
    read_deadline: Instant,
    write_deadline: Instant,
}

impl DeadlineStream {
    fn with_timeout(stream: TcpStream, timeout: Duration) -> Self {
        let deadline = Instant::now() + timeout;
        Self {
            stream,
            read_deadline: deadline,
            write_deadline: deadline,
        }
    }

    fn remaining(deadline: Instant) -> std::io::Result<Duration> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection I/O deadline exceeded",
            ))
        } else {
            Ok(remaining)
        }
    }

    fn map_timeout(error: std::io::Error) -> std::io::Error {
        if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection I/O deadline exceeded",
            )
        } else {
            error
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = Self::remaining(self.read_deadline)?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer).map_err(Self::map_timeout)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = Self::remaining(self.write_deadline)?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buffer).map_err(Self::map_timeout)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let remaining = Self::remaining(self.write_deadline)?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.flush().map_err(Self::map_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::{Request, WireError, decode_request};

    #[test]
    fn slow_chunked_frame_cannot_extend_total_read_deadline() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            thread,
            time::Duration,
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let mut client =
            TcpStream::connect(listener.local_addr().expect("address")).expect("client connection");
        let (server, _) = listener.accept().expect("server connection");
        let reader = thread::spawn(move || {
            let mut stream =
                super::DeadlineStream::with_timeout(server, Duration::from_millis(400));
            let mut frame = [0; 3];
            stream.read_exact(&mut frame)
        });

        client.write_all(b"a").expect("first byte");
        thread::sleep(Duration::from_millis(250));
        client.write_all(b"b").expect("second byte");
        thread::sleep(Duration::from_millis(250));
        let _ = client.write_all(b"c");

        let error = reader.join().expect("reader thread").expect_err("deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn remote_protocol_requires_version_and_rejects_unknown_fields() {
        let valid = br#"{"version":1,"request":{"operation":"load","slot":"sse-slot"}}"#;
        assert!(matches!(
            decode_request(valid),
            Ok(Request::Load { slot }) if slot == "sse-slot"
        ));

        let unsupported = br#"{"version":2,"request":{"operation":"load","slot":"sse-slot"}}"#;
        assert!(matches!(
            decode_request(unsupported),
            Err(WireError::Protocol)
        ));

        let missing_version = br#"{"request":{"operation":"load","slot":"sse-slot"}}"#;
        assert!(matches!(
            decode_request(missing_version),
            Err(WireError::Protocol)
        ));

        let unknown_field =
            br#"{"version":1,"request":{"operation":"load","slot":"sse-slot","extra":true}}"#;
        assert!(matches!(
            decode_request(unknown_field),
            Err(WireError::Protocol)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn tls_pem_key_open_rejects_symlinks_and_group_readable_files() {
        use std::{
            fs,
            os::unix::fs::{PermissionsExt, symlink},
            time::{SystemTime, UNIX_EPOCH},
        };

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("oblivion-tls-pem-{}-{unique}", std::process::id()));
        fs::create_dir(&root).expect("test directory");
        let key = root.join("key.pem");
        fs::write(&key, b"test-only-key").expect("test key file");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("key mode");
        assert!(super::open_pem_file(&key, true).is_err());

        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("private key mode");
        let link = root.join("key-link.pem");
        symlink(&key, &link).expect("key symlink");
        assert!(super::open_pem_file(&link, true).is_err());

        let _ = fs::remove_dir_all(root);
    }
}
