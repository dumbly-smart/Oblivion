//! Bounded authenticated PIR sessions. Geometry and traffic sizes are public.
//! Fresh session secrets must cross a trusted channel (the pipe helpers do this
//! for local child processes). This provides no server non-collusion or TEE.
use crate::{Database, Error, dimensions};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub const HEADER_BYTES: usize = 36;
pub const TAG_BYTES: usize = 16;
const BOOTSTRAP_BYTES: usize = 52;
const VERSION: u16 = 1;

/// Validated, public geometry. All payload allocations use these trusted bounds,
/// never dimensions or lengths supplied by a network peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    count: usize,
    width: usize,
}
impl Geometry {
    pub fn new(count: usize, width: usize) -> Result<Self, Error> {
        dimensions(count, width)?;
        Ok(Self { count, width })
    }
    pub fn count(self) -> usize {
        self.count
    }
    pub fn record_bytes(self) -> usize {
        self.width
    }
    pub fn query_bytes(self) -> usize {
        self.count.div_ceil(8)
    }
    pub fn query_frame_bytes(self) -> usize {
        HEADER_BYTES + TAG_BYTES + self.query_bytes()
    }
    pub fn answer_frame_bytes(self) -> usize {
        HEADER_BYTES + TAG_BYTES + self.width
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}
#[derive(Clone, Copy)]
struct Request {
    sequence: u64,
    epoch: u64,
}

/// One ordered session, with one outstanding request. Secret keys deliberately
/// have no Debug or serialization implementation. Create a new session after
/// restoring a process snapshot; sequence state must never roll back.
pub struct Endpoint {
    geometry: Geometry,
    slot: u32,
    query_cipher: ChaCha20Poly1305,
    answer_cipher: ChaCha20Poly1305,
    role: Role,
    next_sequence: u64,
    received_sequence: Option<u64>,
    pending: Option<Request>,
}
impl Endpoint {
    fn from_root(
        root: &[u8; 32],
        slot: u32,
        geometry: Geometry,
        role: Role,
    ) -> Result<Self, Error> {
        let hk = Hkdf::<Sha256>::new(Some(b"oblivion-pir-secure-v1"), root);
        let mut query_key = [0; 32];
        let mut answer_key = [0; 32];
        hk.expand(b"client-to-server query", &mut query_key)
            .map_err(|_| Error::Protocol)?;
        hk.expand(b"server-to-client answer", &mut answer_key)
            .map_err(|_| Error::Protocol)?;
        Ok(Self {
            geometry,
            slot,
            query_cipher: ChaCha20Poly1305::new((&query_key).into()),
            answer_cipher: ChaCha20Poly1305::new((&answer_key).into()),
            role,
            next_sequence: 0,
            received_sequence: None,
            pending: None,
        })
    }
    pub fn provision(slot: u32, geometry: Geometry) -> Result<(Self, Self), Error> {
        let mut root = [0; 32];
        OsRng
            .try_fill_bytes(&mut root)
            .map_err(|_| Error::Randomness)?;
        Ok((
            Self::from_root(&root, slot, geometry, Role::Client)?,
            Self::from_root(&root, slot, geometry, Role::Server)?,
        ))
    }
    /// Writes only to an inherited private pipe; never route this to TCP/logs.
    pub fn provision_over_pipe(
        slot: u32,
        geometry: Geometry,
        pipe: &mut impl Write,
    ) -> Result<Self, Error> {
        let mut root = [0; 32];
        OsRng
            .try_fill_bytes(&mut root)
            .map_err(|_| Error::Randomness)?;
        let mut bytes = [0; BOOTSTRAP_BYTES];
        bytes[..4].copy_from_slice(b"OPBS");
        bytes[4..6].copy_from_slice(&VERSION.to_be_bytes());
        bytes[8..12].copy_from_slice(&slot.to_be_bytes());
        bytes[12..16].copy_from_slice(&(geometry.count as u32).to_be_bytes());
        bytes[16..20].copy_from_slice(&(geometry.width as u32).to_be_bytes());
        bytes[20..].copy_from_slice(&root);
        pipe.write_all(&bytes)?;
        pipe.flush()?;
        Self::from_root(&root, slot, geometry, Role::Client)
    }
    /// The caller must bound reads from the private bootstrap pipe; this helper
    /// reads exactly 52 bytes and validates dimensions before payload allocation.
    pub fn accept_bootstrap(slot: u32, pipe: &mut impl Read) -> Result<Self, Error> {
        let mut bytes = [0; BOOTSTRAP_BYTES];
        pipe.read_exact(&mut bytes)?;
        if &bytes[..4] != b"OPBS"
            || bytes[4..6] != VERSION.to_be_bytes()
            || bytes[6..8] != [0; 2]
            || bytes[8..12] != slot.to_be_bytes()
        {
            return Err(Error::Protocol);
        }
        let geometry = Geometry::new(
            u32::from_be_bytes(bytes[12..16].try_into().unwrap()) as usize,
            u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize,
        )?;
        Self::from_root(
            bytes[20..].try_into().unwrap(),
            slot,
            geometry,
            Role::Server,
        )
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    fn header(&self, kind: u8, request: Request) -> [u8; HEADER_BYTES] {
        let mut h = [0; HEADER_BYTES];
        h[..4].copy_from_slice(b"OPIR");
        h[4..6].copy_from_slice(&VERSION.to_be_bytes());
        h[6] = kind;
        h[8..12].copy_from_slice(&self.slot.to_be_bytes());
        h[12..16].copy_from_slice(&(self.geometry.count as u32).to_be_bytes());
        h[16..20].copy_from_slice(&(self.geometry.width as u32).to_be_bytes());
        h[20..28].copy_from_slice(&request.sequence.to_be_bytes());
        h[28..36].copy_from_slice(&request.epoch.to_be_bytes());
        h
    }
    fn seal(&self, kind: u8, request: Request, body: &[u8]) -> Result<Vec<u8>, Error> {
        let h = self.header(kind, request);
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&request.sequence.to_be_bytes());
        let cipher = if kind == 1 {
            &self.query_cipher
        } else {
            &self.answer_cipher
        };
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad: &h })
            .map_err(|_| Error::Authentication)?;
        let mut frame = Vec::with_capacity(h.len() + ciphertext.len());
        frame.extend_from_slice(&h);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }
    fn open(&self, kind: u8, frame: &[u8]) -> Result<(Request, Vec<u8>), Error> {
        let expected = if kind == 1 {
            self.geometry.query_frame_bytes()
        } else {
            self.geometry.answer_frame_bytes()
        };
        if frame.len() != expected {
            return Err(Error::Shape);
        }
        let request = Request {
            sequence: u64::from_be_bytes(frame[20..28].try_into().unwrap()),
            epoch: u64::from_be_bytes(frame[28..36].try_into().unwrap()),
        };
        if frame[..HEADER_BYTES] != self.header(kind, request) {
            return Err(Error::Protocol);
        }
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&request.sequence.to_be_bytes());
        let cipher = if kind == 1 {
            &self.query_cipher
        } else {
            &self.answer_cipher
        };
        let body = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &frame[HEADER_BYTES..],
                    aad: &frame[..HEADER_BYTES],
                },
            )
            .map_err(|_| Error::Authentication)?;
        Ok((request, body))
    }
    pub fn seal_query(&mut self, epoch: u64, query: &[u8]) -> Result<Vec<u8>, Error> {
        if self.role != Role::Client || self.pending.is_some() {
            return Err(Error::Sequence);
        }
        if query.len() != self.geometry.query_bytes() {
            return Err(Error::Shape);
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or(Error::Sequence)?;
        let request = Request { sequence, epoch };
        let frame = self.seal(1, request, query)?;
        self.pending = Some(request);
        Ok(frame)
    }
    pub fn open_query(&mut self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        if self.role != Role::Server || self.pending.is_some() {
            return Err(Error::Sequence);
        }
        let (request, body) = self.open(1, frame)?;
        if self
            .received_sequence
            .is_some_and(|last| request.sequence <= last)
        {
            return Err(Error::Sequence);
        }
        self.received_sequence = Some(request.sequence);
        self.pending = Some(request);
        Ok(body)
    }
    pub fn seal_answer(&mut self, answer: &[u8]) -> Result<Vec<u8>, Error> {
        if self.role != Role::Server {
            return Err(Error::Sequence);
        }
        if answer.len() != self.geometry.width {
            return Err(Error::Shape);
        }
        let request = self.pending.ok_or(Error::Sequence)?;
        let frame = self.seal(2, request, answer)?;
        self.pending = None;
        Ok(frame)
    }
    pub fn open_answer(&mut self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        if self.role != Role::Client {
            return Err(Error::Sequence);
        }
        let expected = self.pending.ok_or(Error::Sequence)?;
        let (request, body) = self.open(2, frame)?;
        if request.sequence != expected.sequence || request.epoch != expected.epoch {
            return Err(Error::Sequence);
        }
        self.pending = None;
        Ok(body)
    }
    /// Abandon a failed exchange without reusing its nonce. Late answers cannot
    /// satisfy a later request, even if the application reuses an epoch number.
    pub fn abandon(&mut self) {
        self.pending = None;
    }
}

/// Reusable generic TCP client; one connection per request. A failed exchange
/// consumes its sequence number. Timeouts bound the whole read/write exchange.
pub struct Client {
    address: SocketAddr,
    endpoint: Endpoint,
    timeout: Duration,
}
impl Client {
    pub fn new(address: SocketAddr, endpoint: Endpoint, timeout: Duration) -> Result<Self, Error> {
        if endpoint.role != Role::Client || timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(Error::Protocol);
        }
        Ok(Self {
            address,
            endpoint,
            timeout,
        })
    }
    pub fn geometry(&self) -> Geometry {
        self.endpoint.geometry
    }
    pub fn request(&mut self, epoch: u64, query: &[u8]) -> Result<Vec<u8>, Error> {
        let frame = self.endpoint.seal_query(epoch, query)?;
        let result = (|| {
            let deadline = Instant::now() + self.timeout;
            let mut stream = TcpStream::connect_timeout(&self.address, remaining(deadline)?)?;
            write_frame(&mut stream, &frame, deadline)?;
            let answer = read_frame(
                &mut stream,
                self.endpoint.geometry.answer_frame_bytes(),
                deadline,
            )?;
            self.endpoint.open_answer(&answer)
        })();
        if result.is_err() {
            self.endpoint.abandon();
        }
        result
    }
}

pub fn serve_connection(
    stream: &mut TcpStream,
    database: &Database,
    endpoint: &mut Endpoint,
    timeout: Duration,
) -> Result<(), Error> {
    if endpoint.role != Role::Server
        || endpoint.geometry != Geometry::new(database.count(), database.record_bytes())?
        || timeout.is_zero()
        || timeout > Duration::from_secs(60)
    {
        return Err(Error::Protocol);
    }
    let deadline = Instant::now() + timeout;
    let frame = read_frame(stream, endpoint.geometry.query_frame_bytes(), deadline)?;
    let query = endpoint.open_query(&frame)?;
    // Authentication and replay validation precede the database scan.
    let answer = match database.answer(&query) {
        Ok(answer) => answer,
        Err(e) => {
            endpoint.abandon();
            return Err(e);
        }
    };
    let frame = endpoint.seal_answer(&answer)?;
    write_frame(stream, &frame, deadline)
}
fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "PIR exchange deadline exceeded",
            )
            .into()
        })
}
fn read_frame(stream: &mut TcpStream, size: usize, deadline: Instant) -> Result<Vec<u8>, Error> {
    let mut frame = vec![0; size];
    let mut offset = 0;
    while offset < size {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let read = stream.read(&mut frame[offset..])?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        offset += read;
    }
    Ok(frame)
}
fn write_frame(stream: &mut TcpStream, frame: &[u8], deadline: Instant) -> Result<(), Error> {
    let mut offset = 0;
    while offset < frame.len() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let written = stream.write(&frame[offset..])?;
        if written == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
        }
        offset += written;
    }
    Ok(())
}
