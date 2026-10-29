//! Mutual-TLS transport to an independently administered freshness witness.
//!
//! This service preserves the anchor database's durability assumptions. TLS
//! authenticates the peer and protects the network exchange; it does not make
//! the witness database rollback-resistant.

use std::{
    collections::{HashMap, HashSet},
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
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AnchorDatabase, Error, InvocationReceipt, MAX_INVOCATION_RESPONSE_BYTES, SignedInvocationId,
    SseJournalState,
};
use oblivion_registry::{RegistryCatalogAnchor, RegistryCatalogState};
use oblivion_store::{
    CheckpointAnchor, CheckpointAnchorRecord, Error as StoreError, TRUSTED_CHECKPOINT_HANDLE_BYTES,
};

const MAX_FRAME_BYTES: usize = 512 * 1024;
const MAX_AUTHORIZATION_POLICY_BYTES: usize = 1024 * 1024;
const PROTOCOL_VERSION: u8 = 3;
const INVOCATION_SLOT_BYTES: usize = 128;
const INVOCATION_SNAPSHOT_ID_BYTES: usize = 128;
const INVOCATION_GENERATION_DIGITS: usize = 20;
const INVOCATION_CAPACITY_DIGITS: usize = 5;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_POLL: Duration = Duration::from_millis(10);

/// Errors while loading the witness's certificate-to-slot authorization file.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationPolicyError {
    #[error("could not read authorization policy: {0}")]
    Io(#[from] std::io::Error),
    #[error("authorization policy file is unsafe: {0}")]
    File(String),
    #[error("authorization policy file must not be writable by group or other")]
    WritableFile,
    #[error("authorization policy exceeds the 1 MiB limit")]
    TooLarge,
    #[error("authorization policy JSON is malformed or contains invalid grants")]
    InvalidDocument,
    #[error("authorization policy version is unsupported")]
    UnsupportedVersion,
    #[error("authorization policy must contain at least one client grant")]
    Empty,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationPolicyDocument {
    version: u8,
    clients: Vec<AuthorizationClient>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationClient {
    certificate_sha256: String,
    slots: Vec<String>,
}

/// Exact leaf-certificate SHA-256 fingerprint to remote-anchor-slot grants.
///
/// The policy is immutable while the listener runs. Updating grants requires
/// changing the policy file and restarting the witness.
#[derive(Clone, Debug, Default)]
pub struct ClientAuthorizationPolicy {
    grants: HashMap<[u8; 32], HashSet<String>>,
}

impl ClientAuthorizationPolicy {
    /// Load a version-1 JSON policy, rejecting oversized or empty policies.
    pub fn from_file(path: &Path) -> Result<Self, AuthorizationPolicyError> {
        let mut bytes = Vec::new();
        let file = open_pem_file(path, false)
            .map_err(|error| AuthorizationPolicyError::File(error.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file.metadata()?.permissions().mode() & 0o022 != 0 {
                return Err(AuthorizationPolicyError::WritableFile);
            }
        }
        file.take((MAX_AUTHORIZATION_POLICY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_AUTHORIZATION_POLICY_BYTES {
            return Err(AuthorizationPolicyError::TooLarge);
        }
        Self::from_json(&bytes)
    }

    /// Parse a version-1 JSON policy. Fingerprints are 64 lowercase hex
    /// characters for the complete DER-encoded leaf certificate.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorizationPolicyError> {
        if bytes.len() > MAX_AUTHORIZATION_POLICY_BYTES {
            return Err(AuthorizationPolicyError::TooLarge);
        }
        let document: AuthorizationPolicyDocument =
            serde_json::from_slice(bytes).map_err(|_| AuthorizationPolicyError::InvalidDocument)?;
        if document.version != 1 {
            return Err(AuthorizationPolicyError::UnsupportedVersion);
        }
        if document.clients.is_empty() {
            return Err(AuthorizationPolicyError::Empty);
        }

        let mut grants = HashMap::with_capacity(document.clients.len());
        for client in document.clients {
            let fingerprint = parse_certificate_fingerprint(&client.certificate_sha256)
                .ok_or(AuthorizationPolicyError::InvalidDocument)?;
            let mut slots = HashSet::with_capacity(client.slots.len());
            for slot in client.slots {
                if !valid_policy_slot(&slot) || !slots.insert(slot) {
                    return Err(AuthorizationPolicyError::InvalidDocument);
                }
            }
            if slots.is_empty() || grants.insert(fingerprint, slots).is_some() {
                return Err(AuthorizationPolicyError::InvalidDocument);
            }
        }
        Ok(Self { grants })
    }

    fn allows(&self, certificate_der: &[u8], slot: &str) -> bool {
        let fingerprint: [u8; 32] = Sha256::digest(certificate_der).into();
        self.allows_fingerprint(&fingerprint, slot)
    }

    fn allows_fingerprint(&self, fingerprint: &[u8; 32], slot: &str) -> bool {
        self.grants
            .get(fingerprint)
            .is_some_and(|slots| slots.contains(slot))
    }
}

fn parse_certificate_fingerprint(encoded: &str) -> Option<[u8; 32]> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    let mut fingerprint = [0; 32];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        fingerprint[index] = (decode_hex_nibble(pair[0])? << 4) | decode_hex_nibble(pair[1])?;
    }
    Some(fingerprint)
}

fn valid_policy_slot(slot: &str) -> bool {
    (1..=128).contains(&slot.len())
        && slot
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

impl Request {
    fn slot(&self) -> &str {
        match self {
            Self::Load { slot }
            | Self::CompareAndSwap { slot, .. }
            | Self::CheckpointLoad { slot }
            | Self::CheckpointCompareAndSwap { slot, .. }
            | Self::CatalogLoad { slot }
            | Self::CatalogCompareAndSwap { slot, .. } => slot,
            Self::Invocation { wire } => wire.slot.trim_end_matches(' '),
        }
    }
}

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
    CheckpointLoad {
        slot: String,
    },
    CheckpointCompareAndSwap {
        slot: String,
        expected_generation: Option<u64>,
        state: WireCheckpointState,
    },
    CatalogLoad {
        slot: String,
    },
    CatalogCompareAndSwap {
        slot: String,
        expected: Option<WireCatalogState>,
        next_version: u64,
        next_digest: [u8; 32],
    },
    Invocation {
        wire: WireInvocationRequest,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Loaded { state: Option<WireState> },
    CheckpointLoaded { state: Option<WireCheckpointState> },
    CatalogLoaded { state: Option<WireCatalogState> },
    Invocation { outcome: WireInvocationOutcome },
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCheckpointState {
    snapshot_id: String,
    secret_handle_hex: String,
}

/// Fixed-layout invocation request. The action is the only field whose value
/// varies between load, finish, and confirmation requests. Every byte string
/// is hex-encoded into its protocol maximum; decimal values are left-padded.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireInvocationRequest {
    slot: String,
    action: u8,
    public_key_hex: String,
    invocation_id_hex: String,
    request_digest_hex: String,
    signature_hex: String,
    expected_present: u8,
    expected_generation: String,
    record_present: u8,
    snapshot_id_hex: String,
    secret_handle_hex: String,
    response_capacity: String,
    response_hex: String,
}

impl Drop for WireInvocationRequest {
    fn drop(&mut self) {
        self.response_hex.zeroize();
        self.secret_handle_hex.zeroize();
    }
}

/// Fixed-shape response used by every valid invocation request, including
/// misses and storage errors. `response_hex` is exactly twice the public
/// configured response capacity.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireInvocationOutcome {
    status: u8,
    error_code: u8,
    receipt_present: u8,
    snapshot_id_hex: String,
    generation: String,
    response_hex: String,
}

impl Drop for WireInvocationOutcome {
    fn drop(&mut self) {
        self.response_hex.zeroize();
    }
}

impl WireInvocationOutcome {
    fn empty(status: u8, error_code: u8, response_capacity: usize) -> Self {
        Self {
            status,
            error_code,
            receipt_present: 0,
            snapshot_id_hex: "00".repeat(INVOCATION_SNAPSHOT_ID_BYTES),
            generation: "0".repeat(INVOCATION_GENERATION_DIGITS),
            response_hex: "00".repeat(response_capacity),
        }
    }

    fn from_receipt(
        receipt: &InvocationReceipt,
        response_capacity: usize,
    ) -> Result<Self, WireError> {
        if receipt.response().len() != response_capacity {
            return Err(WireError::Protocol);
        }
        let snapshot_id_hex = encode_padded_hex(
            receipt.snapshot_id().as_bytes(),
            INVOCATION_SNAPSHOT_ID_BYTES,
        )
        .ok_or(WireError::Protocol)?;
        Ok(Self {
            status: 1,
            error_code: 0,
            receipt_present: 1,
            snapshot_id_hex,
            generation: format!("{:020}", receipt.generation()),
            response_hex: encode_hex(receipt.response()),
        })
    }
}

impl WireCheckpointState {
    fn from_record(record: &CheckpointAnchorRecord) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut secret_handle_hex = String::with_capacity(TRUSTED_CHECKPOINT_HANDLE_BYTES * 2);
        for byte in record.secret_handle() {
            secret_handle_hex.push(HEX[(byte >> 4) as usize] as char);
            secret_handle_hex.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Self {
            snapshot_id: record.snapshot_id().to_owned(),
            secret_handle_hex,
        }
    }

    fn to_record(&self) -> Result<CheckpointAnchorRecord, StoreError> {
        if self.secret_handle_hex.len() != TRUSTED_CHECKPOINT_HANDLE_BYTES * 2 {
            return Err(StoreError::Integrity);
        }
        let mut secret_handle = Zeroizing::new([0; TRUSTED_CHECKPOINT_HANDLE_BYTES]);
        let (pairs, remainder) = self.secret_handle_hex.as_bytes().as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(StoreError::Integrity);
        }
        for (index, pair) in pairs.iter().enumerate() {
            let high = decode_hex_nibble(pair[0]).ok_or(StoreError::Integrity)?;
            let low = decode_hex_nibble(pair[1]).ok_or(StoreError::Integrity)?;
            secret_handle[index] = (high << 4) | low;
        }
        CheckpointAnchorRecord::new(&self.snapshot_id, secret_handle.as_ref())
    }
}

impl Drop for WireCheckpointState {
    fn drop(&mut self) {
        self.secret_handle_hex.zeroize();
    }
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl WireInvocationRequest {
    fn validate(&self) -> Result<(), WireError> {
        let slot = self.slot.trim_end_matches(' ');
        if self.slot.len() != INVOCATION_SLOT_BYTES
            || !valid_policy_slot(slot)
            || self.action > 2
            || self.expected_present > 1
            || self.record_present > 1
            || !has_lower_hex(&self.public_key_hex, 32)
            || !has_lower_hex(&self.invocation_id_hex, 16)
            || !has_lower_hex(&self.request_digest_hex, 32)
            || !has_lower_hex(&self.signature_hex, 64)
            || !has_lower_hex(&self.snapshot_id_hex, INVOCATION_SNAPSHOT_ID_BYTES)
            || !has_lower_hex(&self.secret_handle_hex, TRUSTED_CHECKPOINT_HANDLE_BYTES)
        {
            return Err(WireError::Protocol);
        }

        let expected_generation =
            parse_fixed_decimal(&self.expected_generation, INVOCATION_GENERATION_DIGITS)?;
        if (self.expected_present == 0 && expected_generation != 0)
            || (self.expected_present == 1 && expected_generation == 0)
            || (self.action == 1 && self.record_present != 1)
            || (self.action != 1 && self.record_present != 0)
            || (self.action != 1 && self.expected_present != 0)
        {
            return Err(WireError::Protocol);
        }

        let capacity = self.response_capacity()?;
        if !has_lower_hex(&self.response_hex, capacity) {
            return Err(WireError::Protocol);
        }
        if self.action != 1
            && (self.snapshot_id_hex.bytes().any(|byte| byte != b'0')
                || self.secret_handle_hex.bytes().any(|byte| byte != b'0'))
        {
            return Err(WireError::Protocol);
        }
        Ok(())
    }

    fn response_capacity(&self) -> Result<usize, WireError> {
        let capacity = parse_fixed_decimal(&self.response_capacity, INVOCATION_CAPACITY_DIGITS)?;
        let capacity = usize::try_from(capacity).map_err(|_| WireError::Protocol)?;
        if !(1..=MAX_INVOCATION_RESPONSE_BYTES).contains(&capacity) {
            return Err(WireError::Protocol);
        }
        Ok(capacity)
    }

    fn signed_invocation(&self) -> Result<SignedInvocationId, WireError> {
        Ok(SignedInvocationId::new(
            decode_fixed_hex::<32>(&self.public_key_hex)?,
            decode_fixed_hex::<16>(&self.invocation_id_hex)?,
            decode_fixed_hex::<32>(&self.request_digest_hex)?,
            decode_fixed_hex::<64>(&self.signature_hex)?,
        ))
    }

    fn expected_generation(&self) -> Result<Option<u64>, WireError> {
        if self.expected_present == 0 {
            return Ok(None);
        }
        Ok(Some(parse_fixed_decimal(
            &self.expected_generation,
            INVOCATION_GENERATION_DIGITS,
        )?))
    }

    fn checkpoint_record(&self) -> Result<CheckpointAnchorRecord, WireError> {
        let snapshot_id = decode_padded_hex(&self.snapshot_id_hex, INVOCATION_SNAPSHOT_ID_BYTES)?;
        let snapshot_id = std::str::from_utf8(&snapshot_id).map_err(|_| WireError::Protocol)?;
        let secret_handle = Zeroizing::new(decode_fixed_hex::<TRUSTED_CHECKPOINT_HANDLE_BYTES>(
            &self.secret_handle_hex,
        )?);
        CheckpointAnchorRecord::new(snapshot_id, secret_handle.as_ref())
            .map_err(|_| WireError::Protocol)
    }

    fn response_bytes(&self) -> Result<Zeroizing<Vec<u8>>, WireError> {
        let capacity = self.response_capacity()?;
        Ok(Zeroizing::new(decode_hex_bytes(
            &self.response_hex,
            capacity,
        )?))
    }
}

fn has_lower_hex(encoded: &str, byte_count: usize) -> bool {
    encoded.len() == byte_count.saturating_mul(2)
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_fixed_decimal(encoded: &str, width: usize) -> Result<u64, WireError> {
    if encoded.len() != width || !encoded.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WireError::Protocol);
    }
    encoded.parse().map_err(|_| WireError::Protocol)
}

fn decode_fixed_hex<const N: usize>(encoded: &str) -> Result<[u8; N], WireError> {
    let bytes = decode_hex_bytes(encoded, N)?;
    bytes.try_into().map_err(|_| WireError::Protocol)
}

fn decode_padded_hex(encoded: &str, byte_count: usize) -> Result<Vec<u8>, WireError> {
    let bytes = decode_hex_bytes(encoded, byte_count)?;
    let content_len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[content_len..].iter().any(|byte| *byte != 0) {
        return Err(WireError::Protocol);
    }
    Ok(bytes[..content_len].to_vec())
}

fn decode_hex_bytes(encoded: &str, byte_count: usize) -> Result<Vec<u8>, WireError> {
    if !has_lower_hex(encoded, byte_count) {
        return Err(WireError::Protocol);
    }
    let mut decoded = Vec::with_capacity(byte_count);
    for pair in encoded.as_bytes().as_chunks::<2>().0 {
        let high = decode_hex_nibble(pair[0]).ok_or(WireError::Protocol)?;
        let low = decode_hex_nibble(pair[1]).ok_or(WireError::Protocol)?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn encode_padded_hex(bytes: &[u8], capacity: usize) -> Option<String> {
    if bytes.is_empty() || bytes.len() > capacity {
        return None;
    }
    let mut padded = vec![0; capacity];
    padded[..bytes.len()].copy_from_slice(bytes);
    Some(encode_hex(&padded))
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCatalogState {
    version: u64,
    digest: Option<[u8; 32]>,
}

impl From<RegistryCatalogState> for WireCatalogState {
    fn from(state: RegistryCatalogState) -> Self {
        Self {
            version: state.version(),
            digest: state.digest().copied(),
        }
    }
}

impl TryFrom<WireCatalogState> for RegistryCatalogState {
    type Error = oblivion_registry::Error;

    fn try_from(state: WireCatalogState) -> Result<Self, Self::Error> {
        Self::new(state.version, state.digest)
    }
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
    client: RemoteAnchorClient,
}

impl TlsSseJournalAnchor {
    pub fn new(
        address: SocketAddr,
        server_name: &str,
        slot: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Self, Error> {
        Ok(Self {
            client: RemoteAnchorClient::new(address, server_name, slot, config)?,
        })
    }

    pub fn load(&mut self) -> Result<Option<SseJournalState>, Error> {
        match self.client.exchange(Request::Load {
            slot: self.client.slot.clone(),
        })? {
            Response::Loaded { state } => state.map(TryInto::try_into).transpose(),
            Response::Error { code } => Err(error_from_wire(code)),
            Response::Updated
            | Response::CheckpointLoaded { .. }
            | Response::CatalogLoaded { .. }
            | Response::Invocation { .. } => Err(Error::Protocol),
        }
    }

    pub fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        state: SseJournalState,
    ) -> Result<(), Error> {
        match self.client.exchange(Request::CompareAndSwap {
            slot: self.client.slot.clone(),
            expected_generation,
            state: state.into(),
        })? {
            Response::Updated => Ok(()),
            Response::Error { code } => Err(error_from_wire(code)),
            Response::Loaded { .. }
            | Response::CheckpointLoaded { .. }
            | Response::CatalogLoaded { .. }
            | Response::Invocation { .. } => Err(Error::Protocol),
        }
    }
}

/// A synchronous checkpoint anchor over mutually authenticated TLS.
///
/// The witness receives the checkpoint secret handle in plaintext inside the
/// authenticated channel. It can decrypt snapshots it can access, so callers
/// must trust the witness operator with checkpoint confidentiality as well as
/// durable compare-and-swap state.
pub struct TlsCheckpointAnchor {
    client: RemoteAnchorClient,
}

impl TlsCheckpointAnchor {
    pub fn new(
        address: SocketAddr,
        server_name: &str,
        slot: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Self, Error> {
        Ok(Self {
            client: RemoteAnchorClient::new(address, server_name, slot, config)?,
        })
    }
}

impl CheckpointAnchor for TlsCheckpointAnchor {
    fn load(&mut self) -> Result<Option<CheckpointAnchorRecord>, StoreError> {
        match self.client.exchange(Request::CheckpointLoad {
            slot: self.client.slot.clone(),
        }) {
            Ok(Response::CheckpointLoaded { state }) => state
                .as_ref()
                .map(WireCheckpointState::to_record)
                .transpose()
                .map_err(|_| StoreError::Integrity),
            Ok(Response::Error { code }) => Err(store_error_from_wire(code, false)),
            Ok(_) => Err(StoreError::Integrity),
            Err(error) => Err(StoreError::Backend(error.to_string())),
        }
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        next_record: CheckpointAnchorRecord,
    ) -> Result<(), StoreError> {
        let request = Request::CheckpointCompareAndSwap {
            slot: self.client.slot.clone(),
            expected_generation,
            state: WireCheckpointState::from_record(&next_record),
        };
        match self.client.exchange_checkpoint_mutation(request) {
            Ok(Response::Updated) => Ok(()),
            Ok(Response::Error { code }) => Err(store_error_from_wire(code, true)),
            Ok(_) | Err(CheckpointMutationFailure::Indeterminate) => {
                Err(StoreError::AnchorCommitUnknown)
            }
            Err(CheckpointMutationFailure::NotSent(error)) => {
                Err(StoreError::Backend(error.to_string()))
            }
        }
    }
}

/// A synchronous digest-bound registry activation anchor over mutually
/// authenticated TLS. Its freshness guarantee depends on the witness
/// retaining its own SQLite database.
pub struct TlsRegistryCatalogAnchor {
    client: RemoteAnchorClient,
}

impl TlsRegistryCatalogAnchor {
    pub fn new(
        address: SocketAddr,
        server_name: &str,
        slot: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Self, Error> {
        Ok(Self {
            client: RemoteAnchorClient::new(address, server_name, slot, config)?,
        })
    }
}

impl RegistryCatalogAnchor for TlsRegistryCatalogAnchor {
    fn current_catalog(
        &mut self,
    ) -> Result<Option<RegistryCatalogState>, oblivion_registry::Error> {
        match self.client.exchange(Request::CatalogLoad {
            slot: self.client.slot.clone(),
        }) {
            Ok(Response::CatalogLoaded { state }) => state
                .map(TryInto::try_into)
                .transpose()
                .map_err(|error: oblivion_registry::Error| {
                    oblivion_registry::Error::Anchor(error.to_string())
                }),
            Ok(Response::Error { code }) => Err(registry_error_from_wire(code, false)),
            Ok(_) => Err(oblivion_registry::Error::Anchor(
                "invalid remote catalog load response".into(),
            )),
            Err(error) => Err(oblivion_registry::Error::Anchor(error.to_string())),
        }
    }

    fn compare_and_swap_catalog(
        &mut self,
        expected: Option<RegistryCatalogState>,
        next_version: u64,
        next_digest: [u8; 32],
    ) -> Result<(), oblivion_registry::Error> {
        match self.client.exchange(Request::CatalogCompareAndSwap {
            slot: self.client.slot.clone(),
            expected: expected.map(Into::into),
            next_version,
            next_digest,
        }) {
            Ok(Response::Updated) => Ok(()),
            Ok(Response::Error { code }) => Err(registry_error_from_wire(code, true)),
            Ok(_) | Err(_) => Err(oblivion_registry::Error::AnchorCommitUnknown),
        }
    }
}

struct RemoteAnchorClient {
    address: SocketAddr,
    server_name: ServerName<'static>,
    slot: String,
    config: Arc<ClientConfig>,
}

impl RemoteAnchorClient {
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

    fn exchange(&self, request: Request) -> Result<Response, Error> {
        let frame = Zeroizing::new(
            serde_json::to_vec(&RequestEnvelope {
                version: PROTOCOL_VERSION,
                request,
            })
            .map_err(|_| Error::Protocol)?,
        );
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
        let response = Zeroizing::new(read_frame(&mut stream)?);
        let response: ResponseEnvelope =
            serde_json::from_slice(&response).map_err(|_| Error::Protocol)?;
        if response.version != PROTOCOL_VERSION {
            return Err(Error::Protocol);
        }
        Ok(response.response)
    }

    fn exchange_checkpoint_mutation(
        &self,
        request: Request,
    ) -> Result<Response, CheckpointMutationFailure> {
        let frame = Zeroizing::new(
            serde_json::to_vec(&RequestEnvelope {
                version: PROTOCOL_VERSION,
                request,
            })
            .map_err(|_| CheckpointMutationFailure::NotSent(Error::Protocol))?,
        );
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err(CheckpointMutationFailure::NotSent(Error::Protocol));
        }
        let stream = TcpStream::connect_timeout(&self.address, IO_TIMEOUT).map_err(|error| {
            CheckpointMutationFailure::NotSent(Error::Socket(error.to_string()))
        })?;
        let stream = DeadlineStream::with_timeout(stream, IO_TIMEOUT);
        let connection = ClientConnection::new(self.config.clone(), self.server_name.clone())
            .map_err(|error| {
                CheckpointMutationFailure::NotSent(Error::Socket(error.to_string()))
            })?;
        let mut stream = StreamOwned::new(connection, stream);
        // rustls completes the handshake during I/O. Once this call begins, a
        // failed write may have sent some or all of the mutation request.
        write_frame(&mut stream, &frame).map_err(|_| CheckpointMutationFailure::Indeterminate)?;
        let response = Zeroizing::new(
            read_frame(&mut stream).map_err(|_| CheckpointMutationFailure::Indeterminate)?,
        );
        let response: ResponseEnvelope = serde_json::from_slice(&response)
            .map_err(|_| CheckpointMutationFailure::Indeterminate)?;
        if response.version != PROTOCOL_VERSION {
            return Err(CheckpointMutationFailure::Indeterminate);
        }
        Ok(response.response)
    }
}

enum CheckpointMutationFailure {
    NotSent(Error),
    Indeterminate,
}

/// Serve TLS anchor requests until `shutdown` receives a message. The listener
/// is polled so a shutdown request is observed even when the service is idle.
pub fn serve_mtls_with_shutdown(
    listener: TcpListener,
    mut database: AnchorDatabase,
    config: Arc<ServerConfig>,
    authorization: ClientAuthorizationPolicy,
    shutdown: Receiver<()>,
) -> Result<(), Error> {
    serve_mtls_inner(
        listener,
        &mut database,
        config,
        &authorization,
        Some(shutdown),
    )
}

/// Serve TLS anchor requests indefinitely. Use
/// [`serve_mtls_with_shutdown`] when the caller needs orderly shutdown.
pub fn serve_mtls(
    listener: TcpListener,
    mut database: AnchorDatabase,
    config: Arc<ServerConfig>,
    authorization: ClientAuthorizationPolicy,
) -> Result<(), Error> {
    serve_mtls_inner(listener, &mut database, config, &authorization, None)
}

fn serve_mtls_inner(
    listener: TcpListener,
    database: &mut AnchorDatabase,
    config: Arc<ServerConfig>,
    authorization: &ClientAuthorizationPolicy,
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
                let _ = serve_connection(stream, database, &config, authorization);
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
    authorization: &ClientAuthorizationPolicy,
) -> Result<(), Error> {
    let stream = DeadlineStream::with_timeout(stream, IO_TIMEOUT);
    let connection =
        ServerConnection::new(config.clone()).map_err(|error| Error::Socket(error.to_string()))?;
    let mut stream = StreamOwned::new(connection, stream);
    let request_bytes = Zeroizing::new(read_frame(&mut stream)?);
    let response = match decode_request(&request_bytes) {
        Ok(request) => {
            let certificate = stream
                .conn
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .ok_or(Error::Protocol)?;
            if !authorization.allows(certificate.as_ref(), request.slot()) {
                return Err(Error::Protocol);
            }
            serve_request(database, request)
        }
        Err(code) => Response::Error { code },
    };
    let frame = Zeroizing::new(
        serde_json::to_vec(&ResponseEnvelope {
            version: PROTOCOL_VERSION,
            response,
        })
        .map_err(|_| Error::Protocol)?,
    );
    write_frame(&mut stream, &frame)?;
    stream
        .flush()
        .map_err(|error| Error::Socket(error.to_string()))
}

fn decode_request(frame: &[u8]) -> Result<Request, WireError> {
    match serde_json::from_slice::<RequestEnvelope>(frame) {
        Ok(envelope) if envelope.version == PROTOCOL_VERSION => {
            if let Request::Invocation { wire } = &envelope.request {
                wire.validate()?;
            }
            Ok(envelope.request)
        }
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
        Request::CheckpointLoad { slot } => {
            let mut anchor = match database.checkpoint_anchor(&slot) {
                Ok(anchor) => anchor,
                Err(error) => {
                    return Response::Error {
                        code: wire_from_error(error),
                    };
                }
            };
            match anchor.load() {
                Ok(state) => Response::CheckpointLoaded {
                    state: state.as_ref().map(WireCheckpointState::from_record),
                },
                Err(error) => Response::Error {
                    code: wire_from_store_error(error),
                },
            }
        }
        Request::CheckpointCompareAndSwap {
            slot,
            expected_generation,
            state,
        } => {
            let state = match state.to_record() {
                Ok(state) => state,
                Err(_) => {
                    return Response::Error {
                        code: WireError::Protocol,
                    };
                }
            };
            let mut anchor = match database.checkpoint_anchor(&slot) {
                Ok(anchor) => anchor,
                Err(error) => {
                    return Response::Error {
                        code: wire_from_error(error),
                    };
                }
            };
            match anchor.compare_and_swap(expected_generation, state) {
                Ok(()) => Response::Updated,
                Err(error) => Response::Error {
                    code: wire_from_store_error(error),
                },
            }
        }
        Request::CatalogLoad { slot } => {
            match database
                .registry_catalog_anchor(&slot)
                .and_then(|mut anchor| {
                    anchor
                        .current_catalog()
                        .map_err(|error| Error::Database(error.to_string()))
                }) {
                Ok(state) => Response::CatalogLoaded {
                    state: state.map(Into::into),
                },
                Err(error) => Response::Error {
                    code: wire_from_error(error),
                },
            }
        }
        Request::CatalogCompareAndSwap {
            slot,
            expected,
            next_version,
            next_digest,
        } => {
            let expected = match expected.map(TryInto::try_into).transpose() {
                Ok(expected) => expected,
                Err(_) => {
                    return Response::Error {
                        code: WireError::Protocol,
                    };
                }
            };
            match database
                .registry_catalog_anchor(&slot)
                .and_then(|mut anchor| {
                    anchor
                        .compare_and_swap_catalog(expected, next_version, next_digest)
                        .map_err(anchor_error_from_registry)
                }) {
                Ok(()) => Response::Updated,
                Err(error) => Response::Error {
                    code: wire_from_error(error),
                },
            }
        }
        Request::Invocation { wire } => serve_invocation(database, &wire),
    }
}

fn serve_invocation(database: &mut AnchorDatabase, wire: &WireInvocationRequest) -> Response {
    let response_capacity = match wire.response_capacity() {
        Ok(capacity) => capacity,
        Err(code) => return invocation_error_response(2, code, MAX_INVOCATION_RESPONSE_BYTES),
    };
    let invocation = match wire.signed_invocation() {
        Ok(invocation) => invocation,
        Err(code) => return invocation_error_response(2, code, response_capacity),
    };

    let result = match wire.action {
        0 => database
            .load_invocation_receipt(wire.slot.trim_end_matches(' '), &invocation)
            .map_err(wire_from_error),
        1 => {
            let expected_generation = match wire.expected_generation() {
                Ok(generation) => generation,
                Err(code) => {
                    return invocation_error_response(2, code, response_capacity);
                }
            };
            let record = match wire.checkpoint_record() {
                Ok(record) => record,
                Err(code) => {
                    return invocation_error_response(2, code, response_capacity);
                }
            };
            let response = match wire.response_bytes() {
                Ok(response) => response,
                Err(code) => {
                    return invocation_error_response(2, code, response_capacity);
                }
            };
            database
                .commit_invocation(
                    wire.slot.trim_end_matches(' '),
                    &invocation,
                    expected_generation,
                    record,
                    response.as_slice(),
                )
                .map(Some)
                .map_err(wire_from_error)
        }
        2 => {
            let expected_response = match wire.response_bytes() {
                Ok(response) => response,
                Err(code) => {
                    return invocation_error_response(2, code, response_capacity);
                }
            };
            database
                .load_invocation_receipt(wire.slot.trim_end_matches(' '), &invocation)
                .map_err(wire_from_error)
                .and_then(|receipt| match receipt {
                    Some(receipt) if receipt.response() == expected_response.as_slice() => {
                        Ok(Some(receipt))
                    }
                    Some(_) => Err(WireError::Conflict),
                    None => Ok(None),
                })
        }
        _ => Err(WireError::Protocol),
    };

    let outcome = match result {
        Ok(Some(receipt)) => match WireInvocationOutcome::from_receipt(&receipt, response_capacity)
        {
            Ok(outcome) => outcome,
            Err(code) => WireInvocationOutcome::empty(2, wire_error_code(code), response_capacity),
        },
        Ok(None) => WireInvocationOutcome::empty(0, 0, response_capacity),
        Err(code) => WireInvocationOutcome::empty(2, wire_error_code(code), response_capacity),
    };
    Response::Invocation { outcome }
}

fn invocation_error_response(status: u8, code: WireError, response_capacity: usize) -> Response {
    Response::Invocation {
        outcome: WireInvocationOutcome::empty(status, wire_error_code(code), response_capacity),
    }
}

fn wire_error_code(error: WireError) -> u8 {
    match error {
        WireError::Conflict => 1,
        WireError::CommitIndeterminate => 2,
        WireError::Unavailable => 3,
        WireError::Protocol => 4,
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

fn wire_from_store_error(error: StoreError) -> WireError {
    match error {
        StoreError::AnchorConflict => WireError::Conflict,
        StoreError::AnchorCommitUnknown => WireError::CommitIndeterminate,
        StoreError::Backend(_) => WireError::Unavailable,
        _ => WireError::Protocol,
    }
}

fn store_error_from_wire(error: WireError, mutation: bool) -> StoreError {
    match error {
        WireError::Conflict if mutation => StoreError::AnchorConflict,
        WireError::CommitIndeterminate if mutation => StoreError::AnchorCommitUnknown,
        WireError::Conflict | WireError::CommitIndeterminate => {
            StoreError::Backend("unexpected checkpoint witness response".into())
        }
        WireError::Unavailable => {
            StoreError::Backend("remote checkpoint witness unavailable".into())
        }
        WireError::Protocol => StoreError::Integrity,
    }
}

fn anchor_error_from_registry(error: oblivion_registry::Error) -> Error {
    match error {
        oblivion_registry::Error::AnchorConflict => Error::Conflict,
        oblivion_registry::Error::AnchorCommitUnknown => Error::CommitIndeterminate,
        other => Error::Database(other.to_string()),
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

fn registry_error_from_wire(error: WireError, mutation: bool) -> oblivion_registry::Error {
    match error {
        WireError::Conflict if mutation => oblivion_registry::Error::AnchorConflict,
        WireError::CommitIndeterminate if mutation => oblivion_registry::Error::AnchorCommitUnknown,
        WireError::Conflict => {
            oblivion_registry::Error::Anchor("unexpected catalog conflict on load".into())
        }
        WireError::CommitIndeterminate | WireError::Unavailable => {
            oblivion_registry::Error::Anchor("remote anchor unavailable".into())
        }
        WireError::Protocol => {
            oblivion_registry::Error::Anchor("remote anchor rejected catalog request".into())
        }
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
    use super::{
        AnchorDatabase, AuthorizationPolicyError, ClientAuthorizationPolicy,
        MAX_AUTHORIZATION_POLICY_BYTES, Request, Response, SignedInvocationId, WireCheckpointState,
        WireError, WireInvocationOutcome, decode_request,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use oblivion_store::{CheckpointAnchorRecord, TRUSTED_CHECKPOINT_HANDLE_BYTES};

    #[test]
    fn client_authorization_policy_enforces_exact_fingerprint_and_slot() {
        let json = br#"{"version":1,"clients":[{"certificate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","slots":["sse-main-index","oram-main"]}]}"#;
        let policy = ClientAuthorizationPolicy::from_json(json).expect("valid policy");

        assert!(policy.allows_fingerprint(&[0; 32], "sse-main-index"));
        assert!(policy.allows_fingerprint(&[0; 32], "oram-main"));
        assert!(!policy.allows_fingerprint(&[1; 32], "sse-main-index"));
        assert!(!policy.allows_fingerprint(&[0; 32], "unlisted-slot"));
    }

    #[test]
    fn client_authorization_policy_rejects_invalid_grants() {
        let invalid_documents: &[&[u8]] = &[
            br#"{"version":2,"clients":[{"certificate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","slots":["valid-slot"]}]}"#,
            br#"{"version":1,"clients":[]}"#,
            br#"{"version":1,"clients":[{"certificate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","slots":[]}] }"#,
            br#"{"version":1,"clients":[{"certificate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","slots":["valid-slot","valid-slot"]}]}"#,
            br#"{"version":1,"clients":[{"certificate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","slots":["*"]}]}"#,
            br#"{"version":1,"clients":[{"certificate_sha256":"000000000000000000000000000000000000000000000000000000000000000A","slots":["valid-slot"]}]}"#,
            br#"{"version":1,"clients":[{"certificate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","slots":["valid-slot"],"admin":true}]}"#,
        ];
        for document in invalid_documents {
            assert!(
                ClientAuthorizationPolicy::from_json(document).is_err(),
                "invalid policy was accepted: {}",
                String::from_utf8_lossy(document)
            );
        }
    }

    #[test]
    fn client_authorization_policy_rejects_oversized_documents() {
        let document = vec![b' '; MAX_AUTHORIZATION_POLICY_BYTES + 1];
        assert!(matches!(
            ClientAuthorizationPolicy::from_json(&document),
            Err(AuthorizationPolicyError::TooLarge)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn client_authorization_policy_rejects_symlinked_file() {
        use std::{
            fs,
            os::unix::fs::symlink,
            time::{SystemTime, UNIX_EPOCH},
        };

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "oblivion-policy-symlink-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("policy test directory");
        let policy_path = directory.join("policy.json");
        let symlink_path = directory.join("policy-link.json");
        fs::write(
            &policy_path,
            br#"{"version":1,"clients":[{"certificate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","slots":["valid-slot"]}]}"#,
        )
        .expect("policy file");
        symlink(&policy_path, &symlink_path).expect("policy symlink");

        let result = ClientAuthorizationPolicy::from_file(&symlink_path);
        fs::remove_dir_all(directory).expect("cleanup policy test directory");

        assert!(result.is_err(), "policy loader followed a symlink");
    }

    #[cfg(unix)]
    #[test]
    fn client_authorization_policy_rejects_group_writable_file() {
        use std::{
            fs,
            os::unix::fs::PermissionsExt,
            time::{SystemTime, UNIX_EPOCH},
        };

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "oblivion-policy-mode-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("policy test directory");
        let policy_path = directory.join("policy.json");
        fs::write(
            &policy_path,
            br#"{"version":1,"clients":[{"certificate_sha256":"0000000000000000000000000000000000000000000000000000000000000000","slots":["valid-slot"]}]}"#,
        )
        .expect("policy file");
        fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o620))
            .expect("policy permissions");

        let result = ClientAuthorizationPolicy::from_file(&policy_path);
        fs::remove_dir_all(directory).expect("cleanup policy test directory");

        assert!(
            result.is_err(),
            "policy loader accepted a group-writable file"
        );
    }

    #[test]
    fn checkpoint_wire_handle_has_fixed_width_independent_of_secret_bytes() {
        fn record(fill: u8) -> CheckpointAnchorRecord {
            let mut handle = [fill; 88];
            handle[..8].copy_from_slice(b"OBLTRST1");
            handle[8..16].copy_from_slice(&1u64.to_le_bytes());
            handle[16..24].copy_from_slice(&64u64.to_le_bytes());
            CheckpointAnchorRecord::new("snapshot", &handle).expect("valid handle")
        }

        let low = WireCheckpointState::from_record(&record(0));
        let high = WireCheckpointState::from_record(&record(0xff));
        assert_eq!(low.secret_handle_hex.len(), 176);
        assert_eq!(high.secret_handle_hex.len(), 176);
        assert_eq!(
            serde_json::to_vec(&low)
                .expect("low-secret wire encoding")
                .len(),
            serde_json::to_vec(&high)
                .expect("high-secret wire encoding")
                .len()
        );
        let decoded = low.to_record().expect("decode fixed-width handle");
        assert_eq!(decoded.snapshot_id(), "snapshot");
        assert_eq!(decoded.generation(), 1);
        assert_eq!(decoded.secret_handle(), record(0).secret_handle());
    }

    #[test]
    fn checkpoint_wire_handle_rejects_invalid_hex_and_length() {
        for secret_handle_hex in ["gg".repeat(88), "00".repeat(87)] {
            let state = WireCheckpointState {
                snapshot_id: "snapshot".into(),
                secret_handle_hex,
            };
            assert!(matches!(
                state.to_record(),
                Err(oblivion_store::Error::Integrity)
            ));
        }
    }

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
        let valid = br#"{"version":3,"request":{"operation":"load","slot":"sse-slot"}}"#;
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
            br#"{"version":3,"request":{"operation":"load","slot":"sse-slot","extra":true}}"#;
        assert!(matches!(
            decode_request(unknown_field),
            Err(WireError::Protocol)
        ));

        let catalog_load =
            br#"{"version":3,"request":{"operation":"catalog_load","slot":"functions"}}"#;
        assert!(matches!(
            decode_request(catalog_load),
            Ok(Request::CatalogLoad { slot }) if slot == "functions"
        ));

        let malformed_catalog_cas = br#"{"version":3,"request":{"operation":"catalog_compare_and_swap","slot":"functions","expected":null,"next_version":1,"next_digest":[1,2]}}"#;
        assert!(matches!(
            decode_request(malformed_catalog_cas),
            Err(WireError::Protocol)
        ));
    }

    fn fixed_invocation_request(action: u8) -> Vec<u8> {
        format!(
            r#"{{"version":3,"request":{{"operation":"invocation","wire":{{"slot":"{:<128}","action":{},"public_key_hex":"{}","invocation_id_hex":"{}","request_digest_hex":"{}","signature_hex":"{}","expected_present":0,"expected_generation":"{}","record_present":{},"snapshot_id_hex":"{}","secret_handle_hex":"{}","response_capacity":"00080","response_hex":"{}"}}}}}}"#,
            "invocation-slot",
            action,
            "00".repeat(32),
            "00".repeat(16),
            "00".repeat(32),
            "00".repeat(64),
            "0".repeat(20),
            u8::from(action == 1),
            "00".repeat(128),
            "00".repeat(88),
            "00".repeat(80),
        )
        .into_bytes()
    }

    fn signed_invocation(seed: u8, id: [u8; 16], digest: [u8; 32]) -> SignedInvocationId {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let signature = signing_key
            .sign(&SignedInvocationId::signing_message(&id, &digest))
            .to_bytes();
        SignedInvocationId::new(
            signing_key.verifying_key().to_bytes(),
            id,
            digest,
            signature,
        )
    }

    fn checkpoint_record(snapshot_id: &str, generation: u64) -> CheckpointAnchorRecord {
        let mut secret_handle = [0; TRUSTED_CHECKPOINT_HANDLE_BYTES];
        secret_handle[..8].copy_from_slice(b"OBLTRST1");
        secret_handle[8..16].copy_from_slice(&generation.to_le_bytes());
        secret_handle[16..24].copy_from_slice(&48_u64.to_le_bytes());
        secret_handle[24..56].fill(generation as u8);
        secret_handle[56..].fill(0xA5);
        CheckpointAnchorRecord::new(snapshot_id, &secret_handle).expect("checkpoint record")
    }

    fn invocation_wire(
        invocation: &SignedInvocationId,
        action: u8,
        expected_generation: Option<u64>,
        record: Option<&CheckpointAnchorRecord>,
        response: &[u8],
    ) -> super::WireInvocationRequest {
        super::WireInvocationRequest {
            slot: format!("{:<128}", "runtime-slot"),
            action,
            public_key_hex: super::encode_hex(invocation.public_key()),
            invocation_id_hex: super::encode_hex(invocation.invocation_id()),
            request_digest_hex: super::encode_hex(invocation.request_digest()),
            signature_hex: super::encode_hex(invocation.signature()),
            expected_present: u8::from(expected_generation.is_some()),
            expected_generation: format!("{:020}", expected_generation.unwrap_or(0)),
            record_present: u8::from(record.is_some()),
            snapshot_id_hex: record
                .map(|record| {
                    super::encode_padded_hex(
                        record.snapshot_id().as_bytes(),
                        super::INVOCATION_SNAPSHOT_ID_BYTES,
                    )
                    .expect("fixed snapshot ID")
                })
                .unwrap_or_else(|| "00".repeat(super::INVOCATION_SNAPSHOT_ID_BYTES)),
            secret_handle_hex: record
                .map(|record| super::encode_hex(record.secret_handle()))
                .unwrap_or_else(|| "00".repeat(TRUSTED_CHECKPOINT_HANDLE_BYTES)),
            response_capacity: format!("{:05}", response.len()),
            response_hex: super::encode_hex(response),
        }
    }

    fn invocation_outcome(response: &Response) -> &WireInvocationOutcome {
        match response {
            Response::Invocation { outcome } => outcome,
            _ => panic!("invocation response expected"),
        }
    }

    #[test]
    fn invocation_v3_request_actions_have_the_same_fixed_shape() {
        let mut encoded_lengths = Vec::new();

        for action in 0..=2 {
            let frame = fixed_invocation_request(action);
            let request = match decode_request(&frame) {
                Ok(request) => request,
                Err(_) => panic!("valid invocation request was rejected"),
            };
            let encoded = serde_json::to_vec(&super::RequestEnvelope {
                version: super::PROTOCOL_VERSION,
                request,
            })
            .expect("request serialization");
            assert_eq!(frame.len(), encoded.len());
            encoded_lengths.push(encoded.len());
        }

        assert!(encoded_lengths.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn invocation_v3_rejects_malformed_fixed_width_fields() {
        let invalid_hex = String::from_utf8(fixed_invocation_request(0))
            .expect("request frame")
            .replacen(r#""public_key_hex":"00"#, r#""public_key_hex":"0g"#, 1);
        let invalid_capacity = String::from_utf8(fixed_invocation_request(0))
            .expect("request frame")
            .replace(
                r#""response_capacity":"00080""#,
                r#""response_capacity":"00000""#,
            );
        let invalid_slot = String::from_utf8(fixed_invocation_request(0))
            .expect("request frame")
            .replacen("invocation-slot", "invalid slot", 1);

        assert!(decode_request(invalid_hex.as_bytes()).is_err());
        assert!(decode_request(invalid_capacity.as_bytes()).is_err());
        assert!(decode_request(invalid_slot.as_bytes()).is_err());
    }

    #[test]
    fn invocation_response_hit_miss_commit_and_error_have_the_same_shape() {
        let miss = WireInvocationOutcome::empty(0, 0, 80);
        let receipt =
            crate::InvocationReceipt::from_parts("snapshot-1".to_owned(), 1, vec![0x5a; 80])
                .expect("valid receipt");
        let hit = match WireInvocationOutcome::from_receipt(&receipt, 80) {
            Ok(outcome) => outcome,
            Err(_) => panic!("valid receipt was rejected"),
        };
        let replay = match WireInvocationOutcome::from_receipt(&receipt, 80) {
            Ok(outcome) => outcome,
            Err(_) => panic!("valid replay was rejected"),
        };
        let error = WireInvocationOutcome::empty(2, 1, 80);

        let serialized_lengths = [miss, hit, replay, error].map(|outcome| {
            serde_json::to_vec(&super::ResponseEnvelope {
                version: super::PROTOCOL_VERSION,
                response: super::Response::Invocation { outcome },
            })
            .expect("response serialization")
            .len()
        });
        assert!(serialized_lengths.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn invocation_wire_dispatch_commits_atomically_and_replays_the_first_receipt() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "oblivion-wire-invocation-{}-{unique}.sqlite",
            std::process::id()
        ));
        let mut database = AnchorDatabase::open(&path, zeroize::Zeroizing::new([0x37; 32]))
            .expect("anchor database");
        let invocation = signed_invocation(7, [0x42; 16], [0x53; 32]);
        let response = [0x5a; 80];

        let miss = super::serve_invocation(
            &mut database,
            &invocation_wire(&invocation, 0, None, None, &[0; 80]),
        );
        let first = super::serve_invocation(
            &mut database,
            &invocation_wire(
                &invocation,
                1,
                None,
                Some(&checkpoint_record("snapshot-1", 1)),
                &response,
            ),
        );
        let replay = super::serve_invocation(
            &mut database,
            &invocation_wire(
                &invocation,
                1,
                Some(1),
                Some(&checkpoint_record("snapshot-2", 2)),
                &[0x11; 80],
            ),
        );
        let confirmed = super::serve_invocation(
            &mut database,
            &invocation_wire(&invocation, 2, None, None, &response),
        );
        let mismatched_confirmation = super::serve_invocation(
            &mut database,
            &invocation_wire(&invocation, 2, None, None, &[0; 80]),
        );
        let hit = super::serve_invocation(
            &mut database,
            &invocation_wire(&invocation, 0, None, None, &[0; 80]),
        );

        let miss_outcome = invocation_outcome(&miss);
        assert_eq!(miss_outcome.status, 0);
        assert_eq!(miss_outcome.receipt_present, 0);
        for receipt_response in [&first, &replay, &confirmed, &hit] {
            let outcome = invocation_outcome(receipt_response);
            assert_eq!(outcome.status, 1);
            assert_eq!(outcome.receipt_present, 1);
            assert_eq!(
                outcome.snapshot_id_hex,
                super::encode_padded_hex(b"snapshot-1", 128).unwrap()
            );
            assert_eq!(outcome.generation, "00000000000000000001");
            assert_eq!(outcome.response_hex, super::encode_hex(&response));
        }
        let mismatch = invocation_outcome(&mismatched_confirmation);
        assert_eq!(mismatch.status, 2);
        assert_eq!(mismatch.error_code, 1);

        let responses = [miss, first, replay, confirmed, mismatched_confirmation, hit];
        let lengths = responses.map(|response| {
            serde_json::to_vec(&super::ResponseEnvelope {
                version: super::PROTOCOL_VERSION,
                response,
            })
            .expect("response serialization")
            .len()
        });
        assert!(lengths.windows(2).all(|pair| pair[0] == pair[1]));

        drop(database);
        let _ = std::fs::remove_file(path);
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
