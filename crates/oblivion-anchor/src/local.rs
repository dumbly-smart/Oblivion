//! Local, process-separated anchor service over Unix-domain sockets.
//!
//! Socket filesystem permissions are the client authorization boundary. This
//! transport is intended for a trusted local executor/service deployment; it
//! is not a remote-network protocol and does not protect against host root.

use crate::{
    AnchorDatabase, Error, InvocationReceipt, MAX_INVOCATION_RESPONSE_BYTES, SignedInvocationId,
    validate_slot,
};
use oblivion_registry::{self as registry, RegistryVersionAnchor};
use oblivion_store::{self as store, CheckpointAnchor, CheckpointAnchorRecord};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, Permissions},
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::Duration,
};

const PROTOCOL_VERSION: u8 = 1;
const MAX_FRAME_BYTES: usize = 512 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    RegistryLoad {
        version: u8,
        slot: String,
    },
    RegistryCas {
        version: u8,
        slot: String,
        expected: Option<u64>,
        next: u64,
    },
    CheckpointLoad {
        version: u8,
        slot: String,
    },
    CheckpointCas {
        version: u8,
        slot: String,
        expected_generation: Option<u64>,
        snapshot_id: String,
        secret_handle: Vec<u8>,
    },
    InvocationLoad {
        version: u8,
        slot: String,
        public_key: [u8; 32],
        invocation_id: [u8; 16],
        request_digest: [u8; 32],
        signature: Vec<u8>,
    },
    InvocationCommit {
        version: u8,
        slot: String,
        public_key: [u8; 32],
        invocation_id: [u8; 16],
        request_digest: [u8; 32],
        signature: Vec<u8>,
        expected_generation: Option<u64>,
        snapshot_id: String,
        secret_handle: Vec<u8>,
        response: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    RegistryVersion {
        version: u8,
        current: Option<u64>,
    },
    Checkpoint {
        version: u8,
        record: Option<WireCheckpoint>,
    },
    Invocation {
        version: u8,
        receipt: Option<WireInvocationReceipt>,
    },
    Ack {
        version: u8,
    },
    Conflict {
        version: u8,
    },
    CommitUnknown {
        version: u8,
    },
    Invalid {
        version: u8,
    },
    Internal {
        version: u8,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCheckpoint {
    snapshot_id: String,
    generation: u64,
    secret_handle: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInvocationReceipt {
    snapshot_id: String,
    generation: u64,
    response: Vec<u8>,
}

impl From<InvocationReceipt> for WireInvocationReceipt {
    fn from(receipt: InvocationReceipt) -> Self {
        Self {
            snapshot_id: receipt.snapshot_id().to_owned(),
            generation: receipt.generation(),
            response: receipt.response().to_vec(),
        }
    }
}

impl WireInvocationReceipt {
    fn into_receipt(self) -> Result<InvocationReceipt, Error> {
        InvocationReceipt::from_parts(self.snapshot_id, self.generation, self.response)
    }
}

fn serve_request(database: &mut AnchorDatabase, request: Request) -> Response {
    match request {
        Request::RegistryLoad { version, slot } => {
            if version != PROTOCOL_VERSION || validate_slot(&slot).is_err() {
                return Response::Invalid {
                    version: PROTOCOL_VERSION,
                };
            }
            match database.registry_anchor(&slot).and_then(|mut anchor| {
                anchor
                    .current_version()
                    .map_err(|error| Error::Database(error.to_string()))
            }) {
                Ok(current) => Response::RegistryVersion {
                    version: PROTOCOL_VERSION,
                    current,
                },
                Err(_) => Response::Internal {
                    version: PROTOCOL_VERSION,
                },
            }
        }
        Request::RegistryCas {
            version,
            slot,
            expected,
            next,
        } => {
            if version != PROTOCOL_VERSION || validate_slot(&slot).is_err() {
                return Response::Invalid {
                    version: PROTOCOL_VERSION,
                };
            }
            match database.registry_anchor(&slot) {
                Ok(mut anchor) => match anchor.compare_and_swap(expected, next) {
                    Ok(()) => Response::Ack {
                        version: PROTOCOL_VERSION,
                    },
                    Err(registry::Error::AnchorConflict | registry::Error::Rollback) => {
                        Response::Conflict {
                            version: PROTOCOL_VERSION,
                        }
                    }
                    Err(registry::Error::AnchorCommitUnknown) => Response::CommitUnknown {
                        version: PROTOCOL_VERSION,
                    },
                    Err(_) => Response::Internal {
                        version: PROTOCOL_VERSION,
                    },
                },
                Err(_) => Response::Invalid {
                    version: PROTOCOL_VERSION,
                },
            }
        }
        Request::CheckpointLoad { version, slot } => {
            if version != PROTOCOL_VERSION || validate_slot(&slot).is_err() {
                return Response::Invalid {
                    version: PROTOCOL_VERSION,
                };
            }
            match database.checkpoint_anchor(&slot).and_then(|mut anchor| {
                anchor
                    .load()
                    .map_err(|error| Error::Database(error.to_string()))
            }) {
                Ok(record) => Response::Checkpoint {
                    version: PROTOCOL_VERSION,
                    record: record.map(|record| WireCheckpoint {
                        snapshot_id: record.snapshot_id().to_owned(),
                        generation: record.generation(),
                        secret_handle: record.secret_handle().to_vec(),
                    }),
                },
                Err(_) => Response::Internal {
                    version: PROTOCOL_VERSION,
                },
            }
        }
        Request::CheckpointCas {
            version,
            slot,
            expected_generation,
            snapshot_id,
            secret_handle,
        } => {
            if version != PROTOCOL_VERSION
                || validate_slot(&slot).is_err()
                || secret_handle.len() != 88
            {
                return Response::Invalid {
                    version: PROTOCOL_VERSION,
                };
            }
            let record = match CheckpointAnchorRecord::new(&snapshot_id, &secret_handle) {
                Ok(record) => record,
                Err(_) => {
                    return Response::Invalid {
                        version: PROTOCOL_VERSION,
                    };
                }
            };
            match database.checkpoint_anchor(&slot) {
                Ok(mut anchor) => match anchor.compare_and_swap(expected_generation, record) {
                    Ok(()) => Response::Ack {
                        version: PROTOCOL_VERSION,
                    },
                    Err(store::Error::AnchorConflict) => Response::Conflict {
                        version: PROTOCOL_VERSION,
                    },
                    Err(store::Error::AnchorCommitUnknown) => Response::CommitUnknown {
                        version: PROTOCOL_VERSION,
                    },
                    Err(_) => Response::Internal {
                        version: PROTOCOL_VERSION,
                    },
                },
                Err(_) => Response::Invalid {
                    version: PROTOCOL_VERSION,
                },
            }
        }
        Request::InvocationLoad {
            version,
            slot,
            public_key,
            invocation_id,
            request_digest,
            signature,
        } => {
            if version != PROTOCOL_VERSION || validate_slot(&slot).is_err() || signature.len() != 64
            {
                return Response::Invalid {
                    version: PROTOCOL_VERSION,
                };
            }
            let Ok(signature) = <[u8; 64]>::try_from(signature.as_slice()) else {
                return Response::Invalid {
                    version: PROTOCOL_VERSION,
                };
            };
            let token =
                SignedInvocationId::new(public_key, invocation_id, request_digest, signature);
            match database.load_invocation_receipt(&slot, &token) {
                Ok(receipt) => Response::Invocation {
                    version: PROTOCOL_VERSION,
                    receipt: receipt.map(WireInvocationReceipt::from),
                },
                Err(Error::Conflict) => Response::Conflict {
                    version: PROTOCOL_VERSION,
                },
                Err(Error::InvalidInvocationSignature) => Response::Invalid {
                    version: PROTOCOL_VERSION,
                },
                Err(_) => Response::Internal {
                    version: PROTOCOL_VERSION,
                },
            }
        }
        Request::InvocationCommit {
            version,
            slot,
            public_key,
            invocation_id,
            request_digest,
            signature,
            expected_generation,
            snapshot_id,
            secret_handle,
            response,
        } => {
            if version != PROTOCOL_VERSION
                || validate_slot(&slot).is_err()
                || secret_handle.len() != 88
                || signature.len() != 64
                || response.len() > MAX_INVOCATION_RESPONSE_BYTES
            {
                return Response::Invalid {
                    version: PROTOCOL_VERSION,
                };
            }
            let Ok(signature) = <[u8; 64]>::try_from(signature.as_slice()) else {
                return Response::Invalid {
                    version: PROTOCOL_VERSION,
                };
            };
            let token =
                SignedInvocationId::new(public_key, invocation_id, request_digest, signature);
            let record = match CheckpointAnchorRecord::new(&snapshot_id, &secret_handle) {
                Ok(record) => record,
                Err(_) => {
                    return Response::Invalid {
                        version: PROTOCOL_VERSION,
                    };
                }
            };
            match database.commit_invocation(&slot, &token, expected_generation, record, &response)
            {
                Ok(receipt) => Response::Invocation {
                    version: PROTOCOL_VERSION,
                    receipt: Some(WireInvocationReceipt::from(receipt)),
                },
                Err(Error::Conflict) => Response::Conflict {
                    version: PROTOCOL_VERSION,
                },
                Err(Error::CommitIndeterminate) => Response::CommitUnknown {
                    version: PROTOCOL_VERSION,
                },
                Err(Error::InvalidInvocationSignature | Error::InvocationResponseTooLarge) => {
                    Response::Invalid {
                        version: PROTOCOL_VERSION,
                    }
                }
                Err(_) => Response::Internal {
                    version: PROTOCOL_VERSION,
                },
            }
        }
    }
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, Error> {
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

fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> Result<(), Error> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(Error::Protocol);
    }
    let length = u32::try_from(frame.len()).map_err(|_| Error::Protocol)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(frame))
        .and_then(|()| stream.flush())
        .map_err(|error| Error::Socket(error.to_string()))
}

fn serve_connection(mut stream: UnixStream, database: &mut AnchorDatabase) -> Result<(), Error> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| Error::Socket(error.to_string()))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| Error::Socket(error.to_string()))?;
    let frame = read_frame(&mut stream)?;
    let request: Request = serde_json::from_slice(&frame).map_err(|_| Error::Protocol)?;
    let response = serve_request(database, request);
    let frame = serde_json::to_vec(&response).map_err(|_| Error::Protocol)?;
    write_frame(&mut stream, &frame)
}

struct BoundSocket(PathBuf);
impl Drop for BoundSocket {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.0)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
        {
            let _ = fs::remove_file(&self.0);
        }
    }
}

/// Run the local anchor service until its listener fails or the process exits.
/// The socket mode must be `0o600` (same service account) or `0o660` (service
/// account plus its preconfigured group). Its parent directory must be trusted.
pub fn serve_unix(
    socket_path: impl AsRef<Path>,
    database_path: impl AsRef<Path>,
    master_key: zeroize::Zeroizing<[u8; 32]>,
    socket_mode: u32,
) -> Result<(), Error> {
    if !matches!(socket_mode, 0o600 | 0o660) {
        return Err(Error::InvalidSocketMode);
    }
    let database_path = database_path.as_ref();
    validate_database_path(database_path, true)?;
    let mut database = AnchorDatabase::open(database_path, master_key)?;
    validate_database_path(database_path, false)?;
    fs::set_permissions(database_path, Permissions::from_mode(0o600))
        .map_err(|error| Error::Database(error.to_string()))?;
    let socket_path = socket_path.as_ref();
    let listener =
        UnixListener::bind(socket_path).map_err(|error| Error::Socket(error.to_string()))?;
    let _bound_socket = BoundSocket(socket_path.to_path_buf());
    fs::set_permissions(socket_path, Permissions::from_mode(socket_mode))
        .map_err(|error| Error::Socket(error.to_string()))?;
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                // A malformed/abandoned client is isolated to its connection;
                // the service remains available for the next authorized peer.
                let _ = serve_connection(stream, &mut database);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Socket(error.to_string())),
        }
    }
    Ok(())
}

fn validate_database_path(path: &Path, allow_missing: bool) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(Error::InvalidDatabasePath),
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(Error::InvalidDatabasePath)
        }
        Err(error) => Err(Error::Database(error.to_string())),
    }
}

/// Client adapter for one validated service slot. Unix socket permissions are
/// its authentication boundary; clients needing a remote service require a
/// separately authenticated network protocol.
pub struct UnixAnchorClient {
    socket_path: PathBuf,
    slot: String,
}

impl UnixAnchorClient {
    fn new(socket_path: impl Into<PathBuf>, slot: &str) -> Result<Self, Error> {
        validate_slot(slot)?;
        Ok(Self {
            socket_path: socket_path.into(),
            slot: slot.to_owned(),
        })
    }

    pub fn registry(
        socket_path: impl Into<PathBuf>,
        slot: &str,
    ) -> Result<UnixRegistryAnchor, Error> {
        Ok(UnixRegistryAnchor(Self::new(socket_path, slot)?))
    }

    pub fn checkpoint(
        socket_path: impl Into<PathBuf>,
        slot: &str,
    ) -> Result<UnixCheckpointAnchor, Error> {
        Ok(UnixCheckpointAnchor(Self::new(socket_path, slot)?))
    }

    pub fn invocation(
        socket_path: impl Into<PathBuf>,
        slot: &str,
    ) -> Result<UnixInvocationAnchor, Error> {
        Ok(UnixInvocationAnchor(Self::new(socket_path, slot)?))
    }

    fn exchange(&self, request: Request) -> Result<Response, Error> {
        let frame = serde_json::to_vec(&request).map_err(|_| Error::Protocol)?;
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err(Error::Protocol);
        }
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|error| Error::Socket(error.to_string()))?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|error| Error::Socket(error.to_string()))?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|error| Error::Socket(error.to_string()))?;
        write_frame(&mut stream, &frame)?;
        let response = read_frame(&mut stream)?;
        serde_json::from_slice(&response).map_err(|_| Error::Protocol)
    }
}

pub struct UnixRegistryAnchor(UnixAnchorClient);

pub struct UnixCheckpointAnchor(UnixAnchorClient);

pub struct UnixInvocationAnchor(UnixAnchorClient);

impl UnixInvocationAnchor {
    pub fn load(
        &self,
        invocation: &SignedInvocationId,
    ) -> Result<Option<InvocationReceipt>, Error> {
        match self.0.exchange(Request::InvocationLoad {
            version: PROTOCOL_VERSION,
            slot: self.0.slot.clone(),
            public_key: *invocation.public_key(),
            invocation_id: *invocation.invocation_id(),
            request_digest: *invocation.request_digest(),
            signature: invocation.signature().to_vec(),
        })? {
            Response::Invocation { version, receipt } if version == PROTOCOL_VERSION => {
                receipt.map(WireInvocationReceipt::into_receipt).transpose()
            }
            Response::Conflict { .. } => Err(Error::Conflict),
            Response::Invalid { .. } => Err(Error::InvalidInvocationSignature),
            _ => Err(Error::Protocol),
        }
    }

    pub fn commit(
        &self,
        invocation: &SignedInvocationId,
        expected_generation: Option<u64>,
        next_record: CheckpointAnchorRecord,
        response: &[u8],
    ) -> Result<InvocationReceipt, Error> {
        if response.len() > MAX_INVOCATION_RESPONSE_BYTES {
            return Err(Error::InvocationResponseTooLarge);
        }
        let result = self.0.exchange(Request::InvocationCommit {
            version: PROTOCOL_VERSION,
            slot: self.0.slot.clone(),
            public_key: *invocation.public_key(),
            invocation_id: *invocation.invocation_id(),
            request_digest: *invocation.request_digest(),
            signature: invocation.signature().to_vec(),
            expected_generation,
            snapshot_id: next_record.snapshot_id().to_owned(),
            secret_handle: next_record.secret_handle().to_vec(),
            response: response.to_vec(),
        });
        match result {
            Ok(Response::Invocation {
                version,
                receipt: Some(receipt),
            }) if version == PROTOCOL_VERSION => receipt.into_receipt(),
            Ok(Response::Conflict { .. }) => Err(Error::Conflict),
            Ok(Response::Invalid { .. }) => Err(Error::InvalidInvocationSignature),
            Ok(Response::CommitUnknown { .. }) | Err(_) => Err(Error::CommitIndeterminate),
            Ok(Response::Internal { .. }) => {
                Err(Error::Database("anchor service internal error".into()))
            }
            _ => Err(Error::Protocol),
        }
    }
}

impl RegistryVersionAnchor for UnixRegistryAnchor {
    fn current_version(&mut self) -> Result<Option<u64>, registry::Error> {
        let response = self
            .0
            .exchange(Request::RegistryLoad {
                version: PROTOCOL_VERSION,
                slot: self.0.slot.clone(),
            })
            .map_err(|error| registry::Error::Anchor(error.to_string()))?;
        match response {
            Response::RegistryVersion { version, current } if version == PROTOCOL_VERSION => {
                Ok(current)
            }
            Response::Invalid { .. } => {
                Err(registry::Error::Anchor("invalid anchor request".into()))
            }
            _ => Err(registry::Error::Anchor(
                "invalid anchor service response".into(),
            )),
        }
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<u64>,
        next: u64,
    ) -> Result<(), registry::Error> {
        let response = self.0.exchange(Request::RegistryCas {
            version: PROTOCOL_VERSION,
            slot: self.0.slot.clone(),
            expected,
            next,
        });
        match response {
            Ok(Response::Ack { version }) if version == PROTOCOL_VERSION => Ok(()),
            Ok(Response::Conflict { .. }) => Err(registry::Error::AnchorConflict),
            Ok(Response::CommitUnknown { .. }) | Err(_) => {
                Err(registry::Error::AnchorCommitUnknown)
            }
            Ok(Response::Invalid { .. } | Response::Internal { .. }) => Err(
                registry::Error::Anchor("anchor service rejected request".into()),
            ),
            Ok(_) => Err(registry::Error::AnchorCommitUnknown),
        }
    }
}

impl CheckpointAnchor for UnixCheckpointAnchor {
    fn load(&mut self) -> Result<Option<CheckpointAnchorRecord>, store::Error> {
        let response = self
            .0
            .exchange(Request::CheckpointLoad {
                version: PROTOCOL_VERSION,
                slot: self.0.slot.clone(),
            })
            .map_err(|error| store::Error::Backend(error.to_string()))?;
        match response {
            Response::Checkpoint { version, record } if version == PROTOCOL_VERSION => record
                .map(|wire| CheckpointAnchorRecord::new(&wire.snapshot_id, &wire.secret_handle))
                .transpose(),
            Response::Invalid { .. } => Err(store::Error::Backend("invalid anchor request".into())),
            _ => Err(store::Error::Backend(
                "invalid anchor service response".into(),
            )),
        }
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        next_record: CheckpointAnchorRecord,
    ) -> Result<(), store::Error> {
        let response = self.0.exchange(Request::CheckpointCas {
            version: PROTOCOL_VERSION,
            slot: self.0.slot.clone(),
            expected_generation,
            snapshot_id: next_record.snapshot_id().to_owned(),
            secret_handle: next_record.secret_handle().to_vec(),
        });
        match response {
            Ok(Response::Ack { version }) if version == PROTOCOL_VERSION => Ok(()),
            Ok(Response::Conflict { .. }) => Err(store::Error::AnchorConflict),
            Ok(Response::CommitUnknown { .. }) | Err(_) => Err(store::Error::AnchorCommitUnknown),
            Ok(Response::Invalid { .. } | Response::Internal { .. }) => Err(store::Error::Backend(
                "anchor service rejected request".into(),
            )),
            Ok(_) => Err(store::Error::AnchorCommitUnknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnchorDatabase;
    use ed25519_dalek::{Signer, SigningKey};
    use oblivion_registry::RegistryVersionAnchor;
    use oblivion_store::{CheckpointAnchor, CheckpointAnchorRecord};
    use std::time::{SystemTime, UNIX_EPOCH};
    use zeroize::Zeroizing;

    fn root(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "oblivion-anchor-rpc-{label}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn handle() -> [u8; 88] {
        let mut bytes = [0; 88];
        bytes[..8].copy_from_slice(b"OBLTRST1");
        bytes[8..16].copy_from_slice(&1_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&48_u64.to_le_bytes());
        bytes[24..56].fill(3);
        bytes[56..].fill(9);
        bytes
    }

    #[test]
    fn local_service_round_trips_registry_and_checkpoint_anchor_calls() {
        let root = root("roundtrip");
        let socket_path = root.join("anchor.sock");
        let database_path = root.join("anchor.sqlite");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let mut database =
            AnchorDatabase::open(&database_path, Zeroizing::new([0x66; 32])).unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..5 {
                let (stream, _) = listener.accept().unwrap();
                serve_connection(stream, &mut database).unwrap();
            }
        });

        let mut registry = UnixAnchorClient::registry(&socket_path, "registry-a").unwrap();
        assert_eq!(registry.current_version().unwrap(), None);
        registry.compare_and_swap(None, 1).unwrap();

        let mut checkpoint = UnixAnchorClient::checkpoint(&socket_path, "state-a").unwrap();
        let secret = handle();
        checkpoint
            .compare_and_swap(
                None,
                CheckpointAnchorRecord::new("snapshot-a", &secret).unwrap(),
            )
            .unwrap();
        let loaded = checkpoint.load().unwrap().unwrap();
        assert_eq!(loaded.snapshot_id(), "snapshot-a");
        assert_eq!(loaded.secret_handle(), secret);
        assert_eq!(registry.current_version().unwrap(), Some(1));

        server.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_service_round_trips_signed_invocation_receipts() {
        let root = root("invocation");
        let socket_path = root.join("anchor.sock");
        let database_path = root.join("anchor.sqlite");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let mut database =
            AnchorDatabase::open(&database_path, Zeroizing::new([0x77; 32])).unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..4 {
                let (stream, _) = listener.accept().unwrap();
                serve_connection(stream, &mut database).unwrap();
            }
        });

        let signing_key = SigningKey::from_bytes(&[0x33; 32]);
        let invocation_id = [0x44; 16];
        let request_digest = [0x55; 32];
        let signature = signing_key
            .sign(&SignedInvocationId::signing_message(
                &invocation_id,
                &request_digest,
            ))
            .to_bytes();
        let token = SignedInvocationId::new(
            signing_key.verifying_key().to_bytes(),
            invocation_id,
            request_digest,
            signature,
        );
        let client = UnixAnchorClient::invocation(&socket_path, "state-a").unwrap();
        assert!(client.load(&token).unwrap().is_none());
        let invalid = SignedInvocationId::new(
            *token.public_key(),
            *token.invocation_id(),
            *token.request_digest(),
            [0; 64],
        );
        assert!(matches!(
            client.load(&invalid),
            Err(Error::InvalidInvocationSignature)
        ));

        let response = b"exact response bytes";
        let committed = client
            .commit(
                &token,
                None,
                CheckpointAnchorRecord::new("snapshot-a", &handle()).unwrap(),
                response,
            )
            .unwrap();
        assert_eq!(committed.snapshot_id(), "snapshot-a");
        assert_eq!(committed.generation(), 1);
        assert_eq!(committed.response(), response);
        let replayed = client.load(&token).unwrap().unwrap();
        assert_eq!(replayed.snapshot_id(), committed.snapshot_id());
        assert_eq!(replayed.generation(), committed.generation());
        assert_eq!(replayed.response(), committed.response());

        server.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn transport_failure_during_cas_is_indeterminate() {
        let root = root("missing");
        let mut anchor = UnixAnchorClient::checkpoint(root.join("absent.sock"), "state-a").unwrap();
        let secret = handle();
        let result = anchor.compare_and_swap(
            None,
            CheckpointAnchorRecord::new("snapshot-a", &secret).unwrap(),
        );
        assert!(matches!(
            result,
            Err(oblivion_store::Error::AnchorCommitUnknown)
        ));
        std::fs::remove_dir_all(root).unwrap();
    }
}
