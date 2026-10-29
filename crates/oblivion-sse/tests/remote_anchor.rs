use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use oblivion_anchor::{
    AnchorDatabase, ClientAuthorizationPolicy, mtls_client_config, mtls_server_config,
    serve_mtls_with_shutdown,
};
use oblivion_sse::{JournalError, Limits, PersistentClient, Server, TlsSseJournalAnchor};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{RootCertStore, pki_types::PrivateKeyDer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const CLIENT_KEY: [u8; 32] = [0x63; 32];
const WITNESS_KEY: [u8; 32] = [0x92; 32];

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "oblivion-sse-remote-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn identity_pair() -> (
    rustls::pki_types::CertificateDer<'static>,
    PrivateKeyDer<'static>,
    rustls::pki_types::CertificateDer<'static>,
    PrivateKeyDer<'static>,
    rustls::pki_types::CertificateDer<'static>,
) {
    let root_key = KeyPair::generate().expect("root key");
    let mut root_params = CertificateParams::new(vec!["test-root".into()]).expect("root params");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_cert = root_params
        .self_signed(&root_key)
        .expect("root certificate");
    let issuer = Issuer::from_params(&root_params, &root_key);

    let server_key = KeyPair::generate().expect("server key");
    let mut server_params =
        CertificateParams::new(vec!["localhost".into()]).expect("server params");
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, &issuer)
        .expect("server cert");

    let client_key = KeyPair::generate().expect("client key");
    let mut client_params =
        CertificateParams::new(vec!["oblivion-client".into()]).expect("client params");
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params
        .signed_by(&client_key, &issuer)
        .expect("client cert");

    (
        server_cert.der().clone(),
        PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
        client_cert.der().clone(),
        PrivateKeyDer::Pkcs8(client_key.serialize_der().into()),
        root_cert.der().clone(),
    )
}

fn configs() -> (
    Arc<rustls::ServerConfig>,
    Arc<rustls::ClientConfig>,
    ClientAuthorizationPolicy,
) {
    let (server_cert, server_key, client_cert, client_key, root_cert) = identity_pair();
    let mut roots = RootCertStore::empty();
    roots.add(root_cert).expect("root");
    let server_config =
        mtls_server_config(vec![server_cert], server_key, roots.clone()).expect("server TLS");
    let fingerprint: [u8; 32] = Sha256::digest(client_cert.as_ref()).into();
    let fingerprint: String = fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let policy_json = format!(
        "{{\"version\":1,\"clients\":[{{\"certificate_sha256\":\"{fingerprint}\",\"slots\":[\"independent-sse-index\"]}}]}}"
    );
    let authorization = ClientAuthorizationPolicy::from_json(policy_json.as_bytes())
        .expect("valid client authorization policy");
    let client_config =
        mtls_client_config(roots, vec![client_cert], client_key).expect("client TLS");
    (server_config, client_config, authorization)
}

struct Witness {
    address: SocketAddr,
    shutdown: mpsc::Sender<()>,
    thread: thread::JoinHandle<Result<(), oblivion_anchor::Error>>,
}

fn start_witness(
    root: &Path,
    config: Arc<rustls::ServerConfig>,
    authorization: ClientAuthorizationPolicy,
) -> Witness {
    let listener = TcpListener::bind("127.0.0.1:0").expect("witness listener");
    let address = listener.local_addr().expect("witness address");
    let database = AnchorDatabase::open(root.join("witness.sqlite"), Zeroizing::new(WITNESS_KEY))
        .expect("witness database");
    let (shutdown, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        serve_mtls_with_shutdown(listener, database, config, authorization, receiver)
    });
    Witness {
        address,
        shutdown,
        thread,
    }
}

fn anchor(address: SocketAddr, config: Arc<rustls::ClientConfig>) -> TlsSseJournalAnchor {
    TlsSseJournalAnchor::new(address, "localhost", "independent-sse-index", config)
        .expect("TLS SSE anchor")
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("snapshot directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700))
            .expect("private snapshot directory");
    }
    for entry in fs::read_dir(source).expect("journal entries") {
        let entry = entry.expect("journal entry");
        if entry.file_type().expect("entry metadata").is_file() {
            fs::copy(entry.path(), destination.join(entry.file_name())).expect("copy journal file");
        }
    }
}

#[test]
fn restored_application_journal_is_rejected_when_remote_witness_kept_newer_head() {
    let root = TestDirectory::new();
    let journal = root.path().join("journal");
    let old_snapshot = root.path().join("old-journal-snapshot");
    let (server_config, client_config, authorization) = configs();
    let witness = start_witness(root.path(), server_config, authorization);

    let mut client = PersistentClient::create(
        &journal,
        &CLIENT_KEY,
        Limits::default(),
        anchor(witness.address, client_config.clone()),
    )
    .expect("create persistent SSE index");
    let mut server = Server::new(client.index_id(), Limits::default()).expect("SSE server");
    copy_directory(&journal, &old_snapshot);

    let update = client
        .prepare_add(b"private-keyword", 42)
        .expect("prepare update");
    let acknowledgement = server.insert(update).expect("commit server update");
    client
        .finish_add(acknowledgement)
        .expect("publish remote head");
    drop(client);

    fs::remove_dir_all(&journal).expect("remove current local journal");
    copy_directory(&old_snapshot, &journal);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&journal)
                .expect("restored metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let restored = PersistentClient::open(
        &journal,
        &CLIENT_KEY,
        anchor(witness.address, client_config),
    );
    assert!(
        restored.is_err(),
        "old local journal snapshot must not reopen"
    );

    let _ = witness.shutdown.send(());
    witness
        .thread
        .join()
        .expect("witness thread")
        .expect("witness service");
}

#[test]
fn remote_witness_reserves_pending_update_against_stale_writer() {
    let root = TestDirectory::new();
    let journal = root.path().join("journal");
    let (server_config, client_config, authorization) = configs();
    let witness = start_witness(root.path(), server_config, authorization);

    let mut winner = PersistentClient::create(
        &journal,
        &CLIENT_KEY,
        Limits::default(),
        anchor(witness.address, client_config.clone()),
    )
    .expect("create persistent SSE index");
    let mut server = Server::new(winner.index_id(), Limits::default()).expect("SSE server");
    let mut stale = PersistentClient::open(
        &journal,
        &CLIENT_KEY,
        anchor(witness.address, client_config.clone()),
    )
    .expect("open stale writer at the same generation");

    let winning_request = winner
        .prepare_add(b"reserved-keyword", 42)
        .expect("reserve the pending update in the remote witness");
    assert!(matches!(
        stale.prepare_add(b"competing-keyword", 99),
        Err(JournalError::AnchorConflict)
    ));
    assert!(matches!(stale.retry_pending(), Err(JournalError::Poisoned)));
    drop(stale);

    let mut recovered = PersistentClient::open(
        &journal,
        &CLIENT_KEY,
        anchor(witness.address, client_config.clone()),
    )
    .expect("recover the witness-selected journal head");
    let retry = recovered
        .retry_pending()
        .expect("recover the winning pending update");
    assert_eq!(retry.address, winning_request.address);
    assert_eq!(retry.ciphertext, winning_request.ciphertext);
    let acknowledgement = server
        .insert(retry)
        .expect("submit the reserved request exactly once");
    recovered
        .finish_add(acknowledgement)
        .expect("persist the acknowledgement");
    drop(recovered);
    drop(winner);

    let restored = PersistentClient::open(
        &journal,
        &CLIENT_KEY,
        anchor(witness.address, client_config),
    )
    .expect("reopen acknowledged state");
    let (snapshot, request) = restored
        .prepare_search(b"reserved-keyword")
        .expect("prepare winning-keyword search");
    assert_eq!(
        restored
            .finish_search(&snapshot, server.search(&request).expect("search server"))
            .expect("decode winning result"),
        vec![42]
    );
    let (snapshot, request) = restored
        .prepare_search(b"competing-keyword")
        .expect("prepare losing-keyword search");
    assert!(
        restored
            .finish_search(&snapshot, server.search(&request).expect("search server"))
            .expect("decode empty result")
            .is_empty()
    );

    let _ = witness.shutdown.send(());
    witness
        .thread
        .join()
        .expect("witness thread")
        .expect("witness service");
}
