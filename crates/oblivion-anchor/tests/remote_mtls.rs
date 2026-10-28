use std::{
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use oblivion_anchor::{
    AnchorDatabase, SseJournalState, TlsRegistryCatalogAnchor, TlsSseJournalAnchor,
    mtls_client_config, mtls_server_config, serve_mtls_with_shutdown,
};
use oblivion_registry::{
    Record, RegistryCatalogAnchor, RegistryCatalogState, SignedRegistry, VerifiedRegistry,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{RootCertStore, pki_types::PrivateKeyDer};
use zeroize::Zeroizing;

fn test_root(label: &str) -> (rcgen::Certificate, KeyPair, CertificateParams) {
    let key = KeyPair::generate().expect("root key");
    let mut params = CertificateParams::new(vec![label.to_owned()]).expect("root params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).expect("root certificate");
    (cert, key, params)
}

fn signed_identity(
    host: &str,
    eku: ExtendedKeyUsagePurpose,
    issuer_params: &CertificateParams,
    issuer_key: &KeyPair,
) -> (
    rustls::pki_types::CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(vec![host.to_owned()]).expect("leaf params");
    params.extended_key_usages = vec![eku];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let issuer = Issuer::from_params(issuer_params, issuer_key);
    let cert = params.signed_by(&key, &issuer).expect("leaf certificate");
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
}

fn identity_pair(
    root_name: &str,
) -> (
    rustls::pki_types::CertificateDer<'static>,
    PrivateKeyDer<'static>,
    rustls::pki_types::CertificateDer<'static>,
    PrivateKeyDer<'static>,
    rustls::pki_types::CertificateDer<'static>,
) {
    let (root_cert, root_key, root_params) = test_root(root_name);
    let (server_cert, server_key) = signed_identity(
        "localhost",
        ExtendedKeyUsagePurpose::ServerAuth,
        &root_params,
        &root_key,
    );
    let (client_cert, client_key) = signed_identity(
        "oblivion-client",
        ExtendedKeyUsagePurpose::ClientAuth,
        &root_params,
        &root_key,
    );
    (
        server_cert,
        server_key,
        client_cert,
        client_key,
        root_cert.der().clone(),
    )
}

fn root_store(root: rustls::pki_types::CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(root).expect("valid root");
    roots
}

fn temp_database() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("oblivion-anchor-tls-{stamp}.sqlite"))
}

struct RunningWitness {
    address: SocketAddr,
    shutdown: mpsc::Sender<()>,
    thread: thread::JoinHandle<Result<(), oblivion_anchor::Error>>,
}

fn start_witness(path: PathBuf, config: Arc<rustls::ServerConfig>) -> RunningWitness {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind witness");
    let address = listener.local_addr().expect("witness address");
    let database = AnchorDatabase::open(&path, Zeroizing::new([0x5a; 32])).expect("open database");
    let (shutdown, receiver) = mpsc::channel();
    let thread =
        thread::spawn(move || serve_mtls_with_shutdown(listener, database, config, receiver));
    RunningWitness {
        address,
        shutdown,
        thread,
    }
}

fn client(address: SocketAddr, config: Arc<rustls::ClientConfig>) -> TlsSseJournalAnchor {
    TlsSseJournalAnchor::new(address, "localhost", "sse-main-index", config)
        .expect("valid TLS anchor client")
}

#[test]
fn mutually_authenticated_remote_anchor_cas_survives_witness_restart() {
    let path = temp_database();
    let (server_cert, server_key, client_cert, client_key, root_cert) = identity_pair("test-root");
    let server_config =
        mtls_server_config(vec![server_cert], server_key, root_store(root_cert.clone()))
            .expect("server TLS config");
    let client_config = mtls_client_config(root_store(root_cert), vec![client_cert], client_key)
        .expect("client TLS config");

    let first = start_witness(path.clone(), server_config.clone());
    let mut anchor = client(first.address, client_config.clone());
    assert_eq!(anchor.load().expect("initial load"), None);
    let first_state = SseJournalState::new([7; 16], 0, [9; 32]).expect("first state");
    anchor
        .compare_and_swap(None, first_state)
        .expect("initial CAS");
    assert!(matches!(
        anchor.compare_and_swap(None, first_state),
        Err(oblivion_anchor::Error::Conflict)
    ));
    assert_eq!(
        anchor.load().expect("read committed state"),
        Some(first_state)
    );
    let _ = first.shutdown.send(());
    first
        .thread
        .join()
        .expect("first witness thread")
        .expect("first witness");

    let second = start_witness(path.clone(), server_config);
    let mut after_restart = client(second.address, client_config);
    assert_eq!(
        after_restart.load().expect("load after witness restart"),
        Some(first_state)
    );
    let _ = second.shutdown.send(());
    second
        .thread
        .join()
        .expect("second witness thread")
        .expect("second witness");
    let _ = std::fs::remove_file(path);
}

#[test]
fn remote_anchor_rejects_untrusted_client_and_untrusted_witness_certificates() {
    let path = temp_database();
    let (server_cert, server_key, client_cert, client_key, trusted_root) =
        identity_pair("trusted-root");
    let (_bad_server_cert, _bad_server_key, bad_client_cert, bad_client_key, untrusted_root) =
        identity_pair("untrusted-root");
    let server_config = mtls_server_config(
        vec![server_cert],
        server_key,
        root_store(trusted_root.clone()),
    )
    .expect("server TLS config");
    let witness = start_witness(path.clone(), server_config.clone());

    let untrusted_client = mtls_client_config(
        root_store(trusted_root.clone()),
        vec![bad_client_cert],
        bad_client_key,
    )
    .expect("untrusted client TLS config");
    assert!(client(witness.address, untrusted_client).load().is_err());

    let valid_client = mtls_client_config(
        root_store(trusted_root),
        vec![client_cert.clone()],
        client_key.clone_key(),
    )
    .expect("valid client TLS config");
    assert_eq!(
        client(witness.address, valid_client)
            .load()
            .expect("valid peer"),
        None
    );

    let client_with_wrong_root = mtls_client_config(
        root_store(untrusted_root),
        vec![client_cert.clone()],
        client_key.clone_key(),
    )
    .expect("wrong-root client TLS config");
    assert!(
        client(witness.address, client_with_wrong_root)
            .load()
            .is_err()
    );

    let _ = witness.shutdown.send(());
    witness
        .thread
        .join()
        .expect("witness thread")
        .expect("witness");

    let _ = std::fs::remove_file(path);
}

#[test]
fn remote_anchor_fails_closed_when_witness_is_unavailable() {
    let (_server_cert, _server_key, client_cert, client_key, root_cert) =
        identity_pair("offline-root");
    let client_config = mtls_client_config(root_store(root_cert), vec![client_cert], client_key)
        .expect("client TLS config");
    let listener = TcpListener::bind("127.0.0.1:0").expect("temporary listener");
    let address = listener.local_addr().expect("temporary address");
    drop(listener);
    let mut anchor = client(address, client_config.clone());
    assert!(matches!(
        anchor.load(),
        Err(oblivion_anchor::Error::Socket(_))
    ));
    let mut catalog =
        TlsRegistryCatalogAnchor::new(address, "localhost", "registry", client_config)
            .expect("catalog TLS anchor");
    assert_eq!(
        catalog.compare_and_swap_catalog(None, 1, [0x55; 32]),
        Err(oblivion_registry::Error::AnchorCommitUnknown)
    );
}

#[test]
fn remote_catalog_anchor_preserves_digest_cas_and_rejects_stale_writer() {
    let path = temp_database();
    let (server_cert, server_key, client_cert, client_key, root_cert) =
        identity_pair("catalog-root");
    let server_config =
        mtls_server_config(vec![server_cert], server_key, root_store(root_cert.clone()))
            .expect("server TLS config");
    let client_config = mtls_client_config(
        root_store(root_cert.clone()),
        vec![client_cert.clone()],
        client_key.clone_key(),
    )
    .expect("client TLS config");
    let witness = start_witness(path.clone(), server_config.clone());
    let mut anchor = TlsRegistryCatalogAnchor::new(
        witness.address,
        "localhost",
        "function-registry",
        client_config,
    )
    .expect("catalog TLS anchor");

    assert_eq!(anchor.current_catalog().expect("empty catalog"), None);
    let signing = SigningKey::from_bytes(&[0x29; 32]);
    let record =
        Record::sign(0, 1, [0x31; 32], [0x42; 32], 0, &signing).expect("signed function record");
    let encoded = SignedRegistry::sign(1, vec![record], &signing).expect("signed catalog");
    let verified =
        VerifiedRegistry::verify(&encoded, &signing.verifying_key()).expect("verified catalog");
    verified
        .activate_catalog(&mut anchor)
        .expect("first catalog activation");
    verified
        .activate_catalog(&mut anchor)
        .expect("exact catalog restart");
    let expected =
        RegistryCatalogState::new(1, Some(*verified.catalog_digest())).expect("catalog state");
    assert_eq!(
        anchor.current_catalog().expect("published catalog"),
        Some(expected)
    );
    assert_eq!(
        anchor.compare_and_swap_catalog(None, 2, [0x24; 32]),
        Err(oblivion_registry::Error::AnchorConflict)
    );
    assert_eq!(
        anchor.current_catalog().expect("state after stale write"),
        Some(expected)
    );

    let _ = witness.shutdown.send(());
    witness
        .thread
        .join()
        .expect("witness thread")
        .expect("witness");

    let restarted = start_witness(path.clone(), server_config);
    let mut recovered = TlsRegistryCatalogAnchor::new(
        restarted.address,
        "localhost",
        "function-registry",
        mtls_client_config(root_store(root_cert), vec![client_cert], client_key)
            .expect("client TLS config after restart"),
    )
    .expect("recovered catalog TLS anchor");
    assert_eq!(
        recovered.current_catalog().expect("catalog after restart"),
        Some(expected)
    );
    let _ = restarted.shutdown.send(());
    restarted
        .thread
        .join()
        .expect("restarted witness thread")
        .expect("restarted witness");
    let _ = std::fs::remove_file(path);
}
