use std::{
    io::Read,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer, SigningKey};
use oblivion_anchor::{
    AnchorDatabase, ClientAuthorizationPolicy, MAX_INVOCATION_RESPONSE_BYTES, SignedInvocationId,
    SseJournalState, TlsInvocationAnchor, TlsRegistryCatalogAnchor, TlsSseJournalAnchor,
    mtls_client_config, mtls_server_config, serve_mtls_with_shutdown,
};
use oblivion_registry::{
    Record, RegistryCatalogAnchor, RegistryCatalogState, SignedRegistry, VerifiedRegistry,
};
use oblivion_store::{
    CheckpointAnchor, CheckpointAnchorRecord, Config, MemoryBackend, PathOram, TrustedCheckpoint,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    RootCertStore, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::ServerConnection,
};
use sha2::{Digest, Sha256};
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

fn authorization_policy_for(
    certificate: &CertificateDer<'_>,
    slots: &[&str],
) -> ClientAuthorizationPolicy {
    let fingerprint: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
    let fingerprint: String = fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let slots = slots
        .iter()
        .map(|slot| format!("\"{slot}\""))
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(
        "{{\"version\":1,\"clients\":[{{\"certificate_sha256\":\"{fingerprint}\",\"slots\":[{slots}]}}]}}"
    );
    ClientAuthorizationPolicy::from_json(json.as_bytes()).expect("valid client ACL")
}

fn start_witness(
    path: PathBuf,
    config: Arc<rustls::ServerConfig>,
    authorization: ClientAuthorizationPolicy,
) -> RunningWitness {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind witness");
    let address = listener.local_addr().expect("witness address");
    let database = AnchorDatabase::open(&path, Zeroizing::new([0x5a; 32])).expect("open database");
    let (shutdown, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        serve_mtls_with_shutdown(listener, database, config, authorization, receiver)
    });
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

fn checkpoint_client(
    address: SocketAddr,
    slot: &str,
    config: Arc<rustls::ClientConfig>,
) -> oblivion_anchor::TlsCheckpointAnchor {
    oblivion_anchor::TlsCheckpointAnchor::new(address, "localhost", slot, config)
        .expect("valid checkpoint TLS anchor client")
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

fn invocation_handle(generation: u64) -> [u8; 88] {
    let mut bytes = [0; 88];
    bytes[..8].copy_from_slice(b"OBLTRST1");
    bytes[8..16].copy_from_slice(&generation.to_le_bytes());
    bytes[16..24].copy_from_slice(&48_u64.to_le_bytes());
    bytes[24..56].fill(generation as u8);
    bytes[56..].fill(0xA5);
    bytes
}

#[test]
fn mutually_authenticated_remote_anchor_cas_survives_witness_restart() {
    let path = temp_database();
    let (server_cert, server_key, client_cert, client_key, root_cert) = identity_pair("test-root");
    let server_config =
        mtls_server_config(vec![server_cert], server_key, root_store(root_cert.clone()))
            .expect("server TLS config");
    let authorization = authorization_policy_for(&client_cert, &["sse-main-index"]);
    let client_config = mtls_client_config(root_store(root_cert), vec![client_cert], client_key)
        .expect("client TLS config");

    let first = start_witness(path.clone(), server_config.clone(), authorization.clone());
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

    let second = start_witness(path.clone(), server_config, authorization);
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
fn remote_invocation_anchor_commits_replays_and_recovers_the_original_receipt() {
    let root = temp_database();
    let root_dir = root.with_extension("invocation-data");
    std::fs::create_dir(&root_dir).expect("test data directory");
    let database = root_dir.join("anchor.sqlite");
    let snapshot = root_dir.join("snapshot.bin");
    let (server_cert, server_key, client_cert, client_key, root_cert) =
        identity_pair("invocation-root");
    let server_config =
        mtls_server_config(vec![server_cert], server_key, root_store(root_cert.clone()))
            .expect("server TLS config");
    let authorization = authorization_policy_for(&client_cert, &["runtime-slot"]);
    let client_config = mtls_client_config(
        root_store(root_cert.clone()),
        vec![client_cert.clone()],
        client_key.clone_key(),
    )
    .expect("client TLS config");
    for invalid_capacity in [0, MAX_INVOCATION_RESPONSE_BYTES + 1] {
        assert!(
            TlsInvocationAnchor::new(
                SocketAddr::from(([127, 0, 0, 1], 1)),
                "localhost",
                "runtime-slot",
                client_config.clone(),
                invalid_capacity,
            )
            .is_err()
        );
    }
    let witness = start_witness(
        database.clone(),
        server_config.clone(),
        authorization.clone(),
    );
    let mut anchor = TlsInvocationAnchor::new(
        witness.address,
        "localhost",
        "runtime-slot",
        client_config.clone(),
        80,
    )
    .expect("invocation TLS anchor");
    let invocation = signed_invocation(9, [0x42; 16], [0x53; 32]);
    let response = [0x6a; 80];

    let short_response_record =
        CheckpointAnchorRecord::new("snapshot-short-response", &invocation_handle(1))
            .expect("short response record");
    assert!(matches!(
        anchor.commit(
            &invocation,
            None,
            short_response_record,
            &response[..response.len() - 1],
        ),
        Err(oblivion_anchor::Error::Protocol)
    ));

    assert!(
        anchor
            .load(&invocation)
            .expect("initial receipt load")
            .is_none()
    );
    assert!(
        CheckpointAnchor::load(&mut anchor)
            .expect("initial checkpoint load")
            .is_none()
    );

    let mut oram = PathOram::new(
        Config::new(8, 16).expect("ORAM config"),
        MemoryBackend::default(),
    )
    .expect("ORAM");
    oram.write(3, &[3; 16]).expect("initial ORAM write");
    let trusted = oram.checkpoint(&snapshot).expect("ORAM checkpoint");
    let secret_handle = trusted.to_secret_bytes();
    let first_record = CheckpointAnchorRecord::new("snapshot-one", secret_handle.as_ref())
        .expect("first anchor record");
    let receipt = anchor
        .commit(&invocation, None, first_record, &response)
        .expect("atomic remote invocation commit");
    assert_eq!(receipt.snapshot_id(), "snapshot-one");
    assert_eq!(receipt.generation(), 1);
    assert_eq!(receipt.response(), &response);

    let replay_record =
        CheckpointAnchorRecord::new("snapshot-two", secret_handle.as_ref()).expect("replay record");
    let replay = anchor
        .commit(&invocation, Some(1), replay_record, &[0x11; 80])
        .expect("idempotent duplicate finish");
    assert_eq!(replay.snapshot_id(), "snapshot-one");
    assert_eq!(replay.generation(), 1);
    assert_eq!(replay.response(), &response);
    assert_eq!(
        anchor
            .confirm(&invocation, &response)
            .expect("exact receipt confirmation")
            .response(),
        &response
    );
    assert!(matches!(
        anchor.confirm(&invocation, &[0; 80]),
        Err(oblivion_anchor::Error::Conflict)
    ));

    let checkpoint = CheckpointAnchor::load(&mut anchor)
        .expect("load committed checkpoint")
        .expect("checkpoint present");
    assert_eq!(checkpoint.snapshot_id(), "snapshot-one");
    assert_eq!(checkpoint.generation(), 1);

    let invalid_signature = SignedInvocationId::new(
        *invocation.public_key(),
        *invocation.invocation_id(),
        *invocation.request_digest(),
        [0; 64],
    );
    assert!(matches!(
        anchor.load(&invalid_signature),
        Err(oblivion_anchor::Error::InvalidInvocationSignature)
    ));

    let stale = signed_invocation(10, [0x43; 16], [0x54; 32]);
    let stale_record = CheckpointAnchorRecord::new("snapshot-stale", &invocation_handle(1))
        .expect("stale checkpoint record");
    assert!(matches!(
        anchor.commit(&stale, Some(2), stale_record, &response),
        Err(oblivion_anchor::Error::Conflict)
    ));

    let _ = witness.shutdown.send(());
    witness
        .thread
        .join()
        .expect("witness thread")
        .expect("witness");

    let restarted = start_witness(database.clone(), server_config, authorization);
    let mut after_restart = TlsInvocationAnchor::new(
        restarted.address,
        "localhost",
        "runtime-slot",
        mtls_client_config(root_store(root_cert), vec![client_cert], client_key)
            .expect("client TLS config after restart"),
        80,
    )
    .expect("restarted invocation TLS anchor");
    let recovered = after_restart
        .load(&invocation)
        .expect("load receipt after restart")
        .expect("persisted invocation receipt");
    assert_eq!(recovered.snapshot_id(), "snapshot-one");
    assert_eq!(recovered.generation(), 1);
    assert_eq!(recovered.response(), &response);
    let recovered_checkpoint = CheckpointAnchor::load(&mut after_restart)
        .expect("load checkpoint after restart")
        .expect("persisted checkpoint");
    assert_eq!(recovered_checkpoint.snapshot_id(), "snapshot-one");
    assert_eq!(recovered_checkpoint.generation(), 1);

    let _ = restarted.shutdown.send(());
    restarted
        .thread
        .join()
        .expect("restarted witness thread")
        .expect("restarted witness");
    let _ = std::fs::remove_dir_all(root_dir);
}

#[test]
fn remote_invocation_anchor_requires_an_exact_certificate_slot_grant() {
    let path = temp_database();
    let (server_cert, server_key, client_cert, client_key, root_cert) =
        identity_pair("invocation-acl-root");
    let server_config =
        mtls_server_config(vec![server_cert], server_key, root_store(root_cert.clone()))
            .expect("server TLS config");
    let authorization = authorization_policy_for(&client_cert, &["different-slot"]);
    let witness = start_witness(path.clone(), server_config, authorization);
    let client_config = mtls_client_config(root_store(root_cert), vec![client_cert], client_key)
        .expect("client TLS config");
    let anchor = TlsInvocationAnchor::new(
        witness.address,
        "localhost",
        "runtime-slot",
        client_config,
        80,
    )
    .expect("invocation TLS anchor");
    let invocation = signed_invocation(13, [0x44; 16], [0x55; 32]);
    let result = anchor.load(&invocation);

    let _ = witness.shutdown.send(());
    witness
        .thread
        .join()
        .expect("witness thread")
        .expect("witness");
    let _ = std::fs::remove_file(path);

    assert!(result.is_err(), "a different slot grant must be denied");
}

#[test]
fn remote_invocation_anchor_treats_a_lost_finish_reply_as_indeterminate() {
    let path = temp_database();
    let (server_cert, server_key, client_cert, client_key, root_cert) =
        identity_pair("invocation-ambiguous-root");
    let server_config =
        mtls_server_config(vec![server_cert], server_key, root_store(root_cert.clone()))
            .expect("server TLS config");
    let authorization = authorization_policy_for(&client_cert, &["runtime-slot"]);
    let client_config = mtls_client_config(root_store(root_cert), vec![client_cert], client_key)
        .expect("client TLS config");
    let witness = start_witness(path.clone(), server_config.clone(), authorization);
    let anchor = TlsInvocationAnchor::new(
        witness.address,
        "localhost",
        "runtime-slot",
        client_config.clone(),
        80,
    )
    .expect("invocation TLS anchor");
    let invocation = signed_invocation(14, [0x45; 16], [0x56; 32]);
    let response = [0x7b; 80];
    let record =
        CheckpointAnchorRecord::new("snapshot-one", &invocation_handle(1)).expect("anchor record");
    let committed = anchor
        .commit(&invocation, None, record, &response)
        .expect("initial commit");
    assert_eq!(committed.response(), &response);

    let listener = TcpListener::bind("127.0.0.1:0").expect("ambiguous witness listener");
    let ambiguous_address = listener.local_addr().expect("ambiguous witness address");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("ambiguous client");
        let mut stream = StreamOwned::new(
            ServerConnection::new(server_config).expect("TLS server connection"),
            stream,
        );
        let mut header = [0; 4];
        stream
            .read_exact(&mut header)
            .expect("request frame header");
        let frame_len = u32::from_be_bytes(header) as usize;
        assert!(frame_len <= 512 * 1024);
        let mut request = vec![0; frame_len];
        stream
            .read_exact(&mut request)
            .expect("complete invocation request");
        drop(stream);
    });
    let ambiguous_anchor = TlsInvocationAnchor::new(
        ambiguous_address,
        "localhost",
        "runtime-slot",
        client_config,
        80,
    )
    .expect("ambiguous invocation TLS anchor");
    let duplicate = CheckpointAnchorRecord::new("snapshot-duplicate", &invocation_handle(1))
        .expect("duplicate record");
    let error = match ambiguous_anchor.commit(&invocation, Some(1), duplicate, &response) {
        Ok(_) => panic!("a witness that dropped its reply must not look successful"),
        Err(error) => error,
    };
    assert!(matches!(error, oblivion_anchor::Error::CommitIndeterminate));
    server.join().expect("ambiguous witness thread");

    assert_eq!(
        anchor
            .confirm(&invocation, &response)
            .expect("reconcile exact receipt")
            .response(),
        &response
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
    let authorization = authorization_policy_for(&client_cert, &["sse-main-index"]);
    let witness = start_witness(path.clone(), server_config.clone(), authorization);

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
fn remote_anchor_rejects_certificate_granted_for_different_slot() {
    let path = temp_database();
    let (server_cert, server_key, client_cert, client_key, trusted_root) =
        identity_pair("acl-slot-root");
    let server_config = mtls_server_config(
        vec![server_cert],
        server_key,
        root_store(trusted_root.clone()),
    )
    .expect("server TLS config");
    let authorization = authorization_policy_for(&client_cert, &["sse-main-index"]);
    let witness = start_witness(path.clone(), server_config, authorization);
    let client_config = mtls_client_config(root_store(trusted_root), vec![client_cert], client_key)
        .expect("trusted client TLS config");
    let mut other_slot =
        TlsSseJournalAnchor::new(witness.address, "localhost", "private-state", client_config)
            .expect("valid TLS anchor");

    let result = other_slot.load();
    let _ = witness.shutdown.send(());
    witness
        .thread
        .join()
        .expect("witness thread")
        .expect("witness");
    let _ = std::fs::remove_file(path);

    assert!(
        result.is_err(),
        "a client must not read a slot outside its certificate ACL"
    );
}

#[test]
fn remote_anchor_rejects_ca_valid_client_without_slot_grant() {
    let path = temp_database();
    let (server_cert, server_key, client_cert, client_key, trusted_root) =
        identity_pair("acl-trusted-root");
    let server_config = mtls_server_config(
        vec![server_cert],
        server_key,
        root_store(trusted_root.clone()),
    )
    .expect("server TLS config");
    let witness = start_witness(
        path.clone(),
        server_config,
        ClientAuthorizationPolicy::default(),
    );
    let trusted_client =
        mtls_client_config(root_store(trusted_root), vec![client_cert], client_key)
            .expect("trusted client TLS config");

    let result = client(witness.address, trusted_client).load();
    let _ = witness.shutdown.send(());
    witness
        .thread
        .join()
        .expect("witness thread")
        .expect("witness");
    let _ = std::fs::remove_file(path);

    assert!(
        result.is_err(),
        "a CA-valid certificate without an explicit slot grant must be denied"
    );
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
    let invocation = signed_invocation(12, [0x42; 16], [0x53; 32]);
    let invocation_anchor = TlsInvocationAnchor::new(
        address,
        "localhost",
        "oram-state",
        client_config.clone(),
        80,
    )
    .expect("invocation TLS anchor");
    assert!(matches!(
        invocation_anchor.load(&invocation),
        Err(oblivion_anchor::Error::Socket(_))
    ));
    let unavailable_record = CheckpointAnchorRecord::new("snapshot-offline", &invocation_handle(1))
        .expect("offline invocation record");
    assert!(matches!(
        invocation_anchor.commit(&invocation, None, unavailable_record, &[0x7a; 80]),
        Err(oblivion_anchor::Error::Socket(_))
    ));
    let mut checkpoint = checkpoint_client(address, "oram-state", client_config.clone());
    assert!(matches!(
        checkpoint.load(),
        Err(oblivion_store::Error::Backend(_))
    ));
    let snapshot = temp_database().with_extension("offline-snapshot");
    let mut store = PathOram::new(
        Config::new(2, 16).expect("ORAM config"),
        MemoryBackend::default(),
    )
    .expect("ORAM");
    let trusted = store.checkpoint(&snapshot).expect("valid checkpoint");
    let secret = trusted.to_secret_bytes();
    let record = oblivion_store::CheckpointAnchorRecord::new("snapshot-offline", secret.as_ref())
        .expect("valid anchor record");
    assert!(matches!(
        checkpoint.compare_and_swap(None, record),
        Err(oblivion_store::Error::Backend(_))
    ));
    let _ = std::fs::remove_file(snapshot);
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
    let authorization = authorization_policy_for(&client_cert, &["function-registry"]);
    let client_config = mtls_client_config(
        root_store(root_cert.clone()),
        vec![client_cert.clone()],
        client_key.clone_key(),
    )
    .expect("client TLS config");
    let witness = start_witness(path.clone(), server_config.clone(), authorization.clone());
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

    let restarted = start_witness(path.clone(), server_config, authorization);
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

#[test]
fn remote_checkpoint_anchor_recovers_oram_and_rejects_stale_writer_after_restart() {
    let root = temp_database();
    let root_dir = root.with_extension("data");
    std::fs::create_dir(&root_dir).expect("test data directory");
    let database = root_dir.join("anchor.sqlite");
    let checkpoint_one = root_dir.join("checkpoint-one.bin");
    let checkpoint_two = root_dir.join("checkpoint-two.bin");
    let stale_checkpoint = root_dir.join("checkpoint-stale.bin");
    let (server_cert, server_key, client_cert, client_key, root_cert) =
        identity_pair("checkpoint-root");
    let server_config =
        mtls_server_config(vec![server_cert], server_key, root_store(root_cert.clone()))
            .expect("server TLS config");
    let authorization = authorization_policy_for(&client_cert, &["oram-main"]);
    let client_config = mtls_client_config(
        root_store(root_cert.clone()),
        vec![client_cert.clone()],
        client_key.clone_key(),
    )
    .expect("client TLS config");
    let witness = start_witness(
        database.clone(),
        server_config.clone(),
        authorization.clone(),
    );
    let mut anchor = checkpoint_client(witness.address, "oram-main", client_config.clone());
    let config = Config::new(8, 16).expect("ORAM config");
    let mut store = PathOram::new(config.clone(), MemoryBackend::default()).expect("ORAM");
    store.write(3, &[3; 16]).expect("initial ORAM write");
    store
        .checkpoint_anchored(&checkpoint_one, "snapshot-one", &mut anchor)
        .expect("initial remote checkpoint");
    assert_eq!(
        anchor
            .load()
            .expect("load anchored checkpoint")
            .map(|record| (record.snapshot_id().to_owned(), record.generation(),)),
        Some(("snapshot-one".to_owned(), 1))
    );

    let _ = witness.shutdown.send(());
    witness
        .thread
        .join()
        .expect("witness thread")
        .expect("witness");

    let restarted = start_witness(database.clone(), server_config, authorization);
    let mut recovered_anchor = checkpoint_client(
        restarted.address,
        "oram-main",
        mtls_client_config(root_store(root_cert), vec![client_cert], client_key)
            .expect("client TLS config after restart"),
    );
    let record = recovered_anchor
        .load()
        .expect("load after witness restart")
        .expect("persisted checkpoint");
    let trusted = TrustedCheckpoint::from_secret_bytes(record.secret_handle())
        .expect("trusted checkpoint handle");
    let (mut live, mut stale) = (
        PathOram::restore(&checkpoint_one, &trusted, MemoryBackend::default())
            .expect("restore live controller"),
        PathOram::restore(&checkpoint_one, &trusted, MemoryBackend::default())
            .expect("restore stale controller"),
    );
    live.write(3, &[9; 16]).expect("updated ORAM write");
    live.write(4, &[4; 16]).expect("second ORAM write");
    live.checkpoint_anchored(&checkpoint_two, "snapshot-two", &mut recovered_anchor)
        .expect("advance remote checkpoint");
    assert!(matches!(
        stale.checkpoint_anchored(&stale_checkpoint, "snapshot-stale", &mut recovered_anchor),
        Err(oblivion_store::Error::AnchorConflict)
    ));

    let current = recovered_anchor
        .load()
        .expect("load current checkpoint")
        .expect("current checkpoint");
    assert_eq!(current.snapshot_id(), "snapshot-two");
    let trusted = TrustedCheckpoint::from_secret_bytes(current.secret_handle())
        .expect("current checkpoint handle");
    let mut restored =
        PathOram::restore(&checkpoint_two, &trusted, MemoryBackend::default()).expect("restore");
    assert_eq!(restored.read(3).expect("read block 3"), vec![9; 16]);
    assert_eq!(restored.read(4).expect("read block 4"), vec![4; 16]);

    let _ = restarted.shutdown.send(());
    restarted
        .thread
        .join()
        .expect("restarted witness thread")
        .expect("restarted witness");
    let _ = std::fs::remove_dir_all(root_dir);
}
