use ed25519_dalek::{Signer, SigningKey};
use oblivion_registry::{
    Error, RECORD_BYTES, Record, RegistryVersionAnchor, SignedRegistry, VerifiedRegistry,
};
use sha2::{Digest, Sha256};

fn keys(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn catalog(key: &SigningKey, version: u64) -> Vec<u8> {
    let records = (0..3)
        .map(|id| {
            Record::sign(id, version, [id as u8 + 1; 32], [id as u8 + 4; 32], 1, key).unwrap()
        })
        .collect();
    SignedRegistry::sign(version, records, key).unwrap()
}

fn resign_manifest(encoded: &mut [u8], key: &SigningKey) {
    let digest: [u8; 32] = Sha256::digest(&encoded[124..]).into();
    encoded[28..60].copy_from_slice(&digest);
    let version = &encoded[12..20];
    let count = &encoded[20..24];
    let mut message = Vec::from(&b"oblivion/registry/manifest/v1"[..]);
    message.extend_from_slice(version);
    message.extend_from_slice(count);
    message.extend_from_slice(&digest);
    encoded[60..124].copy_from_slice(&key.sign(&message).to_bytes());
}

#[test]
fn signed_catalog_authenticates_records_and_activates_monotonically() {
    #[derive(Default)]
    struct MemoryVersionAnchor(Option<u64>);
    impl RegistryVersionAnchor for MemoryVersionAnchor {
        fn current_version(&mut self) -> Result<Option<u64>, Error> {
            Ok(self.0)
        }
        fn compare_and_swap(&mut self, expected: Option<u64>, next: u64) -> Result<(), Error> {
            if self.0 != expected {
                return Err(Error::AnchorConflict);
            }
            self.0 = Some(next);
            Ok(())
        }
    }

    let signing = keys(7);
    let verifying = signing.verifying_key();
    let encoded = catalog(&signing, 4);
    let verified = VerifiedRegistry::verify(&encoded, &verifying).unwrap();
    assert_eq!(verified.version(), 4);
    assert_eq!(verified.len(), 3);
    let record = verified.get(2).unwrap();
    assert_eq!(record.module_digest(), &[3; 32]);
    assert_eq!(record.location_digest(), &[6; 32]);
    assert_eq!(record.resource_class(), 1);
    assert!(verified.get(3).is_none());
    Record::from_bytes(&record.to_bytes())
        .unwrap()
        .verify(&verifying)
        .unwrap();

    let mut anchor = MemoryVersionAnchor::default();
    verified.activate(&mut anchor).unwrap();
    assert_eq!(anchor.0, Some(4));
    assert!(matches!(
        verified.activate(&mut anchor),
        Err(Error::Rollback)
    ));

    let next = VerifiedRegistry::verify(&catalog(&signing, 5), &verifying).unwrap();
    next.activate(&mut anchor).unwrap();
    assert_eq!(anchor.0, Some(5));
}

#[test]
fn signature_and_manifest_reject_tampering_omission_reordering_and_wrong_keys() {
    let signing = keys(11);
    let encoded = catalog(&signing, 8);
    let verifying = signing.verifying_key();
    let wrong = keys(12).verifying_key();

    for altered in [
        {
            let mut bytes = encoded.clone();
            bytes[124 + 100] ^= 1;
            bytes
        },
        {
            let mut bytes = encoded.clone();
            bytes[124 + 96] ^= 1;
            resign_manifest(&mut bytes, &signing);
            bytes
        },
        {
            let mut bytes = encoded.clone();
            bytes[124 + 77] = 1;
            resign_manifest(&mut bytes, &signing);
            bytes
        },
        {
            let mut bytes = encoded.clone();
            for offset in 0..RECORD_BYTES {
                bytes.swap(124 + offset, 124 + RECORD_BYTES + offset);
            }
            resign_manifest(&mut bytes, &signing);
            bytes
        },
        encoded[..encoded.len() - RECORD_BYTES].to_vec(),
        encoded[..encoded.len() - 1].to_vec(),
    ] {
        assert!(VerifiedRegistry::verify(&altered, &verifying).is_err());
    }
    assert!(VerifiedRegistry::verify(&encoded, &wrong).is_err());
}

#[test]
fn parser_rejects_invalid_geometry_versions_and_duplicate_ids() {
    let signing = keys(31);
    let verifying = signing.verifying_key();
    let encoded = catalog(&signing, 3);
    let mut bad_count = encoded.clone();
    bad_count[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(VerifiedRegistry::verify(&bad_count, &verifying).is_err());

    let duplicate = Record::sign(0, 3, [4; 32], [5; 32], 1, &signing).unwrap();
    let second = Record::sign(0, 3, [6; 32], [7; 32], 1, &signing).unwrap();
    assert!(matches!(
        SignedRegistry::sign(3, vec![duplicate, second], &signing),
        Err(Error::DuplicateFunctionId)
    ));

    let wrong_version = Record::sign(1, 4, [1; 32], [2; 32], 1, &signing).unwrap();
    assert!(matches!(
        SignedRegistry::sign(3, vec![wrong_version], &signing),
        Err(Error::VersionMismatch)
    ));
}

#[test]
fn version_anchor_conflict_fails_closed() {
    #[derive(Default)]
    struct RacingAnchor(Option<u64>);
    impl RegistryVersionAnchor for RacingAnchor {
        fn current_version(&mut self) -> Result<Option<u64>, Error> {
            Ok(self.0)
        }
        fn compare_and_swap(&mut self, _expected: Option<u64>, _next: u64) -> Result<(), Error> {
            self.0 = Some(99);
            Err(Error::AnchorConflict)
        }
    }

    let signer = keys(43);
    let verified = VerifiedRegistry::verify(&catalog(&signer, 1), &signer.verifying_key()).unwrap();
    assert!(matches!(
        verified.activate(&mut RacingAnchor::default()),
        Err(Error::AnchorConflict)
    ));
}
