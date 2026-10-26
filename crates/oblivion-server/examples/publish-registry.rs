//! Offline publisher tool for the five embedded WASM demo modules.
//!
//! Usage: cargo run -p oblivion-server --example publish-registry -- \
//!   PRIVATE_SEED_FILE VERSION NEW_OUTPUT_DIRECTORY

use ed25519_dalek::SigningKey;
use oblivion_registry::{Record, SignedRegistry};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const SOURCES: [&[u8]; 5] = [
    include_bytes!("../../../examples/wasm-functions/echo.wat"),
    include_bytes!("../../../examples/wasm-functions/sum.wat"),
    include_bytes!("../../../examples/wasm-functions/fibonacci.wat"),
    include_bytes!("../../../examples/wasm-functions/hash.wat"),
    include_bytes!("../../../examples/wasm-functions/stateful.wat"),
];

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 3 {
        return Err(
            "usage: publish-registry PRIVATE_SEED_FILE VERSION NEW_OUTPUT_DIRECTORY".into(),
        );
    }
    let key_path = Path::new(&arguments[0]);
    let version = arguments[1]
        .to_str()
        .ok_or("version must be UTF-8")?
        .parse()?;
    if version == 0 {
        return Err("registry version must be positive".into());
    }
    let output = Path::new(&arguments[2]);
    let seed = read_signing_seed(key_path)?;
    let key = SigningKey::from_bytes(&seed);
    let manifest = sign_embedded_registry(&key, version)?;

    fs::create_dir(output)?;
    write_new_file(&output.join("registry.bin"), &manifest)?;
    write_new_file(
        &output.join("publisher.pub"),
        &key.verifying_key().to_bytes(),
    )?;
    Ok(())
}

fn read_signing_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err("publisher seed must be a regular file containing exactly 32 bytes".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("publisher seed permissions must deny group and other access".into());
        }
    }
    let mut seed = Zeroizing::new([0; 32]);
    file.read_exact(&mut *seed)?;
    let mut extra = [0; 1];
    if file.read(&mut extra)? != 0 {
        return Err("publisher seed must contain exactly 32 bytes".into());
    }
    Ok(seed)
}

fn sign_embedded_registry(key: &SigningKey, version: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut records = Vec::with_capacity(SOURCES.len());
    for (id, source) in SOURCES.iter().enumerate() {
        let module_digest: [u8; 32] = Sha256::digest(source).into();
        let mut location = Sha256::new();
        location.update(b"oblivion/demo/embedded-location/v1");
        location.update(u32::try_from(id)?.to_be_bytes());
        location.update(module_digest);
        let location_digest = location.finalize().into();
        records.push(Record::sign(
            u32::try_from(id)?,
            version,
            module_digest,
            location_digest,
            0,
            key,
        )?);
    }
    Ok(SignedRegistry::sign(version, records, key)?)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[test]
fn signed_demo_catalog_verifies_under_the_publisher_key() {
    use oblivion_registry::VerifiedRegistry;

    let key = SigningKey::from_bytes(&[0x83; 32]);
    let manifest = sign_embedded_registry(&key, 12).unwrap();
    let catalog = VerifiedRegistry::verify(&manifest, &key.verifying_key()).unwrap();
    assert_eq!(catalog.version(), 12);
    assert_eq!(catalog.len(), SOURCES.len());
    for (id, source) in SOURCES.iter().enumerate() {
        let record = catalog.get(id as u32).unwrap();
        let expected: [u8; 32] = Sha256::digest(source).into();
        assert_eq!(record.module_digest(), &expected);
    }
}
