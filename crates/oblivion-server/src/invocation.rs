//! Fixed-shape signed invocation identity carried inside the authenticated
//! client/executor envelope.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oblivion_anchor::SignedInvocationId;
use oblivion_batcher::PAYLOAD_BYTES;
use sha2::{Digest, Sha256};

const REQUEST_FIELDS_END: usize = 69;
const ID_START: usize = REQUEST_FIELDS_END;
const ID_END: usize = ID_START + 16;
const PUBLIC_KEY_END: usize = ID_END + 32;
const SIGNATURE_END: usize = PUBLIC_KEY_END + 64;

/// Bind the identity signature to the authenticated channel slot and canonical
/// request fields (real/dummy bit, function ID, and fixed-size input).
fn request_digest(slot: u32, payload: &[u8; PAYLOAD_BYTES]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"OBLIVION::CANONICAL-REQUEST::v1\0");
    hash.update(slot.to_be_bytes());
    hash.update(&payload[..REQUEST_FIELDS_END]);
    hash.finalize().into()
}

/// Sign a client's canonical request and write the fixed identity fields into
/// the envelope payload. The caller owns the key and must retain it if the
/// identity is needed for a retry after reconnect.
pub fn sign_request(
    payload: &mut [u8; PAYLOAD_BYTES],
    slot: u32,
    invocation_id: [u8; 16],
    signing_key: &SigningKey,
) -> SignedInvocationId {
    payload[ID_START..].fill(0);
    let digest = request_digest(slot, payload);
    let public_key = signing_key.verifying_key().to_bytes();
    let signature = signing_key
        .sign(&SignedInvocationId::signing_message(
            &invocation_id,
            &digest,
        ))
        .to_bytes();
    payload[ID_START..ID_END].copy_from_slice(&invocation_id);
    payload[ID_END..PUBLIC_KEY_END].copy_from_slice(&public_key);
    payload[PUBLIC_KEY_END..SIGNATURE_END].copy_from_slice(&signature);
    SignedInvocationId::new(public_key, invocation_id, digest, signature)
}

/// Verify and decode the signed identity against the canonical request bytes.
/// Malformed, noncanonical, or forged suffixes fail closed as `None`.
pub fn verify_request(payload: &[u8; PAYLOAD_BYTES], slot: u32) -> Option<SignedInvocationId> {
    if payload[0] > 1 || payload[SIGNATURE_END..].iter().any(|&byte| byte != 0) {
        return None;
    }
    let invocation_id: [u8; 16] = payload[ID_START..ID_END].try_into().ok()?;
    let public_key_bytes: [u8; 32] = payload[ID_END..PUBLIC_KEY_END].try_into().ok()?;
    let signature_bytes: [u8; 64] = payload[PUBLIC_KEY_END..SIGNATURE_END].try_into().ok()?;
    let digest = request_digest(slot, payload);
    let public_key = VerifyingKey::from_bytes(&public_key_bytes).ok()?;
    let signature = Signature::from_bytes(&signature_bytes);
    public_key
        .verify_strict(
            &SignedInvocationId::signing_message(&invocation_id, &digest),
            &signature,
        )
        .ok()?;
    Some(SignedInvocationId::new(
        public_key_bytes,
        invocation_id,
        digest,
        signature_bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_identity_round_trips_and_binds_slot_and_request_fields() {
        let mut payload = [0; PAYLOAD_BYTES];
        payload[0] = 1;
        payload[1..5].copy_from_slice(&4u32.to_be_bytes());
        payload[5..69].copy_from_slice(&[0x3c; 64]);
        let key = SigningKey::from_bytes(&[0x51; 32]);
        let id = [0x29; 16];
        let signed = sign_request(&mut payload, 7, id, &key);

        let decoded = verify_request(&payload, 7).expect("valid signed request");
        assert_eq!(decoded.public_key(), signed.public_key());
        assert_eq!(decoded.invocation_id(), &id);
        assert_eq!(decoded.request_digest(), signed.request_digest());
        assert!(verify_request(&payload, 8).is_none());

        payload[5] ^= 1;
        assert!(verify_request(&payload, 7).is_none());
    }

    #[test]
    fn noncanonical_reserved_bytes_and_bad_signatures_are_rejected() {
        let mut payload = [0; PAYLOAD_BYTES];
        payload[1..5].copy_from_slice(&4u32.to_be_bytes());
        let key = SigningKey::from_bytes(&[0x52; 32]);
        sign_request(&mut payload, 0, [0x17; 16], &key);

        payload[SIGNATURE_END] = 1;
        assert!(verify_request(&payload, 0).is_none());
        payload[SIGNATURE_END] = 0;
        payload[PUBLIC_KEY_END] ^= 1;
        assert!(verify_request(&payload, 0).is_none());
    }
}
