use crate::Error;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const PAYLOAD_BYTES: usize = 192;
const HEADER: usize = 20;
pub const ENVELOPE_BYTES: usize = HEADER + PAYLOAD_BYTES + 16;

/// Wire v2: OBLV[4], version u16 BE, direction u8, reserved zero u8,
/// epoch u64 BE, slot u32 BE, ciphertext[192], tag[16]. The nonce is
/// derived from slot || epoch. Request and response use independent keys.
#[derive(Clone)]
pub struct Envelope {
    bytes: [u8; ENVELOPE_BYTES],
}
impl Envelope {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ENVELOPE_BYTES
            || &bytes[..4] != b"OBLV"
            || bytes[4..6] != 2u16.to_be_bytes()
            || ![1, 2].contains(&bytes[6])
            || bytes[7] != 0
        {
            return Err(Error::Protocol);
        }
        let mut result = [0; ENVELOPE_BYTES];
        result.copy_from_slice(bytes);
        Ok(Self { bytes: result })
    }
    pub fn as_bytes(&self) -> &[u8; ENVELOPE_BYTES] {
        &self.bytes
    }
    pub fn epoch(&self) -> u64 {
        u64::from_be_bytes(self.bytes[8..16].try_into().expect("fixed header"))
    }
    pub fn slot(&self) -> u32 {
        u32::from_be_bytes(self.bytes[16..20].try_into().expect("fixed header"))
    }
    pub(crate) fn kind(&self) -> u8 {
        self.bytes[6]
    }
    fn header(epoch: u64, slot: u32, kind: u8) -> [u8; HEADER] {
        let mut h = [0; HEADER];
        h[..4].copy_from_slice(b"OBLV");
        h[4..6].copy_from_slice(&2u16.to_be_bytes());
        h[6] = kind;
        h[8..16].copy_from_slice(&epoch.to_be_bytes());
        h[16..20].copy_from_slice(&slot.to_be_bytes());
        h
    }
    pub(crate) fn cover(epoch: u64, slot: u32) -> Result<Self, Error> {
        let mut bytes = [0; ENVELOPE_BYTES];
        bytes[..HEADER].copy_from_slice(&Self::header(epoch, slot, 1));
        OsRng
            .try_fill_bytes(&mut bytes[HEADER..])
            .map_err(|_| Error::Randomness)?;
        Ok(Self { bytes })
    }
}

/// Ephemeral directional channel. Move-only: cloning or restoring its counters
/// under the same keys would permit nonce reuse. No persistence is supported.
/// Provisioning is trusted and in-process; key distribution/attestation is future work.
pub struct Endpoint {
    slot: u32,
    send_kind: u8,
    send_cipher: ChaCha20Poly1305,
    receive_cipher: ChaCha20Poly1305,
    sent: Option<u64>,
    received: Option<u64>,
}
impl Endpoint {
    pub fn provision(slot: u32) -> Result<(Self, Self), Error> {
        let mut root = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(root.as_mut())
            .map_err(|_| Error::Randomness)?;
        Self::from_root(slot, root.as_ref())
    }
    /// Trusted setup only: sends a fresh secret to the dedicated executor pipe.
    /// Never send this bootstrap over the modeled untrusted network or log it.
    pub fn provision_over_pipe(slot: u32, pipe: &mut impl std::io::Write) -> Result<Self, Error> {
        let mut root = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(root.as_mut())
            .map_err(|_| Error::Randomness)?;
        let (client, _) = Self::from_root(slot, root.as_ref())?;
        pipe.write_all(root.as_ref()).map_err(|_| Error::Protocol)?;
        pipe.flush().map_err(|_| Error::Protocol)?;
        Ok(client)
    }
    /// Consume bootstrap exactly once from a trusted private pipe. Replaying a
    /// saved bootstrap resets counters and is UNSUPPORTED: ephemeral sessions only.
    pub fn accept_bootstrap(slot: u32, pipe: &mut impl std::io::Read) -> Result<Self, Error> {
        let mut root = Zeroizing::new([0u8; 32]);
        pipe.read_exact(root.as_mut())
            .map_err(|_| Error::Protocol)?;
        let (_, executor) = Self::from_root(slot, root.as_ref())?;
        Ok(executor)
    }
    fn from_root(slot: u32, root: &[u8]) -> Result<(Self, Self), Error> {
        let hk = Hkdf::<Sha256>::new(Some(b"oblivion/envelope/v1"), root);
        let mut request = Zeroizing::new([0u8; 32]);
        let mut response = Zeroizing::new([0u8; 32]);
        hk.expand(b"request", request.as_mut())
            .map_err(|_| Error::Configuration)?;
        hk.expand(b"response", response.as_mut())
            .map_err(|_| Error::Configuration)?;
        let make = |send: &[u8], receive: &[u8], kind| -> Result<Self, Error> {
            Ok(Self {
                slot,
                send_kind: kind,
                send_cipher: ChaCha20Poly1305::new_from_slice(send)
                    .map_err(|_| Error::Configuration)?,
                receive_cipher: ChaCha20Poly1305::new_from_slice(receive)
                    .map_err(|_| Error::Configuration)?,
                sent: None,
                received: None,
            })
        };
        Ok((
            make(request.as_ref(), response.as_ref(), 1)?,
            make(response.as_ref(), request.as_ref(), 2)?,
        ))
    }
    fn nonce(&self, epoch: u64) -> [u8; 12] {
        let mut n = [0; 12];
        n[..4].copy_from_slice(&self.slot.to_be_bytes());
        n[4..].copy_from_slice(&epoch.to_be_bytes());
        n
    }
    pub fn send(&mut self, epoch: u64, body: &[u8; PAYLOAD_BYTES]) -> Result<Envelope, Error> {
        if self.sent.is_some_and(|last| epoch <= last) {
            return Err(Error::Replay);
        }
        let header = Envelope::header(epoch, self.slot, self.send_kind);
        // Reserve the nonce before encryption; even failure never reuses it.
        self.sent = Some(epoch);
        let cipher = self
            .send_cipher
            .encrypt(
                Nonce::from_slice(&self.nonce(epoch)),
                Payload {
                    msg: body,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Authentication)?;
        let mut bytes = [0; ENVELOPE_BYTES];
        bytes[..HEADER].copy_from_slice(&header);
        bytes[HEADER..].copy_from_slice(&cipher);
        Ok(Envelope { bytes })
    }
    pub fn receive(&mut self, frame: &Envelope) -> Result<[u8; PAYLOAD_BYTES], Error> {
        if frame.slot() != self.slot || frame.kind() == self.send_kind {
            return Err(Error::Protocol);
        }
        let epoch = frame.epoch();
        // This protocol has one current request per client/channel. A delayed
        // but previously unseen older reply must not satisfy a newer request.
        if self.send_kind == 1 && self.sent != Some(epoch) {
            return Err(Error::Epoch);
        }
        if self.received.is_some_and(|last| epoch <= last) {
            return Err(Error::Replay);
        }
        let plain = Zeroizing::new(
            self.receive_cipher
                .decrypt(
                    Nonce::from_slice(&self.nonce(epoch)),
                    Payload {
                        msg: &frame.bytes[HEADER..],
                        aad: &frame.bytes[..HEADER],
                    },
                )
                .map_err(|_| Error::Authentication)?,
        );
        let mut body = [0; PAYLOAD_BYTES];
        body.copy_from_slice(&plain);
        self.received = Some(epoch);
        Ok(body)
    }
}
