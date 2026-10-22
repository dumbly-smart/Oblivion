//! Controlled chosen-file injection: stable-tag encrypted control versus GGM.
//! Observer JSONL on stdout; target association truth goes only to a separate file.
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use oblivion_sse::{Client, Limits, Server};
use rand::{RngCore, SeedableRng, rngs::OsRng, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::HashMap,
    io::{self, BufWriter, Write},
};
use zeroize::Zeroizing;
type Failure = Box<dyn std::error::Error>;
type Posting = ([u8; 32], Vec<u8>);

// Deliberately NON-forward-private control, independently implemented here.
// Stable HMAC tags route real AEAD-encrypted document postings on the server.
struct StableTagIndex {
    tag_key: Zeroizing<[u8; 32]>,
    cipher: ChaCha20Poly1305,
    counter: u64,
    server: HashMap<[u8; 32], Vec<Posting>>,
}
impl StableTagIndex {
    fn new() -> Self {
        let mut tag_key = Zeroizing::new([0; 32]);
        let mut value_key = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(tag_key.as_mut());
        OsRng.fill_bytes(value_key.as_mut());
        Self {
            tag_key,
            cipher: ChaCha20Poly1305::new((&*value_key).into()),
            counter: 0,
            server: HashMap::new(),
        }
    }
    fn tag(&self, keyword: u64) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.tag_key).expect("fixed key");
        mac.update(b"oblivion/injection/control/tag/v1");
        mac.update(&keyword.to_be_bytes());
        mac.finalize().into_bytes().into()
    }
    fn add(&mut self, keyword: u64, id: u64) -> Result<Value, Failure> {
        let tag = self.tag(keyword);
        let mut address = [0; 32];
        OsRng.fill_bytes(&mut address);
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.checked_add(1).ok_or("nonce exhausted")?;
        let aad = [tag.as_slice(), address.as_slice()].concat();
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &id.to_be_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| "encrypt")?;
        let wire =
            json!({"stable_tag":tag,"address":address,"nonce":nonce,"ciphertext":ciphertext});
        let mut stored = nonce.to_vec();
        stored.extend(ciphertext);
        self.server.entry(tag).or_default().push((address, stored));
        Ok(wire)
    }
    fn search(&self, keyword: u64) -> Result<Value, Failure> {
        let tag = self.tag(keyword);
        let postings = self.server.get(&tag).ok_or("unknown keyword")?;
        let mut entries = Vec::new();
        for (address, stored) in postings {
            let aad = [tag.as_slice(), address.as_slice()].concat();
            let plaintext = self
                .cipher
                .decrypt(
                    Nonce::from_slice(&stored[..12]),
                    Payload {
                        msg: &stored[12..],
                        aad: &aad,
                    },
                )
                .map_err(|_| "decrypt")?;
            let _: u64 = u64::from_be_bytes(plaintext.try_into().map_err(|_| "id width")?);
            entries.push(json!({"address":address,"nonce":stored[..12],"ciphertext":stored[12..]}));
        }
        Ok(json!({"request":{"tag":tag},"response":{"entries":entries}}))
    }
}
fn emit(out: &mut impl Write, value: Value) -> Result<(), Failure> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    Ok(())
}
fn main() -> Result<(), Failure> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: injection SEED GROUND_TRUTH_PATH".into());
    }
    let seed = args[1].parse::<u64>()?;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut old_order: Vec<u64> = (0..8).collect();
    old_order.shuffle(&mut rng);
    let mut injections: Vec<u64> = (0..8).collect();
    injections.shuffle(&mut rng);
    let mut next_order: Vec<u64> = (0..8).collect();
    next_order.shuffle(&mut rng);
    let truth: Vec<_> = injections
        .iter()
        .map(|keyword| {
            old_order
                .iter()
                .position(|k| k == keyword)
                .expect("permutation")
        })
        .collect();
    std::fs::write(
        &args[2],
        serde_json::to_vec_pretty(&json!({"slots":truth}))?,
    )?;
    let mut out = BufWriter::new(io::stdout().lock());
    for mode in ["stable_tag_control", "ggm"] {
        let mut baseline = StableTagIndex::new();
        let limits = Limits::default();
        let mut client = Client::new(limits)?;
        let mut server = Server::new(client.index_id(), limits)?;
        for keyword in 0u64..8 {
            for id in 0..4 {
                let request = if mode == "ggm" {
                    let request = client.prepare_add(&keyword.to_be_bytes(), id)?;
                    let ack = server.insert(request.clone())?;
                    client.finish_add(ack)?;
                    serde_json::to_value(request)?
                } else {
                    baseline.add(keyword, id)?
                };
                emit(
                    &mut out,
                    json!({"mode":mode,"phase":"setup_update","request":request}),
                )?;
            }
        }
        for (phase, order) in [("past_search", &old_order), ("fresh_search", &next_order)] {
            if phase == "fresh_search" {
                for (injection, &keyword) in injections.iter().enumerate() {
                    let request = if mode == "ggm" {
                        let request = client.prepare_add(&keyword.to_be_bytes(), 999)?;
                        let ack = server.insert(request.clone())?;
                        client.finish_add(ack)?;
                        serde_json::to_value(request)?
                    } else {
                        baseline.add(keyword, 999)?
                    };
                    emit(
                        &mut out,
                        json!({"mode":mode,"phase":"injected_update","injection":injection,"request":request}),
                    )?;
                }
            }
            for (slot, &keyword) in order.iter().enumerate() {
                let event = if mode == "ggm" {
                    let (snapshot, request) = client.prepare_search(&keyword.to_be_bytes())?;
                    let response = server.search(&request)?;
                    let ids = client.finish_search(&snapshot, response.clone())?;
                    let mut expected = vec![0, 1, 2, 3];
                    if phase == "fresh_search" {
                        expected.push(999);
                    }
                    if ids != expected {
                        return Err("GGM client oracle".into());
                    }
                    json!({"request":request,"response":response})
                } else {
                    baseline.search(keyword)?
                };
                emit(
                    &mut out,
                    json!({"mode":mode,"phase":phase,"slot":slot,"request":event["request"],"response":event["response"]}),
                )?;
            }
        }
    }
    out.flush()?;
    Ok(())
}
