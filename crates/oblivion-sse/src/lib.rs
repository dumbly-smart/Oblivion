//! Ephemeral, append-only, Diana-inspired constrained-GGM keyword index.
//!
//! This is a bounded research implementation, not an implementation of Diana's
//! security theorem. Search reveals posting history, volume and search equality.
//! A fresh client key is generated for each instance. There is no state restore API.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const TREE_DEPTH: u8 = 32;
pub const TREE_CAPACITY: u64 = 1u64 << TREE_DEPTH;
pub type Address = [u8; 32];
pub type IndexId = [u8; 16];
pub type DocumentId = u64;
pub const VERSION: u8 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("configured resource limit exceeded or invalid")]
    Limit,
    #[error("an add is pending; retry and acknowledge it first")]
    Pending,
    #[error("no add is pending")]
    NoPending,
    #[error("acknowledgment does not identify the pending posting")]
    WrongAcknowledgment,
    #[error("tree exhausted: rotate the keyword before adding")]
    Exhausted,
    #[error("invalid protocol version or index identity")]
    WrongIndex,
    #[error("malformed or noncanonical constraint cover")]
    MalformedCover,
    #[error("leaf is outside the constrained capability")]
    OutsideConstraint,
    #[error("conflicting ciphertext at an immutable address")]
    ConflictingAddress,
    #[error("search response does not match its local snapshot")]
    InvalidResponse,
    #[error("a required posting is missing")]
    MissingPosting,
    #[error("posting authentication failed")]
    Authentication,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Limits {
    pub postings: usize,
    pub keywords: usize,
    pub keyword_bytes: usize,
    pub epochs_per_keyword: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            postings: 100_000,
            keywords: 10_000,
            keyword_bytes: 4096,
            epochs_per_keyword: 16,
        }
    }
}

impl Limits {
    fn validate(self) -> Result<Self, Error> {
        let cap = Self::default();
        if self.postings == 0
            || self.postings > cap.postings
            || self.keywords == 0
            || self.keywords > cap.keywords
            || self.keyword_bytes == 0
            || self.keyword_bytes > cap.keyword_bytes
            || self.epochs_per_keyword == 0
            || self.epochs_per_keyword > cap.epochs_per_keyword
        {
            return Err(Error::Limit);
        }
        Ok(self)
    }
}

fn prf(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("fixed HMAC key");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn kdf(key: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(info, out.as_mut())
        .expect("32 bytes is a valid SHA256 HKDF length");
    out
}

fn child(seed: &[u8; 32], bit: u8) -> [u8; 32] {
    prf(seed, &[b"oblivion/sse/v1/child", &[bit]])
}

pub fn leaf_address(seed: &[u8; 32]) -> Address {
    let mut hash = Sha256::new();
    hash.update(b"oblivion/sse/v1/address");
    hash.update(seed);
    hash.finalize().into()
}

/// Released node seed: deliberately usable by the server for its whole subtree.
/// No Debug implementation: callers must opt into exporting capability bytes.
#[derive(Clone, Serialize, Deserialize)]
pub struct ConstraintNode {
    pub depth: u8,
    pub prefix: u64,
    pub seed: [u8; 32],
}

fn span(depth: u8, prefix: u64, tree_depth: u8) -> Result<(u64, u64), Error> {
    if tree_depth > TREE_DEPTH || depth > tree_depth || prefix >= (1u64 << depth) {
        return Err(Error::MalformedCover);
    }
    let size = 1u64 << (tree_depth - depth);
    Ok((prefix * size, (prefix + 1) * size))
}

fn shape(tree_depth: u8, count: u64) -> Result<Vec<(u8, u64)>, Error> {
    if tree_depth > TREE_DEPTH || count > (1u64 << tree_depth) {
        return Err(Error::MalformedCover);
    }
    fn visit(d: u8, p: u64, total: u8, n: u64, out: &mut Vec<(u8, u64)>) {
        let size = 1u64 << (total - d);
        let lo = p * size;
        if lo >= n {
            return;
        }
        if lo + size <= n {
            out.push((d, p));
        } else {
            visit(d + 1, p * 2, total, n, out);
            visit(d + 1, p * 2 + 1, total, n, out);
        }
    }
    let mut out = Vec::new();
    visit(0, 0, tree_depth, count, &mut out);
    Ok(out)
}

fn derive_leaf(root: &[u8; 32], i: u64, tree_depth: u8) -> Result<[u8; 32], Error> {
    if tree_depth > TREE_DEPTH || i >= (1u64 << tree_depth) {
        return Err(Error::OutsideConstraint);
    }
    let mut seed = Zeroizing::new(*root);
    for shift in (0..tree_depth).rev() {
        *seed = child(&seed, ((i >> shift) & 1) as u8);
    }
    Ok(*seed)
}

fn cover(root: &[u8; 32], count: u64, tree_depth: u8) -> Result<Vec<ConstraintNode>, Error> {
    shape(tree_depth, count)?
        .into_iter()
        .map(|(depth, prefix)| {
            Ok(ConstraintNode {
                depth,
                prefix,
                seed: derive_leaf(root, prefix, depth)?,
            })
        })
        .collect()
}

/// Evaluate a retained capability. This checks interval membership, not a
/// cryptographic proof that its seed originated at the client.
pub fn constrained_eval(nodes: &[ConstraintNode], i: u64) -> Result<[u8; 32], Error> {
    constrained_eval_depth(nodes, i, TREE_DEPTH)
}

fn constrained_eval_depth(
    nodes: &[ConstraintNode],
    i: u64,
    tree_depth: u8,
) -> Result<[u8; 32], Error> {
    if nodes.len() > 32 || i >= (1u64 << tree_depth) {
        return Err(Error::OutsideConstraint);
    }
    let mut selected = None;
    for node in nodes {
        let (lo, hi) = span(node.depth, node.prefix, tree_depth)?;
        if i >= lo && i < hi && selected.replace(node).is_some() {
            return Err(Error::MalformedCover);
        }
    }
    let node = selected.ok_or(Error::OutsideConstraint)?;
    let mut seed = Zeroizing::new(node.seed);
    for shift in (0..tree_depth - node.depth).rev() {
        *seed = child(&seed, ((i >> shift) & 1) as u8);
    }
    Ok(*seed)
}

fn enumerate(nodes: &[ConstraintNode]) -> Result<Vec<(u64, [u8; 32])>, Error> {
    fn walk(d: u8, p: u64, seed: Zeroizing<[u8; 32]>, out: &mut Vec<(u64, [u8; 32])>) {
        if d == TREE_DEPTH {
            out.push((p, *seed));
        } else {
            walk(d + 1, p * 2, Zeroizing::new(child(&seed, 0)), out);
            walk(d + 1, p * 2 + 1, Zeroizing::new(child(&seed, 1)), out);
        }
    }
    let mut out = Vec::new();
    for node in nodes {
        span(node.depth, node.prefix, TREE_DEPTH)?;
        walk(node.depth, node.prefix, Zeroizing::new(node.seed), &mut out);
    }
    Ok(out)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateRequest {
    pub version: u8,
    pub index_id: IndexId,
    pub address: Address,
    pub ciphertext: [u8; 24],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EpochCover {
    pub epoch: u64,
    pub count: u64,
    pub nodes: Vec<ConstraintNode>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SearchRequest {
    pub version: u8,
    pub index_id: IndexId,
    pub tag: [u8; 32],
    pub epochs: Vec<EpochCover>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SearchEntry {
    pub epoch: u64,
    pub index: u64,
    pub address: Address,
    pub ciphertext: Option<[u8; 24]>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub version: u8,
    pub index_id: IndexId,
    pub entries: Vec<SearchEntry>,
}

/// Local-only snapshot. Contains the keyword and is never serialized.
pub struct SearchSnapshot {
    index_id: IndexId,
    keyword: Zeroizing<Vec<u8>>,
    counts: Vec<u64>,
}

struct PendingAdd {
    request: UpdateRequest,
}

/// Trusted ephemeral client. It deliberately supports neither Clone nor serde.
pub struct Client {
    index_id: IndexId,
    tree_key: Zeroizing<[u8; 32]>,
    value_key: Zeroizing<[u8; 32]>,
    tag_key: Zeroizing<[u8; 32]>,
    keywords: HashMap<Vec<u8>, Vec<u64>>,
    pending: Option<PendingAdd>,
    postings: usize,
    limits: Limits,
}

impl Drop for Client {
    fn drop(&mut self) {
        // HashMap keys cannot be mutated in place; drain before zeroizing.
        for (keyword, _) in self.keywords.drain() {
            drop(Zeroizing::new(keyword));
        }
    }
}

impl Client {
    pub fn new(limits: Limits) -> Result<Self, Error> {
        let limits = limits.validate()?;
        let mut master = Zeroizing::new([0; 32]);
        let mut index_id = [0; 16];
        OsRng.fill_bytes(master.as_mut());
        OsRng.fill_bytes(&mut index_id);
        Ok(Self {
            index_id,
            tree_key: kdf(master.as_ref(), &index_id, b"oblivion/sse/v1/tree"),
            value_key: kdf(master.as_ref(), &index_id, b"oblivion/sse/v1/value"),
            tag_key: kdf(master.as_ref(), &index_id, b"oblivion/sse/v1/search-tag"),
            keywords: HashMap::new(),
            pending: None,
            postings: 0,
            limits,
        })
    }

    pub fn index_id(&self) -> IndexId {
        self.index_id
    }

    fn validate_keyword(&self, keyword: &[u8]) -> Result<(), Error> {
        if keyword.len() > self.limits.keyword_bytes {
            return Err(Error::Limit);
        }
        Ok(())
    }

    fn root(&self, keyword: &[u8], epoch: u64) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(prf(
            &self.tree_key,
            &[
                b"oblivion/sse/v1/root",
                &(keyword.len() as u32).to_be_bytes(),
                keyword,
                &epoch.to_be_bytes(),
            ],
        ))
    }

    fn record_key(&self, address: &Address) -> Zeroizing<[u8; 32]> {
        kdf(self.value_key.as_ref(), address, b"oblivion/sse/v1/record")
    }

    fn ad(&self, address: &Address) -> Vec<u8> {
        [
            b"oblivion/sse/v1/posting".as_slice(),
            &self.index_id,
            address,
        ]
        .concat()
    }

    pub fn prepare_add(&mut self, keyword: &[u8], id: DocumentId) -> Result<UpdateRequest, Error> {
        if self.pending.is_some() {
            return Err(Error::Pending);
        }
        self.validate_keyword(keyword)?;
        if self.postings >= self.limits.postings
            || (!self.keywords.contains_key(keyword) && self.keywords.len() >= self.limits.keywords)
        {
            return Err(Error::Limit);
        }
        let counts = self.keywords.get(keyword);
        let epoch = counts.map_or(0, |c| c.len() as u64 - 1);
        let count = counts.map_or(0, |c| c[epoch as usize]);
        if count >= TREE_CAPACITY {
            return Err(Error::Exhausted);
        }
        let leaf = Zeroizing::new(derive_leaf(&self.root(keyword, epoch), count, TREE_DEPTH)?);
        let address = leaf_address(&leaf);
        let key = self.record_key(&address);
        let plaintext = Zeroizing::new(id.to_be_bytes());
        let ciphertext = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("fixed AEAD key")
            .encrypt(
                Nonce::from_slice(&[0; 12]),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &self.ad(&address),
                },
            )
            .map_err(|_| Error::Authentication)?;
        let request = UpdateRequest {
            version: VERSION,
            index_id: self.index_id,
            address,
            ciphertext: ciphertext.try_into().map_err(|_| Error::Authentication)?,
        };
        let counts = self
            .keywords
            .entry(keyword.to_vec())
            .or_insert_with(|| vec![0]);
        counts[epoch as usize] += 1;
        self.postings += 1;
        self.pending = Some(PendingAdd {
            request: request.clone(),
        });
        Ok(request)
    }

    pub fn retry_pending(&self) -> Result<UpdateRequest, Error> {
        self.pending
            .as_ref()
            .map(|p| p.request.clone())
            .ok_or(Error::NoPending)
    }

    pub fn finish_add(&mut self, address: Address) -> Result<(), Error> {
        let pending = self.pending.as_ref().ok_or(Error::NoPending)?;
        if pending.request.address != address {
            return Err(Error::WrongAcknowledgment);
        }
        self.pending = None;
        Ok(())
    }

    pub fn rotate_keyword(&mut self, keyword: &[u8]) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Pending);
        }
        self.validate_keyword(keyword)?;
        if !self.keywords.contains_key(keyword) && self.keywords.len() >= self.limits.keywords {
            return Err(Error::Limit);
        }
        let old_len = self.keywords.get(keyword).map_or(1, Vec::len);
        if old_len >= self.limits.epochs_per_keyword {
            return Err(Error::Limit);
        }
        self.keywords
            .entry(keyword.to_vec())
            .or_insert_with(|| vec![0])
            .push(0);
        Ok(())
    }

    pub fn prepare_search(&self, keyword: &[u8]) -> Result<(SearchSnapshot, SearchRequest), Error> {
        if self.pending.is_some() {
            return Err(Error::Pending);
        }
        self.validate_keyword(keyword)?;
        let counts = self.keywords.get(keyword).cloned().unwrap_or_default();
        let epochs = counts
            .iter()
            .enumerate()
            .map(|(e, &count)| {
                Ok(EpochCover {
                    epoch: e as u64,
                    count,
                    nodes: cover(&self.root(keyword, e as u64), count, TREE_DEPTH)?,
                })
            })
            .collect::<Result<_, Error>>()?;
        let tag = prf(
            &self.tag_key,
            &[
                b"oblivion/sse/v1/tag",
                &(keyword.len() as u32).to_be_bytes(),
                keyword,
            ],
        );
        Ok((
            SearchSnapshot {
                index_id: self.index_id,
                keyword: Zeroizing::new(keyword.to_vec()),
                counts,
            },
            SearchRequest {
                version: VERSION,
                index_id: self.index_id,
                tag,
                epochs,
            },
        ))
    }

    pub fn finish_search(
        &self,
        snapshot: &SearchSnapshot,
        response: SearchResponse,
    ) -> Result<Vec<DocumentId>, Error> {
        if snapshot.index_id != self.index_id
            || response.index_id != self.index_id
            || response.version != VERSION
        {
            return Err(Error::WrongIndex);
        }
        let expected_count: u64 = snapshot.counts.iter().sum();
        if response.entries.len() as u64 != expected_count {
            return Err(Error::InvalidResponse);
        }
        let mut entries = response.entries.into_iter();
        let mut ids = Vec::with_capacity(expected_count as usize);
        for (epoch, &count) in snapshot.counts.iter().enumerate() {
            let nodes = cover(
                &self.root(&snapshot.keyword, epoch as u64),
                count,
                TREE_DEPTH,
            )?;
            for (index, seed) in enumerate(&nodes)? {
                let seed = Zeroizing::new(seed);
                let a = leaf_address(&seed);
                let entry = entries.next().ok_or(Error::InvalidResponse)?;
                if entry.epoch != epoch as u64 || entry.index != index || entry.address != a {
                    return Err(Error::InvalidResponse);
                }
                let ciphertext = entry.ciphertext.ok_or(Error::MissingPosting)?;
                let key = self.record_key(&a);
                let plain = Zeroizing::new(
                    ChaCha20Poly1305::new_from_slice(key.as_ref())
                        .expect("fixed AEAD key")
                        .decrypt(
                            Nonce::from_slice(&[0; 12]),
                            Payload {
                                msg: &ciphertext,
                                aad: &self.ad(&a),
                            },
                        )
                        .map_err(|_| Error::Authentication)?,
                );
                let bytes: [u8; 8] = plain
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Authentication)?;
                ids.push(u64::from_be_bytes(bytes));
            }
        }
        Ok(ids)
    }
}

/// Untrusted in-memory map. Nothing here needs plaintext keywords or client keys.
pub struct Server {
    index_id: IndexId,
    postings: HashMap<Address, [u8; 24]>,
    limits: Limits,
}

impl Server {
    pub fn new(index_id: IndexId, limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            index_id,
            postings: HashMap::new(),
            limits: limits.validate()?,
        })
    }

    pub fn posting_count(&self) -> usize {
        self.postings.len()
    }

    pub fn insert(&mut self, request: UpdateRequest) -> Result<Address, Error> {
        if request.version != VERSION || request.index_id != self.index_id {
            return Err(Error::WrongIndex);
        }
        if let Some(old) = self.postings.get(&request.address) {
            if old != &request.ciphertext {
                return Err(Error::ConflictingAddress);
            }
        } else {
            if self.postings.len() >= self.limits.postings {
                return Err(Error::Limit);
            }
            self.postings.insert(request.address, request.ciphertext);
        }
        Ok(request.address)
    }

    pub fn search(&self, request: &SearchRequest) -> Result<SearchResponse, Error> {
        if request.version != VERSION || request.index_id != self.index_id {
            return Err(Error::WrongIndex);
        }
        if request.epochs.len() > self.limits.epochs_per_keyword {
            return Err(Error::Limit);
        }
        let mut total = 0u64;
        // Validate all metadata and bounds before expanding any seed.
        for (epoch, item) in request.epochs.iter().enumerate() {
            if item.epoch != epoch as u64 || item.nodes.len() > TREE_DEPTH as usize {
                return Err(Error::MalformedCover);
            }
            total = total.checked_add(item.count).ok_or(Error::Limit)?;
            if total > self.limits.postings as u64 {
                return Err(Error::Limit);
            }
            let expected = shape(TREE_DEPTH, item.count)?;
            if item.nodes.len() != expected.len()
                || !item
                    .nodes
                    .iter()
                    .zip(expected)
                    .all(|(node, (d, p))| node.depth == d && node.prefix == p)
            {
                return Err(Error::MalformedCover);
            }
        }
        let mut entries = Vec::with_capacity(total as usize);
        for epoch in &request.epochs {
            for (index, seed) in enumerate(&epoch.nodes)? {
                let seed = Zeroizing::new(seed);
                let address = leaf_address(&seed);
                entries.push(SearchEntry {
                    epoch: epoch.epoch,
                    index,
                    address,
                    ciphertext: self.postings.get(&address).copied(),
                });
            }
        }
        Ok(SearchResponse {
            version: VERSION,
            index_id: self.index_id,
            entries,
        })
    }
}

#[cfg(test)]
mod tests;

mod journal;
pub use journal::{
    JournalError, PersistentClient, SseJournalAnchor, SseJournalAnchorError, SseJournalAnchorRecord,
};

mod anchor;
pub use oblivion_anchor::TlsSseJournalAnchor;
#[cfg(unix)]
pub use oblivion_anchor::{UnixAnchorClient, UnixSseJournalAnchor};
