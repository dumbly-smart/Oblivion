use super::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn fixture() -> (Client, Server) {
    let client = Client::new(Limits::default()).unwrap();
    let server = Server::new(client.index_id(), Limits::default()).unwrap();
    (client, server)
}

fn add(client: &mut Client, server: &mut Server, w: &[u8], id: u64) -> UpdateRequest {
    let req = client.prepare_add(w, id).unwrap();
    let ack = server.insert(req.clone()).unwrap();
    client.finish_add(ack).unwrap();
    req
}

fn search(client: &Client, server: &Server, w: &[u8]) -> Vec<u64> {
    let (snapshot, request) = client.prepare_search(w).unwrap();
    client
        .finish_search(&snapshot, server.search(&request).unwrap())
        .unwrap()
}

#[test]
fn exhaustive_small_tree_prefix_capabilities() {
    let root = [7; 32];
    for depth in [0, 4, 8] {
        for n in 0..=1u64 << depth {
            let nodes = cover(&root, n, depth).unwrap();
            assert!(nodes.len() <= usize::from(depth.max(1)));
            let mut intervals = Vec::new();
            for node in &nodes {
                intervals.push(span(node.depth, node.prefix, depth).unwrap());
            }
            let mut end = 0;
            for (lo, hi) in intervals {
                assert_eq!(lo, end);
                end = hi;
            }
            assert_eq!(end, n);
            for i in 0..1u64 << depth {
                let result = constrained_eval_depth(&nodes, i, depth);
                if i < n {
                    assert_eq!(result.unwrap(), derive_leaf(&root, i, depth).unwrap());
                } else {
                    assert_eq!(result, Err(Error::OutsideConstraint));
                }
            }
        }
    }
    let nodes = cover(&root, 5, 4).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|n| (n.depth, n.prefix))
            .collect::<Vec<_>>(),
        vec![(2, 0), (4, 4)]
    );
    let full = cover(&root, 16, 4).unwrap();
    assert_eq!((full[0].depth, full[0].prefix, full[0].seed), (0, 0, root));
    assert!(cover(&root, TREE_CAPACITY + 1, TREE_DEPTH).is_err());
    assert!(span(33, 0, TREE_DEPTH).is_err());
    assert!(span(0, 1, TREE_DEPTH).is_err());
}

#[test]
fn retained_all_past_constraints_and_root_positive_control() {
    let (mut c, mut s) = fixture();
    let mut retained = Vec::<SearchRequest>::new();
    let mut updates = Vec::new();
    for i in 0..20 {
        let req = add(&mut c, &mut s, b"secret", i);
        // Every previously retained node is considered, including overlapping
        // capabilities from earlier searches. No client root is given to attacker.
        for old in &retained {
            for epoch in &old.epochs {
                for node in &epoch.nodes {
                    for index in 0..=i {
                        if let Ok(seed) = constrained_eval(std::slice::from_ref(node), index) {
                            assert_ne!(leaf_address(&seed), req.address);
                        }
                    }
                }
            }
        }
        updates.push(req);
        if i % 3 == 0 {
            let (_, request) = c.prepare_search(b"secret").unwrap();
            // Deliberately retain the request without waiting for its response.
            retained.push(request);
        }
    }
    let (_, final_request) = c.prepare_search(b"secret").unwrap();
    for (i, req) in updates.iter().enumerate() {
        assert_eq!(
            leaf_address(&constrained_eval(&final_request.epochs[0].nodes, i as u64).unwrap()),
            req.address
        );
    }
    // Positive control: leaking the root authorizes the next unused leaf.
    let leaked_root = ConstraintNode {
        depth: 0,
        prefix: 0,
        seed: *c.root(b"secret", 0),
    };
    let predicted = leaf_address(&constrained_eval(&[leaked_root], 20).unwrap());
    let next = add(&mut c, &mut s, b"secret", 999);
    assert_eq!(predicted, next.address);
    // Rotation freezes the prefix and changes the root. Even all retained
    // capabilities plus the deliberately leaked old root cannot predict it.
    c.rotate_keyword(b"secret").unwrap();
    let fresh = add(&mut c, &mut s, b"secret", 1000);
    assert_ne!(fresh.address, updates[0].address);
    let (_, request) = c.prepare_search(b"secret").unwrap();
    assert_eq!(
        request.epochs.iter().map(|e| e.count).collect::<Vec<_>>(),
        vec![21, 1]
    );
    assert_eq!(search(&c, &s, b"secret").len(), 22);
    // Positive control: attaching a stable search tag to an update trivially
    // exposes its keyword's search-equivalence class.
    let (_, other) = c.prepare_search(b"other").unwrap();
    let wrongly_attached_tag = final_request.tag;
    assert_eq!(wrongly_attached_tag, request.tag);
    assert_ne!(wrongly_attached_tag, other.tag);
}

#[test]
fn pending_retries_and_limits_are_atomic() {
    let limits = Limits {
        postings: 1,
        keywords: 1,
        epochs_per_keyword: 2,
        ..Limits::default()
    };
    let mut c = Client::new(limits).unwrap();
    let mut s = Server::new(c.index_id(), limits).unwrap();
    let req = c.prepare_add(b"w", 42).unwrap();
    assert!(matches!(c.prepare_add(b"w", 43), Err(Error::Pending)));
    assert!(matches!(c.prepare_search(b"w"), Err(Error::Pending)));
    assert_eq!(c.rotate_keyword(b"w"), Err(Error::Pending));
    assert_eq!(c.finish_add([0; 32]), Err(Error::WrongAcknowledgment));
    let retry = c.retry_pending().unwrap();
    assert_eq!(retry.address, req.address);
    assert_eq!(retry.ciphertext, req.ciphertext);
    s.insert(req.clone()).unwrap(); // lost acknowledgment
    let ack = s.insert(retry).unwrap(); // accepted even when storage is full
    c.finish_add(ack).unwrap();
    assert_eq!(s.posting_count(), 1);
    assert_eq!(search(&c, &s, b"w"), vec![42]);
    assert!(matches!(c.retry_pending(), Err(Error::NoPending)));
    assert!(matches!(c.prepare_add(b"w", 43), Err(Error::Limit)));
    assert_eq!(c.rotate_keyword(b"other"), Err(Error::Limit));
    c.rotate_keyword(b"w").unwrap();
    assert_eq!(c.rotate_keyword(b"w"), Err(Error::Limit));
    assert_eq!(search(&c, &s, b"w"), vec![42]);
    let mut conflict = req;
    conflict.ciphertext[0] ^= 1;
    assert_eq!(s.insert(conflict), Err(Error::ConflictingAddress));
    assert_eq!(search(&c, &s, b"w"), vec![42]);
    assert!(matches!(
        Client::new(Limits {
            postings: usize::MAX,
            ..limits
        }),
        Err(Error::Limit)
    ));
}

#[test]
fn payload_authentication_snapshot_and_response_checks() {
    let (mut c, mut s) = fixture();
    let a = add(&mut c, &mut s, b"w", 77);
    let b = add(&mut c, &mut s, b"w", 77);
    let d = add(&mut c, &mut s, b"other", 77);
    assert_ne!(a.address, b.address);
    assert_ne!(a.ciphertext, b.ciphertext);
    assert_ne!(*c.record_key(&a.address), *c.record_key(&b.address));
    assert_ne!(*c.record_key(&a.address), *c.record_key(&d.address));
    let (snapshot, req) = c.prepare_search(b"w").unwrap();
    let response = s.search(&req).unwrap();
    assert_eq!(
        c.finish_search(&snapshot, response.clone()).unwrap(),
        vec![77, 77]
    );
    let mut bad = response.clone();
    bad.entries[0].ciphertext.as_mut().unwrap()[0] ^= 1;
    assert_eq!(c.finish_search(&snapshot, bad), Err(Error::Authentication));
    let mut bad = response.clone();
    bad.entries[0].ciphertext = response.entries[1].ciphertext;
    assert_eq!(c.finish_search(&snapshot, bad), Err(Error::Authentication));
    let mut bad = response.clone();
    bad.entries[1] = bad.entries[0].clone();
    assert_eq!(c.finish_search(&snapshot, bad), Err(Error::InvalidResponse));
    let mut bad = response.clone();
    bad.entries.pop();
    assert_eq!(c.finish_search(&snapshot, bad), Err(Error::InvalidResponse));
    let mut bad = response.clone();
    bad.entries.push(response.entries[0].clone());
    assert_eq!(c.finish_search(&snapshot, bad), Err(Error::InvalidResponse));
    let mut bad = response.clone();
    bad.entries[0].ciphertext = None;
    assert_eq!(c.finish_search(&snapshot, bad), Err(Error::MissingPosting));
    let mut bad = response.clone();
    bad.index_id[0] ^= 1;
    assert_eq!(c.finish_search(&snapshot, bad), Err(Error::WrongIndex));
    // Later writes do not invalidate a valid earlier local search snapshot.
    add(&mut c, &mut s, b"w", 88);
    assert_eq!(c.finish_search(&snapshot, response).unwrap(), vec![77, 77]);
    let (other_client, _) = fixture();
    assert!(matches!(
        other_client.finish_search(&snapshot, s.search(&req).unwrap()),
        Err(Error::WrongIndex)
    ));
}

#[test]
fn malformed_covers_are_rejected_before_expansion() {
    let (mut c, mut s) = fixture();
    add(&mut c, &mut s, b"w", 1);
    let (_, req) = c.prepare_search(b"w").unwrap();
    let mut bad = req.clone();
    bad.epochs[0].nodes[0].depth = 0;
    bad.epochs[0].nodes[0].prefix = 0;
    assert!(matches!(s.search(&bad), Err(Error::MalformedCover)));
    let mut bad = req.clone();
    let duplicate = bad.epochs[0].nodes[0].clone();
    bad.epochs[0].nodes.push(duplicate);
    assert!(matches!(s.search(&bad), Err(Error::MalformedCover)));
    let mut bad = req.clone();
    bad.epochs[0].count = u64::MAX;
    assert!(matches!(s.search(&bad), Err(Error::Limit)));
    let mut bad = req.clone();
    bad.epochs[0].epoch = 1;
    assert!(matches!(s.search(&bad), Err(Error::MalformedCover)));
    let mut bad = req.clone();
    bad.version = 99;
    assert!(matches!(s.search(&bad), Err(Error::WrongIndex)));
    let mut bad = req;
    bad.epochs[0].nodes[0].seed[0] ^= 1;
    let response = s.search(&bad).unwrap();
    assert!(response.entries[0].ciphertext.is_none());
}

#[test]
fn rollback_negative_fixture_reuses_exposed_address() {
    let (mut c, mut s) = fixture();
    let old = add(&mut c, &mut s, b"w", 7);
    let (_, exposed) = c.prepare_search(b"w").unwrap();
    // Only this internal negative fixture can corrupt private client counters.
    // There is intentionally no supported restore/import API.
    c.keywords.get_mut(b"w".as_slice()).unwrap()[0] = 0;
    let reused = c.prepare_add(b"w", 8).unwrap();
    assert_eq!(reused.address, old.address);
    let attacker = leaf_address(&constrained_eval(&exposed.epochs[0].nodes, 0).unwrap());
    assert_eq!(attacker, reused.address);
    assert_ne!(reused.ciphertext, old.ciphertext);
    assert_eq!(s.insert(reused), Err(Error::ConflictingAddress));
}

#[test]
fn full_epoch_is_retired_until_rotation() {
    let (mut c, mut s) = fixture();
    add(&mut c, &mut s, b"w", 1);
    // Exercise capacity transition without allocating billions of postings.
    c.keywords.get_mut(b"w".as_slice()).unwrap()[0] = TREE_CAPACITY;
    assert!(matches!(c.prepare_add(b"w", 2), Err(Error::Exhausted)));
    c.rotate_keyword(b"w").unwrap();
    let req = c.prepare_add(b"w", 2).unwrap();
    assert_ne!(
        req.address,
        leaf_address(&derive_leaf(&c.root(b"w", 0), 0, TREE_DEPTH).unwrap())
    );
    c.finish_add(s.insert(req).unwrap()).unwrap();
}

#[test]
fn hundred_thousand_operations_match_plaintext_oracle() {
    let (mut c, mut s) = fixture();
    let mut rng = ChaCha20Rng::seed_from_u64(0x534553455f5631);
    let mut oracle = HashMap::<Vec<u8>, Vec<u64>>::new();
    for step in 0..100_000 {
        let keyword = rng.gen_range(0u32..4096).to_be_bytes().to_vec();
        if step % 997 == 0 {
            c.rotate_keyword(&keyword).unwrap();
        }
        if rng.gen_range(0..5) == 0 {
            assert_eq!(
                search(&c, &s, &keyword),
                oracle.get(&keyword).cloned().unwrap_or_default()
            );
        } else {
            let id = rng.gen_range(0..1024);
            add(&mut c, &mut s, &keyword, id);
            oracle.entry(keyword).or_default().push(id);
        }
    }
    for (keyword, ids) in &oracle {
        assert_eq!(&search(&c, &s, keyword), ids);
    }
}
