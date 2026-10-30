use oblivion_pir::{Database, Error, QueryPair, recover};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn retrieves_all_indices_with_fixed_shapes() {
    for count in [1usize, 2, 7, 8, 9, 65] {
        let records: Vec<Vec<u8>> = (0..count).map(|i| vec![i as u8; 32]).collect();
        let first = Database::new(records.clone()).unwrap();
        let second = Database::new(records.clone()).unwrap();
        for (index, expected) in records.iter().enumerate() {
            let pair = QueryPair::generate(count, index).unwrap();
            assert_eq!(pair.first.len(), count.div_ceil(8));
            assert_eq!(pair.second.len(), pair.first.len());
            let a = first.answer(&pair.first).unwrap();
            let b = second.answer(&pair.second).unwrap();
            assert_eq!(a.len(), 32);
            assert_eq!(b.len(), 32);
            assert_eq!(recover(&a, &b).unwrap(), *expected);
            // Collusion reconstructs the unit vector: document the actual failure.
            for bit in 0..count {
                assert_eq!(
                    ((pair.first[bit / 8] ^ pair.second[bit / 8]) >> (bit % 8)) & 1,
                    u8::from(bit == index)
                );
            }
        }
    }
}

#[test]
fn malformed_database_queries_and_answers_rejected() {
    assert!(Database::new(vec![]).is_err());
    assert!(Database::new(vec![vec![]]).is_err());
    assert!(Database::new(vec![vec![1], vec![2, 3]]).is_err());
    assert!(QueryPair::generate(0, 0).is_err());
    assert!(QueryPair::generate(8, 8).is_err());
    assert!(QueryPair::generate(usize::MAX, 0).is_err());
    let server = Database::new(vec![vec![3; 16]; 9]).unwrap();
    assert!(matches!(server.answer(&[0]), Err(Error::Shape)));
    assert!(matches!(recover(&[1], &[1, 2]), Err(Error::Shape)));
    assert!(recover(&[], &[]).is_err());
}

#[test]
fn bit_marginals_do_not_depend_on_requested_index() {
    // Broad diagnostic, not a security proof or full multivariate test.
    for requested in [0, 3, 7] {
        let mut ones = [[0usize; 8]; 2];
        for _ in 0..4096 {
            let pair = QueryPair::generate(8, requested).unwrap();
            for (server, query) in [&pair.first, &pair.second].iter().enumerate() {
                for (bit, count) in ones[server].iter_mut().enumerate() {
                    *count += ((query[0] >> bit) & 1) as usize;
                }
            }
        }
        for server in ones {
            for count in server {
                assert!((1700..2400).contains(&count));
            }
        }
    }
}

#[test]
fn ten_thousand_kib_records() {
    let mut rng = ChaCha20Rng::seed_from_u64(123);
    let records: Vec<Vec<u8>> = (0..10000)
        .map(|_| {
            let mut v = vec![0; 1024];
            rng.fill(v.as_mut_slice());
            v
        })
        .collect();
    let first = Database::new(records.clone()).unwrap();
    let second = Database::new(records.clone()).unwrap();
    for _ in 0..16 {
        let index = rng.gen_range(0..10000);
        let pair = QueryPair::generate(10000, index).unwrap();
        assert_eq!(
            recover(
                &first.answer(&pair.first).unwrap(),
                &second.answer(&pair.second).unwrap()
            )
            .unwrap(),
            records[index]
        );
    }
}
