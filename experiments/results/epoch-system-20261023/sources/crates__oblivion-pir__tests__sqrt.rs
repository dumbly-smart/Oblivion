use oblivion_pir::{Error, MAX_DATABASE_BYTES, MAX_RECORD_BYTES, recover, sqrt::Geometry};

fn record(index: usize, width: usize) -> Vec<u8> {
    (0..width)
        .map(|j| (((index * 131) ^ (j * 17) ^ (index >> (j % 8))) & 255) as u8)
        .collect()
}

#[test]
fn all_indices_match_full_record_oracle_with_independent_servers() {
    for n in [1, 2, 3, 7, 9, 10, 63, 64, 65, 100, 101] {
        for width in [1, 8, 17] {
            let geometry = Geometry::new(n, width).unwrap();
            let a = geometry
                .server((0..n).map(|i| record(i, width)).collect())
                .unwrap();
            let b = geometry
                .server((0..n).map(|i| record(i, width)).collect())
                .unwrap();
            for index in 0..n {
                let (query, state) = geometry.query(index).unwrap();
                let first = a.answer(&query.first).unwrap();
                let second = b.answer(&query.second).unwrap();
                assert_eq!(
                    state.recover(&first, &second).unwrap(),
                    record(index, width)
                );
                assert_eq!(query.first.len(), geometry.rows().div_ceil(8));
                assert_eq!(first.len(), geometry.columns() * width);
            }
        }
    }
}

#[test]
fn nonsquare_geometry_zero_pads_the_last_row() {
    let g = Geometry::new(10, 8).unwrap();
    assert_eq!(
        (g.rows(), g.columns(), g.row_bytes(), g.padded_bytes()),
        (4, 4, 32, 128)
    );
    let a = g.server((0..10).map(|i| record(i, 8)).collect()).unwrap();
    let b = g.server((0..10).map(|i| record(i, 8)).collect()).unwrap();
    let (q, state) = g.query(9).unwrap();
    let x = a.answer(&q.first).unwrap();
    let y = b.answer(&q.second).unwrap();
    let row = recover(&x, &y).unwrap();
    assert_eq!(&row[0..8], record(8, 8));
    assert_eq!(&row[8..16], record(9, 8));
    assert_eq!(&row[16..], &[0; 16]);
    assert_eq!(state.recover(&x, &y).unwrap(), record(9, 8));
}

#[test]
fn validates_limits_without_overflow_or_large_allocation() {
    for (n, b) in [
        (0, 8),
        (1, 0),
        (usize::MAX, 1),
        (1, usize::MAX),
        (1_000_001, 1),
        (2, MAX_RECORD_BYTES),
    ] {
        assert!(matches!(Geometry::new(n, b), Err(Error::Database)));
    }
    let g = Geometry::new(65536, 1024).unwrap();
    assert_eq!(g.padded_bytes(), MAX_DATABASE_BYTES);
    assert!(matches!(Geometry::new(65537, 1024), Err(Error::Database)));
    assert_eq!(
        Geometry::new(4095, 16384).unwrap().row_bytes(),
        MAX_RECORD_BYTES
    );
    // Original bytes fit; square padding exceeds 64 MiB.
    assert!(matches!(Geometry::new(65026, 1028), Err(Error::Database)));
}

#[test]
fn rejects_bad_server_dimensions_and_malformed_shapes() {
    let g = Geometry::new(10, 8).unwrap();
    assert!(matches!(
        g.server(vec![vec![0; 8]; 9]),
        Err(Error::Database)
    ));
    assert!(matches!(
        g.server(vec![vec![0; 7]; 10]),
        Err(Error::Database)
    ));
    assert!(matches!(g.query(10), Err(Error::Index)));
    let a = g.server(vec![vec![0; 8]; 10]).unwrap();
    assert!(matches!(a.answer(&[]), Err(Error::Shape)));
    let (_, state) = g.query(0).unwrap();
    for (x, y) in [
        (vec![], vec![]),
        (vec![0; 8], vec![0; 8]),
        (vec![0; 32], vec![0; 31]),
    ] {
        assert!(matches!(state.recover(&x, &y), Err(Error::Shape)));
    }
}

#[test]
fn joint_shares_reveal_row_and_do_not_encode_the_private_column() {
    let g = Geometry::new(65, 8).unwrap();
    for index in 0..65 {
        let (q, _) = g.query(index).unwrap();
        let joint: Vec<_> = q.first.iter().zip(&q.second).map(|(a, b)| a ^ b).collect();
        let mut expected = vec![0; g.rows().div_ceil(8)];
        let row = index / g.columns();
        expected[row / 8] = 1 << (row % 8);
        assert_eq!(joint, expected);
    }
}
