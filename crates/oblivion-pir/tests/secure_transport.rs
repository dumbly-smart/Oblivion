use oblivion_pir::{
    Database, QueryPair, recover,
    secure::{Client, Endpoint, Geometry, serve_connection},
};
use std::{net::TcpListener, time::Duration};

#[test]
fn large_database_over_real_tcp_has_geometry_sized_frames() {
    let geometry = Geometry::new(10_000, 1024).unwrap();
    assert_eq!(geometry.query_bytes(), 1250);
    assert_eq!(geometry.query_frame_bytes(), 1250 + 52);
    assert_eq!(geometry.answer_frame_bytes(), 1024 + 52);
    let records: Vec<_> = (0..10_000).map(|i| vec![(i % 251) as u8; 1024]).collect();
    let query = QueryPair::generate(10_000, 9999).unwrap();
    let mut answers = Vec::new();
    let mut handles = Vec::new();
    for share in [query.first, query.second] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let database = Database::new(records.clone()).unwrap();
        let (endpoint, mut server) = Endpoint::provision(7, geometry).unwrap();
        handles.push(std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            serve_connection(&mut stream, &database, &mut server, Duration::from_secs(5)).unwrap();
        }));
        answers.push(
            Client::new(address, endpoint, Duration::from_secs(5))
                .unwrap()
                .request(42, &share)
                .unwrap(),
        );
    }
    assert_eq!(recover(&answers[0], &answers[1]).unwrap(), records[9999]);
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn authenticates_geometry_version_epoch_sequence_and_payload_before_accepting() {
    let geometry = Geometry::new(9, 256).unwrap();
    let (mut client, mut server) = Endpoint::provision(1, geometry).unwrap();
    let query = client.seal_query(5, &[1, 0]).unwrap();
    for offset in [0, 4, 6, 7, 8, 12, 16, 20, 28, 36, query.len() - 1] {
        let mut bad = query.clone();
        bad[offset] ^= 1;
        assert!(server.open_query(&bad).is_err(), "offset {offset}");
    }
    assert_eq!(server.open_query(&query).unwrap(), vec![1, 0]);
    assert!(server.open_query(&query).is_err());
    let answer = server.seal_answer(&vec![8; 256]).unwrap();
    assert_eq!(client.open_answer(&answer).unwrap(), vec![8; 256]);
    assert!(client.open_answer(&answer).is_err());
    let _next = client.seal_query(6, &[0, 1]).unwrap();
    assert!(client.open_answer(&answer).is_err());
}

#[test]
fn private_bootstrap_round_trip_and_geometry_bounds() {
    let geometry = Geometry::new(100, 2048).unwrap();
    let mut pipe = Vec::new();
    let mut client = Endpoint::provision_over_pipe(3, geometry, &mut pipe).unwrap();
    let mut server = Endpoint::accept_bootstrap(3, &mut pipe.as_slice()).unwrap();
    assert_eq!(server.geometry(), geometry);
    let query = client.seal_query(0, &[0; 13]).unwrap();
    assert_eq!(server.open_query(&query).unwrap(), vec![0; 13]);
    assert!(Endpoint::accept_bootstrap(4, &mut pipe.as_slice()).is_err());
    for (count, width) in [(0, 1), (1, 0), (usize::MAX, 1), (10_000, 1_000_000)] {
        assert!(Geometry::new(count, width).is_err());
    }
}

#[test]
fn tampered_and_replayed_tcp_queries_never_produce_an_answer() {
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpStream},
    };
    let geometry = Geometry::new(9, 256).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (mut client, mut server) = Endpoint::provision(0, geometry).unwrap();
    let handle = std::thread::spawn(move || {
        let database = Database::new(vec![vec![42; 256]; 9]).unwrap();
        for should_pass in [false, true, false] {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                serve_connection(&mut stream, &database, &mut server, Duration::from_secs(1))
                    .is_ok(),
                should_pass
            );
        }
    });
    let _frame = client.seal_query(0, &[1, 0]).unwrap();
    let frame = client.seal_query(0, &[1, 0]);
    assert!(frame.is_err()); // Exactly one outstanding request.
    client.abandon();
    let frame = client.seal_query(0, &[1, 0]).unwrap();
    for (ordinal, mut bytes) in [frame.clone(), frame.clone(), frame]
        .into_iter()
        .enumerate()
    {
        if ordinal == 0 {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&bytes).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        if ordinal == 1 {
            assert_eq!(client.open_answer(&answer).unwrap(), vec![42; 256]);
        } else {
            assert!(answer.is_empty());
        }
    }
    handle.join().unwrap();
}

#[test]
fn timeout_disconnect_and_delayed_answer_do_not_match_a_new_request() {
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpStream},
        time::Instant,
    };
    let geometry = Geometry::new(8, 32).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (endpoint, mut server) = Endpoint::provision(1, geometry).unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut frame = vec![0; geometry.query_frame_bytes()];
        stream.read_exact(&mut frame).unwrap();
        server.open_query(&frame).unwrap();
        let delayed = server.seal_answer(&[9; 32]).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        drop(stream);
        let (mut stream, _) = listener.accept().unwrap();
        stream.read_exact(&mut frame).unwrap();
        server.open_query(&frame).unwrap();
        stream.write_all(&delayed).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();
    });
    let mut client = Client::new(address, endpoint, Duration::from_millis(70)).unwrap();
    let start = Instant::now();
    assert!(client.request(0, &[1]).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(150));
    assert!(client.request(0, &[1]).is_err()); // Same epoch, different sequence.
    handle.join().unwrap();
    assert!(TcpStream::connect(address).is_err());
    assert!(client.request(1, &[1]).is_err());
}

#[test]
fn independent_sessions_and_tampered_answers_are_rejected_without_consuming_pending() {
    let geometry = Geometry::new(8, 32).unwrap();
    let (mut first, mut server) = Endpoint::provision(9, geometry).unwrap();
    let (mut unrelated, mut unrelated_server) = Endpoint::provision(9, geometry).unwrap();
    let query = first.seal_query(1, &[1]).unwrap();
    assert!(unrelated_server.open_query(&query).is_err());
    server.open_query(&query).unwrap();
    let answer = server.seal_answer(&[3; 32]).unwrap();
    unrelated.seal_query(1, &[1]).unwrap();
    assert!(unrelated.open_answer(&answer).is_err());
    for offset in [4, 12, 16, 20, 28, 36, answer.len() - 1] {
        let mut bad = answer.clone();
        bad[offset] ^= 1;
        assert!(first.open_answer(&bad).is_err());
    }
    assert_eq!(first.open_answer(&answer).unwrap(), vec![3; 32]);
}

#[test]
fn server_deadline_bounds_trickled_input_and_rejects_database_geometry_mismatch() {
    use std::{io::Write, net::TcpStream, time::Instant};
    let geometry = Geometry::new(8, 32).unwrap();
    let (mut client, mut server) = Endpoint::provision(0, geometry).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let wrong_database = Database::new(vec![vec![0; 16]; 8]).unwrap();
        assert!(
            serve_connection(
                &mut stream,
                &wrong_database,
                &mut server,
                Duration::from_secs(1)
            )
            .is_err()
        );
        let database = Database::new(vec![vec![0; 32]; 8]).unwrap();
        let start = Instant::now();
        assert!(
            serve_connection(
                &mut stream,
                &database,
                &mut server,
                Duration::from_millis(100)
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    });
    let mut stream = TcpStream::connect(address).unwrap();
    for byte in client.seal_query(0, &[1]).unwrap() {
        if stream.write_all(&[byte]).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    handle.join().unwrap();
}
