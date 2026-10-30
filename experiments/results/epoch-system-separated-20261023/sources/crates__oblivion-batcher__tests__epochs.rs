use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, EpochBatcher, Error, PAYLOAD_BYTES};
use std::time::{Duration, Instant};

#[test]
fn real_and_dummy_envelopes_have_same_shape_and_replay_is_rejected() {
    let (mut client, mut executor) = Endpoint::provision(0).unwrap();
    for epoch in 0..10 {
        let mut payload = [0; PAYLOAD_BYTES];
        payload[0] = (epoch % 2) as u8;
        let frame = client.send(epoch, &payload).unwrap();
        assert_eq!(frame.as_bytes().len(), ENVELOPE_BYTES);
        assert_eq!(executor.receive(&frame).unwrap(), payload);
        assert!(matches!(executor.receive(&frame), Err(Error::Replay)));
        assert!(matches!(client.send(epoch, &payload), Err(Error::Replay)));
        let response = executor.send(epoch, &payload).unwrap();
        assert_eq!(client.receive(&response).unwrap(), payload);
    }
}

#[test]
fn tamper_wrong_direction_and_unknown_participant_are_rejected() {
    let (mut client, mut executor) = Endpoint::provision(0).unwrap();
    let frame = client.send(0, &[7; PAYLOAD_BYTES]).unwrap();
    assert!(client.receive(&frame).is_err());
    for byte in [4, 8, 20, ENVELOPE_BYTES - 1] {
        let mut bytes = frame.as_bytes().to_vec();
        bytes[byte] ^= 1;
        if let Ok(bad) = Envelope::from_bytes(&bytes) {
            assert!(executor.receive(&bad).is_err());
        }
    }
    assert_eq!(executor.receive(&frame).unwrap(), [7; PAYLOAD_BYTES]);
    let (_, mut other) = Endpoint::provision(1).unwrap();
    assert!(other.receive(&frame).is_err());
    assert!(Envelope::from_bytes(&[]).is_err());
}

#[test]
fn fixed_batches_across_real_ratios_and_missing_clients() {
    for real_count in [0, 2, 4] {
        let start = Instant::now();
        let period = Duration::from_millis(10);
        let mut batcher = EpochBatcher::new(4, period, start).unwrap();
        let mut peers = Vec::new();
        for slot in 0..4 {
            let (mut client, peer) = Endpoint::provision(slot).unwrap();
            let mut payload = [0; PAYLOAD_BYTES];
            payload[0] = u8::from(slot < real_count);
            let frame = client.send(0, &payload).unwrap();
            batcher.submit(frame.clone()).unwrap();
            assert!(matches!(batcher.submit(frame), Err(Error::Duplicate)));
            peers.push(peer);
        }
        assert!(matches!(batcher.emit(start), Err(Error::Early)));
        let batch = batcher.emit(start + period).unwrap();
        assert_eq!(batch.envelopes.len(), 4);
        assert!(batch.missing_slots.is_empty());
        for (slot, (peer, frame)) in peers.iter_mut().zip(batch.envelopes.iter()).enumerate() {
            assert_eq!(
                peer.receive(frame).unwrap()[0],
                u8::from(slot < (real_count as usize))
            );
            assert_eq!(frame.as_bytes().len(), ENVELOPE_BYTES);
        }
        let missing = batcher.emit(start + 2 * period).unwrap();
        assert_eq!(missing.envelopes.len(), 4);
        assert_eq!(missing.missing_slots.len(), 4);
        // Random cover must be handled as dummy work by the trusted pipeline;
        // it is intentionally not a forged authenticated client request.
        for (peer, frame) in peers.iter_mut().zip(&missing.envelopes) {
            assert!(peer.receive(frame).is_err());
        }
    }
}

#[test]
fn queues_reject_future_epochs_and_out_of_range_slots() {
    let start = Instant::now();
    assert!(EpochBatcher::new(0, Duration::from_millis(10), start).is_err());
    assert!(EpochBatcher::new(2048, Duration::from_millis(10), start).is_err());
    let mut batcher = EpochBatcher::new(1, Duration::from_millis(10), start).unwrap();
    let (mut client, _) = Endpoint::provision(0).unwrap();
    assert!(
        batcher
            .submit(client.send(1, &[0; PAYLOAD_BYTES]).unwrap())
            .is_err()
    );
    let (mut outsider, _) = Endpoint::provision(1).unwrap();
    assert!(
        batcher
            .submit(outsider.send(0, &[0; PAYLOAD_BYTES]).unwrap())
            .is_err()
    );
}

#[test]
fn bootstrap_over_private_pipe_preserves_directional_keys() {
    let mut pipe = Vec::new();
    let mut client = Endpoint::provision_over_pipe(3, &mut pipe).unwrap();
    let mut peer = Endpoint::accept_bootstrap(3, &mut pipe.as_slice()).unwrap();
    let frame = client.send(0, &[4; PAYLOAD_BYTES]).unwrap();
    assert_eq!(peer.receive(&frame).unwrap(), [4; PAYLOAD_BYTES]);
    let response = peer.send(0, &[8; PAYLOAD_BYTES]).unwrap();
    assert_eq!(client.receive(&response).unwrap(), [8; PAYLOAD_BYTES]);
}

#[test]
fn delayed_unseen_response_cannot_satisfy_a_new_request() {
    let (mut client, mut server) = Endpoint::provision(0).unwrap();
    let first = client.send(0, &[0; PAYLOAD_BYTES]).unwrap();
    server.receive(&first).unwrap();
    let old = server.send(0, &[1; PAYLOAD_BYTES]).unwrap();
    let second = client.send(1, &[0; PAYLOAD_BYTES]).unwrap();
    server.receive(&second).unwrap();
    let current = server.send(1, &[2; PAYLOAD_BYTES]).unwrap();
    assert!(client.receive(&old).is_err());
    assert_eq!(client.receive(&current).unwrap(), [2; PAYLOAD_BYTES]);
}
