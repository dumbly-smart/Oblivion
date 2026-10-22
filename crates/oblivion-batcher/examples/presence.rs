//! Synthetic presence model: real batcher/envelopes, virtual monotonic epochs.
use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, EpochBatcher, PAYLOAD_BYTES};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::{
    fs::File,
    io::Write,
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: presence SEED EPOCHS ONLINE_PERCENT TRUTH_PATH BEACON_PATH".into());
    }
    let seed: u64 = args[1].parse()?;
    let epochs: usize = args[2].parse()?;
    let percent: u32 = args[3].parse()?;
    if !(1..=4096).contains(&epochs) || !(1..=100).contains(&percent) {
        return Err("bounds".into());
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let owner: usize = rng.gen_range(0..8);
    let mut online = Vec::new();
    let mut work = Vec::new();
    let mut beacon = File::create(&args[5])?;
    for epoch in 0..epochs {
        let mut on = [false; 8];
        let mut real = [false; 8];
        for slot in 0..8 {
            on[slot] = rng.gen_ratio(percent, 100);
            real[slot] = on[slot] && rng.gen_ratio(1, 4);
        }
        writeln!(beacon, "{{\"epoch\":{epoch},\"event\":{}}}", real[owner])?;
        online.push(on);
        work.push(real);
    }
    let mut truth = File::create(&args[4])?;
    let stdout = std::io::stdout();
    let mut output = std::io::BufWriter::new(stdout.lock());
    // Positive control is exported first. Modes reuse the exact latent workload.
    for mode in [
        "intermittent_control",
        "fixed_rate_online",
        "always_participating",
    ] {
        let mut clients = Vec::new();
        let mut receivers = Vec::new();
        for slot in 0..8 {
            let (client, receiver) = Endpoint::provision(slot)?;
            clients.push(client);
            receivers.push(receiver);
        }
        let period = Duration::from_millis(10);
        let start = Instant::now();
        let mut batcher = EpochBatcher::new(8, period, start)?;
        for epoch in 0..epochs {
            let mut incoming = Vec::new();
            let mut bodies = [[0u8; PAYLOAD_BYTES]; 8];
            for slot in 0..8 {
                if online[epoch][slot] || mode == "always_participating" {
                    bodies[slot][0] = u8::from(work[epoch][slot]);
                    let frame = clients[slot].send(epoch as u64, &bodies[slot])?;
                    assert_eq!(frame.as_bytes().len(), ENVELOPE_BYTES);
                    batcher.submit(frame)?;
                    incoming.push(slot as u32);
                }
            }
            let batch = batcher.emit(start + period * (epoch as u32 + 1))?;
            let outgoing: Vec<_> = batch.envelopes.iter().map(|f| f.slot()).collect();
            let outgoing_bytes: usize = batch.envelopes.iter().map(|f| f.as_bytes().len()).sum();
            let mut verified = 0;
            let mut cover_rejected = 0;
            for frame in &batch.envelopes {
                let slot = frame.slot() as usize;
                if incoming.contains(&(slot as u32)) {
                    assert_eq!(receivers[slot].receive(frame)?, bodies[slot]);
                    verified += 1;
                } else {
                    assert!(receivers[slot].receive(frame).is_err());
                    cover_rejected += 1;
                }
            }
            assert_eq!(verified + cover_rejected, 8);
            writeln!(
                output,
                "{{\"mode\":\"{mode}\",\"epoch\":{epoch},\"incoming\":{incoming:?},\"missing_slots\":{:?},\"outgoing\":{outgoing:?},\"incoming_bytes\":{},\"outgoing_bytes\":{outgoing_bytes},\"emit_ns\":{},\"late_by_ns\":{}}}",
                batch.missing_slots,
                incoming.len() * ENVELOPE_BYTES,
                (epoch + 1) * 10_000_000,
                batch.late_by_ns
            )?;
            let online_slots: Vec<_> = (0..8).filter(|&s| online[epoch][s]).collect();
            let real_slots: Vec<_> = (0..8).filter(|&s| work[epoch][s]).collect();
            writeln!(
                truth,
                "{{\"mode\":\"{mode}\",\"epoch\":{epoch},\"seed\":{seed},\"owner\":{owner},\"online\":{online_slots:?},\"real\":{real_slots:?},\"verified\":{verified},\"cover_rejected\":{cover_rejected},\"authenticated_dummy_frames\":{}}}",
                verified - real_slots.len()
            )?;
        }
    }
    output.flush()?;
    Ok(())
}
