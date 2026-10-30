//! Actual EpochBatcher timer measurement only; no execution/storage simulation.
use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, EpochBatcher, PAYLOAD_BYTES};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::{
    io::Write,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Arrival {
    epoch: u64,
    slot: usize,
    planned_ns: u128,
    arrived_ns: u128,
    emitted_ns: u128,
    real: bool,
}
struct Emission {
    epoch: u64,
    due_ns: u128,
    emitted_ns: u128,
    late_ns: u64,
    frames: usize,
    dummy: usize,
}
fn wait_until(deadline: Instant) {
    if let Some(wait) = deadline.checked_duration_since(Instant::now()) {
        std::thread::sleep(wait);
    }
}
fn measure(
    period_ms: u64,
    epochs: u64,
    participants: usize,
    real_percent: u32,
    seed: u64,
) -> Result<(Vec<Arrival>, Vec<Emission>)> {
    if !(2..=1000).contains(&period_ms)
        || !(1..=1024).contains(&epochs)
        || !(1..=64).contains(&participants)
        || ![0, 50, 100].contains(&real_percent)
    {
        return Err("period2..1000ms epochs1..1024 participants1..64 real_percent0|50|100".into());
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let mut clients = Vec::new();
    let mut executors = Vec::new();
    for slot in 0..participants {
        let (client, executor) = Endpoint::provision(slot as u32)?;
        clients.push(client);
        executors.push(executor);
    }
    let period = Duration::from_millis(period_ms);
    let start = Instant::now();
    let mut batcher = EpochBatcher::new(participants, period, start)?;
    let mut arrivals = Vec::new();
    let mut emissions = Vec::new();
    for epoch in 0..epochs {
        let epoch_start = start + period * (epoch as u32);
        let due = epoch_start + period;
        let mut phases = (0..participants)
            .map(|slot| (rng.gen_range(0..period.as_nanos() as u64), slot))
            .collect::<Vec<_>>();
        phases.sort_unstable();
        let offset = arrivals.len();
        for (phase, slot) in phases {
            let planned = epoch_start + Duration::from_nanos(phase);
            wait_until(planned);
            let real = real_percent == 100
                || (real_percent == 50 && (epoch as usize * participants + slot).is_multiple_of(2));
            let mut payload = [0; PAYLOAD_BYTES];
            payload[0] = u8::from(real);
            let frame = clients[slot].send(epoch, &payload)?;
            let arrived = Instant::now();
            batcher.submit(frame)?;
            arrivals.push(Arrival {
                epoch,
                slot,
                planned_ns: planned.duration_since(start).as_nanos(),
                arrived_ns: arrived.duration_since(start).as_nanos(),
                emitted_ns: 0,
                real,
            });
        }
        wait_until(due);
        let batch = batcher.emit(Instant::now())?;
        let emitted = Instant::now();
        let mut dummy = 0;
        for (slot, frame) in batch.envelopes.iter().enumerate() {
            let payload = executors[slot].receive(frame)?;
            dummy += usize::from(payload[0] == 0);
            if frame.as_bytes().len() != ENVELOPE_BYTES {
                return Err("frame shape changed".into());
            }
        }
        if !batch.missing_slots.is_empty() || batch.envelopes.len() != participants {
            return Err("batch shape changed".into());
        }
        for arrival in &mut arrivals[offset..] {
            arrival.emitted_ns = emitted.duration_since(start).as_nanos();
        }
        emissions.push(Emission {
            epoch,
            due_ns: due.duration_since(start).as_nanos(),
            emitted_ns: emitted.duration_since(start).as_nanos(),
            late_ns: batch.late_by_ns,
            frames: batch.envelopes.len(),
            dummy,
        });
    }
    Ok((arrivals, emissions))
}
fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 6 {
        return Err("usage: batch_measure PERIOD_MS EPOCHS PARTICIPANTS REAL_PERCENT SEED".into());
    }
    let (arrivals, emissions) = measure(
        args[1].parse()?,
        args[2].parse()?,
        args[3].parse()?,
        args[4].parse()?,
        args[5].parse()?,
    )?;
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    for row in arrivals {
        writeln!(
            output,
            "{{\"type\":\"arrival\",\"epoch\":{},\"slot\":{},\"planned_ns\":{},\"arrived_ns\":{},\"emitted_ns\":{},\"queue_wait_ns\":{},\"arrival_late_ns\":{},\"real\":{},\"frame_bytes\":{}}}",
            row.epoch,
            row.slot,
            row.planned_ns,
            row.arrived_ns,
            row.emitted_ns,
            row.emitted_ns - row.arrived_ns,
            row.arrived_ns.saturating_sub(row.planned_ns),
            row.real,
            ENVELOPE_BYTES
        )?;
    }
    for row in emissions {
        writeln!(
            output,
            "{{\"type\":\"emission\",\"epoch\":{},\"due_ns\":{},\"emitted_ns\":{},\"late_ns\":{},\"frames\":{},\"dummy_frames\":{},\"frame_bytes\":{},\"batch_bytes\":{}}}",
            row.epoch,
            row.due_ns,
            row.emitted_ns,
            row.late_ns,
            row.frames,
            row.dummy,
            ENVELOPE_BYTES,
            row.frames * ENVELOPE_BYTES
        )?;
    }
    output.flush()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_timers_emit_authenticated_fixed_batches_and_count_dummies() {
        for percent in [0, 50, 100] {
            let (arrivals, emissions) = measure(2, 2, 8, percent, 123).unwrap();
            assert_eq!(arrivals.len(), 16);
            assert_eq!(emissions.len(), 2);
            assert!(arrivals.iter().all(|row| row.arrived_ns <= row.emitted_ns));
            assert!(
                emissions
                    .iter()
                    .all(|row| row.frames == 8 && row.emitted_ns >= row.due_ns)
            );
            assert_eq!(
                emissions.iter().map(|row| row.dummy).sum::<usize>(),
                16 * (100 - percent as usize) / 100
            );
        }
    }
}
