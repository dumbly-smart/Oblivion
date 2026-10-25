//! Actual timer/queue driver. Observer stdout excludes trusted real/dummy labels.
use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, EpochBatcher, PAYLOAD_BYTES};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};
use std::{
    io::Write,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Clone, Copy)]
enum Mode {
    Plaintext,
    Protected,
}
struct Arrival {
    epoch: u64,
    slot: usize,
    arrived_ns: u128,
    frame: Envelope,
}
struct Emission {
    epoch: u64,
    emitted_ns: u128,
    frames: Vec<Envelope>,
}
struct Truth {
    epoch: u64,
    slot: usize,
    real: bool,
}
struct Trace {
    arrivals: Vec<Arrival>,
    emissions: Vec<Emission>,
    truth: Vec<Truth>,
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
    percent: u32,
    seed: u64,
    mode: Mode,
) -> Result<Trace> {
    if !(2..=1000).contains(&period_ms)
        || !(2..=64).contains(&epochs)
        || !(2..=64).contains(&participants)
        || !participants.is_multiple_of(2)
        || ![0, 50, 100].contains(&percent)
    {
        return Err("bounded configuration required".into());
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
    let mut trace = Trace {
        arrivals: Vec::new(),
        emissions: Vec::new(),
        truth: Vec::new(),
    };
    for epoch in 0..epochs {
        let epoch_start = start + period * (epoch as u32);
        let due = epoch_start + period;
        let mut flags: Vec<_> = (0..participants)
            .map(|i| i < participants * percent as usize / 100)
            .collect();
        flags.shuffle(&mut rng);
        let mut phases: Vec<_> = (0..participants)
            .map(|slot| (rng.gen_range(0..period.as_nanos() as u64), slot))
            .collect();
        phases.sort_unstable();
        for (phase, slot) in phases {
            wait_until(epoch_start + Duration::from_nanos(phase));
            let real = flags[slot];
            let mut body = [0; PAYLOAD_BYTES];
            body[0] = u8::from(real);
            body[1..9].copy_from_slice(&epoch.to_be_bytes());
            body[9..13].copy_from_slice(&(slot as u32).to_be_bytes());
            let frame = match mode {
                Mode::Protected => clients[slot].send(epoch, &body)?,
                Mode::Plaintext => {
                    // Deliberately unauthenticated public control, not valid AEAD.
                    let mut bytes = [0u8; ENVELOPE_BYTES];
                    bytes[..4].copy_from_slice(b"OBLV");
                    bytes[4..6].copy_from_slice(&2u16.to_be_bytes());
                    bytes[6] = 1;
                    bytes[8..16].copy_from_slice(&epoch.to_be_bytes());
                    bytes[16..20].copy_from_slice(&(slot as u32).to_be_bytes());
                    bytes[20..20 + PAYLOAD_BYTES].copy_from_slice(&body);
                    Envelope::from_bytes(&bytes)?
                }
            };
            let arrived_ns = start.elapsed().as_nanos();
            batcher.submit(frame.clone())?;
            trace.arrivals.push(Arrival {
                epoch,
                slot,
                arrived_ns,
                frame,
            });
            trace.truth.push(Truth { epoch, slot, real });
        }
        wait_until(due);
        let batch = batcher.emit(Instant::now())?;
        let emitted_ns = start.elapsed().as_nanos();
        if batch.envelopes.len() != participants || !batch.missing_slots.is_empty() {
            return Err("unexpected public participation shape".into());
        }
        for (slot, frame) in batch.envelopes.iter().enumerate() {
            let body = match mode {
                Mode::Protected => executors[slot].receive(frame)?.to_vec(),
                Mode::Plaintext => frame.as_bytes()[20..20 + PAYLOAD_BYTES].to_vec(),
            };
            let mut expected = [0u8; PAYLOAD_BYTES];
            expected[0] = u8::from(flags[slot]);
            expected[1..9].copy_from_slice(&epoch.to_be_bytes());
            expected[9..13].copy_from_slice(&(slot as u32).to_be_bytes());
            if body != expected {
                return Err("trusted full-payload verification failed".into());
            }
        }
        trace.emissions.push(Emission {
            epoch,
            emitted_ns,
            frames: batch.envelopes,
        });
    }
    Ok(trace)
}
fn write_observer(trace: &Trace, out: &mut impl Write) -> Result<()> {
    for a in &trace.arrivals {
        writeln!(
            out,
            "{{\"type\":\"arrival\",\"epoch\":{},\"slot\":{},\"arrived_ns\":{},\"destination\":\"batcher\",\"frame\":{:?}}}",
            a.epoch,
            a.slot,
            a.arrived_ns,
            a.frame.as_bytes()
        )?;
    }
    for e in &trace.emissions {
        write!(
            out,
            "{{\"type\":\"emission\",\"epoch\":{},\"emitted_ns\":{},\"destination\":\"executor\",\"frames\":[",
            e.epoch, e.emitted_ns
        )?;
        for (i, frame) in e.frames.iter().enumerate() {
            if i > 0 {
                write!(out, ",")?;
            }
            write!(out, "{:?}", frame.as_bytes())?;
        }
        writeln!(out, "]}}")?;
    }
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 9 {
        return Err("usage: load_trace PERIOD EPOCHS PARTICIPANTS PERCENT SEED plaintext|protected NEW_TRUTH_PATH PROCESS_ID".into());
    }
    let mode = match args[6].as_str() {
        "plaintext" => Mode::Plaintext,
        "protected" => Mode::Protected,
        _ => return Err("unknown mode".into()),
    };
    let percent: u32 = args[4].parse()?;
    let trace = measure(
        args[1].parse()?,
        args[2].parse()?,
        args[3].parse()?,
        percent,
        args[5].parse()?,
        mode,
    )?;
    // Private evaluator file; never part of observer stdout or attacker input.
    let mut truth = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[7])?;
    if !args[8]
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("process ID format".into());
    }
    write!(
        truth,
        "{{\"process_id\":\"{}\",\"real_percent\":{},\"requests\":[",
        args[8], percent
    )?;
    for (i, r) in trace.truth.iter().enumerate() {
        if i > 0 {
            write!(truth, ",")?;
        }
        write!(
            truth,
            "{{\"epoch\":{},\"slot\":{},\"real\":{}}}",
            r.epoch, r.slot, r.real
        )?;
    }
    writeln!(truth, "]}}")?;
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    write_observer(&trace, &mut output)?;
    output.flush()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_timer_plaintext_control_exposes_only_public_wire_opcodes() {
        let trace = measure(2, 2, 8, 50, 123, Mode::Plaintext).unwrap();
        assert_eq!(trace.arrivals.len(), 16);
        assert_eq!(trace.emissions.len(), 2);
        assert_eq!(
            trace
                .arrivals
                .iter()
                .filter(|a| a.frame.as_bytes()[20] == 1)
                .count(),
            8
        );
        let mut wire = Vec::new();
        write_observer(&trace, &mut wire).unwrap();
        let wire = String::from_utf8(wire).unwrap();
        assert!(!wire.contains("\"real\"") && !wire.contains("\"real_percent\""));
    }
    #[test]
    fn protected_actual_timer_authenticates_fixed_batches_for_every_load() {
        for percentage in [0, 50, 100] {
            let trace = measure(2, 2, 8, percentage, 123, Mode::Protected).unwrap();
            assert_eq!(
                trace.truth.iter().filter(|r| r.real).count(),
                16 * percentage as usize / 100
            );
            assert!(trace.emissions.iter().all(|e| e.frames.len() == 8));
            assert!(
                trace
                    .arrivals
                    .iter()
                    .all(|a| a.frame.as_bytes().len() == ENVELOPE_BYTES)
            );
            for arrival in &trace.arrivals {
                let emitted = &trace.emissions[arrival.epoch as usize];
                assert!(arrival.arrived_ns <= emitted.emitted_ns);
                assert_eq!(
                    arrival.frame.as_bytes(),
                    emitted.frames[arrival.slot].as_bytes()
                );
            }
        }
    }
}
