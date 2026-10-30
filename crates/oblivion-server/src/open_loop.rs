//! Offered-load experiment with an independent producer and explicit admission
//! leakage. This command does not provide constant-rate cover on overload.
use crate::{Result, pipeline};
use ed25519_dalek::SigningKey;
use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, PAYLOAD_BYTES};
use oblivion_server::invocation::sign_request;
use rand::{RngCore, rngs::OsRng};
use std::{
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::Path,
    sync::mpsc::{self, TrySendError},
    time::{Duration, Instant},
};

struct Offer {
    id: usize,
    at: Instant,
}
fn ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}
fn row(file: &mut impl Write, value: serde_json::Value) -> std::io::Result<()> {
    serde_json::to_writer(&mut *file, &value)?;
    writeln!(file)
}

/// Sum observed process CPU ticks and resident memory for the driver, executor
/// and current PIR children. Linux procfs accounting, not a billing estimate.
fn resources(executor: u32) -> Option<(u64, u64)> {
    let children = fs::read_to_string(format!("/proc/{executor}/task/{executor}/children")).ok()?;
    let mut pids = vec![std::process::id(), executor];
    pids.extend(
        children
            .split_whitespace()
            .filter_map(|pid| pid.parse::<u32>().ok()),
    );
    let mut ticks = 0;
    let mut rss = 0;
    for pid in pids {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields: Vec<_> = stat.rsplit_once(')')?.1.split_whitespace().collect();
        ticks += fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
        let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        rss += status.lines().find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })?;
    }
    Some((ticks, rss))
}
fn percentile(values: &mut [u64], percentile: usize) -> u64 {
    values.sort_unstable();
    values[(values.len() * percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(values.len() - 1)]
}

pub fn run(output: &Path, interval_ms: u64, count: usize, capacity: usize) -> Result<()> {
    if !(1..=1_000).contains(&interval_ms)
        || !(1..=100_000).contains(&count)
        || !(1..=1024).contains(&capacity)
    {
        return Err("interval 1..1000 ms, count 1..100000, queue capacity 1..1024 required".into());
    }
    fs::create_dir(output)?;
    pipeline::write_metadata(output, 100, 1, false)?;
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("metadata.json"))?)?;
    metadata["configuration"] = serde_json::json!({"mode":"open-loop","offered_interval_ms":interval_ms,"offered_count":count,"queue_capacity":capacity,"participants":1,"class_ms":100,"slo_ms":250});
    metadata["workload"] = serde_json::json!(
        "Independent monotonic producer, constant stateful input; OS-random crypto; bounded drop-tail admission; accepted work uses sequential authenticated epochs"
    );
    fs::write(
        output.join("metadata.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    let mut executor = pipeline::spawn(
        "executor-worker",
        &[output.to_str().ok_or("non-UTF8 path")?, "1"],
    )?;
    let mut input = executor.0.stdin.take().ok_or("missing stdin")?;
    let mut endpoint = Endpoint::provision_over_pipe(0, &mut input)?;
    let mut seed = zeroize::Zeroizing::new([0; 32]);
    OsRng.try_fill_bytes(&mut *seed)?;
    let invocation_key = SigningKey::from_bytes(&seed);
    let mut responses = executor.0.stdout.take().ok_or("missing stdout")?;
    let (response_tx, response_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut ready = [0; 1];
        if responses.read_exact(&mut ready).is_err() || response_tx.send(ready.to_vec()).is_err() {
            return;
        }
        loop {
            let mut bytes = vec![0; ENVELOPE_BYTES];
            if responses.read_exact(&mut bytes).is_err() || response_tx.send(bytes).is_err() {
                return;
            }
        }
    });
    if response_rx.recv_timeout(Duration::from_secs(10))? != [1] {
        return Err("executor startup failed".into());
    }
    let baseline = resources(executor.0.id());
    let mut last = baseline;
    let mut peak_rss = baseline.map(|(_, rss)| rss);
    let clock_ticks = std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .filter(|value| value.status.success())
        .and_then(|value| {
            String::from_utf8(value.stdout)
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()
        });
    let mut offers = BufWriter::new(File::create(output.join("offered-arrivals.jsonl"))?);
    let mut latency = BufWriter::new(File::create(output.join("open-loop-latencies.jsonl"))?);
    let (send, receive) = mpsc::sync_channel::<Offer>(capacity);
    let start = Instant::now();
    let producer = std::thread::spawn(move || -> std::io::Result<(usize, usize)> {
        let mut admitted = 0;
        let mut dropped = 0;
        for id in 0..count {
            let scheduled = start + Duration::from_millis(interval_ms * id as u64);
            if let Some(wait) = scheduled.checked_duration_since(Instant::now()) {
                std::thread::sleep(wait);
            }
            let at = Instant::now();
            let accepted = match send.try_send(Offer { id, at }) {
                Ok(()) => {
                    admitted += 1;
                    true
                }
                Err(TrySendError::Full(_)) => {
                    dropped += 1;
                    false
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(std::io::Error::other("executor consumer disconnected"));
                }
            };
            row(
                &mut offers,
                serde_json::json!({"offered_id":id,"scheduled_ns":ns(scheduled.duration_since(start)),"offered_ns":ns(at.duration_since(start)),"arrival_late_ns":ns(at.saturating_duration_since(scheduled)),"admitted":accepted,"queue_capacity":capacity}),
            )?;
        }
        offers.flush()?;
        Ok((admitted, dropped))
    });
    let mut completed = 0u64;
    let mut successes = 0u64;
    let mut errors = 0u64;
    let mut slo_misses = 0u64;
    let mut slo_failures = 0u64;
    let mut max_queue = 0;
    let mut latencies = Vec::new();
    for offer in receive {
        let dequeued = Instant::now();
        let queue = ns(dequeued.duration_since(offer.at));
        max_queue = max_queue.max(queue);
        let mut payload = [0; PAYLOAD_BYTES];
        payload[0] = 1;
        payload[1..5].copy_from_slice(&4u32.to_be_bytes());
        let mut invocation_id = [0; 16];
        OsRng.try_fill_bytes(&mut invocation_id)?;
        sign_request(&mut payload, 0, invocation_id, &invocation_key);
        let sent = Instant::now();
        input.write_all(endpoint.send(completed, &payload)?.as_bytes())?;
        input.flush()?;
        let bytes = response_rx.recv_timeout(Duration::from_secs(5))?;
        let result = endpoint.receive(&Envelope::from_bytes(&bytes)?)?;
        let finished = Instant::now();
        let ok = result[0] == 0;
        if ok {
            successes += 1;
            if u32::from_le_bytes(result[1..5].try_into()?) != successes as u32 {
                return Err("open-loop state oracle mismatch".into());
            }
        } else {
            errors += 1;
            if result[1..].iter().any(|&byte| byte != 0) {
                return Err("error payload disclosed result".into());
            }
        }
        let elapsed = ns(finished.duration_since(offer.at));
        let missed = elapsed > 250_000_000;
        slo_misses += u64::from(missed);
        slo_failures += u64::from(missed || !ok);
        latencies.push(elapsed);
        if let Some(current) = resources(executor.0.id()) {
            peak_rss = Some(peak_rss.unwrap_or(0).max(current.1));
            last = Some(current);
        }
        row(
            &mut latency,
            serde_json::json!({"offered_id":offer.id,"accepted_epoch":completed,"offered_ns":ns(offer.at.duration_since(start)),"dequeued_ns":ns(dequeued.duration_since(start)),"completed_ns":ns(finished.duration_since(start)),"queue_wait_ns":queue,"service_ns":ns(finished.duration_since(sent)),"end_to_end_ns":elapsed,"success":ok,"slo_missed":missed,"request_bytes":ENVELOPE_BYTES,"response_bytes":ENVELOPE_BYTES}),
        )?;
        completed += 1;
    }
    let (admitted, dropped) = producer.join().map_err(|_| "arrival producer panicked")??;
    let elapsed = start.elapsed();
    latency.flush()?;
    drop(input);
    executor.finish()?;
    let cpu_ticks = baseline
        .zip(last)
        .map(|(before, after)| after.0.saturating_sub(before.0));
    let cpu_seconds = cpu_ticks
        .zip(clock_ticks)
        .map(|(ticks, hz)| ticks as f64 / hz as f64);
    let summary = serde_json::json!({"mode":"open-loop","offered":count,"admitted":admitted,"completed":completed,"dropped":dropped,"successes":successes,"errors":errors,"offered_interval_ms":interval_ms,"queue_capacity":capacity,"slo_ms":250,"slo_misses_admitted":slo_misses,"slo_failures_including_drops":slo_failures+dropped as u64,"wall_ns":ns(elapsed),"max_queue_wait_ns":max_queue,"p50_end_to_end_ns":percentile(&mut latencies,50),"p95_end_to_end_ns":percentile(&mut latencies,95),"p99_end_to_end_ns":percentile(&mut latencies,99),"cpu_ticks_observed":cpu_ticks,"clock_ticks_per_second":clock_ticks,"cpu_seconds_observed":cpu_seconds,"peak_sampled_aggregate_rss_kib":peak_rss,"resource_scope":"Linux procfs snapshots of driver+executor+two PIR children; excludes startup/teardown CPU; RSS sampled at startup and completion, may miss peaks","logical_oram_operations_per_admitted_request":16,"admission_policy":"bounded drop-tail, producer does not wait for responses","privacy_limit":"offered timing, queue admission, drops, accepted invocation count and overload are visible; no constant cover or availability claim"});
    fs::write(
        output.join("open-loop-summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    println!(
        "Open-loop: {count} offered, {admitted} admitted, {dropped} dropped, {successes} success, {errors} errors: {}",
        output.display()
    );
    Ok(())
}
