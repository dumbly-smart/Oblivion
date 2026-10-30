use crate::{Result, system};
use oblivion_batcher::{ENVELOPE_BYTES, Endpoint, Envelope, EpochBatcher, PAYLOAD_BYTES};
use oblivion_exec::Class;
use serde::Serialize;
use serde_json::json;
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL: Duration = Duration::from_millis(10);

/// Reads a non-empty, length-prefixed frame.
///
/// The four-byte big-endian length is checked before allocating the body. A
/// clean EOF is returned only when no byte of a new prefix was received.
#[cfg(test)]
pub(super) fn read_frame(reader: &mut impl Read, maximum: usize) -> io::Result<Option<Vec<u8>>> {
    let Some(length) = read_frame_length(reader)? else {
        return Ok(None);
    };
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length is zero or exceeds the configured maximum",
        ));
    }

    read_frame_body(reader, length).map(Some)
}

/// Reads one frame whose body must have exactly `expected` bytes.
///
/// The length is checked immediately after the prefix, before allocating or
/// reading the body. This is used at protocol boundaries with mode-specific
/// fixed shapes.
pub(super) fn read_fixed_frame(
    reader: &mut impl Read,
    expected: usize,
) -> io::Result<Option<Vec<u8>>> {
    if expected == 0 || u32::try_from(expected).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected frame length is zero or cannot be represented",
        ));
    }

    let Some(length) = read_frame_length(reader)? else {
        return Ok(None);
    };
    if length != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length does not match the fixed protocol shape",
        ));
    }

    read_frame_body(reader, length).map(Some)
}

/// Reads a fixed-shape TCP frame under one absolute deadline.
///
/// The remaining duration is applied before every socket read, so a peer
/// cannot renew the total budget by slowly sending one byte at a time.
pub(super) fn read_fixed_frame_with_timeout(
    stream: &mut TcpStream,
    expected: usize,
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame deadline overflow"))?;
    let mut reader = FrameDeadlineReader { stream, deadline };
    read_fixed_frame(&mut reader, expected)
}

struct FrameDeadlineReader<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl Read for FrameDeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute frame read deadline elapsed",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        match self.stream.read(buffer) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "absolute frame read deadline elapsed",
                ))
            }
            result => result,
        }
    }
}

fn read_frame_length(reader: &mut impl Read) -> io::Result<Option<usize>> {
    let mut prefix = [0_u8; 4];
    let first = loop {
        match reader.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(count) => break count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    };
    debug_assert_eq!(first, 1);
    reader.read_exact(&mut prefix[1..])?;

    Ok(Some(u32::from_be_bytes(prefix) as usize))
}

fn read_frame_body(reader: &mut impl Read, length: usize) -> io::Result<Vec<u8>> {
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(body)
}

/// Writes one non-empty frame with a four-byte big-endian length prefix.
pub(super) fn write_frame(
    writer: &mut impl Write,
    body: &[u8],
    maximum: usize,
) -> io::Result<usize> {
    if body.is_empty() || body.len() > maximum || u32::try_from(body.len()).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame length is zero or exceeds the configured maximum",
        ));
    }

    let frame_size = 4_usize
        .checked_add(body.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame size overflow"))?;
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(body)?;
    Ok(frame_size)
}

fn write_json_line(writer: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writeln!(writer)?;
    Ok(())
}

fn monotonic_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

pub(super) fn worker(output: &Path, mode_name: &str, maximum_frame: usize) -> Result<()> {
    let mode = system::MODES
        .iter()
        .find(|mode| mode.name == mode_name)
        .copied()
        .ok_or("unknown system mode")?;
    let fixed_frame = if mode.encrypted {
        ENVELOPE_BYTES
    } else {
        PAYLOAD_BYTES
    };
    if maximum_frame != fixed_frame {
        return Err("worker frame bound does not match the fixed mode shape".into());
    }

    fs::create_dir(output)?;
    let mut socket_observer = BufWriter::new(File::create(output.join("socket-observer.jsonl"))?);
    let mut public_observer = BufWriter::new(File::create(output.join("observer.jsonl"))?);
    let mut storage_observer = BufWriter::new(File::create(output.join("storage-observer.jsonl"))?);
    let mut private = BufWriter::new(File::create(output.join("private.jsonl"))?);
    let mut runtime = system::WorkerRuntime::new(mode)?;

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "READY {address}")?;
    stdout.flush()?;

    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut endpoint =
        Endpoint::accept_bootstrap(0, &mut stdin).map_err(|error| error.to_string())?;
    drop(stdin);

    let accept_deadline = Instant::now() + SOCKET_TIMEOUT;
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= accept_deadline {
                    return Err("timed out waiting for invocation client".into());
                }
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    };
    stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;

    let service_started = Instant::now();
    let mut sequence = 0_u64;
    while let Some(body) = read_fixed_frame_with_timeout(&mut stream, fixed_frame, SOCKET_TIMEOUT)?
    {
        let request_observed_ns = monotonic_ns(service_started);
        let invocation_started = Instant::now();
        write_json_line(
            &mut socket_observer,
            &json!({"version":1,"observer":"invocation","direction":"request","sequence":sequence,"bytes":body.len()+4,"elapsed_ns":request_observed_ns,"frame":&body}),
        )?;
        let (epoch, decoded) = if mode.encrypted {
            let envelope = Envelope::from_bytes(&body).map_err(|error| error.to_string())?;
            let epoch = envelope.epoch();
            let payload = endpoint
                .receive(&envelope)
                .map_err(|error| error.to_string())?;
            (epoch, payload)
        } else {
            let mut payload = [0; PAYLOAD_BYTES];
            payload.copy_from_slice(&body);
            (sequence, payload)
        };

        let mut outcome = runtime.invoke(&decoded, epoch, invocation_started)?;
        let response = if mode.encrypted {
            endpoint
                .send(epoch, &outcome.payload)
                .map_err(|error| error.to_string())?
                .as_bytes()
                .to_vec()
        } else {
            outcome.payload[..outcome.plaintext_response_bytes].to_vec()
        };

        let mut driver_overrun_ns = 0;
        let mut publication_lateness_ns = 0;
        if mode.padding {
            let deadline = invocation_started + Duration::from_millis(Class::small().deadline_ms);
            driver_overrun_ns = Instant::now()
                .saturating_duration_since(deadline)
                .as_nanos()
                .min(u64::MAX as u128) as u64;
            if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                thread::sleep(remaining);
            }
            publication_lateness_ns = Instant::now()
                .saturating_duration_since(deadline)
                .as_nanos()
                .min(u64::MAX as u128) as u64;
            outcome.execution_ns = invocation_started
                .elapsed()
                .as_nanos()
                .min(u64::MAX as u128) as u64;
            outcome.deadline_missed |= driver_overrun_ns > 0;
        }

        let response_wire_bytes = write_frame(&mut stream, &response, maximum_frame)?;
        write_json_line(
            &mut socket_observer,
            &json!({"version":1,"observer":"invocation","direction":"response","sequence":sequence,"bytes":response_wire_bytes,"elapsed_ns":monotonic_ns(service_started),"frame":&response}),
        )?;

        let storage_bytes = outcome
            .storage_events
            .iter()
            .map(|event| event.bytes)
            .sum::<usize>();
        let last_bucket = outcome
            .storage_events
            .iter()
            .rev()
            .find(|event| event.direction == oblivion_store::StorageDirection::Read)
            .map_or(-1_i64, |event| event.bucket as i64);
        let first_storage_ns = outcome
            .storage_events
            .first()
            .map_or(0, |event| event.elapsed_ns);
        let last_storage_ns = outcome
            .storage_events
            .last()
            .map_or(0, |event| event.elapsed_ns);
        for event in &outcome.storage_events {
            write_json_line(
                &mut storage_observer,
                &json!({"version":1,"sequence":sequence,"elapsed_ns":event.elapsed_ns,"direction":event.direction,"bucket":event.bucket,"bytes":event.bytes}),
            )?;
        }
        write_json_line(
            &mut public_observer,
            &json!({"version":1,"sequence":sequence,"request_bytes":body.len(),"response_bytes":response.len(),"registry_bytes":outcome.registry_bytes,"registry_index":outcome.registry_index,"storage_events":outcome.storage_events.len(),"storage_bytes":storage_bytes,"last_bucket":last_bucket,"storage_span_ns":last_storage_ns.saturating_sub(first_storage_ns),"instance_count":1}),
        )?;
        write_json_line(
            &mut private,
            &json!({"sequence":sequence,"registry_ns":outcome.registry_ns,"execution_ns":outcome.execution_ns,"work_ns":outcome.work_ns,"deadline_missed":outcome.deadline_missed,"driver_work_overrun_ns":driver_overrun_ns,"publication_lateness_ns":publication_lateness_ns}),
        )?;
        sequence = sequence.checked_add(1).ok_or("request sequence overflow")?;
    }

    socket_observer.flush()?;
    public_observer.flush()?;
    storage_observer.flush()?;
    write_json_line(&mut private, &runtime.storage_stats()?)?;
    private.flush()?;
    Ok(())
}

struct ManagedChild(Child);

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl ManagedChild {
    fn wait_success(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.0.try_wait()? {
                if status.success() {
                    return Ok(());
                }
                return Err(format!("TCP worker exited with {status}").into());
            }
            if Instant::now() >= deadline {
                return Err("TCP worker did not exit after the client closed".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn start_worker(output: &Path, mode: system::Mode) -> Result<(ManagedChild, Endpoint, TcpStream)> {
    let maximum_frame = if mode.encrypted {
        ENVELOPE_BYTES
    } else {
        PAYLOAD_BYTES
    };
    let executable = std::env::current_exe()?;
    let child = Command::new(executable)
        .arg("system-tcp-worker")
        .arg(output)
        .arg(mode.name)
        .arg(maximum_frame.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut child = ManagedChild(child);

    let stdout = child.0.stdout.take().ok_or("worker stdout was not piped")?;
    let (ready_sender, ready_receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| line);
        let _ = ready_sender.send(result);
    });
    let ready = ready_receiver
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "timed out waiting for TCP worker readiness")??;
    let address: SocketAddr = ready
        .strip_prefix("READY ")
        .ok_or("invalid TCP worker readiness message")?
        .trim()
        .parse()?;
    if !address.ip().is_loopback() {
        return Err("TCP worker advertised a non-loopback address".into());
    }

    let mut pipe = child.0.stdin.take().ok_or("worker stdin was not piped")?;
    let endpoint =
        Endpoint::provision_over_pipe(0, &mut pipe).map_err(|error| error.to_string())?;
    drop(pipe);

    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    Ok((child, endpoint, stream))
}

pub(super) fn run(config_path: &Path, out: &Path) -> Result<()> {
    run_selected(config_path, out, None)
}

pub(super) fn run_with_modes(config_path: &Path, out: &Path, mode_list: &str) -> Result<()> {
    let selected = parse_mode_list(mode_list)?;
    run_selected(config_path, out, Some(&selected))
}

fn parse_mode_list(mode_list: &str) -> Result<Vec<system::Mode>> {
    let mut selected = [false; 7];
    for name in mode_list.split(',') {
        let index = system::MODES
            .iter()
            .position(|mode| mode.name == name)
            .ok_or("mode list contains an unknown or empty mode")?;
        if std::mem::replace(&mut selected[index], true) {
            return Err("mode list contains a duplicate mode".into());
        }
    }

    Ok(system::MODES
        .iter()
        .enumerate()
        .filter_map(|(index, mode)| selected[index].then_some(*mode))
        .collect())
}

fn run_selected(
    config_path: &Path,
    out: &Path,
    selected_modes: Option<&[system::Mode]>,
) -> Result<()> {
    let canonical_modes = selected_modes.unwrap_or(&system::MODES);
    let config = system::load_experiment(config_path)?;
    fs::create_dir(out)?;
    fs::write(out.join("config.json"), serde_json::to_vec_pretty(&config)?)?;
    fs::write(
        out.join("mode-selection.json"),
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "modes": canonical_modes.iter().map(|mode| mode.name).collect::<Vec<_>>(),
        }))?,
    )?;
    let mut metrics = BufWriter::new(File::create(out.join("metrics.jsonl"))?);
    for trial in 0..config.trials {
        for session in 0..config.sessions {
            let (labels, modes) = system::schedule(&config, trial, session)?;
            for mode in modes.into_iter().filter(|mode| {
                canonical_modes
                    .iter()
                    .any(|selected| selected.name == mode.name)
            }) {
                run_session(out, &mut metrics, &config, trial, session, mode, &labels)?;
            }
        }
        metrics.flush()?;
        eprintln!(
            "TCP system experiment completed trial {}/{}",
            trial + 1,
            config.trials
        );
    }
    Ok(())
}

fn run_session(
    out: &Path,
    metrics: &mut impl Write,
    config: &system::Experiment,
    trial: usize,
    session: usize,
    mode: system::Mode,
    labels: &[usize],
) -> Result<()> {
    let path = out.join(mode.name).join(format!("{trial}-{session}"));
    fs::create_dir_all(path.parent().ok_or("session path has no parent")?)?;
    let worker_start = Instant::now();
    let (mut child, mut endpoint, mut stream) = start_worker(&path, mode)?;
    let cold_start_ns = monotonic_ns(worker_start);
    let mut truth = BufWriter::new(File::create(path.join("ground-truth.jsonl"))?);
    let session_start = Instant::now();
    let period = Duration::from_millis(config.epoch_ms);
    let mut batcher = EpochBatcher::new(1, period, session_start)?;
    let mut state_counter = 0_u32;
    let maximum_frame = if mode.encrypted {
        ENVELOPE_BYTES
    } else {
        PAYLOAD_BYTES
    };

    for (step, &label) in labels.iter().enumerate() {
        let opportunity_started = Instant::now();
        let epoch = step as u64;
        let real = label != 0;
        let id = if label == 1 { 0_u32 } else { 4_u32 };
        let mut payload = [0; PAYLOAD_BYTES];
        payload[0] = u8::from(real);
        payload[1..5].copy_from_slice(&id.to_be_bytes());
        payload[5] = 10;

        let active = mode.batching || real;
        let mut request_body_bytes = 0;
        let mut request_wire_bytes = 0;
        let mut response_body_bytes = 0;
        let mut response_wire_bytes = 0;
        let mut latency_ns = 0;
        let mut late_by_ns = 0;
        if active {
            let mut request = if mode.encrypted {
                endpoint
                    .send(epoch, &payload)
                    .map_err(|error| error.to_string())?
                    .as_bytes()
                    .to_vec()
            } else {
                payload.to_vec()
            };
            let submitted;
            if mode.batching {
                let due = session_start + period * (step as u32 + 1);
                if let Some(remaining) = due.checked_duration_since(Instant::now()) {
                    thread::sleep(remaining);
                }
                submitted = Instant::now();
                batcher.submit(Envelope::from_bytes(&request)?)?;
                let batch = batcher.emit(Instant::now())?;
                late_by_ns = batch.late_by_ns;
                request = batch.envelopes[0].as_bytes().to_vec();
            } else {
                submitted = Instant::now();
            }
            request_body_bytes = request.len();
            request_wire_bytes = write_frame(&mut stream, &request, maximum_frame)?;
            let expected_response_bytes = if mode.encrypted {
                ENVELOPE_BYTES
            } else if real && id == 0 {
                65
            } else {
                5
            };
            let response = read_fixed_frame_with_timeout(
                &mut stream,
                expected_response_bytes,
                SOCKET_TIMEOUT,
            )?
            .ok_or("TCP worker closed before returning an invocation response")?;
            response_body_bytes = response.len();
            response_wire_bytes = response.len() + 4;
            latency_ns = submitted.elapsed().as_nanos().min(u64::MAX as u128) as u64;

            let decoded = if mode.encrypted {
                let envelope =
                    Envelope::from_bytes(&response).map_err(|error| error.to_string())?;
                endpoint
                    .receive(&envelope)
                    .map_err(|error| error.to_string())?
            } else {
                if response.len() > PAYLOAD_BYTES {
                    return Err("plaintext response exceeded the fixed payload width".into());
                }
                let mut payload = [0; PAYLOAD_BYTES];
                payload[..response.len()].copy_from_slice(&response);
                payload
            };
            validate_response(
                &decoded,
                response.len(),
                mode.encrypted,
                real,
                id,
                &payload,
                &mut state_counter,
            )?;
        }

        write_json_line(&mut truth, &json!({"step":step,"label":label}))?;
        write_json_line(
            metrics,
            &json!({"transport":"loopback_tcp","mode":mode.name,"trial":trial,"session":session,"step":step,"oracle_ok":true,"active":active,"latency_ns":latency_ns,"request_bytes":request_body_bytes,"request_wire_bytes":request_wire_bytes,"response_bytes":response_body_bytes,"response_wire_bytes":response_wire_bytes,"cold_start_ns":if step==0{cold_start_ns}else{0},"late_by_ns":late_by_ns,"opportunity_wall_ns":opportunity_started.elapsed().as_nanos().min(u64::MAX as u128) as u64}),
        )?;
    }

    truth.flush()?;
    drop(stream);
    child.wait_success()?;
    Ok(())
}

fn validate_response(
    response: &[u8; PAYLOAD_BYTES],
    response_frame_bytes: usize,
    encrypted: bool,
    real: bool,
    id: u32,
    request: &[u8; PAYLOAD_BYTES],
    state_counter: &mut u32,
) -> Result<()> {
    if response[0] != 0 {
        return Err("response presence marker was not normalized".into());
    }
    if !real {
        if response.iter().any(|byte| *byte != 0) {
            return Err("dummy invocation response was not masked".into());
        }
        if !encrypted && response_frame_bytes != 5 {
            return Err("plaintext dummy response did not use its fixed shape".into());
        }
        return Ok(());
    }

    let (expected, expected_frame_bytes): (Vec<u8>, usize) = if id == 0 {
        (request[5..69].to_vec(), 65)
    } else {
        *state_counter = state_counter
            .checked_add(1)
            .ok_or("state oracle overflow")?;
        (state_counter.to_le_bytes().to_vec(), 5)
    };
    if response[1..1 + expected.len()] != expected {
        return Err("WASM response differed from the client oracle".into());
    }
    if response[1 + expected.len()..].iter().any(|byte| *byte != 0) {
        return Err("response padding bytes were not zero".into());
    }
    if !encrypted && response_frame_bytes != expected_frame_bytes {
        return Err("plaintext response shape differed from the baseline contract".into());
    }
    if encrypted && response_frame_bytes != ENVELOPE_BYTES {
        return Err("encrypted response did not have the fixed envelope size".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Cursor, Read, Write},
        net::{TcpListener, TcpStream},
        thread,
        time::{Duration, Instant},
    };

    struct ShortReader {
        inner: Cursor<Vec<u8>>,
        max_chunk: usize,
    }

    impl Read for ShortReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = buffer.len().min(self.max_chunk);
            self.inner.read(&mut buffer[..count])
        }
    }

    struct ShortWriter {
        bytes: Vec<u8>,
        max_chunk: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(self.max_chunk);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writes_big_endian_length_and_complete_body_after_short_writes() {
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            max_chunk: 2,
        };

        let written = super::write_frame(&mut writer, &[0x10, 0x20, 0x30], 8).unwrap();

        assert_eq!(written, 7);
        assert_eq!(writer.bytes, [0, 0, 0, 3, 0x10, 0x20, 0x30]);
    }

    #[test]
    fn reads_complete_frame_after_short_reads_then_reports_clean_eof() {
        let mut reader = ShortReader {
            inner: Cursor::new(vec![0, 0, 0, 2, 0xaa, 0xbb]),
            max_chunk: 1,
        };

        assert_eq!(
            super::read_frame(&mut reader, 8).unwrap(),
            Some(vec![0xaa, 0xbb])
        );
        assert_eq!(super::read_frame(&mut reader, 8).unwrap(), None);
    }

    #[test]
    fn clean_eof_before_a_new_prefix_is_not_a_truncated_frame() {
        let mut reader = Cursor::new(Vec::<u8>::new());

        assert_eq!(super::read_frame(&mut reader, 8).unwrap(), None);
    }

    #[test]
    fn rejects_truncated_length_prefix_and_truncated_body() {
        let mut short_prefix = Cursor::new(vec![0, 0]);
        let mut short_body = Cursor::new(vec![0, 0, 0, 2, 0xaa]);

        assert_eq!(
            super::read_frame(&mut short_prefix, 8).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            super::read_frame(&mut short_body, 8).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn rejects_zero_length_and_oversized_frames_before_reading_a_body() {
        let mut zero = Cursor::new(vec![0, 0, 0, 0]);
        let mut oversized = Cursor::new(vec![0, 0, 0, 9]);

        assert_eq!(
            super::read_frame(&mut zero, 8).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            super::read_frame(&mut oversized, 8).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(oversized.position(), 4);
    }

    #[test]
    fn trickled_frame_cannot_extend_its_absolute_read_deadline() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in [0, 0, 0, 2, 0xaa, 0xbb] {
                thread::sleep(Duration::from_millis(20));
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
            }
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let started = Instant::now();
        let error = super::read_fixed_frame_with_timeout(&mut stream, 2, Duration::from_millis(50))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(250));
        writer.join().unwrap();
    }

    #[test]
    fn refuses_to_write_empty_or_over_limit_bodies() {
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            max_chunk: 8,
        };

        assert_eq!(
            super::write_frame(&mut writer, &[], 8).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            super::write_frame(&mut writer, &[0; 9], 8)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(writer.bytes.is_empty());
    }
}
