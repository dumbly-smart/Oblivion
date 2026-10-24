//! Fixed-size bucket RPC for isolated service-side timing measurements.
use oblivion_store::{Backend, Error, StorageDirection};
use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Instant;

const HEADER_BYTES: usize = 9;

#[derive(Clone, Debug)]
pub struct ServiceEvent {
    pub direction: StorageDirection,
    pub bucket: usize,
    pub bytes: usize,
    pub service_ns: u64,
}

enum Input {
    Process(ChildStdin),
    #[cfg(test)]
    Test(std::os::unix::net::UnixStream),
}
impl Write for Input {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Process(stream) => stream.write(bytes),
            #[cfg(test)]
            Self::Test(stream) => stream.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Process(stream) => stream.flush(),
            #[cfg(test)]
            Self::Test(stream) => stream.flush(),
        }
    }
}

enum Output {
    Process(ChildStdout),
    #[cfg(test)]
    Test(std::os::unix::net::UnixStream),
}
impl Read for Output {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Process(stream) => stream.read(bytes),
            #[cfg(test)]
            Self::Test(stream) => stream.read(bytes),
        }
    }
}

pub struct IsolatedBackend {
    input: Option<Input>,
    output: Output,
    child: Option<Child>,
    bucket_count: usize,
    bucket_bytes: usize,
    recording: bool,
    events: Vec<ServiceEvent>,
    worker_pid: u32,
}

impl IsolatedBackend {
    pub fn spawn(
        executable: &std::path::Path,
        bucket_count: usize,
        bucket_bytes: usize,
    ) -> io::Result<Self> {
        if bucket_count == 0 || bucket_bytes == 0 || bucket_bytes > 1 << 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid isolated bucket geometry",
            ));
        }
        let mut child = Command::new(executable)
            .args([
                "--bucket-server",
                &bucket_count.to_string(),
                &bucket_bytes.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let worker_pid = child.id();
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("bucket worker stdin unavailable"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("bucket worker stdout unavailable"))?;
        Ok(Self {
            input: Some(Input::Process(input)),
            output: Output::Process(output),
            child: Some(child),
            bucket_count,
            bucket_bytes,
            recording: false,
            events: Vec::new(),
            worker_pid,
        })
    }

    #[cfg(test)]
    fn from_stream(
        stream: std::os::unix::net::UnixStream,
        bucket_count: usize,
        bucket_bytes: usize,
    ) -> Self {
        let output = Output::Test(stream.try_clone().unwrap());
        Self {
            input: Some(Input::Test(stream)),
            output,
            child: None,
            bucket_count,
            bucket_bytes,
            recording: false,
            events: Vec::new(),
            worker_pid: u32::MAX,
        }
    }

    pub fn set_recording(&mut self, enabled: bool) {
        self.recording = enabled;
        if !enabled {
            self.events.clear();
        }
    }

    pub fn take_events(&mut self) -> Vec<ServiceEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn worker_pid(&self) -> u32 {
        self.worker_pid
    }
    pub fn request_bytes(&self) -> usize {
        HEADER_BYTES + self.bucket_bytes
    }
    pub fn response_bytes(&self) -> usize {
        HEADER_BYTES + self.bucket_bytes
    }

    fn transact(
        &mut self,
        direction: StorageDirection,
        bucket: usize,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if bucket >= self.bucket_count || payload.len() != self.bucket_bytes {
            return Err(Error::Backend("isolated request bounds".into()));
        }
        let request_bytes = HEADER_BYTES + self.bucket_bytes;
        let response_bytes = request_bytes;
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| Error::Backend("isolated worker is closed".into()))?;
        let mut request = vec![0; request_bytes];
        request[0] = match direction {
            StorageDirection::Read => 0,
            StorageDirection::Write => 1,
        };
        request[1..9].copy_from_slice(&(bucket as u64).to_le_bytes());
        request[9..].copy_from_slice(payload);
        input.write_all(&request).map_err(io_error)?;
        input.flush().map_err(io_error)?;

        let mut response = vec![0; response_bytes];
        self.output.read_exact(&mut response).map_err(io_error)?;
        if response[0] != 0 {
            return Err(Error::Backend(
                "isolated bucket service rejected request".into(),
            ));
        }
        let service_ns =
            u64::from_le_bytes(response[1..9].try_into().map_err(|_| Error::Integrity)?);
        if self.recording {
            self.events.push(ServiceEvent {
                direction,
                bucket,
                bytes: self.bucket_bytes,
                service_ns,
            });
        }
        if direction == StorageDirection::Write && response[9..].iter().any(|&byte| byte != 0) {
            return Err(Error::Integrity);
        }
        Ok(response[9..].to_vec())
    }
}

impl Backend for IsolatedBackend {
    fn read_bucket(&mut self, bucket: usize) -> Result<Vec<u8>, Error> {
        self.transact(StorageDirection::Read, bucket, &vec![0; self.bucket_bytes])
    }

    fn write_bucket(&mut self, bucket: usize, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() != self.bucket_bytes {
            return Err(Error::Backend("isolated bucket shape".into()));
        }
        self.transact(StorageDirection::Write, bucket, bytes)
            .map(|_| ())
    }
}

impl Drop for IsolatedBackend {
    fn drop(&mut self) {
        self.input.take(); // EOF asks the bounded worker to stop cleanly.
        if let Some(mut child) = self.child.take()
            && child.wait().is_err()
        {
            let _ = child.kill();
        }
    }
}

fn io_error(error: io::Error) -> Error {
    Error::Backend(error.to_string())
}

/// Child service timing covers only the in-memory bucket handler, excluding
/// controller path processing, IPC wait, response serialization and file output.
pub fn serve(
    mut input: impl Read,
    mut output: impl Write,
    bucket_count: usize,
    bucket_bytes: usize,
) -> io::Result<()> {
    if bucket_count == 0 || bucket_bytes == 0 || bucket_bytes > 1 << 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid isolated bucket geometry",
        ));
    }
    let mut buckets = vec![vec![0; bucket_bytes]; bucket_count];
    let mut request = vec![0; HEADER_BYTES + bucket_bytes];
    let mut response = vec![0; HEADER_BYTES + bucket_bytes];
    loop {
        match input.read(&mut request[..1]) {
            Ok(0) => return Ok(()),
            Ok(_) => input.read_exact(&mut request[1..])?,
            Err(error) => return Err(error),
        }
        let operation = request[0];
        let bucket_u64 = u64::from_le_bytes(request[1..9].try_into().expect("fixed header"));
        let started = Instant::now();
        response.fill(0);
        let valid = bucket_u64 < bucket_count as u64 && matches!(operation, 0 | 1);
        if valid {
            let bucket = bucket_u64 as usize;
            if operation == 0 {
                response[HEADER_BYTES..].copy_from_slice(&buckets[bucket]);
            } else {
                buckets[bucket].copy_from_slice(&request[HEADER_BYTES..]);
            }
        } else {
            response[0] = 1;
        }
        let service_ns = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        response[1..9].copy_from_slice(&service_ns.to_le_bytes());
        output.write_all(&response)?;
        output.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn requests_and_replies_have_equal_fixed_shape_and_actual_server_timing() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let mut server_out = server.try_clone().unwrap();
        let worker =
            std::thread::spawn(move || serve(&mut server, &mut server_out, 4, 32).unwrap());
        let mut backend = IsolatedBackend::from_stream(client, 4, 32);
        backend.set_recording(true);
        let expected: Vec<u8> = (0..32).collect();
        backend.write_bucket(2, &expected).unwrap();
        assert_eq!(backend.read_bucket(2).unwrap(), expected);
        let events = backend.take_events();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.service_ns > 0));
        assert_eq!(backend.request_bytes(), backend.response_bytes());
        assert_eq!(backend.request_bytes(), 41);
        assert_eq!(events[0].direction, StorageDirection::Write);
        assert_eq!(events[0].bucket, 2);
        assert_eq!(events[1].direction, StorageDirection::Read);
        drop(backend);
        worker.join().unwrap();
    }

    #[test]
    fn invalid_bucket_or_shape_is_rejected_without_service_request() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let mut server_out = server.try_clone().unwrap();
        let worker = std::thread::spawn(move || serve(&mut server, &mut server_out, 2, 8).unwrap());
        let mut backend = IsolatedBackend::from_stream(client, 2, 8);
        backend.set_recording(true);
        assert!(backend.read_bucket(2).is_err());
        assert!(backend.write_bucket(0, &[1; 7]).is_err());
        assert!(backend.take_events().is_empty());
        drop(backend);
        worker.join().unwrap();
    }

    #[test]
    fn truncated_frame_is_an_error_but_clean_eof_is_shutdown() {
        let mut replies = Vec::new();
        assert!(serve(&mut &b"\0"[..], &mut replies, 2, 8).is_err());
        assert!(serve(&mut &b""[..], &mut replies, 2, 8).is_ok());
    }
}
