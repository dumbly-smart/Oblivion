#[cfg(unix)]
mod unix {
    use std::{
        collections::{BTreeMap, BTreeSet},
        env, fs,
        io::{self, Read, Write},
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    use oblivion_anchor::UnixAnchorClient;
    use oblivion_sse::{Limits, PersistentClient, Server};
    use rand::{
        Rng, RngCore, SeedableRng,
        rngs::{OsRng, StdRng},
        seq::SliceRandom,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use zeroize::Zeroizing;

    const CHECKPOINT_INTERVAL: u64 = 256;

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        schema_version: u8,
        index_sizes: Vec<usize>,
        trials: usize,
        recovery_repetitions: usize,
        schedule_seed: u64,
    }

    struct PrivateWork(PathBuf);

    impl PrivateWork {
        fn create(output: &Path) -> io::Result<Self> {
            let path = output.join(".work");
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for PrivateWork {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args = env::args().skip(1).collect::<Vec<_>>();
        match args.first().map(String::as_str) {
            Some("run") => run_benchmark(&args[1..]),
            Some("recover") => recover_child(&args[1..]),
            _ => Err(invalid(
                "usage: sse-journal-benchmark run SOCKET CONFIG.json NEW_OUTPUT_DIR | recover SOCKET JOURNAL_DIR SLOT EXPECTED_GENERATION",
            )),
        }
    }

    fn run_benchmark(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        if args.len() != 3 {
            return Err(invalid(
                "usage: sse-journal-benchmark run SOCKET CONFIG.json NEW_OUTPUT_DIR",
            ));
        }
        let socket = PathBuf::from(&args[0]);
        let config_path = PathBuf::from(&args[1]);
        let output = PathBuf::from(&args[2]);
        let config_bytes = fs::read(&config_path)?;
        let config: Config = serde_json::from_slice(&config_bytes)?;
        validate_config(&config)?;

        fs::create_dir(&output).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("output directory must be new and empty: {error}"),
            )
        })?;
        fs::write(output.join("config.json"), &config_bytes)?;
        let private_work = PrivateWork::create(&output)?;

        let mut run_nonce = [0u8; 8];
        OsRng.try_fill_bytes(&mut run_nonce)?;
        let run_prefix = format!("journal-bench-{}", hex(&run_nonce));
        let current_exe = env::current_exe()?;
        let mut samples = Vec::new();
        let mut schedule_rng = StdRng::seed_from_u64(config.schedule_seed);

        for trial in 0..config.trials {
            let mut order = config.index_sizes.clone();
            order.shuffle(&mut schedule_rng);
            for index_size in order {
                let sample = run_sample(
                    &socket,
                    &current_exe,
                    private_work.path(),
                    &run_prefix,
                    trial,
                    index_size,
                    config.recovery_repetitions,
                )?;
                samples.push(sample);
            }
        }

        let report = json!({
            "schema_version": 1,
            "generated_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            "software_version": env!("CARGO_PKG_VERSION"),
            "source_revision": git_revision(),
            "tracked_source_dirty": tracked_source_dirty(),
            "environment": environment(),
            "configuration": config,
            "measurement_definitions": {
                "logical_input_bytes": "sum over postings of UTF-8 keyword bytes plus the 8-byte document identifier",
                "journal_record_bytes_written": "sum of immutable encrypted journal frame file lengths at creation, including the initial checkpoint and later records that are eventually pruned",
                "journal_byte_amplification": "journal_record_bytes_written / logical_input_bytes; application-level journal bytes, not block-device, filesystem, SQLite, or WAL write amplification",
                "retained_journal_bytes": "sum of journal frame file lengths remaining after checkpoint pruning",
                "update_timings": "PersistentClient prepare_add and finish_add wall durations, including serialization, encryption, durable file sync, and the local anchor round trip; SSE server.insert is measured separately",
                "recovery_open_ns": "time inside a fresh child process for UnixAnchorClient creation and PersistentClient::open, including anchor lookup, journal read, authentication, state validation, checkpoint load, and journal replay",
                "recovery_process_total_ns": "parent-observed child process launch, key-pipe delivery, recovery, JSON response, and exit; reported separately from recovery_open_ns",
                "statistical_unit": "index-build trial; repeated fresh-process opens within a trial are nested and are not independent trial samples",
                "bootstrap": "5000 deterministic percentile resamples over index-build trial summaries; seed is 202_610_280_001 + index_size; intervals estimate means of trial-level values",
                "cryptographic_randomness": "OS CSPRNG for client storage keys, index IDs, nonces, and run namespace; synthetic keyword and document identifiers are deterministic enumerations"
            },
            "samples": samples,
            "summary": summarize(&samples, &config.index_sizes)
        });
        let mut file = fs::File::create(output.join("report.json"))?;
        serde_json::to_writer_pretty(&mut file, &report)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(private_work);
        println!("wrote {}", output.join("report.json").display());
        Ok(())
    }

    fn validate_config(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
        let limits = Limits::default();
        if config.schema_version != 1
            || config.index_sizes.is_empty()
            || config.trials == 0
            || config.trials > 100
            || config.recovery_repetitions == 0
            || config.recovery_repetitions > 100
        {
            return Err(invalid(
                "schema_version must be 1; sizes, trials and recovery repetitions must be nonzero; trials <= 100 and recovery repetitions <= 100",
            ));
        }
        let mut seen = BTreeSet::new();
        for &size in &config.index_sizes {
            if size == 0 || size > limits.postings || size > limits.keywords || !seen.insert(size) {
                return Err(invalid(
                    "index_sizes must be unique positive values within the default SSE posting and keyword limits",
                ));
            }
        }
        Ok(())
    }

    fn run_sample(
        socket: &Path,
        current_exe: &Path,
        work: &Path,
        run_prefix: &str,
        trial: usize,
        index_size: usize,
        recovery_repetitions: usize,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let slot = format!("{run_prefix}-{trial}-{index_size}");
        let journal_dir = work.join(format!("trial-{trial}-size-{index_size}"));
        fs::create_dir(&journal_dir)?;
        fs::set_permissions(&journal_dir, fs::Permissions::from_mode(0o700))?;

        let anchor = UnixAnchorClient::sse_journal(socket, &slot)?;
        let mut storage_key = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(&mut *storage_key)?;
        let limits = Limits::default();
        let initialization_start = Instant::now();
        let mut client = PersistentClient::create(&journal_dir, &storage_key, limits, anchor)?;
        let initialization_ns = nanos(initialization_start.elapsed().as_nanos());
        let mut record_bytes_written = 0u64;
        let mut journal_records_written = 0u64;
        let initial_files = journal_files(&journal_dir)?;
        if initial_files.len() != 1 {
            return Err(invalid(
                "new persistent SSE index did not emit exactly one initial checkpoint",
            ));
        }
        record_bytes_written += initial_files.values().copied().sum::<u64>();
        journal_records_written += initial_files.len() as u64;
        let mut checkpoint_generations = vec![0u64];

        let mut server = Server::new(client.index_id(), limits)?;
        let mut prepare_add_ns = Vec::with_capacity(index_size);
        let mut finish_add_ns = Vec::with_capacity(index_size);
        let mut server_insert_ns = Vec::with_capacity(index_size);
        let mut logical_input_bytes = 0u64;
        let build_start = Instant::now();

        for document_id in 0..index_size as u64 {
            let keyword = format!("benchmark-keyword-{document_id:08}");
            logical_input_bytes += keyword.len() as u64 + 8;

            let before_prepare = journal_files(&journal_dir)?;
            let prepare_start = Instant::now();
            let request = client.prepare_add(keyword.as_bytes(), document_id)?;
            prepare_add_ns.push(nanos(prepare_start.elapsed().as_nanos()));
            let after_prepare = journal_files(&journal_dir)?;
            record_bytes_written += emitted_record_bytes(&before_prepare, &after_prepare)?;
            journal_records_written += 1;

            let insert_start = Instant::now();
            let address = server.insert(request)?;
            server_insert_ns.push(nanos(insert_start.elapsed().as_nanos()));

            let before_finish = journal_files(&journal_dir)?;
            let finish_start = Instant::now();
            client.finish_add(address)?;
            finish_add_ns.push(nanos(finish_start.elapsed().as_nanos()));
            let after_finish = journal_files(&journal_dir)?;
            record_bytes_written += emitted_record_bytes(&before_finish, &after_finish)?;
            journal_records_written += 1;
            let generation = client.generation();
            if generation % CHECKPOINT_INTERVAL == 0 {
                checkpoint_generations.push(generation);
            }
        }
        let index_build_ns = nanos(build_start.elapsed().as_nanos());
        let generation = client.generation();
        let retained_files = journal_files(&journal_dir)?;
        let retained_journal_bytes = retained_files.values().copied().sum::<u64>();
        drop(client);

        let mut recovery_open_ns = Vec::with_capacity(recovery_repetitions);
        let mut recovery_process_total_ns = Vec::with_capacity(recovery_repetitions);
        let mut recovery_child_pids = Vec::with_capacity(recovery_repetitions);
        for _ in 0..recovery_repetitions {
            let (open_ns, process_ns, child_pid) = recover_fresh_process(
                current_exe,
                socket,
                &journal_dir,
                &slot,
                generation,
                &storage_key,
            )?;
            recovery_open_ns.push(open_ns);
            recovery_process_total_ns.push(process_ns);
            recovery_child_pids.push(child_pid);
        }

        Ok(json!({
            "trial": trial,
            "index_size": index_size,
            "initialization_ns": initialization_ns,
            "index_build_ns": index_build_ns,
            "logical_input_bytes": logical_input_bytes,
            "generation": generation,
            "journal_records_written": journal_records_written,
            "journal_record_bytes_written": record_bytes_written,
            "journal_byte_amplification": record_bytes_written as f64 / logical_input_bytes as f64,
            "retained_journal_records": retained_files.len(),
            "retained_journal_bytes": retained_journal_bytes,
            "checkpoint_generations": checkpoint_generations,
            "anchor_compare_and_swap_calls": 1 + 2 * index_size,
            "anchor_load_calls_during_recovery": recovery_repetitions,
            "prepare_add_ns": prepare_add_ns,
            "server_insert_ns": server_insert_ns,
            "finish_add_ns": finish_add_ns,
            "recovery_open_ns": recovery_open_ns,
            "recovery_process_total_ns": recovery_process_total_ns,
            "recovery_child_pids": recovery_child_pids
        }))
    }

    fn journal_files(
        directory: &Path,
    ) -> Result<BTreeMap<PathBuf, u64>, Box<dyn std::error::Error>> {
        let mut files = BTreeMap::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "journal")
            {
                let metadata = fs::symlink_metadata(&path)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(invalid("journal directory contains a non-regular record"));
                }
                files.insert(path, metadata.len());
            }
        }
        Ok(files)
    }

    fn emitted_record_bytes(
        before: &BTreeMap<PathBuf, u64>,
        after: &BTreeMap<PathBuf, u64>,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let emitted = after
            .iter()
            .filter(|(path, _)| !before.contains_key(*path))
            .map(|(_, bytes)| *bytes)
            .collect::<Vec<_>>();
        if emitted.len() != 1 {
            return Err(invalid(
                "a successful durable SSE mutation must emit exactly one new immutable journal record",
            ));
        }
        Ok(emitted[0])
    }

    fn recover_fresh_process(
        executable: &Path,
        socket: &Path,
        journal_dir: &Path,
        slot: &str,
        generation: u64,
        storage_key: &[u8; 32],
    ) -> Result<(u64, u64, u64), Box<dyn std::error::Error>> {
        let start = Instant::now();
        let mut child = Command::new(executable)
            .arg("recover")
            .arg(socket)
            .arg(journal_dir)
            .arg(slot)
            .arg(generation.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let child_pid = u64::from(child.id());
        child
            .stdin
            .take()
            .ok_or_else(|| invalid("recovery child stdin was not piped"))?
            .write_all(storage_key)?;
        let output = child.wait_with_output()?;
        let process_ns = nanos(start.elapsed().as_nanos());
        if !output.status.success() {
            return Err(invalid(format!(
                "fresh recovery child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let response: Value = serde_json::from_slice(&output.stdout)?;
        let child_open_ns = response["open_ns"]
            .as_u64()
            .ok_or_else(|| invalid("recovery child omitted open_ns"))?;
        let recovered_generation = response["generation"]
            .as_u64()
            .ok_or_else(|| invalid("recovery child omitted generation"))?;
        let reported_pid = response["pid"]
            .as_u64()
            .ok_or_else(|| invalid("recovery child omitted pid"))?;
        if recovered_generation != generation || reported_pid != child_pid {
            return Err(invalid(
                "fresh recovery child returned unexpected generation or PID",
            ));
        }
        Ok((child_open_ns, process_ns, child_pid))
    }

    fn recover_child(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        if args.len() != 4 {
            return Err(invalid(
                "usage: sse-journal-benchmark recover SOCKET JOURNAL_DIR SLOT EXPECTED_GENERATION",
            ));
        }
        let expected_generation = args[3].parse::<u64>()?;
        let mut storage_key = Zeroizing::new([0u8; 32]);
        io::stdin().read_exact(&mut *storage_key)?;
        let open_start = Instant::now();
        let anchor = UnixAnchorClient::sse_journal(&args[0], &args[2])?;
        let client = PersistentClient::open(&args[1], &storage_key, anchor)?;
        let open_ns = nanos(open_start.elapsed().as_nanos());
        if client.generation() != expected_generation {
            return Err(invalid(
                "recovered client generation did not match expected generation",
            ));
        }
        println!(
            "{}",
            json!({
                "generation": client.generation(),
                "open_ns": open_ns,
                "pid": u64::from(std::process::id())
            })
        );
        Ok(())
    }

    fn summarize(samples: &[Value], index_sizes: &[usize]) -> Vec<Value> {
        index_sizes
            .iter()
            .map(|&index_size| {
                let rows = samples
                    .iter()
                    .filter(|sample| sample["index_size"].as_u64() == Some(index_size as u64))
                    .collect::<Vec<_>>();
                let record_bytes = rows
                    .iter()
                    .filter_map(|row| row["journal_record_bytes_written"].as_f64())
                    .collect::<Vec<_>>();
                let amplification = rows
                    .iter()
                    .filter_map(|row| row["journal_byte_amplification"].as_f64())
                    .collect::<Vec<_>>();
                let prepare = nested_numbers(&rows, "prepare_add_ns");
                let insert = nested_numbers(&rows, "server_insert_ns");
                let finish = nested_numbers(&rows, "finish_add_ns");
                let recovery = nested_numbers(&rows, "recovery_open_ns");
                let recovery_process = nested_numbers(&rows, "recovery_process_total_ns");
                let trial_recovery_medians = rows
                    .iter()
                    .map(|row| {
                        let mut values = row["recovery_open_ns"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_f64)
                            .collect::<Vec<_>>();
                        quantile(&mut values, 0.5)
                    })
                    .collect::<Vec<_>>();
                let build_times = rows
                    .iter()
                    .filter_map(|row| row["index_build_ns"].as_f64())
                    .collect::<Vec<_>>();
                let seed = 202_610_280_001u64 + index_size as u64;
                json!({
                    "index_size": index_size,
                    "trial_count": rows.len(),
                    "journal_record_bytes_written": trial_metric_summary(record_bytes, seed),
                    "journal_byte_amplification": trial_metric_summary(amplification, seed + 1),
                    "index_build_ns": trial_metric_summary(build_times, seed + 2),
                    "prepare_add_ns": quantile_summary(prepare),
                    "server_insert_ns": quantile_summary(insert),
                    "finish_add_ns": quantile_summary(finish),
                    "recovery_open_ns_all_processes_descriptive": quantile_summary(recovery),
                    "recovery_open_trial_median_ns": trial_metric_summary(trial_recovery_medians, seed + 3),
                    "recovery_process_total_ns_descriptive": quantile_summary(recovery_process)
                })
            })
            .collect()
    }

    fn nested_numbers(rows: &[&Value], key: &str) -> Vec<f64> {
        rows.iter()
            .filter_map(|row| row[key].as_array())
            .flatten()
            .filter_map(Value::as_f64)
            .collect()
    }

    fn quantile_summary(mut values: Vec<f64>) -> Value {
        if values.is_empty() {
            return json!({ "count": 0 });
        }
        values.sort_by(f64::total_cmp);
        let count = values.len();
        let mean = values.iter().sum::<f64>() / count as f64;
        json!({
            "count": count,
            "mean": mean,
            "p50": quantile_sorted(&values, 0.50),
            "p95": quantile_sorted(&values, 0.95),
            "p99": quantile_sorted(&values, 0.99)
        })
    }

    fn trial_metric_summary(values: Vec<f64>, seed: u64) -> Value {
        let mut summary = quantile_summary(values.clone());
        if let Some(object) = summary.as_object_mut() {
            object.insert(
                "mean_bootstrap_ci95".to_owned(),
                bootstrap_mean_ci95(&values, seed),
            );
            object.insert("bootstrap_replicates".to_owned(), json!(5000));
            object.insert("bootstrap_seed".to_owned(), json!(seed));
        }
        summary
    }

    fn bootstrap_mean_ci95(values: &[f64], seed: u64) -> Value {
        if values.is_empty() {
            return Value::Null;
        }
        let mut rng = StdRng::seed_from_u64(seed);
        let mut means = Vec::with_capacity(5000);
        for _ in 0..5000 {
            let sum = (0..values.len())
                .map(|_| values[rng.gen_range(0..values.len())])
                .sum::<f64>();
            means.push(sum / values.len() as f64);
        }
        means.sort_by(f64::total_cmp);
        json!([
            quantile_sorted(&means, 0.025),
            quantile_sorted(&means, 0.975)
        ])
    }

    fn quantile(values: &mut [f64], p: f64) -> f64 {
        values.sort_by(f64::total_cmp);
        quantile_sorted(values, p)
    }

    fn quantile_sorted(values: &[f64], p: f64) -> f64 {
        if values.len() == 1 {
            return values[0];
        }
        let position = (values.len() - 1) as f64 * p;
        let lower = position.floor() as usize;
        let upper = position.ceil() as usize;
        let weight = position - lower as f64;
        values[lower] * (1.0 - weight) + values[upper] * weight
    }

    fn environment() -> Value {
        let cpu_model = fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|contents| {
                contents.lines().find_map(|line| {
                    line.strip_prefix("model name\t: ")
                        .or_else(|| line.strip_prefix("Hardware\t: "))
                        .map(str::to_owned)
                })
            });
        let rustc = Command::new("rustc")
            .arg("--version")
            .output()
            .ok()
            .filter(|result| result.status.success())
            .map(|result| String::from_utf8_lossy(&result.stdout).trim().to_owned());
        json!({
            "os": env::consts::OS,
            "architecture": env::consts::ARCH,
            "logical_cpus": std::thread::available_parallelism().ok().map(usize::from),
            "cpu_model": cpu_model,
            "rustc": rustc
        })
    }

    fn git_revision() -> Option<String> {
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|result| result.status.success())
            .map(|result| String::from_utf8_lossy(&result.stdout).trim().to_owned())
    }

    fn tracked_source_dirty() -> Option<bool> {
        Command::new("git")
            .args(["status", "--porcelain", "--untracked-files=no"])
            .output()
            .ok()
            .filter(|result| result.status.success())
            .map(|result| !result.stdout.is_empty())
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn nanos(value: u128) -> u64 {
        u64::try_from(value).unwrap_or(u64::MAX)
    }

    fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error> {
        Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
    }
}

#[cfg(unix)]
fn main() {
    if let Err(error) = unix::run() {
        eprintln!("sse-journal-benchmark: {error}");
        std::process::exit(2);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("sse-journal-benchmark requires Unix-domain sockets");
    std::process::exit(2);
}
