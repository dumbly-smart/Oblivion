//! Run `cargo run --release -p oblivion-sse --example measure -- [trace.jsonl]`.
//! Optional JSONL contains full server capabilities/ciphertexts; no client keys.
use oblivion_sse::{Client, Limits, SearchRequest, Server, constrained_eval, leaf_address};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::json;
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Instant,
};

struct Trace {
    output: Option<BufWriter<File>>,
    sequence: u64,
    start: Instant,
}

impl Trace {
    fn event(
        &mut self,
        operation: &str,
        request: serde_json::Value,
        response: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.sequence += 1;
        if let Some(output) = &mut self.output {
            serde_json::to_writer(
                &mut *output,
                &json!({
                    "sequence": self.sequence, "elapsed_ns": self.start.elapsed().as_nanos(),
                    "operation":operation,"request":request,"response":response
                }),
            )?;
            writeln!(output)?;
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1);
    let mut trace = Trace {
        output: path
            .as_ref()
            .map(File::create)
            .transpose()?
            .map(BufWriter::new),
        sequence: 0,
        start: Instant::now(),
    };
    let limits = Limits::default();
    let mut client = Client::new(limits)?;
    let mut server = Server::new(client.index_id(), limits)?;
    let mut random = ChaCha20Rng::seed_from_u64(20261020);
    let start = Instant::now();
    let mut update_ns = Vec::new();
    for id in 0..10_000u64 {
        let keyword = (id % 100).to_be_bytes();
        let tick = Instant::now();
        let request = client.prepare_add(&keyword, id)?;
        let ack = server.insert(request.clone())?;
        client.finish_add(ack)?;
        update_ns.push(tick.elapsed().as_nanos() as u64);
        trace.event(
            "add",
            serde_json::to_value(&request)?,
            json!({"acknowledged_address":ack}),
        )?;
    }
    let build_elapsed_ns = start.elapsed().as_nanos();
    let mut search_measurements = Vec::new();
    for result_count in [0, 1, 10, 100, 1000] {
        let keyword = format!("volume-{result_count}");
        for id in 0..result_count {
            let request = client.prepare_add(keyword.as_bytes(), id)?;
            let ack = server.insert(request.clone())?;
            client.finish_add(ack)?;
            trace.event(
                "add",
                serde_json::to_value(&request)?,
                json!({"acknowledged_address":ack}),
            )?;
        }
        let mut samples = Vec::new();
        let mut request_bytes = 0;
        let mut response_bytes = 0;
        let mut nodes = 0;
        for _ in 0..10 {
            let tick = Instant::now();
            let (snapshot, request) = client.prepare_search(keyword.as_bytes())?;
            let response = server.search(&request)?;
            let ids = client.finish_search(&snapshot, response.clone())?;
            samples.push(tick.elapsed().as_nanos() as u64);
            assert_eq!(ids.len() as u64, result_count);
            request_bytes = serde_json::to_vec(&request)?.len();
            response_bytes = serde_json::to_vec(&response)?.len();
            nodes = request.epochs.iter().map(|e| e.nodes.len()).sum::<usize>();
            trace.event(
                "search",
                serde_json::to_value(&request)?,
                serde_json::to_value(&response)?,
            )?;
        }
        samples.sort_unstable();
        search_measurements.push(json!({"postings":result_count,"median_ns":samples[5],"json_request_bytes":request_bytes,"json_response_bytes":response_bytes,"constraint_nodes":nodes}));
    }

    // Balanced binary challenge. At the beginning of every trial both keyword
    // histories have identical counts. The second update restores that balance.
    let mut retained = Vec::<SearchRequest>::new();
    let mut guesses_correct = 0u64;
    let mut derived_fresh_addresses = 0u64;
    let mut authorized_later = 0u64;
    let mut positive_control_correct = 0u64;
    let trials = 400u64;
    let mut node_count = 0;
    for trial in 0..trials {
        let candidates = [b"challenge-a".as_slice(), b"challenge-b".as_slice()];
        let mut tags = Vec::new();
        for keyword in candidates {
            let (_, request) = client.prepare_search(keyword)?;
            tags.push(request.tag);
            node_count += request.epochs.iter().map(|e| e.nodes.len()).sum::<usize>();
            let response = server.search(&request)?;
            trace.event(
                "search",
                serde_json::to_value(&request)?,
                serde_json::to_value(&response)?,
            )?;
            retained.push(request);
        }
        let target = random.gen_range(0usize..2);
        // Deliberately leaky baseline, evaluated separately from the protected
        // request: append the already-known search tag to the update header.
        let leaked_tag = tags[target];
        let recovered_class = tags.iter().position(|tag| *tag == leaked_tag);
        positive_control_correct += u64::from(recovered_class == Some(target));
        let request = client.prepare_add(candidates[target], trial)?;
        // The attacker has ALL past requests. On this next counter each one
        // must refuse evaluation. No API predicate is treated as a proof.
        let found = retained.iter().any(|old| {
            old.epochs.iter().any(|epoch| {
                constrained_eval(&epoch.nodes, trial)
                    .ok()
                    .is_some_and(|leaf| leaf_address(&leaf) == request.address)
            })
        });
        derived_fresh_addresses += u64::from(found);
        // Without a capability match this deliberately simple attacker guesses.
        guesses_correct += u64::from(random.gen_range(0usize..2) == target);
        let ack = server.insert(request.clone())?;
        client.finish_add(ack)?;
        trace.event(
            "add",
            serde_json::to_value(&request)?,
            json!({"acknowledged_address":ack}),
        )?;
        let (_, next) = client.prepare_search(candidates[target])?;
        let seed = constrained_eval(&next.epochs[0].nodes, trial)?;
        authorized_later += u64::from(leaf_address(&seed) == request.address);
        let response = server.search(&next)?;
        trace.event(
            "search",
            serde_json::to_value(&next)?,
            serde_json::to_value(&response)?,
        )?;
        node_count += next.epochs.iter().map(|e| e.nodes.len()).sum::<usize>();
        retained.push(next);
        let request = client.prepare_add(candidates[1 - target], trial)?;
        let ack = server.insert(request.clone())?;
        client.finish_add(ack)?;
        trace.event(
            "add",
            serde_json::to_value(&request)?,
            json!({"acknowledged_address":ack}),
        )?;
    }
    if let Some(output) = &mut trace.output {
        output.flush()?;
    }
    update_ns.sort_unstable();
    // Wilson interval for this specific guessing experiment only.
    let n = trials as f64;
    let p = guesses_correct as f64 / n;
    let z = 1.959963984540054;
    let center = (p + z * z / (2.0 * n)) / (1.0 + z * z / n);
    let radius = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt() / (1.0 + z * z / n);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "scheme":"bounded GGM SSE; ephemeral; no formal adaptive proof",
            "workload_seed":20261020,"build_postings":10000,"build_elapsed_ns_including_optional_trace":build_elapsed_ns,
            "update_median_ns":update_ns[update_ns.len()/2],"update_p99_ns":update_ns[update_ns.len()*99/100],
            "stored_postings":server.posting_count(),"crypto_bytes_per_posting":56,
            "update_logical_bytes_including_version_and_index":73,
            "searches":search_measurements,"challenge_trials":trials,"chance_accuracy":0.5,
            "attacker":"retain all constraints; test fresh counter then random guess",
            "retained_search_requests":retained.len(),"retained_constraint_nodes":node_count,
            "fresh_address_capability_matches":derived_fresh_addresses,
            "guess_correct":guesses_correct,"guess_accuracy":p,"guess_wilson_95":[center-radius,center+radius],
            "matching_addresses_after_next_search":authorized_later,
            "stable_tag_on_update_positive_control_correct":positive_control_correct,
            "stable_tag_on_update_positive_control_accuracy":positive_control_correct as f64/n,
            "positive_control_basis":"attaching the known tag reveals class exactly; root-disclosure positive control runs in unit tests",
            "trace_path":path,"trace_contains":"server wire requests/responses, including all released constraint seeds; no plaintext keyword or id fields",
            "limitation":"chance guessing is a regression experiment, not cryptographic evidence or a security theorem"
        }))?
    );
    Ok(())
}
