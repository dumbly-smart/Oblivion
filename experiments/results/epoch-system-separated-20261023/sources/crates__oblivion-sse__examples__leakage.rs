//! Actual bounded GGM SSE leakage exporter. Input is trusted workload JSON.
//! Output is server wire data only; client filtering never enters this stream.
use oblivion_sse::{Client, Limits, Server};
use serde::Deserialize;
use serde_json::json;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

#[derive(Deserialize)]
struct Workload {
    counts: Vec<u64>,
    queries: Vec<Vec<usize>>,
    pad_to: Option<u64>,
    update_order: Vec<(usize, u64)>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input: Workload = serde_json::from_reader(io::stdin())?;
    if input.counts.is_empty() || input.counts.len() > 100 || input.queries.len() > 10 {
        return Err("invalid workload dimensions".into());
    }
    let limits = Limits::default();
    let mut client = Client::new(limits)?;
    let mut server = Server::new(client.index_id(), limits)?;
    let mut out = BufWriter::new(io::stdout().lock());
    let mut seen = vec![0u64; input.counts.len()];
    for &(keyword, offset) in &input.update_order {
        let count = *input.counts.get(keyword).ok_or("invalid update keyword")?;
        let total = input.pad_to.unwrap_or(count);
        if total < count || offset >= total || offset != seen[keyword] {
            return Err("invalid padding or posting order".into());
        }
        seen[keyword] += 1;
        // High bit is a client-only dummy marker inside AEAD plaintext.
        let id = if offset < count {
            offset
        } else {
            offset | (1u64 << 63)
        };
        let request = client.prepare_add(&keyword.to_be_bytes(), id)?;
        let ack = server.insert(request.clone())?;
        client.finish_add(ack)?;
        serde_json::to_writer(&mut out, &json!({"op":"add","request":request,"ack":ack}))?;
        writeln!(out)?;
    }
    for (keyword, &count) in input.counts.iter().enumerate() {
        if seen[keyword] != input.pad_to.unwrap_or(count) {
            return Err("incomplete workload".into());
        }
    }
    for (session, queries) in input.queries.iter().enumerate() {
        for (step, &keyword) in queries.iter().enumerate() {
            let expected = *input.counts.get(keyword).ok_or("invalid query keyword")?;
            let start = Instant::now();
            let (snapshot, request) = client.prepare_search(&keyword.to_be_bytes())?;
            let response = server.search(&request)?;
            let server_ns = start.elapsed().as_nanos();
            let result = client.finish_search(&snapshot, response.clone())?;
            let real: Vec<_> = result.into_iter().filter(|id| id >> 63 == 0).collect();
            if real != (0..expected).collect::<Vec<_>>() {
                return Err("trusted client result verification failed".into());
            }
            let request_json = serde_json::to_vec(&request)?;
            let response_json = serde_json::to_vec(&response)?;
            serde_json::to_writer(
                &mut out,
                &json!({"op":"search","session":session,"step":step,
                "request":request,"response":response,"request_json_bytes":request_json.len(),
                "response_json_bytes":response_json.len(),"server_ns":server_ns}),
            )?;
            writeln!(out)?;
        }
    }
    out.flush()?;
    Ok(())
}
