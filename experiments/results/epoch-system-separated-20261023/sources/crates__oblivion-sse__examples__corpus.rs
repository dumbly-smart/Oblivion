//! Trusted bounded text-posting driver. Stdout contains actual server wire only.
use oblivion_sse::{Client, Limits, Server};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::io::{self, BufWriter, Read, Write};
use std::time::Instant;

#[derive(Deserialize)]
struct Workload {
    postings: Vec<Vec<u64>>,
    queries: Vec<Vec<usize>>,
    pad_to: Option<usize>,
    update_order: Vec<(usize, usize)>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bound untrusted JSON input as well as parsed dimensions.
    let mut bytes = Vec::new();
    io::stdin().take(4_000_001).read_to_end(&mut bytes)?;
    if bytes.len() > 4_000_000 {
        return Err("input size limit".into());
    }
    let input: Workload = serde_json::from_slice(&bytes)?;
    if input.postings.len() != 8
        || input.queries.is_empty()
        || input.queries.len() > 2
        || input.queries.iter().any(|q| q.is_empty() || q.len() > 128)
    {
        return Err("workload dimensions".into());
    }
    let totals: Vec<_> = input
        .postings
        .iter()
        .map(|p| input.pad_to.unwrap_or(p.len()))
        .collect();
    if totals.iter().any(|total| *total > 100_000)
        || totals.iter().sum::<usize>() > 100_000
        || input.update_order.len() != totals.iter().sum::<usize>()
    {
        return Err("posting limit".into());
    }
    for (p, total) in input.postings.iter().zip(&totals) {
        if *total < p.len()
            || p.iter().any(|id| id >> 63 != 0)
            || p.iter().collect::<HashSet<_>>().len() != p.len()
        {
            return Err("invalid real postings or padding".into());
        }
    }
    let limits = Limits {
        keywords: 8,
        ..Limits::default()
    };
    let mut client = Client::new(limits)?;
    let mut server = Server::new(client.index_id(), limits)?;
    let mut seen = [0usize; 8];
    let mut out = BufWriter::new(io::stdout().lock());
    for &(keyword, offset) in &input.update_order {
        let p = input.postings.get(keyword).ok_or("update keyword")?;
        if offset != seen[keyword] || offset >= totals[keyword] {
            return Err("invalid posting order".into());
        }
        seen[keyword] += 1;
        let id = p
            .get(offset)
            .copied()
            .unwrap_or((offset as u64) | (1u64 << 63));
        let request = client.prepare_add(&keyword.to_be_bytes(), id)?;
        let ack = server.insert(request.clone())?;
        client.finish_add(ack)?;
        serde_json::to_writer(&mut out, &json!({"op":"add", "request":request, "ack":ack}))?;
        writeln!(out)?;
    }
    if seen.as_slice() != totals.as_slice() {
        return Err("incomplete postings".into());
    }
    for (session, queries) in input.queries.iter().enumerate() {
        for (step, &keyword) in queries.iter().enumerate() {
            let expected = input.postings.get(keyword).ok_or("query keyword")?;
            let start = Instant::now();
            let (snapshot, request) = client.prepare_search(&keyword.to_be_bytes())?;
            let response = server.search(&request)?;
            let server_ns = start.elapsed().as_nanos();
            let result = client.finish_search(&snapshot, response.clone())?;
            let real: Vec<_> = result.into_iter().filter(|id| id >> 63 == 0).collect();
            if &real != expected {
                return Err("authenticated corpus posting verification failed".into());
            }
            let request_json_bytes = serde_json::to_vec(&request)?.len();
            let response_json_bytes = serde_json::to_vec(&response)?.len();
            serde_json::to_writer(
                &mut out,
                &json!({"op":"search", "session":session,"step":step,
                "request":request,"response":response,"server_ns":server_ns,
                "request_json_bytes":request_json_bytes,"response_json_bytes":response_json_bytes}),
            )?;
            writeln!(out)?;
        }
    }
    out.flush()?;
    Ok(())
}
