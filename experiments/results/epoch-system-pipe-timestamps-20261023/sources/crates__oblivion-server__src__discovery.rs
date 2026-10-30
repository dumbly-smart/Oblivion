//! Trusted-client metadata lookup. The untrusted SSE map receives only protocol
//! objects; discovery intentionally happens before the invocation envelope.
use crate::Result;
use oblivion_sse::{Client, Limits, Server};

pub const NAMES: [&str; 5] = ["echo", "sum", "fibonacci", "hash", "stateful"];

pub struct Discovery {
    client: Client,
    server: Server,
    pub verified: u64,
    pub trace: Vec<serde_json::Value>,
}
impl Discovery {
    pub fn new() -> Result<Self> {
        let limits = Limits {
            postings: 5,
            keywords: 5,
            keyword_bytes: 32,
            epochs_per_keyword: 1,
        };
        let mut client = Client::new(limits)?;
        let mut server = Server::new(client.index_id(), limits)?;
        let mut trace = Vec::new();
        for (id, name) in NAMES.iter().enumerate() {
            let update = client.prepare_add(name.as_bytes(), id as u64)?;
            trace.push(serde_json::json!({"operation":"update","request":&update}));
            client.finish_add(server.insert(update)?)?;
        }
        Ok(Self {
            client,
            server,
            verified: 0,
            trace,
        })
    }
    pub fn select(&mut self, keyword: &str) -> Result<u32> {
        let (snapshot, request) = self.client.prepare_search(keyword.as_bytes())?;
        let response = self.server.search(&request)?;
        self.trace.push(
            serde_json::json!({"operation":"search","request":&request,"response":&response}),
        );
        let ids = self.client.finish_search(&snapshot, response)?;
        // Independent plaintext metadata oracle: never select a requested id
        // without verifying the authenticated search result against deployment.
        let expected = NAMES
            .iter()
            .position(|name| *name == keyword)
            .ok_or("unknown function metadata")? as u64;
        if ids != [expected] {
            return Err("SSE discovery disagrees with metadata oracle".into());
        }
        self.verified += 1;
        Ok(u32::try_from(ids[0])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_search_returns_exact_deployment_ids_and_rejects_missing_keyword() {
        let mut index = Discovery::new().unwrap();
        for (id, name) in NAMES.iter().enumerate() {
            assert_eq!(index.select(name).unwrap(), id as u32);
        }
        assert!(index.select("not-deployed").is_err());
        assert_eq!(index.verified, 5);
    }
}
