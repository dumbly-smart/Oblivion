//! Local process integration demo, not a deployed serverless service.
mod discovery;
mod open_loop;
mod pipeline;
mod secure_pir;
use oblivion_pir::{Database, wire};
use std::{io::Write, net::TcpListener, path::Path};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("pir-worker") => {
            let database = Database::new(pipeline::registry())?;
            let listener = TcpListener::bind("127.0.0.1:0")?;
            println!("{}", listener.local_addr()?);
            std::io::stdout().flush()?;
            for stream in listener.incoming() {
                let mut stream = stream?;
                let _ = wire::serve_connection(&mut stream, &database);
            }
        }
        Some("secure-pir-worker") if args.len() == 3 => secure_pir::serve(args[2].parse()?)?,
        Some("executor-worker") if args.len() == 3 || args.len() == 4 => pipeline::worker(Path::new(&args[2]),args.get(3).map_or(Ok(1),|s|s.parse::<usize>())?)?,
        Some("open-loop") if (5..=6).contains(&args.len()) => open_loop::run(
            Path::new(&args[2]), args[3].parse()?, args[4].parse()?,
            args.get(5).map_or(Ok(4), |value| value.parse())?,
        )?,
        Some("demo-sse") if (3..=6).contains(&args.len()) => pipeline::demo_with_discovery(
            Path::new(&args[2]),
            args.get(3).map_or(Ok(50), |s| s.parse::<u32>())?,
            args.get(4).map_or(Ok(1), |s| s.parse::<usize>())?,
            args.get(5).is_some_and(|s|s=="mixed"),
            true,
        )?,
        Some("demo") if (3..=6).contains(&args.len()) => pipeline::demo(
            Path::new(&args[2]),
            args.get(3).map_or(Ok(50), |s| s.parse::<u32>())?,
            args.get(4).map_or(Ok(1), |s| s.parse::<usize>())?,
            args.get(5).is_some_and(|s|s=="mixed"),
        )?,
        _ => return Err("usage: oblivion-server demo|demo-sse NEW_OUTPUT_DIRECTORY [0|50|100] [1..4 PARTICIPANTS] [mixed]; or open-loop NEW_OUTPUT_DIRECTORY INTERVAL_MS COUNT [QUEUE_CAPACITY]".into()),
    }
    Ok(())
}
