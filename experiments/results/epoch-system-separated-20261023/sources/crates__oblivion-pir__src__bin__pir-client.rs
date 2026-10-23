use oblivion_pir::{QueryPair, recover, wire};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: pir-client SERVER1 SERVER2 COUNT WIDTH INDEX".into());
    }
    let count: usize = args[3].parse()?;
    let width: usize = args[4].parse()?;
    let index: usize = args[5].parse()?;
    let query = QueryPair::generate(count, index)?;
    let a = wire::request(args[1].parse()?, count, width, &query.first)?;
    let b = wire::request(args[2].parse()?, count, width, &query.second)?;
    // Trusted client output, not a server-visible log.
    let result = recover(&a, &b)?;
    for byte in result {
        print!("{byte:02x}");
    }
    println!();
    Ok(())
}
