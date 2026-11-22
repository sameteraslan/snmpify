//! snmpwalk in a few lines.
//!
//!     cargo run --release --example walk -- 127.0.0.1:1161 public 1.3.6.1.2.1.1

use std::time::Instant;

use snmpify::client::{Client, Community};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "127.0.0.1:161".into());
    let community = args.next().unwrap_or_else(|| "public".into());
    let root = args.next().unwrap_or_else(|| "1.3.6.1.2.1".into());

    let client = Client::connect(&target, Community::v2c(community)).await?;
    let t = Instant::now();
    let mut walk = client.walk(root.as_str())?;
    let mut n = 0;
    while let Some(vb) = walk.next().await {
        println!("{}", vb?);
        n += 1;
    }
    eprintln!("{n} objects in {:.1} ms", t.elapsed().as_secs_f64() * 1e3);
    Ok(())
}
