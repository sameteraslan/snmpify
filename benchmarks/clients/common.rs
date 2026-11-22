// Shared by the Rust clients (included with `include!`): arguments and
// the JSON line every client prints.

pub const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
pub const TABLE: &str = "1.3.6.1.4.1.99999.1";
pub const MAX_REP: u32 = 25;
pub const WRITABLE: &str = "1.3.6.1.4.1.99999.3.0";
pub const BULK_REP: u32 = 50;
pub const LINK_DOWN: &str = "1.3.6.1.6.3.1.1.5.3";

pub struct Args {
    pub scenario: String,
    pub host: String,
    pub port: u16,
    pub n: usize,
}

pub fn args() -> Args {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: {} walk|walk3|get|poll HOST PORT N", a[0]);
        std::process::exit(2);
    }
    Args {
        scenario: a[1].clone(),
        host: a[2].clone(),
        port: a[3].parse().unwrap(),
        n: a[4].parse().unwrap(),
    }
}

pub fn report(items: usize, ms: f64, latencies_us: &mut [f64]) {
    let pct = |v: &mut [f64], p: f64| -> f64 {
        if v.is_empty() {
            return 0.0;
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[((v.len() - 1) as f64 * p).round() as usize]
    };
    let p50 = pct(latencies_us, 0.50);
    let p99 = pct(latencies_us, 0.99);
    println!("{{\"items\": {items}, \"ms\": {ms:.3}, \"p50_us\": {p50:.1}, \"p99_us\": {p99:.1}}}");
}

pub fn unsupported() -> ! {
    println!("{{\"unsupported\": true}}");
    std::process::exit(0);
}
