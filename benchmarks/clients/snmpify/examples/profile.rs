//! A sampling profile (SIGPROF, no perf needed) of 300 walks.
use snmpify::client::{Client, Community, Options};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let c = Client::connect("127.0.0.1:16100", Community::v2c("public"))
        .await
        .unwrap()
        .with_options(Options {
            max_repetitions: 25,
            ..Options::default()
        });
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(4999)
        .build()
        .unwrap();
    for _ in 0..300 {
        c.walk_with("1.3.6.1.4.1.99999.1", |vb| {
            std::hint::black_box(vb);
        })
        .await
        .unwrap();
    }
    let report = guard.report().build().unwrap();
    let f = std::fs::File::create(std::env::args().nth(1).unwrap_or("flame.svg".into())).unwrap();
    report.flamegraph(f).unwrap();
    // Self time by function (leaf frames).
    let mut leaf: std::collections::HashMap<String, isize> = Default::default();
    let mut incl: std::collections::HashMap<String, isize> = Default::default();
    let mut total = 0;
    for (frames, count) in report.data.iter() {
        total += *count;
        if let Some(f) = frames.frames.first().and_then(|s| s.first()) {
            *leaf.entry(f.name()).or_default() += *count;
        }
        let mut seen = std::collections::HashSet::new();
        for s in frames.frames.iter().flatten() {
            let n = s.name();
            let short: String = n
                .split("::")
                .filter(|p| !p.starts_with('h') || p.len() != 17)
                .collect::<Vec<_>>()
                .join("::");
            if seen.insert(short.clone()) {
                *incl.entry(short).or_default() += *count;
            }
        }
    }
    let mut v: Vec<_> = leaf.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    println!("total samples {total}\n-- self --");
    for (n, c) in v.iter().take(25) {
        println!(
            "{:5.1}%  {}",
            *c as f64 * 100.0 / total as f64,
            &n[..n.len().min(110)]
        );
    }
    let mut v: Vec<_> = incl
        .into_iter()
        .filter(|(n, _)| n.contains("snmpify"))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    println!("-- inclusive (snmpify) --");
    for (n, c) in v.iter().take(30) {
        println!(
            "{:5.1}%  {}",
            *c as f64 * 100.0 / total as f64,
            &n[..n.len().min(110)]
        );
    }
}
