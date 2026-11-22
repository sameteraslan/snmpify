use snmp2::{AsyncSession, Oid, Value};
use std::time::Instant;
fn cpu_ns() -> u64 {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("schedstat")).ok())
        .map(|s| s.split_whitespace().next().unwrap().parse::<u64>().unwrap())
        .sum()
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let root: Vec<u64> = vec![1, 3, 6, 1, 4, 1, 99999, 1];
    let root = Oid::from(root.as_slice()).unwrap().to_owned();
    let mut s = AsyncSession::new_v2c("127.0.0.1:16100", b"public", 0)
        .await
        .unwrap();
    let mut walk = |n: usize| {
        let _ = n;
    };
    walk(0);
    let mut total = 0;
    let (c0, t0) = (cpu_ns(), Instant::now());
    for _ in 0..100 {
        let mut cur = root.clone();
        'w: loop {
            let pdu = s.getbulk(&[&cur], 0, 25).await.unwrap();
            let mut last = None;
            for (name, value) in pdu.varbinds {
                if matches!(value, Value::EndOfMibView) || !name.starts_with(&root) {
                    break 'w;
                }
                total += 1;
                last = Some(name.to_owned());
            }
            match last {
                Some(l) => cur = l,
                None => break,
            }
        }
    }
    println!(
        "snmp2:  {:.1} ms CPU, {:.1} ms wall ({total})",
        (cpu_ns() - c0) as f64 / 1e6,
        t0.elapsed().as_secs_f64() * 1e3
    );
}
