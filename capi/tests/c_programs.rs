//! Builds tests/test.c and tests/test.cpp against the static library and
//! runs them (skipped when no C/C++ compiler is found). The CMake build
//! (CTest) runs them too, and the shared library.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Builds the C library (the lib target is not built for tests) and
/// returns the path of libsnmpify.a, from cargo's JSON messages.
fn static_lib() -> PathBuf {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["build", "-p", "snmpify-c", "--message-format=json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let end = text
        .find("libsnmpify.a\"")
        .expect("libsnmpify.a in cargo's output")
        + "libsnmpify.a".len();
    let start = text[..end].rfind('"').unwrap() + 1;
    PathBuf::from(&text[start..end])
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn build_and_run(compiler: &str, src: &str, std: &str) {
    if !have(compiler) {
        eprintln!("{compiler} not found; skipped");
        return;
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = static_lib();
    assert!(lib.exists(), "{} missing", lib.display());
    let out = std::env::temp_dir().join(format!(
        "snmpify-{}-{}",
        src.replace('.', "-"),
        std::process::id()
    ));
    let mut cmd = Command::new(compiler);
    cmd.arg(format!("-std={std}"))
        .args(["-Wall", "-Wextra", "-Werror", "-I"])
        .arg(dir.join("include"))
        .arg(dir.join("tests").join(src))
        .arg(&lib)
        .arg("-o")
        .arg(&out);
    if cfg!(target_os = "linux") {
        cmd.args(["-lpthread", "-ldl", "-lm"]);
    }
    let st = cmd.status().unwrap();
    assert!(st.success(), "{compiler} failed on {src}");
    let run = Command::new(&out).output().unwrap();
    print!("{}", String::from_utf8_lossy(&run.stdout));
    eprint!("{}", String::from_utf8_lossy(&run.stderr));
    assert!(run.status.success(), "{src} failed");
}

#[test]
fn c_program() {
    build_and_run("cc", "test.c", "c99");
}

#[test]
fn cpp_program() {
    build_and_run("c++", "test.cpp", "c++17");
}
