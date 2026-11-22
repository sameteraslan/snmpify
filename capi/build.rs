// The shared library names itself (soname / install name), so programs
// find it by name and rpath instead of by the path it was linked from.
fn main() {
    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("linux") | Ok("freebsd") => {
            println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libsnmpify.so")
        }
        Ok("macos") => {
            println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libsnmpify.dylib")
        }
        _ => {}
    }
}
