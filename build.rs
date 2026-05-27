fn main() {
    // Feature detection for target differentiation
    let is_cli = std::env::var("CARGO_FEATURE_CLI").is_ok();
    let is_ffi = std::env::var("CARGO_FEATURE_FFI").is_ok();

    if is_cli {
        println!("cargo:rustc-cfg=gx_cli");
    }
    if is_ffi {
        println!("cargo:rustc-cfg=gx_ffi");
    }
}
