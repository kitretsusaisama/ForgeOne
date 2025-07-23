//! Build script for the ForgeOne Plugin Manager

fn main() {
    // Check if at least one WebAssembly runtime is enabled
    let wasmtime_enabled = std::env::var("CARGO_FEATURE_WASMTIME_RUNTIME").is_ok();
    let wasmer_enabled = std::env::var("CARGO_FEATURE_WASMER_RUNTIME").is_ok();

    if !wasmtime_enabled && !wasmer_enabled {
        println!(
            "cargo:warning=No WebAssembly runtime enabled. Enable at least one of 'wasmtime-runtime' or 'wasmer-runtime' features."
        );
    }

    // Rerun this build script if Cargo.toml changes
    println!("cargo:rerun-if-changed=Cargo.toml");
}
