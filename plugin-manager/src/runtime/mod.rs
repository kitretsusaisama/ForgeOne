//! Runtime module for the ForgeOne Plugin Manager
//!
//! Provides the runtime environment for executing WebAssembly plugins with
//! secure sandboxing and resource limits.

pub mod execution;
pub mod wasmtime_engine;
pub mod wasmer_engine;
pub mod wasm_plugin;

// Re-exports
pub use execution::*;
#[cfg(feature = "wasmtime-runtime")]
pub use wasmtime_engine::*;
#[cfg(feature = "wasmer-runtime")]
pub use wasmer_engine::*;
pub use wasm_plugin::{WasmPlugin, load_wasm_plugin};