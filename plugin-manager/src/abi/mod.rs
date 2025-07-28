//! ABI module for the ForgeOne Plugin Manager
//!
//! Provides the Application Binary Interface (ABI) for communication between
//! the host and WebAssembly plugins.

pub mod vm;

// Re-exports
pub use vm::*;