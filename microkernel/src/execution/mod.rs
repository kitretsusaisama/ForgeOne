//! Execution module for the ForgeOne Microkernel
//!
//! The Execution module provides the functionality for executing workloads,
//! including WebAssembly modules, native code, and containers.

pub mod wasm;
pub mod syscall;
pub mod sandbox;

// Re-exports
pub use wasm::*;
pub use syscall::*;
pub use sandbox::*;