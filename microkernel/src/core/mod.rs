//! Core module for the ForgeOne Microkernel
//!
//! The Core module provides the fundamental functionality for the microkernel,
//! including boot logic, runtime orchestration, and smart scheduling.

pub mod boot;
pub mod runtime;
pub mod scheduler;

// Re-exports
pub use boot::*;
pub use runtime::*;
pub use scheduler::*;
