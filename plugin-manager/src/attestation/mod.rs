//! Attestation module for the ForgeOne Plugin Manager
//!
//! Provides plugin signature and hash verification for ensuring the integrity
//! and authenticity of plugins.

pub mod verify;

// Re-exports
pub use verify::*;