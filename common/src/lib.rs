//! # ForgeOne `common` Crate
//!
//! ## Conscious Substrate (10^17x Class)
//!
//! This crate is the sentient core of ForgeOne, providing a trust-aware, AI-augmented,
//! self-adaptive foundation for enterprise container intelligence.
//!
//! Every function, type, and trace is:
//! * **Contextual** (aware of who, where, why)
//! * **Causal** (tracks origin, intent, and policy path)
//! * **Comprehensible** (LLM-readable, developer-debuggable, auditor-verifiable)
//! * **Cryptographic** (provable, signed, and tamper-evident)
//! * **Resilient** (self-healing, fault-tolerant, and recoverable)

// Re-export all modules for easy access
pub mod audit;
pub mod bootstrap;
pub mod config;
pub mod crypto;
pub mod db;
pub mod diagnostics;
pub mod error;
pub mod identity;
pub mod macros;
pub mod model;
pub mod observer;
pub mod policy;
pub mod prelude;
pub mod syscall_client;
pub mod telemetry;
pub mod trust;
pub use syscall_client::SyscallAPI;

/// Initialize the common crate with default configuration
pub fn init() -> Result<(), error::ForgeError> {
    bootstrap::init()
}

/// Initialize the common crate with custom configuration
pub fn init_with_config(config_path: &str) -> Result<(), error::ForgeError> {
    let config = config::load_config(config_path)?;
    bootstrap::init_with_config(&config)
}

/// Initialize the common crate with database support
pub fn init_with_db(config_path: &str) -> Result<(), error::ForgeError> {
    let config = config::load_config(config_path)?;
    bootstrap::init_with_config(&config)?;

    // Initialize database with default options
    bootstrap::init_db(None)?;

    Ok(())
}

/// Initialize the common crate with database support and custom database options
pub fn init_with_db_options(
    config_path: &str,
    db_options: db::DbOptions,
) -> Result<(), error::ForgeError> {
    let config = config::load_config(config_path)?;
    bootstrap::init_with_config(&config)?;

    // Initialize database with custom options
    bootstrap::init_db(Some(db_options))?;

    Ok(())
}

/// Shutdown the common crate
pub fn shutdown() -> Result<(), error::ForgeError> {
    bootstrap::shutdown()
}
