//! # ForgeOne Plugin Manager
//!
//! A secure, production-ready plugin system with Zero Trust Architecture (ZTA) enforcement,
//! providing a sandboxed environment for running WebAssembly plugins with strict security
//! policies and comprehensive telemetry.
//!
//! ## Features
//!
//! - **Military-grade ZTA**: All plugins run in a sandboxed environment with strict security policies
//! - **Production-scale modularity**: Plugins are loaded, instantiated, and managed with comprehensive lifecycle management
//! - **File-level clarity**: Clear separation of concerns with modular design
//! - **Optimization-ready**: Performance telemetry and metrics for monitoring and optimization
//! - **Secure ABI bridge**: Safe communication between host and plugins
//! - **Plugin attestation**: Signature and hash verification for plugins
//! - **Secure syscall bus**: Async syscall execution with ZTA enforcement

// Core modules
pub mod abi;
pub mod attestation;
pub use common::error::*;
pub mod extension;
pub mod lifecycle;
pub mod loader;
pub mod manager;
pub mod metrics;
pub mod plugin;
pub mod registry;
pub mod runtime;
pub mod sandbox;
pub mod syscall;

// Re-export common error types
pub use common::error::{ForgeError, Result};

/// Version of the plugin manager
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the plugin manager with default configuration
pub fn init() -> Result<registry::PluginRegistry> {
    // Initialize telemetry
    common::telemetry::init_plugin_metrics()?;

    let registry = registry::PluginRegistry::new();
    tracing::info!(version = VERSION, "ForgeOne Plugin Manager initialized");
    Ok(registry)
}

/// Initialize the plugin manager with custom configuration
pub fn init_with_config(config_path: &str) -> Result<registry::PluginRegistry> {
    // Load configuration
    let config = common::config::load_config(config_path)?;

    // Initialize telemetry
    common::telemetry::init_plugin_metrics()?;

    let registry = registry::PluginRegistry::new_with_config(&config);
    tracing::info!(
        version = VERSION,
        "ForgeOne Plugin Manager initialized with custom configuration"
    );
    Ok(registry)
}
