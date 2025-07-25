//! # ForgeOne Quantum-Grade HyperContainer Runtime
//!
//! A system engineered with Zero Trust Architecture, Quantum-Aware compute, and
//! ultra-scale modular engineering. This runtime provides a secure, scalable, and
//! high-performance container execution environment.
//!
//! ## Features
//!
//! - **Modular Execution Engine**: Support for WASM, Native, MicroVM, and future AI agents
//! - **ZTA-Native Contracts**: Every container has its trust signature and runtime DNA
//! - **Secure Image Format**: OCI + ForgePkg + Encrypted Snapshots
//! - **Self-Aware Containers**: Each container introspects its lifecycle
//! - **Agent Scheduler Compatible**: Integrates with dynamic multi-agent runtime
//! - **Forensic Tracing**: Full trace from spawn → syscall → response
//! - **Inter-Container RPC**: MessageBus abstraction over async IPC
//! - **Per-Container Prometheus Metrics**: Isolation-level observability
//! - **Hot Reloadable**: Controlled rolling runtime reload

// Core modules
// pub mod abi;
pub mod attestation;
pub mod config;
pub mod contract;
pub mod dna;
pub mod engine;
pub mod fs;
pub mod lifecycle;
pub mod mesh;
pub mod metrics;
pub mod network;
pub mod plugin_bridge;
pub mod registry;
pub mod rpc;
pub mod runtime;
pub mod scheduler;
pub mod state;
pub mod tracing;

// Re-export common error types
pub use common::error::{ForgeError, Result};

/// Version of the container runtime
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the container runtime with default configuration
pub fn init() -> Result<runtime::RuntimeContext> {
    let runtime_context = runtime::init()?;
    Ok(runtime_context)
}

/// Initialize the container runtime with custom configuration
pub fn init_with_config(config_path: &str) -> Result<runtime::RuntimeContext> {
    let config = config::load_config(Some(config_path), None)?;
    let runtime_context = runtime::init_with_config(&config)?;
    Ok(runtime_context)
}

/// Shutdown the container runtime
pub fn shutdown() -> Result<()> {
    runtime::shutdown()?;
    Ok(())
}

/// Create a new container from an image
pub fn create_container(
    image_path: &str,
    container_id: Option<&str>,
    config: Option<&config::ContainerConfig>,
) -> Result<String> {
    registry::create_container(image_path, container_id, config)
}

/// Start a container
pub fn start_container(container_id: &str) -> Result<()> {
    lifecycle::start_container(container_id)
}

/// Stop a container
pub fn stop_container(container_id: &str) -> Result<()> {
    lifecycle::stop_container(container_id)
}

/// Pause a container
pub fn pause_container(container_id: &str) -> Result<()> {
    lifecycle::pause_container(container_id)
}

/// Resume a container
pub fn resume_container(container_id: &str) -> Result<()> {
    lifecycle::resume_container(container_id)
}

/// Remove a container
pub fn remove_container(container_id: &str) -> Result<()> {
    lifecycle::remove_container(container_id)
}

/// Get container status
pub fn get_container_status(container_id: &str) -> Result<lifecycle::ContainerState> {
    lifecycle::get_container_status(container_id)
}

/// List all containers
pub fn list_containers() -> Result<Vec<String>> {
    Ok(registry::list_containers()?
        .into_iter()
        .map(|r| r.id)
        .collect())
}

/// Get container metrics
pub fn get_container_metrics(container_id: &str) -> Result<metrics::ContainerMetrics> {
    metrics::get_container_metrics(container_id)
}

// /// Send a message to a container
// pub fn send_message(container_id: &str, message: &[u8]) -> Result<()> {
//     rpc::send_message(container_id, message)
// }
