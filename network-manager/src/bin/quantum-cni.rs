//! # Quantum CNI Plugin Binary
//!
//! This binary implements the CNI plugin for the Quantum-Network Fabric Layer.
//! It can be invoked by container runtimes to connect containers to networks.

use common::error::Result;
use network_manager::cni::plugin::cni_main;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    // Run the CNI plugin
    cni_main().await
}